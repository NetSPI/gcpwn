from __future__ import annotations

import json
from typing import Any, Iterable

from google.cloud.logging_v2 import types
from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
from google.cloud.logging_v2.services.logging_service_v2 import LoggingServiceV2Client
from google.cloud.logging_v2.services.metrics_service_v2 import MetricsServiceV2Client

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import DownloadBudget, handle_service_error

# Default per-log cap when --download is used, so 50+ logs never hold everything up.
DEFAULT_DOWNLOAD_LIMIT = 1000


def _config(session):
    return ConfigServiceV2Client(credentials=session.credentials)


def _logging(session):
    return LoggingServiceV2Client(credentials=session.credentials)


def _metrics(session):
    return MetricsServiceV2Client(credentials=session.credentials)


def _err(session, exc, api_name, resource_name):
    handle_service_error(exc, api_name=api_name, resource_name=resource_name, service_label="Cloud Logging")


def list_sinks(session, project_id: str) -> list[dict[str, Any]]:
    """Log export sinks -- ``destination`` is an exfil/persistence target and
    ``writer_identity`` is the SA that writes there (both high-signal)."""
    rows: list[dict[str, Any]] = []
    try:
        for sink in _config(session).list_sinks(request=types.ListSinksRequest(parent=f"projects/{project_id}")):
            data = resource_to_dict(sink)
            name = str(data.get("name") or "")
            rows.append({
                "name": name,
                "sink_id": extract_path_tail(name),
                "destination": str(data.get("destination") or ""),
                "filter": str(data.get("filter") or ""),
                "writer_identity": str(data.get("writer_identity") or data.get("writerIdentity") or ""),
                "disabled": "yes" if data.get("disabled") else "no",
                "include_children": "yes" if (data.get("include_children") or data.get("includeChildren")) else "no",
                "raw_json": json.dumps(data, default=str),
            })
    except Exception as exc:
        _err(session, exc, "logging.sinks.list", f"projects/{project_id}")
        return []
    return rows


def list_buckets(session, project_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for bucket in _config(session).list_buckets(
            request=types.ListBucketsRequest(parent=f"projects/{project_id}/locations/-")
        ):
            data = resource_to_dict(bucket)
            name = str(data.get("name") or "")
            rows.append({
                "name": name,
                "bucket_id": extract_path_tail(name),
                "retention_days": str(data.get("retention_days") or data.get("retentionDays") or ""),
                "locked": "yes" if data.get("locked") else "no",
                "lifecycle_state": str(data.get("lifecycle_state") or data.get("lifecycleState") or ""),
                "raw_json": json.dumps(data, default=str),
            })
    except Exception as exc:
        _err(session, exc, "logging.buckets.list", f"projects/{project_id}")
        return []
    return rows


def list_log_names(session, project_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for log_name in _logging(session).list_logs(request=types.ListLogsRequest(parent=f"projects/{project_id}")):
            rows.append({"log_name": str(log_name), "raw_json": json.dumps({"logName": str(log_name)})})
    except Exception as exc:
        _err(session, exc, "logging.logs.list", f"projects/{project_id}")
        return []
    return rows


def list_metrics(session, project_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for metric in _metrics(session).list_log_metrics(
            request=types.ListLogMetricsRequest(parent=f"projects/{project_id}")
        ):
            data = resource_to_dict(metric)
            name = str(data.get("name") or "")
            rows.append({
                "name": name,
                "metric_id": extract_path_tail(name),
                "filter": str(data.get("filter") or ""),
                "disabled": "yes" if data.get("disabled") else "no",
                "raw_json": json.dumps(data, default=str),
            })
    except Exception as exc:
        _err(session, exc, "logging.logMetrics.list", f"projects/{project_id}")
        return []
    return rows


def download_log_entries(
    session,
    project_id: str,
    *,
    log_names: Iterable[str],
    per_log_limit: int = DEFAULT_DOWNLOAD_LIMIT,
    output: str | None = None,
) -> list[str]:
    """Download up to ``per_log_limit`` newest entries PER log to one JSON file each.

    Bounded by design: each log fetches at most ``per_log_limit`` entries (page_size
    capped at 1000), so even 50+ logs stay fast. Returns the file paths written.
    """
    limit = max(1, int(per_log_limit or DEFAULT_DOWNLOAD_LIMIT))
    client = _logging(session)
    written: list[str] = []
    budget = DownloadBudget(session, label="log entries")
    for log_name in log_names:
        if budget.exceeded():  # per-type --download-timeout cap: stop and move on
            break
        log_name = str(log_name or "").strip()
        if not log_name:
            continue
        # Strip double-quotes so a user-supplied --logs value can't break out of the
        # filter string; legitimate log names never contain quotes.
        safe_log_name = log_name.replace('"', "")
        entries: list[dict[str, Any]] = []
        try:
            request = types.ListLogEntriesRequest(
                resource_names=[f"projects/{project_id}"],
                filter=f'logName="{safe_log_name}"',
                order_by="timestamp desc",
                page_size=min(limit, 1000),
            )
            for entry in client.list_log_entries(request=request):
                entries.append(resource_to_dict(entry))
                if len(entries) >= limit:
                    break
        except Exception as exc:
            _err(session, exc, "logging.logEntries.list", log_name)
            continue
        if not entries:
            continue
        # Keep only filename-safe chars from the log's tail (defends the download path).
        short = "".join(c for c in log_name.split("/")[-1] if c.isalnum() or c in "._-") or "log"
        destination = resolve_download_path(session, service_name="logging", project_id=project_id, filename=f"logging_{short}_entries.json", output=output)
        destination.write_text(json.dumps(entries, indent=2, default=str), encoding="utf-8")
        written.append(str(destination))
    return written
