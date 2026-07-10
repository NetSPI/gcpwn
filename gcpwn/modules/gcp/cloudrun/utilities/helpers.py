from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_segment,
    extract_path_tail,
    region_resolver_for,
)
from gcpwn.core.utils.service_runtime import DownloadBudget


resolve_regions = region_resolver_for("cloudrun")


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_lines(value: Any, *, indent: int = 0) -> list[str]:
    prefix = " " * max(0, int(indent))
    if isinstance(value, dict):
        if not value:
            return [prefix + "{}"]
        lines: list[str] = []
        for key, item in value.items():
            key_text = json.dumps(str(key), ensure_ascii=False)
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key_text}:")
                lines.extend(_yaml_lines(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}{key_text}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [prefix + "[]"]
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(prefix + "-")
                lines.extend(_yaml_lines(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [prefix + _yaml_scalar(value)]


def _to_yaml_text(payload: Any) -> str:
    return "\n".join(_yaml_lines(payload)) + "\n"


def _extract_revision_env_snapshot(revision_row: dict[str, Any], *, project_id: str) -> dict[str, Any]:
    """Pull per-container env vars (literal values + value_source refs) out of a revision row.

    Tolerates both the flat ``containers`` shape and the nested ``template.containers``
    shape, and both proto (``value_source``) and JSON (``valueSource``) key spellings.
    Returns a dict tagged ``kind: CloudRunRevisionEnvSnapshot`` ready to serialize to YAML;
    containers with no env entries are dropped. WHY: surfaces secrets/config leaked via
    Cloud Run service environment variables.
    """
    revision_name = str(revision_row.get("name") or "").strip()
    location = extract_location_from_resource_name(revision_name)
    service_id = extract_path_segment(revision_name, "services")
    revision_id = extract_path_segment(revision_name, "revisions") or extract_path_tail(revision_name, default="revision")

    container_rows = revision_row.get("containers")
    if not isinstance(container_rows, list):
        template = revision_row.get("template")
        if isinstance(template, dict):
            nested = template.get("containers")
            container_rows = nested if isinstance(nested, list) else []
        else:
            container_rows = []

    containers: list[dict[str, Any]] = []
    for idx, container in enumerate(container_rows):
        if not isinstance(container, dict):
            continue
        env_rows = container.get("env")
        if not isinstance(env_rows, list):
            env_rows = []

        env_entries: list[dict[str, Any]] = []
        for env in env_rows:
            if not isinstance(env, dict):
                continue
            entry: dict[str, Any] = {}
            env_name = str(env.get("name") or "").strip()
            if env_name:
                entry["name"] = env_name
            if "value" in env:
                entry["value"] = env.get("value")
            value_source = env.get("value_source")
            if value_source is None:
                value_source = env.get("valueSource")
            if value_source not in (None, "", {}):
                entry["value_source"] = value_source
            if entry:
                env_entries.append(entry)

        if not env_entries:
            continue
        containers.append(
            {
                "name": str(container.get("name") or "").strip() or f"container-{idx}",
                "image": str(container.get("image") or "").strip(),
                "env": env_entries,
            }
        )

    return {
        "kind": "CloudRunRevisionEnvSnapshot",
        "project_id": str(project_id or "").strip(),
        "location": location,
        "service_id": service_id,
        "revision_id": revision_id,
        "revision_name": revision_name,
        "containers": containers,
    }


class _CloudRunResource(GcpListResource):
    SERVICE_LABEL = "Cloud Run"
    CLIENT_ATTR = ""  # attribute on google.cloud.run_v2

    def _build_client(self, session):
        try:
            from google.cloud import run_v2  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Run enumeration requires the `google-cloud-run` package."
            ) from exc
        return getattr(run_v2, self.CLIENT_ATTR)(credentials=session.credentials)


class CloudRunServicesResource(_CloudRunResource):
    """Enumerate Cloud Run services per location into ``cloudrun_services`` (url/ingress/latest revision)."""

    TABLE_NAME = "cloudrun_services"
    COLUMNS = ["location", "service_id", "name", "url", "ingress", "latest_ready_revision"]
    ACTION_RESOURCE_TYPE = "services"
    LIST_PERMISSION = "run.services.list"
    LIST_API_NAME = "run.projects.locations.services.list"
    GET_PERMISSION = "run.services.get"
    GET_API_NAME = "run.projects.locations.services.get"
    TEST_IAM_API_NAME = "run.services.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("run.services.")
    CLIENT_ATTR = "ServicesClient"
    LIST_METHOD = "list_services"
    GET_METHOD = "get_service"
    ID_FIELD = "service_id"

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "url": raw.get("uri") or "",
            "ingress": raw.get("ingress") or "",
            "latest_ready_revision": raw.get("latest_ready_revision") or "",
        }


class CloudRunRevisionsResource(_CloudRunResource):
    """List/fetch Cloud Run revisions (under a parent service) to download their env config.

    Not persisted to a table; listing is gated by ``run.revisions.list`` on the parent
    service (LIST_RESOURCE_TYPE='services'). Used purely to harvest env-var snapshots.
    """

    # Revisions are listed/fetched (for env download) but not persisted to a table.
    ACTION_RESOURCE_TYPE = "revisions"
    LIST_PERMISSION = "run.revisions.list"
    LIST_RESOURCE_TYPE = "services"  # listing revisions is a permission on the service
    LIST_API_NAME = "run.projects.locations.services.revisions.list"
    GET_PERMISSION = "run.revisions.get"
    GET_API_NAME = "run.projects.locations.services.revisions.get"
    CLIENT_ATTR = "RevisionsClient"
    LIST_METHOD = "list_revisions"
    GET_METHOD = "get_revision"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent service

    def _revision_env_download_budget(self) -> DownloadBudget:
        # Lazily created once per resource instance (the caller constructs one
        # CloudRunRevisionsResource per project run and calls download_env_yaml per
        # revision in a loop), so this caps total wall-clock time for the
        # "cloud run revision env" download type without a caller-threaded budget.
        budget = getattr(self, "_download_budget", None)
        if budget is None:
            budget = DownloadBudget(self.session, label="cloud run revision env")
            self._download_budget = budget
        return budget

    def download_env_yaml(self, *, revision_row: dict[str, Any], project_id: str) -> Path | None:
        """Write a revision's env-var snapshot to a YAML file under the loot dir; return its path.

        Returns None when the row is empty, has no name, or exposes no env vars (nothing
        worth saving), or once this instance's --download-timeout budget for
        "cloud run revision env" is spent. Side effect: writes a file via
        session.get_download_save_path.
        """
        if self._revision_env_download_budget().exceeded():
            return None
        if not isinstance(revision_row, dict) or not revision_row:
            return None
        revision_name = str(revision_row.get("name") or "").strip()
        if not revision_name:
            return None
        snapshot = _extract_revision_env_snapshot(revision_row, project_id=project_id)
        if not list(snapshot.get("containers") or []):
            return None
        filename = compact_filename_component(
            f"{snapshot.get('location')}_{snapshot.get('service_id')}_{snapshot.get('revision_id')}_env.yaml"
        )
        destination = self.session.get_download_save_path(
            service_name="cloudrun",
            project_id=project_id,
            subdirs=["revisions"],
            filename=filename,
        )
        destination.write_text(_to_yaml_text(snapshot), encoding="utf-8")
        return destination


class CloudRunJobsResource(_CloudRunResource):
    """Enumerate Cloud Run jobs per location into the ``cloudrun_jobs`` table."""

    TABLE_NAME = "cloudrun_jobs"
    COLUMNS = ["location", "job_id", "name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "run.jobs.list"
    LIST_API_NAME = "run.projects.locations.jobs.list"
    GET_PERMISSION = "run.jobs.get"
    GET_API_NAME = "run.projects.locations.jobs.get"
    TEST_IAM_API_NAME = "run.jobs.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("run.jobs.")
    CLIENT_ATTR = "JobsClient"
    LIST_METHOD = "list_jobs"
    GET_METHOD = "get_job"
    ID_FIELD = "job_id"
