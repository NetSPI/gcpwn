from __future__ import annotations

from typing import Any

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)


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
