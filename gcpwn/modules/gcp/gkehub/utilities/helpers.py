from __future__ import annotations

import time
from typing import Any

import requests as _rlib

from google.api_core.exceptions import GoogleAPICallError, PermissionDenied
from google.cloud import gkehub_v1

from gcpwn.core.resource import RestListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    extract_project_id_from_resource,
)


# ---------------------------------------------------------------------------
# Fleet membership resource
# ---------------------------------------------------------------------------

class GkehubMembershipsResource(RestListResource):
    """Fleet memberships — clusters enrolled in a GKE Hub Fleet."""

    SERVICE_LABEL = "GKE Hub"
    TABLE_NAME = "gkehub_memberships"
    COLUMNS = ["location", "membership_id", "name", "state", "cluster_link",
               "create_time", "update_time", "description"]
    ACTION_RESOURCE_TYPE = "memberships"
    LIST_PERMISSION = "gkehub.memberships.list"
    GET_PERMISSION = "gkehub.memberships.get"
    ID_FIELD = "membership_id"

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        try:
            client = gkehub_v1.GkeHubClient(credentials=self.session.credentials)
            pager = client.list_memberships(parent=f"projects/{project_id}/locations/-")
            rows = []
            for m in pager:
                ep = m.endpoint.gke_cluster if m.endpoint else None
                rows.append({
                    "name": m.name,
                    "description": m.description or "",
                    "state": m.state.code.name if m.state else "",
                    "cluster_link": ep.resource_link if ep else "",
                    "create_time": str(m.create_time)[:19] if m.create_time else "",
                    "update_time": str(m.update_time)[:19] if m.update_time else "",
                })
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except PermissionDenied:
            return []
        except GoogleAPICallError:
            return []

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "membership_id": extract_path_tail(str(raw.get("name", "") or "")),
        }


# ---------------------------------------------------------------------------
# Fleet scopes resource
# ---------------------------------------------------------------------------

class GkehubScopesResource(RestListResource):
    """Fleet scopes — named groupings of memberships, always at location/global."""

    SERVICE_LABEL = "GKE Hub"
    TABLE_NAME = "gkehub_scopes"
    COLUMNS = ["scope_id", "name", "state", "create_time"]
    ACTION_RESOURCE_TYPE = "scopes"
    LIST_PERMISSION = "gkehub.scopes.list"
    GET_PERMISSION = "gkehub.scopes.get"
    ID_FIELD = "scope_id"

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        try:
            client = gkehub_v1.GkeHubClient(credentials=self.session.credentials)
            pager = client.list_scopes(parent=f"projects/{project_id}/locations/-")
            rows = []
            for s in pager:
                rows.append({
                    "name": s.name,
                    "state": s.state.code.name if s.state else "",
                    "create_time": str(s.create_time)[:19] if s.create_time else "",
                })
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except PermissionDenied:
            return []
        except GoogleAPICallError:
            return []

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "scope_id": extract_path_tail(str(raw.get("name", "") or "")),
        }


# ---------------------------------------------------------------------------
# Fleet RBAC role bindings resource  (NESTED under scopes)
# ---------------------------------------------------------------------------

class GkehubRbacBindingsResource(RestListResource):
    """Fleet RBAC role bindings — per-scope K8s RBAC grants for GCP identities.

    Column ``group_user`` avoids the SQL reserved word ``group``.
    """

    SERVICE_LABEL = "GKE Hub"
    TABLE_NAME = "gkehub_rbac_bindings"
    COLUMNS = ["scope_name", "binding_id", "name", "user", "group_user",
               "predefined_role", "state"]
    ACTION_RESOURCE_TYPE = "rbacrolebindings"
    LIST_PERMISSION = "gkehub.rbacrolebindings.list"
    GET_PERMISSION = "gkehub.rbacrolebindings.get"
    ID_FIELD = "binding_id"

    def list(self, *, project_id: str | None = None, location: str | None = None,
             parent: str | None = None, action_dict=None, **kwargs):
        if parent and not project_id:
            project_id = extract_project_id_from_resource(
                parent,
                fallback_project=getattr(self.session, "project_id", "") or "",
            )
        try:
            client = gkehub_v1.GkeHubClient(credentials=self.session.credentials)
            pager = client.list_scope_rbac_role_bindings(parent=parent)
            rows = []
            for r in pager:
                rows.append({
                    "name": r.name,
                    "user": r.user or "",
                    "group_user": r.group or "",
                    "predefined_role": r.role.predefined_role.name if r.role else "",
                    "state": r.state.code.name if r.state else "",
                })
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except PermissionDenied:
            return []
        except GoogleAPICallError:
            return []

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = str(raw.get("name", "") or "")
        parts = name.split("/rbacrolebindings/")
        scope_name = parts[0] if len(parts) == 2 else ""
        return {
            "binding_id": extract_path_tail(name),
            "scope_name": scope_name,
        }


# ---------------------------------------------------------------------------
# Connect Gateway helpers (used by the exploit module)
# These are inherently raw HTTP — they tunnel Kubernetes API calls through
# the Connect Gateway proxy, which has no GAPIC equivalent.
# ---------------------------------------------------------------------------

def gateway_base_url(region: str, project_number: str, membership_name: str) -> str:
    """Return the Connect Gateway base URL for a fleet membership."""
    short_name = extract_path_tail(membership_name)
    host = f"https://{region}-connectgateway.googleapis.com"
    return (
        f"{host}/v1beta1/projects/{project_number}"
        f"/locations/{region}/gkeMemberships/{short_name}"
    )


def gw_request(
    method: str,
    url: str,
    token: str,
    *,
    body: Any = None,
    content_type: str = "application/json",
    timeout: int = 30,
) -> tuple[int, Any]:
    """One authenticated request to the Connect Gateway (or any k8s-style API).

    Returns (status_code, response_body_dict_or_text) — never raises on non-2xx.
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": content_type}
    try:
        if content_type == "application/json":
            resp = _rlib.request(
                str(method or "GET").upper(),
                url,
                headers=headers,
                json=body,
                timeout=timeout,
            )
        else:
            import json as _json
            body_data = _json.dumps(body) if body is not None else None
            resp = _rlib.request(
                str(method or "GET").upper(),
                url,
                headers=headers,
                data=body_data,
                timeout=timeout,
            )
    except Exception as exc:
        return 0, {"error": str(exc)}
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"_raw": resp.text[:800]}


def poll_pod_phase(
    gw_base: str,
    token: str,
    namespace: str,
    pod_name: str,
    *,
    timeout: int = 300,
    interval: int = 10,
) -> tuple[str, str]:
    """Poll a pod via the Connect Gateway until it reaches a terminal phase."""
    url = f"{gw_base}/api/v1/namespaces/{namespace}/pods/{pod_name}"
    deadline = time.time() + timeout
    phase = "Unknown"
    reason = ""
    while time.time() < deadline:
        status_code, data = gw_request("GET", url, token)
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            phase_val = (data.get("status") or {}).get("phase", "Unknown")
            reason_val = (data.get("status") or {}).get("reason", "")
            if phase_val:
                phase = phase_val
                reason = reason_val
        print(
            f"  [pod] {pod_name}: phase={phase}"
            + (f" ({reason})" if reason else ""),
            flush=True,
        )
        if phase in ("Succeeded", "Failed"):
            return phase, reason
        if status_code == 404:
            return "NotFound", ""
        time.sleep(interval)
    return phase, reason


def fetch_pod_logs(
    gw_base: str,
    token: str,
    namespace: str,
    pod_name: str,
    container: str = "pwn",
) -> str:
    """Retrieve pod logs via the Connect Gateway log subresource."""
    url = f"{gw_base}/api/v1/namespaces/{namespace}/pods/{pod_name}/log"
    params = {"container": container}
    try:
        headers = {"Authorization": f"Bearer {token}"}
        resp = _rlib.get(url, headers=headers, params=params, timeout=30)
        return resp.text or ""
    except Exception as exc:
        return f"[log-fetch error: {exc}]"


def delete_pod(
    gw_base: str,
    token: str,
    namespace: str,
    pod_name: str,
) -> None:
    """Best-effort pod deletion via the Connect Gateway."""
    url = f"{gw_base}/api/v1/namespaces/{namespace}/pods/{pod_name}"
    try:
        gw_request("DELETE", url, token)
    except Exception:
        pass
