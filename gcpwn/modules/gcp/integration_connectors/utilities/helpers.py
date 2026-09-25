from __future__ import annotations

import json as _json

import requests as _rlib

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.service_runtime import get_bearer_token
from gcpwn.core.utils.module_helpers import (
    extract_project_id_from_resource,
    static_locations,
)

_CONN_BASE = "https://connectors.googleapis.com/v1"

_DEFAULT_REGIONS = static_locations("connectors")

_CONN_LIST_PERMISSION = "connectors.connections.list"
_CONN_PERMISSIONS = tuple(permissions_with_prefixes("connectors.connections."))


# ── REST helpers (used by ConnectionsResource and exploit) ─────────────────────

def list_connections(token: str, project_id: str, region: str) -> list[dict]:
    url = f"{_CONN_BASE}/projects/{project_id}/locations/{region}/connections"
    headers = {"Authorization": f"Bearer {token}"}
    results = []
    page_token = None
    while True:
        params: dict = {"pageSize": 100}
        if page_token:
            params["pageToken"] = page_token
        resp = _rlib.get(url, headers=headers, params=params, timeout=20)
        if resp.status_code != 200:
            break
        data = resp.json()
        results.extend(data.get("connections", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return results


def get_connection(token: str, name: str) -> dict | None:
    headers = {"Authorization": f"Bearer {token}"}
    resp = _rlib.get(f"{_CONN_BASE}/{name}", headers=headers, timeout=20)
    if resp.status_code == 200:
        return resp.json()
    return None


def create_connection(token: str, project_id: str, region: str, conn_id: str, body: dict) -> tuple[int, dict]:
    url = f"{_CONN_BASE}/projects/{project_id}/locations/{region}/connections"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = _rlib.post(url, headers=headers, json=body, params={"connectionId": conn_id}, timeout=30)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"_raw": resp.text[:600]}


def delete_connection(token: str, name: str) -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {token}"}
    resp = _rlib.delete(f"{_CONN_BASE}/{name}", headers=headers, timeout=30)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"_raw": resp.text[:300]}


def _normalize_connection(c: dict, location: str) -> dict:
    name = c.get("name", "")
    connection_id = name.rsplit("/", 1)[-1] if "/" in name else name
    cv = c.get("connectorVersion", "")
    connector = cv.split("/connectors/")[-1].split("/")[0] if "/connectors/" in cv else ""
    return {
        "name": name,
        "connection_id": connection_id,
        "connector": connector,
        "status": (c.get("status") or {}).get("state", ""),
        "service_account": c.get("serviceAccount", ""),
        "location": location,
        "raw_json": _json.dumps(c),
    }


# ── GcpListResource subclass ────────────────────────────────────────────────────

class ConnectionsResource(GcpListResource):
    """List Integration Connector connections via REST (no GAPIC package exists).

    Overrides list() with a paginated REST call (proper 403/"Not Enabled" handling)
    and test_iam_permissions() with a REST POST. save() is inherited unchanged
    since _normalize_connection already produces flat rows with the right column names.
    """

    SERVICE_LABEL = "Integration Connectors"
    TABLE_NAME = "connectors_connections"
    COLUMNS = ["project_id", "location", "connection_id", "name", "connector",
               "status", "service_account", "raw_json"]
    ACTION_RESOURCE_TYPE = "connections"
    LIST_PERMISSION = _CONN_LIST_PERMISSION
    TEST_IAM_PERMISSIONS = _CONN_PERMISSIONS
    TEST_IAM_API_NAME = "connectors.googleapis.com"
    ID_FIELD = "connection_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None  # REST-only

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        tok = get_bearer_token(self.session)
        url = f"{_CONN_BASE}/projects/{project_id}/locations/{location}/connections"
        results = []
        page_token = None
        while True:
            params: dict = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            resp = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, params=params, timeout=20)
            if resp.status_code != 200:
                try:
                    msg = (resp.json().get("error", {}).get("message") or "").lower()
                    if any(k in msg for k in ("api not enabled", "disabled", "has not been used")):
                        return "Not Enabled"
                except Exception:
                    pass
                return None
            data = resp.json()
            results.extend(data.get("connections", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        rows = [_normalize_connection(c, location) for c in results]
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return rows

    def get(self, name: str) -> dict | None:
        return get_connection(get_bearer_token(self.session), name)

    def create(self, project_id: str, region: str, conn_id: str, body: dict) -> tuple[int, dict]:
        return create_connection(get_bearer_token(self.session), project_id, region, conn_id, body)

    def delete(self, name: str) -> tuple[int, dict]:
        return delete_connection(get_bearer_token(self.session), name)

    def test_iam_permissions(self, *, resource_id, action_dict=None):
        if not self.TEST_IAM_PERMISSIONS:
            return []
        tok = get_bearer_token(self.session)
        try:
            resp = _rlib.post(
                f"{_CONN_BASE}/{resource_id}:testIamPermissions",
                headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                json={"permissions": list(self.TEST_IAM_PERMISSIONS)},
                timeout=15,
            )
            if resp.status_code != 200:
                return []
            granted = resp.json().get("permissions", [])
        except Exception:
            return []
        if granted:
            project_id = extract_project_id_from_resource(
                resource_id, fallback_project=self._fallback_project()
            )
            record_permissions(
                action_dict,
                permissions=granted,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return granted
