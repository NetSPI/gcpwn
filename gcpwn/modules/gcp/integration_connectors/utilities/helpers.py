from __future__ import annotations

import json as _json

import requests as _rlib

from gcpwn.core.resource import RestListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.iam_permissions import call_rest_test_iam_permissions
from gcpwn.core.utils.service_runtime import bearer_headers, get_bearer_token
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    extract_project_id_from_resource,
    static_locations,
)

_CONN_BASE = "https://connectors.googleapis.com/v1"

_DEFAULT_REGIONS = static_locations("connectors")

_CONN_LIST_PERMISSION = "connectors.connections.list"
_CONN_PERMISSIONS = tuple(permissions_with_prefixes("connectors.connections."))


# ── REST helpers ──────────────────────────────────────────────────────────────


def get_connection(token: str, name: str) -> dict | None:
    headers = bearer_headers(token, json_content=False)
    resp = _rlib.get(f"{_CONN_BASE}/{name}", headers=headers, timeout=20)
    if resp.status_code == 200:
        return resp.json()
    return None


def create_connection(token: str, project_id: str, region: str, conn_id: str, body: dict) -> tuple[int, dict]:
    url = f"{_CONN_BASE}/projects/{project_id}/locations/{region}/connections"
    headers = bearer_headers(token)
    resp = _rlib.post(url, headers=headers, json=body, params={"connectionId": conn_id}, timeout=30)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"_raw": resp.text[:600]}


def delete_connection(token: str, name: str) -> tuple[int, dict]:
    headers = bearer_headers(token, json_content=False)
    resp = _rlib.delete(f"{_CONN_BASE}/{name}", headers=headers, timeout=30)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"_raw": resp.text[:300]}


def _normalize_connection(c: dict, location: str) -> dict:
    name = c.get("name", "")
    connection_id = extract_path_tail(name)
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

class ConnectionsResource(RestListResource):
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
    API_BASE = _CONN_BASE
    API_PATH = "connections"
    COLLECTION_KEY = "connections"
    PAGE_SIZE = 100

    def _normalize_rest_row(self, raw, *, location=None):
        return _normalize_connection(raw, location)

    def get(self, name: str) -> dict | None:
        return get_connection(get_bearer_token(self.session), name)

    def create(self, project_id: str, region: str, conn_id: str, body: dict) -> tuple[int, dict]:
        return create_connection(get_bearer_token(self.session), project_id, region, conn_id, body)

    def delete(self, name: str) -> tuple[int, dict]:
        return delete_connection(get_bearer_token(self.session), name)

    def test_iam_permissions(self, *, resource_id, action_dict=None):
        if not self.TEST_IAM_PERMISSIONS:
            return []
        granted = call_rest_test_iam_permissions(
            token=get_bearer_token(self.session),
            url=f"{_CONN_BASE}/{resource_id}:testIamPermissions",
            permissions=self.TEST_IAM_PERMISSIONS,
        )
        if granted:
            record_permissions(
                action_dict,
                permissions=granted,
                project_id=extract_project_id_from_resource(
                    resource_id, fallback_project=self._fallback_project()
                ),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return granted
