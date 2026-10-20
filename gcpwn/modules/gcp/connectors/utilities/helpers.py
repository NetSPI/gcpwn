from __future__ import annotations

import requests as _rlib

from gcpwn.core.utils.module_helpers import get_bearer_token, static_locations

_CONN_BASE = "https://connectors.googleapis.com/v1"

_DEFAULT_REGIONS = static_locations("connectors")


def caller_token(session) -> str:
    return get_bearer_token(session)


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


def list_connector_versions(token: str, project_id: str, provider: str = "default", connector: str = "http") -> list[dict]:
    url = (
        f"{_CONN_BASE}/projects/{project_id}/locations/global"
        f"/providers/{provider}/connectors/{connector}/versions"
    )
    headers = {"Authorization": f"Bearer {token}"}
    resp = _rlib.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        return resp.json().get("connectorVersions", [])
    return []
