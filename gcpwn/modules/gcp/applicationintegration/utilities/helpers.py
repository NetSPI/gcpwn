from __future__ import annotations

import json as _json

import requests as _rlib
from google.auth.transport.requests import Request as GoogleRequest

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    get_bearer_token,
    static_locations,
)

_INT_BASE = "https://integrations.googleapis.com/v1"

_DEFAULT_REGIONS = static_locations("applicationintegration")

_INT_LIST_PERMISSION = "integrations.integrations.list"
_INT_PERMISSIONS = tuple(permissions_with_prefixes("integrations.integrations."))


def _normalize_integration(i: dict, location: str) -> dict:
    name = i.get("name", "")
    integration_id = name.rsplit("/", 1)[-1] if "/" in name else name
    return {
        "name": name,
        "integration_id": integration_id,
        "state": i.get("state", ""),
        "run_as_service_account": i.get("runAsServiceAccount", ""),
        "location": location,
        "raw_json": _json.dumps(i),
    }


class IntegrationsResource(GcpListResource):
    """List Application Integration integrations via REST.

    Flags any integration carrying a non-default runAsServiceAccount — these
    are candidates for the PE path in exploit_app_integration_as_sa.
    """

    SERVICE_LABEL = "Application Integration"
    TABLE_NAME = "appintegration_integrations"
    COLUMNS = ["project_id", "location", "integration_id", "name",
               "state", "run_as_service_account", "raw_json"]
    ACTION_RESOURCE_TYPE = "integrations"
    LIST_PERMISSION = _INT_LIST_PERMISSION
    TEST_IAM_PERMISSIONS = ()   # no per-resource testIamPermissions on integrations
    ID_FIELD = "integration_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None  # REST-only

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        tok = get_bearer_token(self.session)
        url = f"{_INT_BASE}/projects/{project_id}/locations/{location}/integrations"
        results = []
        page_token = None
        while True:
            params: dict = {"pageSize": 200}
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
            results.extend(data.get("integrations", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        rows = [_normalize_integration(i, location) for i in results]
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return rows


def _req(token: str, url: str, body=None, method: str | None = None) -> tuple[int, dict]:
    """Execute an authorized REST call; return (status_code, parsed_json)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if method == "DELETE":
        resp = _rlib.delete(url, headers=headers, timeout=20)
    elif method == "POST" or body is not None:
        resp = _rlib.post(url, headers=headers, json=body or {}, timeout=20)
    else:
        resp = _rlib.get(url, headers=headers, timeout=20)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"_raw": resp.text[:800]}


def caller_token(session) -> str:
    creds = session.credentials
    if not creds.valid:
        creds.refresh(GoogleRequest())
    return creds.token


def list_integrations(token: str, project_id: str, region: str) -> list[dict]:
    """Return raw integration dicts from the App Integration REST API."""
    url = f"{_INT_BASE}/projects/{project_id}/locations/{region}/integrations"
    headers = {"Authorization": f"Bearer {token}"}
    results = []
    page_token = None
    while True:
        params = {"pageSize": 200}
        if page_token:
            params["pageToken"] = page_token
        resp = _rlib.get(url, headers=headers, params=params, timeout=20)
        if resp.status_code != 200:
            break
        data = resp.json()
        results.extend(data.get("integrations", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return results


def list_integration_versions(token: str, project_id: str, region: str, integration_name: str) -> list[dict]:
    """List versions for a specific integration."""
    url = (
        f"{_INT_BASE}/projects/{project_id}/locations/{region}"
        f"/integrations/{integration_name}/versions"
    )
    headers = {"Authorization": f"Bearer {token}"}
    resp = _rlib.get(url, headers=headers, params={"pageSize": 50}, timeout=20)
    if resp.status_code == 200:
        return resp.json().get("integrationVersions", [])
    return []


# ── Version enumeration helpers (used by enum module) ─────────────────────────

def enumerate_integration_versions(
    session, project_id: str, integrations: list[dict], *, download: bool = False
) -> None:
    """Fetch and print versions for each integration row.

    When ``download`` is True also persists each version JSON to the session
    download directory.
    """
    import json as _json_mod
    from gcpwn.core.output_paths import resolve_download_path
    from gcpwn.core.utils.service_runtime import DownloadBudget

    tok = get_bearer_token(session)
    collected: list[tuple[str, str, dict]] = []

    for row in integrations:
        location = row.get("location", "")
        integration_id = row.get("integration_id", "")
        if not (location and integration_id):
            continue
        versions = list_integration_versions(tok, project_id, location, integration_id)
        if not versions:
            continue
        from gcpwn.core.console import UtilityTools
        print(f"\n{UtilityTools.CYAN}[*] {location}/{integration_id} — {len(versions)} version(s){UtilityTools.RESET}")
        for v in versions:
            v_name = v.get("name", "").split("/")[-1]
            v_state = v.get("state", "")
            v_sa = v.get("runAsServiceAccount", "")
            v_sa_label = f"  SA={v_sa}" if v_sa else ""
            v_flag = f" {UtilityTools.YELLOW}[PE]{UtilityTools.RESET}" if v_sa else ""
            print(f"    v/{v_name:<36s} state={v_state:<10s}{v_sa_label}{v_flag}")
            if download:
                collected.append((location, integration_id, v))

    if not (download and collected):
        return

    budget = DownloadBudget(session, label="integration version configs")
    from gcpwn.core.console import UtilityTools
    downloaded = 0
    for location, integration_id, v in collected:
        if budget.exceeded():
            break
        v_name = v.get("name", "")
        version_id = v_name.split("/")[-1] if "/" in v_name else (v_name or "unknown")
        path = resolve_download_path(
            session, service_name="applicationintegration", project_id=project_id,
            subdirs=[location, integration_id], filename=f"{integration_id}_{version_id}.json",
        )
        path.write_text(_json_mod.dumps(v, indent=2), encoding="utf-8")
        print(f"{UtilityTools.GREEN}[+] Saved → {path}{UtilityTools.RESET}")
        downloaded += 1
    if downloaded:
        from gcpwn.core.console import UtilityTools
        print(f"{UtilityTools.CYAN}[*] Downloaded {downloaded} integration version JSON file(s).{UtilityTools.RESET}")


# ── Exploit helpers ────────────────────────────────────────────────────────────

def create_integration_version(
    token: str, project_id: str, region: str,
    integration_name: str, body: dict,
) -> tuple[int, dict]:
    """Create an IntegrationVersion. Returns (status_code, response_json)."""
    url = f"{_INT_BASE}/projects/{project_id}/locations/{region}/integrations/{integration_name}/versions"
    return _req(token, url, body=body)


def publish_integration_version(token: str, version_name: str) -> tuple[int, dict]:
    """Publish an IntegrationVersion by its full resource name."""
    return _req(token, f"{_INT_BASE}/{version_name}:publish", body={})


def execute_integration(
    token: str, project_id: str, region: str,
    integration_name: str, trigger_name: str,
) -> tuple[int, dict]:
    """Fire an integration via API trigger. Returns (status_code, response_json)."""
    url = f"{_INT_BASE}/projects/{project_id}/locations/{region}/integrations/{integration_name}:execute"
    return _req(token, url, body={"triggerId": f"api_trigger/{trigger_name}", "inputParameters": {}})


def delete_integration(token: str, project_id: str, region: str, integration_name: str) -> tuple[int, dict]:
    """Delete an integration and all its versions."""
    url = f"{_INT_BASE}/projects/{project_id}/locations/{region}/integrations/{integration_name}"
    return _req(token, url, method="DELETE")
