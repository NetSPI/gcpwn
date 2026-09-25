from __future__ import annotations

import json as _json
import time

import requests
import requests as _rlib

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import get_bearer_token
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    extract_project_id_from_resource,
    region_resolver_for,
)

_VM_BASE = "https://vmmigration.googleapis.com/v1"

resolve_locations = region_resolver_for("vmmigration", ("vmmigration", "v1"))

# ---------------------------------------------------------------------------
# Shared REST helper
# ---------------------------------------------------------------------------


def _vma_list(session, url: str, key: str):
    """Paginating REST GET for vmmigration resources.

    Returns a list of raw dicts on success, ``"Not Enabled"`` when the API is
    disabled, or ``None`` on any other error (4xx/5xx).
    """
    tok = get_bearer_token(session)
    headers = {"Authorization": f"Bearer {tok}"}
    results: list[dict] = []
    page_token: str | None = None
    while True:
        params: dict = {"pageSize": 200}
        if page_token:
            params["pageToken"] = page_token
        resp = _rlib.get(url, headers=headers, params=params, timeout=20)
        if resp.status_code != 200:
            try:
                msg = (resp.json().get("error", {}).get("message") or "").lower()
                if any(k in msg for k in ("api not enabled", "disabled", "has not been used")):
                    return "Not Enabled"
            except Exception:
                pass
            return None
        data = resp.json()
        results.extend(data.get(key, []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return results


def _source_provider(item: dict) -> str:
    for p in ("vmware", "aws", "azure"):
        if p in item:
            return p
    return "unknown"


# ---------------------------------------------------------------------------
# Enumeration resource classes
# ---------------------------------------------------------------------------


class VmMigrationSourcesResource(GcpListResource):
    """List VM Migration sources (VMware/AWS/Azure vCenter connections)."""

    SERVICE_LABEL = "VM Migration"
    TABLE_NAME = "vmmigration_sources"
    COLUMNS = ["project_id", "location", "source_id", "name", "description",
               "provider", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "sources"
    LIST_PERMISSION = "vmmigration.sources.list"
    GET_PERMISSION = "vmmigration.sources.get"
    TEST_IAM_PERMISSIONS = ()
    ID_FIELD = "source_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        url = f"{_VM_BASE}/projects/{project_id}/locations/{location}/sources"
        items = _vma_list(self.session, url, "sources")
        if items is None or items == "Not Enabled":
            return items
        rows = [
            {
                "name": s.get("name", ""),
                "description": s.get("description", ""),
                "provider": _source_provider(s),
                "create_time": s.get("createTime", ""),
                "update_time": s.get("updateTime", ""),
            }
            for s in items
        ]
        if self.LIST_PERMISSION:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def _extra_save_fields(self, raw: dict) -> dict:
        return {"source_id": extract_path_tail(raw.get("name", ""))}


class VmMigrationMigratingVmsResource(GcpListResource):
    """List VM Migration migratingVms nested under each source."""

    SERVICE_LABEL = "VM Migration"
    TABLE_NAME = "vmmigration_migrating_vms"
    COLUMNS = [
        "project_id", "location", "source_id", "vm_id", "name",
        "display_name", "description", "source_vm_id", "state",
        "state_time", "group", "target_project", "target_zone", "raw_json",
    ]
    ACTION_RESOURCE_TYPE = "migratingVms"
    LIST_PERMISSION = "vmmigration.migratingVms.list"
    GET_PERMISSION = "vmmigration.migratingVms.get"
    TEST_IAM_PERMISSIONS = ()
    ID_FIELD = "vm_id"
    PARENT_FROM_PROJECT_LOCATION = False
    LIST_PROJECT_SCOPE = True

    def _build_client(self, session):
        return None

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        url = f"{_VM_BASE}/{parent}/migratingVms"
        items = _vma_list(self.session, url, "migratingVms")
        if items is None or items == "Not Enabled":
            return items
        rows = []
        for vm in items:
            ce = vm.get("computeEngineTargetDefaults") or {}
            rows.append({
                "name": vm.get("name", ""),
                "display_name": vm.get("displayName", ""),
                "description": vm.get("description", ""),
                "source_vm_id": vm.get("sourceVmId", ""),
                "state": vm.get("state", ""),
                "state_time": vm.get("stateTime", ""),
                "group": extract_path_tail(str(vm.get("group", ""))),
                "target_project": extract_path_segment(str(ce.get("targetProject", "")), "targetProjects"),
                "target_zone": ce.get("zone", ""),
                "raw_json": _json.dumps(vm),
            })
        if self.LIST_PERMISSION:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(parent or "", fallback_project=project_id or ""),
            )
        return rows

    def _extra_save_fields(self, raw: dict) -> dict:
        name = raw.get("name", "")
        return {
            "vm_id": extract_path_segment(name, "migratingVms") or extract_path_tail(name),
            "source_id": extract_path_segment(name, "sources"),
        }


class VmMigrationGroupsResource(GcpListResource):
    """List VM Migration groups."""

    SERVICE_LABEL = "VM Migration"
    TABLE_NAME = "vmmigration_groups"
    COLUMNS = ["project_id", "location", "group_id", "name", "display_name",
               "description", "migration_target_type", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "groups"
    LIST_PERMISSION = "vmmigration.groups.list"
    GET_PERMISSION = "vmmigration.groups.get"
    TEST_IAM_PERMISSIONS = ()
    ID_FIELD = "group_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        url = f"{_VM_BASE}/projects/{project_id}/locations/{location}/groups"
        items = _vma_list(self.session, url, "groups")
        if items is None or items == "Not Enabled":
            return items
        rows = [
            {
                "name": g.get("name", ""),
                "display_name": g.get("displayName", ""),
                "description": g.get("description", ""),
                "migration_target_type": g.get("migrationTargetType", ""),
                "create_time": g.get("createTime", ""),
                "update_time": g.get("updateTime", ""),
            }
            for g in items
        ]
        if self.LIST_PERMISSION:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def _extra_save_fields(self, raw: dict) -> dict:
        return {"group_id": extract_path_tail(raw.get("name", ""))}


class VmMigrationTargetProjectsResource(GcpListResource):
    """List VM Migration targetProjects (always in the global location)."""

    SERVICE_LABEL = "VM Migration"
    TABLE_NAME = "vmmigration_target_projects"
    COLUMNS = ["project_id", "target_project_id", "name", "target_project",
               "description", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "targetProjects"
    LIST_PERMISSION = "vmmigration.targetProjects.list"
    TEST_IAM_PERMISSIONS = ()
    ID_FIELD = "target_project_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        # targetProjects are always global regardless of the location passed
        url = f"{_VM_BASE}/projects/{project_id}/locations/global/targetProjects"
        items = _vma_list(self.session, url, "targetProjects")
        if items is None or items == "Not Enabled":
            return items
        rows = [
            {
                "name": tp.get("name", ""),
                "target_project": tp.get("project", ""),
                "description": tp.get("description", ""),
                "create_time": tp.get("createTime", ""),
                "update_time": tp.get("updateTime", ""),
            }
            for tp in items
        ]
        if self.LIST_PERMISSION:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def _extra_save_fields(self, raw: dict) -> dict:
        return {"target_project_id": extract_path_tail(raw.get("name", ""))}


class VmMigrationImageImportResource:
    """REST wrapper for VM Migration imageImports and targetProjects APIs.

    The vmmigration_v1 GAPIC client is not installed in this environment, so
    all calls go through the REST API with a bearer token obtained from the
    session credentials.  Used by the ImageImport PE exploit path.
    """

    def __init__(self, session) -> None:
        self.session = session

    def _req(self, method: str, url: str, body=None, params=None) -> tuple[int, dict]:
        tok = get_bearer_token(self.session)
        hdrs = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        r = requests.request(method, url, headers=hdrs, json=body, params=params, timeout=30)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:600]}

    def create_target_project(self, parent: str, tp_id: str, body: dict) -> tuple[int, dict]:
        """Create a VM Migration targetProject (always a global-location resource).

        parent is expected to be ``projects/<p>/locations/global``.
        Returns (status_code, response_dict).
        """
        return self._req(
            "POST",
            f"{_VM_BASE}/{parent}/targetProjects",
            body=body,
            params={"targetProjectId": tp_id},
        )

    def list_target_projects(self, parent: str) -> list[dict]:
        """List VM Migration targetProjects under parent (projects/<p>/locations/global).

        Returns a list of targetProject dicts, or an empty list on error.
        """
        _s, resp = self._req("GET", f"{_VM_BASE}/{parent}/targetProjects")
        return resp.get("targetProjects", []) if isinstance(resp, dict) else []

    def create(self, parent: str, image_import_id: str, body: dict) -> tuple[int, dict]:
        """Create an ImageImport under parent. Returns (status_code, response_dict)."""
        return self._req(
            "POST",
            f"{_VM_BASE}/{parent}/imageImports",
            body=body,
            params={"imageImportId": image_import_id},
        )

    def get(self, name: str) -> tuple[int, dict]:
        """Fetch an ImageImport's current state by full resource name."""
        return self._req("GET", f"{_VM_BASE}/{name}")

    def delete(self, name: str) -> tuple[int, dict]:
        """Delete an ImageImport by full resource name."""
        return self._req("DELETE", f"{_VM_BASE}/{name}")

    def poll_operation(self, name: str, *, timeout: int = 300) -> dict:
        """Poll an ImageImport until it reaches a terminal state or timeout elapses.

        Prints the current state in-place every 15 s.  Returns the last
        fetched response dict (which may be empty if the first GET fails).
        """
        terminal = {"SUCCEEDED", "FAILED"}
        deadline = time.monotonic() + timeout
        last: dict = {}
        while time.monotonic() < deadline:
            _s, last = self.get(name)
            state = last.get("state", "")
            print(f"    state={state}", end="\r")
            if state in terminal:
                print()
                break
            time.sleep(15)
        return last


class VmMigrationSourceResource:
    """REST wrapper for VM Migration sources and migratingVms APIs.

    Used by the MigratingVm PE exploit path.  Handles both the source
    (VMware vCenter registration) and the MigratingVm nested under it.
    """

    def __init__(self, session) -> None:
        self.session = session

    def _req(self, method: str, url: str, body=None, params=None) -> tuple[int, dict]:
        tok = get_bearer_token(self.session)
        hdrs = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
        r = requests.request(method, url, headers=hdrs, json=body, params=params, timeout=30)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:600]}

    def create_source(self, parent: str, source_id: str, body: dict) -> tuple[int, dict]:
        """Create a VM Migration source under parent. Returns (status_code, response_dict)."""
        return self._req(
            "POST",
            f"{_VM_BASE}/{parent}/sources",
            body=body,
            params={"sourceId": source_id},
        )

    def delete_source(self, name: str) -> tuple[int, dict]:
        """Delete a source by full resource name."""
        return self._req("DELETE", f"{_VM_BASE}/{name}")

    def create_migrating_vm(self, source_name: str, vm_id: str, body: dict) -> tuple[int, dict]:
        """Create a MigratingVm under source_name. Returns (status_code, response_dict)."""
        return self._req(
            "POST",
            f"{_VM_BASE}/{source_name}/migratingVms",
            body=body,
            params={"migratingVmId": vm_id},
        )

    def delete_migrating_vm(self, name: str) -> tuple[int, dict]:
        """Delete a MigratingVm by full resource name."""
        return self._req("DELETE", f"{_VM_BASE}/{name}")
