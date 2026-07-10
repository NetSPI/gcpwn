"""
Google Workspace admin roles + role assignments helpers (Admin SDK Directory API).

These helpers enumerate the highest-value Workspace privilege data for attack-path
analysis: which roles exist (and which are super-admin roles), and who those roles
are assigned to.

API host: `admin.googleapis.com` (Admin SDK Directory API, `directory_v1`)
Client:   `googleapiclient.discovery.build("admin", "directory_v1")`

Calls (read-only):
- `roles().list(customer=<customerId>)`
  - REST: `GET /admin/directory/v1/customer/<customerId>/roles`
  - Returns `{"items":[{roleId, roleName, isSuperAdminRole, isSystemRole, rolePrivileges:[...]}], "nextPageToken": ...}`
- `roleAssignments().list(customer=<customerId>[, userKey=...])`
  - REST: `GET /admin/directory/v1/customer/<customerId>/roleassignments`
  - Returns `{"items":[{roleAssignmentId, roleId, assignedTo, scopeType, orgUnitId}], "nextPageToken": ...}`

Tenant scope: `customer` is the Directory Customer ID (`directoryCustomerId`, e.g. `C0xxxxxxx`)
or the literal `my_customer`. Rows are stored workspace-scoped on `customer_id`.

Access model (same as the rest of this package): a Workspace admin USER works directly;
a service account needs domain-wide delegation + an admin subject to impersonate. The
required read-only scope here is:
`https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly`.

We do NOT edit the shared `common.py`; we reuse its `build_directory_service` and error
helpers, and re-scope the credentials to include the rolemanagement scope.
"""

from __future__ import annotations

from typing import Any

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.service_runtime import paged_list
from gcpwn.modules.workspace.common import (
    _http_error_details,
    build_directory_service,
    ensure_scoped_credentials,
)

ROLEMANAGEMENT_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
)


def _build_service(session, subject: str | None):
    """Build a Directory API client scoped for role management (read-only)."""
    credentials = ensure_scoped_credentials(session.credentials, ROLEMANAGEMENT_SCOPES)
    return build_directory_service(credentials, subject=subject)


class WorkspaceAdminRolesResource:
    """Admin SDK Directory API: `roles().list(customer=...)`."""

    TABLE_NAME = "workspace_admin_roles"
    COLUMNS = [
        "customer_id",
        "role_id",
        "role_name",
        "role_description",
        "is_super_admin_role",
        "is_system_role",
        "role_privileges",
        "raw_json",
    ]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.last_call_ok: bool | None = None
        self.last_error_status: int | None = None
        self.last_error_message: str | None = None

    def list(self, *, customer: str, page_size: int = 100) -> list[dict[str, Any]]:
        """List admin roles for the given Directory customer. Graceful on error."""
        self.last_error_status = None
        self.last_error_message = None
        try:
            service = _build_service(self.session, self.subject)

            def _factory(token: str | None):
                # roles.list caps maxResults at 100 (roleAssignments.list allows 200),
                # so clamp -- the shared --page-size default of 200 else yields HTTP 400.
                return service.roles().list(
                    customer=customer,
                    maxResults=min(int(page_size), 100),
                    pageToken=token,
                )

            rows = paged_list(_factory, items_key="items")
            self.last_call_ok = True
            return rows
        except Exception as exc:
            self.last_call_ok = False
            status, detail = _http_error_details(exc)
            self.last_error_status = status
            self.last_error_message = detail
            if status == 403:
                print("[*] Admin SDK Directory rolemanagement access denied; skipping admin roles enumeration.")
                return []
            if status == 404:
                print("[*] Admin SDK Directory API not enabled or no Google Workspace org; skipping admin roles enumeration.")
                return []
            print(f"[*] Admin SDK Directory roles enumeration failed: {type(exc).__name__}: {exc}")
            return []

    def save(self, roles, *, customer_id: str) -> None:
        rows: list[dict[str, Any]] = []
        for role in roles or []:
            if not isinstance(role, dict):
                continue
            role_id = str(role.get("roleId") or "").strip()
            if not role_id:
                continue
            rows.append(
                {
                    "customer_id": customer_id,
                    "role_id": role_id,
                    "role_name": str(role.get("roleName") or ""),
                    "role_description": str(role.get("roleDescription") or ""),
                    "is_super_admin_role": "true" if role.get("isSuperAdminRole") else "false",
                    "is_system_role": "true" if role.get("isSystemRole") else "false",
                    "role_privileges": role.get("rolePrivileges") if isinstance(role.get("rolePrivileges"), list) else [],
                    "raw_json": role,
                }
            )
        if rows:
            save_to_table(self.session, "workspace_admin_roles", rows, defaults={"customer_id": customer_id})


class WorkspaceRoleAssignmentsResource:
    """Admin SDK Directory API: `roleAssignments().list(customer=...[, userKey=...])`."""

    TABLE_NAME = "workspace_role_assignments"
    COLUMNS = [
        "customer_id",
        "role_assignment_id",
        "role_id",
        "assigned_to",
        "scope_type",
        "org_unit_id",
        "raw_json",
    ]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.last_call_ok: bool | None = None
        self.last_error_status: int | None = None
        self.last_error_message: str | None = None

    def list(self, *, customer: str, user_key: str | None = None, page_size: int = 200) -> list[dict[str, Any]]:
        """List role assignments for the given Directory customer (optionally filtered by user). Graceful on error."""
        self.last_error_status = None
        self.last_error_message = None
        try:
            service = _build_service(self.session, self.subject)

            def _factory(token: str | None):
                kwargs: dict[str, Any] = {
                    "customer": customer,
                    "maxResults": int(page_size),
                    "pageToken": token,
                }
                if user_key:
                    kwargs["userKey"] = str(user_key)
                return service.roleAssignments().list(**kwargs)

            rows = paged_list(_factory, items_key="items")
            self.last_call_ok = True
            return rows
        except Exception as exc:
            self.last_call_ok = False
            status, detail = _http_error_details(exc)
            self.last_error_status = status
            self.last_error_message = detail
            if status == 403:
                print("[*] Admin SDK Directory rolemanagement access denied; skipping role assignment enumeration.")
                return []
            if status == 404:
                print("[*] Admin SDK Directory API not enabled or no Google Workspace org; skipping role assignment enumeration.")
                return []
            print(f"[*] Admin SDK Directory roleAssignments enumeration failed: {type(exc).__name__}: {exc}")
            return []

    def save(self, assignments, *, customer_id: str) -> None:
        rows: list[dict[str, Any]] = []
        for assignment in assignments or []:
            if not isinstance(assignment, dict):
                continue
            assignment_id = str(assignment.get("roleAssignmentId") or "").strip()
            if not assignment_id:
                continue
            rows.append(
                {
                    "customer_id": customer_id,
                    "role_assignment_id": assignment_id,
                    "role_id": str(assignment.get("roleId") or ""),
                    "assigned_to": str(assignment.get("assignedTo") or ""),
                    "scope_type": str(assignment.get("scopeType") or ""),
                    "org_unit_id": str(assignment.get("orgUnitId") or ""),
                    "raw_json": assignment,
                }
            )
        if rows:
            save_to_table(self.session, "workspace_role_assignments", rows, defaults={"customer_id": customer_id})
