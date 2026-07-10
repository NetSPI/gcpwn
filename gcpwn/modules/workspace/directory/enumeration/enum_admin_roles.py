"""
Google Workspace admin roles + role assignments enumeration module.

This module talks to the *Admin SDK Directory API* via the Google API Discovery client
(`googleapiclient.discovery.build("admin", "directory_v1")`).

Primary API calls (read-only):
- Directory: `roles().list(customer=<customerId>)` -> admin roles (flags super-admin/system roles)
- Directory: `roleAssignments().list(customer=<customerId>[, userKey=...])` -> who holds each role

This is the highest attack-path value Workspace data: it reveals super-admins and
privileged delegated admins.

Tenant scoping:
- Best case: caller supplies `--customer-id C...` (Directory Customer ID / `directoryCustomerId`)
- Otherwise: derive `directoryCustomerId` from the current GCP Organization via
  Resource Manager `organizations.get` (see `resolve_directory_customer_id()`).

Access model: a Workspace admin USER works directly; a service account needs domain-wide
delegation + an admin subject to impersonate (see `--impersonate`).
"""

from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import parse_component_args, resolve_selected_components
from gcpwn.modules.workspace.common import (
    track_workspace_permission as _track_workspace_permission,
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)
from gcpwn.modules.workspace.directory.utilities.admin_roles_helpers import (
    WorkspaceAdminRolesResource,
    WorkspaceRoleAssignmentsResource,
)


COMPONENTS = [
    ("roles", "List Google Workspace admin roles (Admin SDK Directory API)"),
    ("assignments", "List Google Workspace role assignments (who holds which admin role)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID (numeric) used to resolve directoryCustomerId")
        parser.add_argument("--directory-customer", required=False, default=None, help="Directory API customer selector (default: resolved customer ID or my_customer)")
        parser.add_argument("--user-key", required=False, help="Filter role assignments to a single user (email or user id)")
        parser.add_argument("--page-size", required=False, type=int, default=200, help="Page size (best-effort)")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (service-account domain-wide delegation); or set `configs set workspace_admin_subject admin@domain`")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace admin roles and role assignments",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False))
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    # Tenant scope resolution (same approach as enum_cloud_identity).
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))

    UtilityTools.dlog(
        debug,
        "workspace admin roles scope resolved",
        project_id=session.project_id,
        credname=getattr(session, "credname", None),
        customer_id=customer_id,
        subject=subject,
        selected=selected,
    )

    if not customer_id:
        print(
            f"{UtilityTools.YELLOW}[*] Cannot enumerate admin roles without a customer ID (directoryCustomerId).{UtilityTools.RESET}\n"
            "    Supply `--customer-id C...` (or set `configs set workspace_customer_id C...`),\n"
            "    or supply `--org-id <numeric>` to resolve it from the GCP organization."
        )
        return -1

    # The Directory API customer selector: explicit override, else the resolved
    # customer id, else the literal `my_customer`.
    directory_customer = str(args.directory_customer or customer_id or "my_customer")

    roles_resource = WorkspaceAdminRolesResource(session, subject=subject)
    assignments_resource = WorkspaceRoleAssignmentsResource(session, subject=subject)
    workspace_actions: dict[str, dict[str, set[str]]] = {"workspace_permissions": {}}

    roles: list[dict] = []
    if selected.get("roles", False):
        UtilityTools.dlog(debug, "calling directory roles.list", customer=directory_customer)
        roles = roles_resource.list(customer=directory_customer, page_size=args.page_size)
        if roles:
            roles_resource.save(roles, customer_id=customer_id)
        if roles_resource.last_call_ok:
            _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="rolemanagement.roles.read")
        UtilityTools.dlog(
            debug,
            "directory roles.list complete",
            ok=roles_resource.last_call_ok,
            count=len(roles),
            error_status=roles_resource.last_error_status,
            error=roles_resource.last_error_message,
        )

        UtilityTools.summary_wrapup(
            session.project_id,
            "Google Workspace Admin Roles",
            [
                {
                    "role_id": str(r.get("roleId") or ""),
                    "role_name": str(r.get("roleName") or ""),
                    "super_admin": "true" if r.get("isSuperAdminRole") else "false",
                    "system_role": "true" if r.get("isSystemRole") else "false",
                }
                for r in roles
            ],
            ["role_id", "role_name", "super_admin", "system_role"],
            primary_resource="Admin Roles",
            primary_sort_key="role_name",
        )

    if selected.get("assignments", False):
        UtilityTools.dlog(
            debug,
            "calling directory roleAssignments.list",
            customer=directory_customer,
            user_key=getattr(args, "user_key", None),
        )
        assignments = assignments_resource.list(
            customer=directory_customer,
            user_key=getattr(args, "user_key", None),
            page_size=args.page_size,
        )
        if assignments:
            assignments_resource.save(assignments, customer_id=customer_id)
        if assignments_resource.last_call_ok:
            _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="rolemanagement.roleAssignments.read")
        UtilityTools.dlog(
            debug,
            "directory roleAssignments.list complete",
            ok=assignments_resource.last_call_ok,
            count=len(assignments),
            error_status=assignments_resource.last_error_status,
            error=assignments_resource.last_error_message,
        )

        # Best-effort: resolve numeric assignedTo user ids to emails from cached
        # workspace_users so "who holds each role" is readable (run --users first;
        # group/SA assignees won't resolve and fall back to the raw id).
        user_rows = session.get_data("workspace_users", columns=["user_id", "email"]) or []
        id_to_email = {str(r.get("user_id") or ""): str(r.get("email") or "") for r in user_rows if r.get("user_id")}

        UtilityTools.summary_wrapup(
            session.project_id,
            "Google Workspace Role Assignments",
            [
                {
                    "role_assignment_id": str(a.get("roleAssignmentId") or ""),
                    "role_id": str(a.get("roleId") or ""),
                    "assigned_to": str(a.get("assignedTo") or ""),
                    "assigned_email": id_to_email.get(str(a.get("assignedTo") or ""), ""),
                    "scope_type": str(a.get("scopeType") or ""),
                }
                for a in assignments
            ],
            ["assigned_email", "assigned_to", "role_id", "scope_type", "role_assignment_id"],
            primary_resource="Role Assignments",
            primary_sort_key="assigned_to",
        )

    if workspace_actions["workspace_permissions"]:
        session.insert_actions(workspace_actions)

    return 1
