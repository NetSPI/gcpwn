"""
Google Workspace / Cloud Identity enumeration module.

This module talks to the *Cloud Identity* REST API via the Google API Discovery client
(`googleapiclient.discovery.build("cloudidentity", "v1")`).

Primary API calls:
- Cloud Identity: `groups.list` (scoped by `parent=customers/<directoryCustomerId>`)
- Cloud Identity: `groups.search` (scoped by a query string; useful when list parent is unknown)
- Cloud Identity: `groups.memberships.list` (lists members for a given `groups/<id>` resource)
- Cloud Identity: `groups.memberships.searchTransitiveMemberships` (nested memberships when `--transitive` is set)

Tenant scoping:
- Best case: caller supplies `--customer-id C...` (Directory Customer ID / `directoryCustomerId`)
- Otherwise: try to derive `directoryCustomerId` from the current GCP Organization via
  Resource Manager `organizations.get` (see `resolve_directory_customer_id()`).
"""

from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import parse_component_args, resolve_selected_components
from gcpwn.modules.workspace.cloud_identity.utilities.helpers import (
    CloudIdentityGroupMembershipsResource,
    CloudIdentityGroupsResource,
    WorkspaceGroup,
    WorkspaceUsersResource,
)
from gcpwn.modules.workspace.common import (
    track_workspace_permission as _track_workspace_permission,
    record_workspace_delegation,
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)


COMPONENTS = [
    ("groups", "List Google Workspace / Cloud Identity groups"),
    ("memberships", "List group memberships (members for each group)"),
    ("users", "List Google Workspace users (Admin SDK Directory API)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID (numeric) used to resolve directoryCustomerId")
        parser.add_argument("--parent", required=False, help="Cloud Identity parent for groups list, e.g. customers/C046psxkn")
        parser.add_argument("--view", required=False, default="FULL", help="Group view (FULL or BASIC)")
        parser.add_argument("--page-size", required=False, type=int, default=1000, help="Page size (best-effort)")
        parser.add_argument("--filter", required=False, help="Cloud Identity groups.list filter (passed as-is)")
        parser.add_argument("--query", required=False, help="Cloud Identity groups.search query (passed as-is)")
        parser.add_argument("--transitive", action="store_true", help="Try transitive (nested) memberships when supported")
        parser.add_argument("--directory-customer", required=False, default="my_customer", help="Directory API customer selector (default: my_customer)")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (service-account domain-wide delegation); or set `configs set workspace_admin_subject admin@domain`")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace / Cloud Identity resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def _normalize_parent(customer_id: str | None, parent: str | None) -> str | None:
    if parent:
        return str(parent).strip()
    if customer_id:
        return f"customers/{str(customer_id).strip()}"
    return None


def _derive_customer_id(customer_id: str | None, raw: dict) -> str:
    """Best-effort customer scope for a group row when no directoryCustomerId resolved.

    The search-only flow (a SA with Cloud Identity DWD but no Resource Manager org
    access) resolves no customer id, yet workspace_groups' primary key requires
    one -- so derive it from the group's ``parent`` (``customers/<id>``), else the
    group email's domain. Without this the row silently fails its PK and is dropped.
    """
    if customer_id:
        return str(customer_id)
    parent = str(raw.get("parent") or "").strip()
    if parent.startswith("customers/"):
        return parent.split("/", 1)[1]
    email = str(raw.get("email") or (raw.get("groupKey") or {}).get("id") or "").strip()
    if "@" in email:
        return email.split("@", 1)[1]
    return ""


def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False))
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    # Tenant scope resolution:
    # - Prefer explicit `--customer-id`
    # - Else try `configs set workspace_customer_id C...`
    # - Else try Resource Manager `organizations.get` to retrieve `directoryCustomerId`
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    parent = _normalize_parent(customer_id, args.parent)
    # Workspace access model: an admin USER works directly; a service account needs
    # domain-wide delegation + an admin subject to impersonate (see --impersonate).
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))
    UtilityTools.dlog(
        debug,
        "cloud identity scope resolved",
        project_id=session.project_id,
        credname=getattr(session, "credname", None),
        customer_id=customer_id,
        parent=parent,
        query=getattr(args, "query", None),
        selected=selected,
    )

    if selected.get("groups", False) and not (parent or args.query):
        print(
            f"{UtilityTools.YELLOW}[*] Cannot list groups without a Cloud Identity parent or search query.{UtilityTools.RESET}\n"
            "    Supply `--customer-id C...` (or set `configs set workspace_customer_id C...`) to use `groups.list`,\n"
            "    or supply `--query ...` to use `groups.search`."
        )
        return -1

    groups_resource = CloudIdentityGroupsResource(session, subject=subject)
    memberships_resource = CloudIdentityGroupMembershipsResource(session, subject=subject)
    users_resource = WorkspaceUsersResource(session, subject=subject)
    workspace_actions: dict[str, dict[str, set[str]]] = {"workspace_permissions": {}}

    raw_groups = []
    groups_from_cache = False
    if selected.get("groups", False):
        if not args.get and not args.query and customer_id:
            cached = session.get_data("workspace_groups", where={"customer_id": customer_id}) or []
            UtilityTools.dlog(
                debug,
                "workspace_groups cache lookup",
                customer_id=customer_id,
                cache_rows=len(cached),
                used_get=bool(args.get),
                used_query=bool(args.query),
            )
            if cached:
                for row in cached:
                    raw_groups.append(dict(row))
                groups_from_cache = True
                UtilityTools.dlog(debug, "using cached workspace_groups rows", count=len(raw_groups))
        if not raw_groups:
            if args.query:
                UtilityTools.dlog(
                    debug,
                    "calling cloudidentity groups.search",
                    query=args.query,
                    page_size=args.page_size,
                )
                raw_groups = groups_resource.search(query=args.query, page_size=args.page_size)
                if groups_resource.last_call_ok:
                    _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="groups.read")
            else:
                UtilityTools.dlog(
                    debug,
                    "calling cloudidentity groups.list",
                    parent=parent,
                    view=args.view,
                    page_size=args.page_size,
                    filter=args.filter,
                )
                raw_groups = groups_resource.list(parent=parent, view=args.view, page_size=args.page_size, filter_value=args.filter)
                if groups_resource.last_call_ok:
                    _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="groups.read")
            UtilityTools.dlog(
                debug,
                "cloudidentity groups call complete",
                method=groups_resource.last_method,
                ok=groups_resource.last_call_ok,
                count=len(raw_groups),
                request=groups_resource.last_request,
                error_status=groups_resource.last_error_status,
                error=groups_resource.last_error_message,
            )

    groups: list[WorkspaceGroup] = []
    if raw_groups:
        for raw in raw_groups:
            name = str(raw.get("name", "")).strip()
            email = str(raw.get("email", "")).strip() or str(raw.get("groupKey", {}).get("id", "")).strip() or ""
            if not email:
                email = str(raw.get("preferredGroupKey", {}).get("id", "")).strip()
            if not email:
                # last resort: best-effort identifier
                email = name
            groups.append(
                WorkspaceGroup(
                    customer_id=_derive_customer_id(customer_id, raw),
                    name=name,
                    email=email,
                    display_name=str(raw.get("displayName") or raw.get("display_name") or ""),
                    description=str(raw.get("description") or ""),
                    labels=raw.get("labels") if isinstance(raw.get("labels"), dict) else {},
                    create_time=str(raw.get("createTime") or raw.get("create_time") or ""),
                    update_time=str(raw.get("updateTime") or raw.get("update_time") or ""),
                    raw=raw,
                )
            )

        groups_resource.save(groups)

    if selected.get("groups", False) and not groups:
        if debug:
            UtilityTools.dlog(
                True,
                "no groups returned",
                from_cache=groups_from_cache,
                method=groups_resource.last_method,
                request=groups_resource.last_request,
                call_ok=groups_resource.last_call_ok,
                error_status=groups_resource.last_error_status,
                error=groups_resource.last_error_message,
            )
        if not groups_from_cache and groups_resource.last_call_ok:
            print(
                f"{UtilityTools.YELLOW}[*] Cloud Identity call succeeded but returned 0 groups for this scope.{UtilityTools.RESET}"
            )
            if parent:
                print(f"    parent={parent}")
            if args.query:
                print(f"    query={args.query}")
            print("    Try: modules run enum_cloud_identity --query \"parent=='customers/<C_ID>'\" -v")

    if workspace_actions["workspace_permissions"]:
        session.insert_actions(workspace_actions)

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace Groups",
        [{"email": group.email, "name": group.name, "display_name": group.display_name} for group in groups],
        ["email", "display_name", "name"],
        primary_resource="Groups",
        primary_sort_key="email",
        )

    if selected.get("memberships", False):
        if not groups and selected.get("groups", False) is False:
            # If caller requested memberships only, they should have cached groups in workspace_groups already.
            cached = session.get_data("workspace_groups", where={"customer_id": customer_id} if customer_id else None) or []
            for row in cached:
                groups.append(
                    WorkspaceGroup(
                        customer_id=str(row.get("customer_id", "")),
                        name=str(row.get("name", "")),
                        email=str(row.get("email", "")),
                        display_name=str(row.get("display_name", "")),
                        description=str(row.get("description", "")),
                        labels={},
                        create_time=str(row.get("create_time", "")),
                        update_time=str(row.get("update_time", "")),
                        raw=None,
                    )
                )

        if not groups:
            print(f"{UtilityTools.YELLOW}[*] No groups available to enumerate memberships.{UtilityTools.RESET}")
            return 1

        memberships_summary = []
        all_member_emails: set[str] = set()
        any_membership_success = False
        for group in groups:
            if not group.name:
                continue
            memberships = memberships_resource.list(group_name=group.name, view="FULL", page_size=args.page_size, transitive=bool(args.transitive))
            any_membership_success = any_membership_success or bool(memberships_resource.last_call_ok)
            membership_source = (
                "cloudidentity.groups.memberships.searchTransitiveMemberships"
                if args.transitive
                else "cloudidentity.groups.memberships.list"
            )
            member_emails = memberships_resource.save(
                customer_id=customer_id or group.customer_id,
                group=group,
                memberships=memberships,
                transitive=bool(args.transitive),
                source=membership_source,
            )
            for email in member_emails:
                all_member_emails.add(email)
            memberships_summary.append({"group": group.email, "members": "\n".join(member_emails)})

        if any_membership_success:
            _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="groups.read")
            if workspace_actions["workspace_permissions"]:
                session.insert_actions(workspace_actions)

        if all_member_emails and customer_id:
            users_resource.save_emails(customer_id=customer_id, member_emails=sorted(all_member_emails))

        UtilityTools.summary_wrapup(
            session.project_id,
            "Google Workspace Group Memberships",
            memberships_summary,
            ["group", "members"],
            primary_resource="Group Memberships",
            primary_sort_key="group",
            )

    if selected.get("users", False):
        # Admin SDK Directory API user listing (requires Workspace admin scopes/privileges).
        if not customer_id:
            print(f"{UtilityTools.YELLOW}[*] Cannot enumerate users without a customer ID (directoryCustomerId).{UtilityTools.RESET}")
            return 1

        directory_users = users_resource.list(customer=str(args.directory_customer), max_results=500, order_by="email")
        if directory_users:
            users_resource.save_users(customer_id=customer_id, users=directory_users)
        if users_resource.last_call_ok:
            _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="users.read")
            if workspace_actions["workspace_permissions"]:
                session.insert_actions(workspace_actions)

        UtilityTools.summary_wrapup(
            session.project_id,
            "Google Workspace Users",
            [{"email": str(u.get("primaryEmail") or ""), "full_name": str((u.get("name") or {}).get("fullName") or "")} for u in directory_users],
            ["email", "full_name"],
            primary_resource="Users",
            primary_sort_key="email",
            )

    # A service account that successfully impersonated an admin here has proven
    # domain-wide delegation to this tenant -> record it for the OpenGraph edge.
    if subject and (groups_resource.last_call_ok or memberships_resource.last_call_ok or users_resource.last_call_ok):
        record_workspace_delegation(session, customer_id=customer_id, subject=subject)

    return 1
