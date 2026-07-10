from __future__ import annotations

"""
Stage 10: principal and membership seeding.

Responsibilities:
- seed Google Workspace user/group nodes
- backfill IAM-only principal nodes not present in Workspace data
- emit explicit group membership edges
- emit inferred domain membership edges when domain nodes exist
"""

import json
import sys
from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import normalize_str_set
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    OpenGraphBuilder,
    is_convenience_member,
    principal_member_properties,
    principal_node_id,
    principal_type,
)


def _normalized_principal_tokens(values: Iterable[str] | None) -> list[str]:
    return sorted(
        {
            principal_node_id(str(token or "").strip())
            for token in values or []
            if str(token or "").strip()
        }
    )


def _progress_interval(total: int) -> int:
    if total <= 0:
        return 1
    return max(1, total // 100)


def _should_log_progress(processed: int, total: int, *, interval: int | None = None) -> bool:
    if total <= 0 or processed <= 0:
        return False
    step = interval if interval is not None else _progress_interval(total)
    return processed == total or processed == 1 or processed % step == 0


def _print_progress_inline(label: str, processed: int, total: int) -> None:
    if not _should_log_progress(processed, total):
        return
    message = f"[*] {label}: {processed}/{total} (remaining {max(0, total - processed)})"
    if sys.stdout.isatty():
        print(f"\r{message}", end="", flush=True)
        if processed == total:
            print("")
        return
    print(message)


def _ensure_principal_node(
    builder: OpenGraphBuilder,
    member: str,
    *,
    source: str = "",
) -> str:
    token = principal_node_id(member)
    if not token:
        return ""
    props = dict(principal_member_properties(token))
    if source:
        props["source"] = source
    builder.add_node(token, principal_type(token), **props)
    return token


def _scope_chain(start_scope: str, parent_by_name: dict[str, str]) -> list[str]:
    chain = [start_scope.strip()]
    if not chain[0]:
        return []
    seen = {chain[0]}
    cursor = chain[0]
    while True:
        parent = parent_by_name.get(cursor, "").strip()
        if not parent or parent in seen:
            break
        seen.add(parent)
        chain.append(parent)
        cursor = parent
    return chain


def _add_workspace_principal_nodes(
    builder: OpenGraphBuilder,
    *,
    rows: Iterable[dict[str, Any]] | None,
    member_prefix: str,
    node_type: str,
    source: str,
    progress_label: str,
) -> None:
    # Shared Google Workspace principal-node seeding helper.
    # Expected row examples:
    # - user row:  {"email":"alice@example.com","display_name":"Alice","user_id":"123","customer_id":"C..."}
    # - group row: {"email":"eng@example.com","display_name":"Engineering","description":"...","customer_id":"C..."}
    #
    row_list = [row for row in (rows or []) if isinstance(row, dict)]
    total_rows = len(row_list)
    for index, row in enumerate(row_list, start=1):
        email = str(row.get("email") or "").strip().lower()
        if email:
            member = f"{member_prefix}:{email}"
            node_id = principal_node_id(member)
            if node_id:
                props = dict(principal_member_properties(member))
                row_display_name = str(row.get("display_name") or "").strip()
                if row_display_name:
                    props["display_name"] = row_display_name
                    props["name"] = row_display_name

                # Keep full workspace row fidelity on the node while preserving canonical
                # principal properties when keys overlap.
                extras = dict(row)
                node_props = {**extras, **props}
                node_props["source"] = source
                builder.add_node(
                    node_id,
                    node_type,
                    **node_props,
                )
        _print_progress_inline(progress_label, index, total_rows)


def _add_workspace_nodes(
    builder: OpenGraphBuilder,
    *,
    workspace_users: Iterable[dict[str, Any]] | None,
    workspace_groups: Iterable[dict[str, Any]] | None,
) -> None:
    # Seed high-confidence identity nodes from Google Workspace inventory first.
    # This allows later IAM-derived principal nodes to merge into richer user/group nodes
    # instead of remaining generic principal-only objects.
    _add_workspace_principal_nodes(
        builder,
        rows=workspace_users,
        member_prefix="user",
        node_type="GoogleUser",
        source="workspace_users",
        progress_label="Users processed",
    )
    _add_workspace_principal_nodes(
        builder,
        rows=workspace_groups,
        member_prefix="group",
        node_type="GoogleGroup",
        source="workspace_groups",
        progress_label="Groups processed",
    )


def _add_group_membership_edges(
    builder: OpenGraphBuilder,
    group_memberships: Iterable[dict[str, Any]] | None,
) -> None:
    # Add explicit group membership edges from workspace membership rows.
    # Expected row shape (canonical): {"group_member":"group:...","member":"user:/serviceAccount:...","source":"..."}
    row_list = [row for row in (group_memberships or []) if isinstance(row, dict)]
    total_rows = len(row_list)
    for index, row in enumerate(row_list, start=1):
        source = str(row.get("source") or "").strip() or "workspace_group_memberships"
        group = principal_node_id(str(row.get("group_member") or "").strip())
        member = principal_node_id(str(row.get("member") or "").strip())
        if group and member and not is_convenience_member(member):
            # Ensure source/destination principal nodes exist before adding edge.
            _ensure_principal_node(builder, member)
            _ensure_principal_node(builder, group)
            builder.add_edge(
                member,
                group,
                "GOOGLE_MEMBER_OF",
                source=source,
            )
        _print_progress_inline("Group memberships processed", index, total_rows)


def _add_admin_role_edges(
    builder: OpenGraphBuilder,
    *,
    admin_roles: Iterable[dict[str, Any]] | None,
    role_assignments: Iterable[dict[str, Any]] | None,
    workspace_users: Iterable[dict[str, Any]] | None,
) -> None:
    # A Google Workspace SUPER-ADMIN can impersonate, and reset the password of, ANY
    # user in the tenant -> emit CAN_IMPERSONATE / CAN_RESET_PASSWORD edges from each
    # super-admin principal to every Workspace user node (a user who then holds GCP IAM
    # is an attack path: super-admin -> user -> GCP resource).
    #
    # ADD-ONLY / no-op safety: when no super-admin role data is present -- which is the
    # case for every graph built before Workspace admin-role enumeration existed -- this
    # returns immediately, so existing graph output is byte-for-byte unchanged. New
    # edges appear ONLY once workspace_admin_roles + workspace_role_assignments have been
    # enumerated. Edge kinds match the BloodHound edge-kind regex ^[A-Za-z0-9_]+$.
    super_admin_role_ids = {
        str(role.get("role_id") or "").strip()
        for role in (admin_roles or [])
        if isinstance(role, dict) and str(role.get("is_super_admin_role") or "").strip().lower() == "true"
    }
    super_admin_role_ids.discard("")
    if not super_admin_role_ids:
        return

    # Workspace user id -> principal node id, plus the full set of user nodes (targets).
    user_node_by_id: dict[str, str] = {}
    user_nodes: list[str] = []
    for user in workspace_users or []:
        if not isinstance(user, dict):
            continue
        email = str(user.get("email") or "").strip()
        if not email:
            continue
        node = principal_node_id(f"user:{email}")
        if not node:
            continue
        user_nodes.append(node)
        user_id = str(user.get("user_id") or "").strip()
        if user_id:
            user_node_by_id[user_id] = node
    if not user_nodes:
        return

    # roleAssignments.assignedTo is the directory user id; fall back to an email-like value.
    super_admins: set[str] = set()
    for assignment in role_assignments or []:
        if not isinstance(assignment, dict):
            continue
        if str(assignment.get("role_id") or "").strip() not in super_admin_role_ids:
            continue
        assigned_to = str(assignment.get("assigned_to") or "").strip()
        node = user_node_by_id.get(assigned_to)
        if not node and "@" in assigned_to:
            node = principal_node_id(f"user:{assigned_to}")
        if node:
            super_admins.add(node)
    if not super_admins:
        return

    for admin in sorted(super_admins):
        _ensure_principal_node(builder, admin)
        for target in user_nodes:
            if target == admin:
                continue
            _ensure_principal_node(builder, target)
            builder.add_edge(admin, target, "CAN_IMPERSONATE", source="workspace_role_assignments")
            builder.add_edge(admin, target, "CAN_RESET_PASSWORD", source="workspace_role_assignments")


def _add_domain_wide_delegation_edges(
    builder: OpenGraphBuilder,
    *,
    delegations: Iterable[dict[str, Any]] | None,
    workspace_users: Iterable[dict[str, Any]] | None,
) -> None:
    # A SERVICE ACCOUNT with Google Workspace domain-wide delegation (DWD) can
    # impersonate ANY user in the tenant -> emit a DOMAIN_WIDE_DELEG edge from the SA
    # principal to every Workspace user node, plus a GoogleWorkspaceTenant hub node the
    # SA DELEGATES_INTO and users are WORKSPACE_MEMBER of. This is a GCP->Workspace
    # takeover path invisible to normal IAM enumeration (the grant lives in the Admin
    # console; gcpwn proves it by successfully impersonating an admin, recorded in
    # workspace_delegations).
    #
    # ADD-ONLY / no-op safety: returns immediately when no workspace_delegations rows
    # exist -- i.e. every graph built before a SA was proven to hold DWD -- so existing
    # graph output is byte-for-byte unchanged. Edge kinds match ^[A-Za-z0-9_]+$.
    delegation_rows = [row for row in (delegations or []) if isinstance(row, dict)]
    if not delegation_rows:
        return

    users_by_customer: dict[str, list[str]] = {}
    for user in workspace_users or []:
        if not isinstance(user, dict):
            continue
        email = str(user.get("email") or "").strip()
        node = principal_node_id(f"user:{email}") if email else ""
        if not node:
            continue
        users_by_customer.setdefault(str(user.get("customer_id") or "").strip(), []).append(node)

    # Tenant hub node + user membership, once per customer that has a proven delegation.
    delegated_customers = sorted(
        normalize_str_set([row.get('customer_id') for row in delegation_rows])
    )
    for customer in delegated_customers:
        tenant_node = f"workspace_tenant:{customer}"
        builder.add_node(
            tenant_node,
            "GoogleWorkspaceTenant",
            customer_id=customer,
            name=customer,
            display_name=customer,
            source="workspace_delegations",
        )
        for target in users_by_customer.get(customer, []):
            _ensure_principal_node(builder, target)
            builder.add_edge(target, tenant_node, "WORKSPACE_MEMBER", source="workspace_users")

    # SA -> DELEGATES_INTO -> tenant, and SA -> DOMAIN_WIDE_DELEG -> every user in it.
    for row in delegation_rows:
        sa_email = str(row.get("sa_email") or "").strip()
        customer = str(row.get("customer_id") or "").strip()
        if not (sa_email and customer):
            continue
        sa_node = principal_node_id(f"serviceAccount:{sa_email}")
        if not sa_node:
            continue
        tenant_node = f"workspace_tenant:{customer}"
        _ensure_principal_node(builder, sa_node)
        builder.add_edge(
            sa_node,
            tenant_node,
            "DELEGATES_INTO",
            source="workspace_delegations",
            admin_subject=str(row.get("admin_subject") or ""),
        )
        for target in users_by_customer.get(customer, []):
            _ensure_principal_node(builder, target)
            builder.add_edge(sa_node, target, "DOMAIN_WIDE_DELEG", source="workspace_delegations", customer_id=customer)


def _add_group_join_edges(
    builder: OpenGraphBuilder,
    *,
    group_settings: Iterable[dict[str, Any]] | None,
) -> None:
    # Self-join-open Google Workspace groups are an attack path: a principal who can
    # self-join a group inherits every IAM binding / membership that group holds. Emit
    # a CAN_JOIN edge into each open group from the broadest principal that can join it:
    #   whoCanJoin=ALL_IN_DOMAIN_CAN_JOIN -> PrincipalsInOrg (any authenticated user in
    #     the tenant/org; one node per directoryCustomerId)
    #   whoCanJoin=ANYONE_CAN_JOIN        -> GCPAllUsers (anyone on the internet /
    #     anonymous -- the existing "allUsers" node, connecting to the GCP graph)
    # Groups requiring an invite / request-with-approval are NOT open and get no edge.
    #
    # ADD-ONLY / no-op safety: returns immediately with no workspace_group_settings rows
    # (or none open-join), so existing graph output is byte-for-byte unchanged.
    rows = [row for row in (group_settings or []) if isinstance(row, dict)]
    if not rows:
        return

    for row in rows:
        group_email = str(row.get("group_email") or "").strip()
        group_node = principal_node_id(f"group:{group_email}") if group_email else ""
        if not group_node:
            continue
        who_can_join = str(row.get("who_can_join") or "").strip().upper()
        allow_external = str(row.get("allow_external_members") or "").strip().lower() == "true"

        if who_can_join == "ANYONE_CAN_JOIN":
            origin = principal_node_id("allUsers")  # GCPAllUsers -- anonymous / anyone
            _ensure_principal_node(builder, origin)
        elif who_can_join == "ALL_IN_DOMAIN_CAN_JOIN":
            customer = str(row.get("customer_id") or "").strip() or "unknown"
            origin = f"principals_in_org:{customer}"
            # add_node only (NOT _ensure_principal_node, which would re-type it to a
            # generic principal kind and drop PrincipalsInOrg).
            builder.add_node(
                origin,
                "PrincipalsInOrg",
                customer_id=customer,
                name="Principals In Org",
                display_name="Principals In Org",
                source="workspace_group_settings",
            )
        else:
            continue

        _ensure_principal_node(builder, group_node)
        builder.add_edge(
            origin,
            group_node,
            "CAN_JOIN",
            source="workspace_group_settings",
            who_can_join=who_can_join,
            allow_external_members=str(allow_external).lower(),
        )


def _add_drive_share_edges(
    builder: OpenGraphBuilder,
    *,
    drive_files: Iterable[dict[str, Any]] | None,
) -> None:
    # A Drive file shared to "anyone" is a direct data-exposure path: anyone on the
    # internet (public / anyone-with-link) can read it. Emit a GoogleDriveFile node and
    # a CAN_READ edge into it from GCPAllUsers (the existing anonymous "allUsers" node),
    # tying Drive exposure into the same graph as public buckets/IAM.
    #
    # ADD-ONLY / no-op safety: only public + anyone_with_link files produce edges, so the
    # graph is byte-for-byte unchanged until such a file is enumerated.
    rows = [row for row in (drive_files or []) if isinstance(row, dict)]
    if not rows:
        return

    for row in rows:
        exposure = str(row.get("exposure") or "").strip().lower()
        if exposure not in ("public", "anyone_with_link"):
            continue
        file_id = str(row.get("file_id") or "").strip()
        if not file_id:
            continue
        # OpenGraph node ids must not contain ':' -> use a '_' separator.
        file_node = f"drive_file_{file_id}"
        name = str(row.get("name") or file_id)
        builder.add_node(
            file_node,
            "GoogleDriveFile",
            name=name,
            display_name=name,
            file_id=file_id,
            exposure=exposure,
            owner=str(row.get("owner_email") or ""),
            web_view_link=str(row.get("web_view_link") or ""),
            source="workspace_drive_files",
        )
        origin = principal_node_id("allUsers")  # GCPAllUsers -- anonymous / anyone
        _ensure_principal_node(builder, origin)
        # Role of the "anyone" grant (reader/writer/commenter), if present in raw ACLs.
        role = _anyone_role(row)
        builder.add_edge(
            origin,
            file_node,
            "CAN_READ",
            source="workspace_drive_files",
            exposure=exposure,
            role=role,
        )


def _anyone_role(row: dict[str, Any]) -> str:
    # raw_json is a dict in-process at save time but comes back from the DB as a JSON
    # string, so accept either -- otherwise a world-*writable* public file would be
    # mislabeled role="reader" on its CAN_READ edge.
    raw = row.get("raw_json")
    if isinstance(raw, str) and raw.strip():
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            raw = None
    if isinstance(raw, dict):
        for perm in raw.get("permissions") or []:
            if isinstance(perm, dict) and str(perm.get("type") or "") == "anyone":
                return str(perm.get("role") or "reader")
    return "reader"


def _add_iam_member_nodes(
    builder: OpenGraphBuilder,
    members: Iterable[str] | None,
) -> None:
    # Add principals observed in IAM bindings.
    # `members` typically comes from simplified["member_binding_index"].keys(), e.g.
    # ["user:alice@example.com", "group:eng@example.com", "domain:example.com", "allUsers"].
    #
    # Skip convenience members (projectOwner/projectEditor/projectViewer):
    # context.simplified_hierarchy_permissions() already expands them to
    # concrete principals and carries `derived_from` metadata in
    # member_binding_index[*].binding_records for IAM stages. We do not materialize the
    # pseudo-principal itself as a standalone identity node in stage 10.
    #
    # Also skip nodes already present (often seeded via Workspace data).
    normalized_members = _normalized_principal_tokens(members)
    total_members = len(normalized_members)
    for index, member in enumerate(normalized_members, start=1):
        if member and not is_convenience_member(member) and member not in builder.node_map:
            _ensure_principal_node(builder, member, source="iam_members")
        _print_progress_inline("IAM principals processed", index, total_members)


def _member_email(member: str) -> str:
    # Extract email-ish identity tokens from principal strings.
    # Deleted principals are already filtered by principal_node_id().
    # Examples:
    # - user:alice@example.com                -> alice@example.com
    # - allUsers                               -> ""
    token = principal_node_id(member)
    if ":" not in token:
        return ""
    _prefix, value = token.split(":", 1)
    email = value.split("?", 1)[0].strip().lower()
    return email if "@" in email else ""


def _add_domain_wide_membership_edges(builder: OpenGraphBuilder) -> None:
    # Add inferred user/group/serviceAccount -> domain:<suffix> edges
    # only when the destination domain node already exists.
    #
    # Example:
    # - source principal: user:alice@example.com
    # - inferred edge: user:alice@example.com -[DOMAIN_MEMBER_OF]-> domain:example.com
    domain_node_ids = {
        token
        for token in builder.node_map.keys()
        if token.startswith("domain:")
    }
    if not domain_node_ids:
        return

    for src_id, node in builder.node_map.items():
        props = dict(node.properties or {})
        email = str(props.get("email") or "").strip().lower()
        if not email:
            email = _member_email(str(props.get("member") or src_id).strip())
        if "@" not in email:
            continue

        domain = email.split("@", 1)[1].strip().lower()
        if not domain:
            continue
        dst_id = principal_node_id(f"domain:{domain}")
        if dst_id not in domain_node_ids or dst_id == src_id:
            continue

        builder.add_edge(
            src_id,
            dst_id,
            "DOMAIN_MEMBER_OF",
            source="domain_wide_memberships",
            membership_scope="domain",
        )


def _add_crm_service_account_principal_set_edges(
    builder: OpenGraphBuilder,
    *,
    iam_service_accounts_rows: Iterable[dict[str, Any]] | None,
    project_scope_by_project_id: dict[str, str],
    parent_by_name: dict[str, str],
) -> int:
    # Expand CRM service-account principal sets that are already present in IAM members:
    #   serviceAccount:<email> -[GCP_PRINCIPAL_SET]-> principalSet://cloudresourcemanager.googleapis.com/.../type/ServiceAccount
    edges_added = 0

    crm_principal_set_nodes = {
        node_id
        for node_id in builder.node_map.keys()
        if node_id.startswith("principalSet://cloudresourcemanager.googleapis.com/")
        and node_id.endswith("/type/ServiceAccount")
    }
    if not crm_principal_set_nodes:
        return 0

    for row in iam_service_accounts_rows or []:
        principal_type_token = str(row.get("type") or "").strip().lower()
        if "service" not in principal_type_token:
            continue
        email = str(row.get("email") or "").strip().lower()
        project_id = str(row.get("project_id") or "").strip()
        project_scope = project_scope_by_project_id.get(project_id, "").strip()
        if not email or not project_scope:
            continue

        member = f"serviceAccount:{email}"
        service_account_id = _ensure_principal_node(builder, member, source="iam_service_accounts")
        if not service_account_id:
            continue

        for scope_name in _scope_chain(project_scope, parent_by_name):
            if "/" not in scope_name:
                continue
            scope_kind, scope_number = scope_name.split("/", 1)
            if scope_kind not in {"projects", "folders", "organizations"} or not scope_number:
                continue
            principal_set_member = (
                f"principalSet://cloudresourcemanager.googleapis.com/{scope_kind}/{scope_number}/type/ServiceAccount"
            )
            principal_set_id = principal_node_id(principal_set_member)
            if principal_set_id not in crm_principal_set_nodes:
                continue

            edge_key = (service_account_id, "GCP_PRINCIPAL_SET", principal_set_id)
            if edge_key in builder.edge_map:
                continue
            builder.add_edge(
                service_account_id,
                principal_set_id,
                "GCP_PRINCIPAL_SET",
                source="stage_1_principals",
                principal_set_kind="crm_service_accounts",
                principal_set_scope_name=scope_name,
                membership_dynamic=True,
            )
            edges_added += 1
    return edges_added


def build_users_groups_graph(context) -> dict[str, int | bool]:
    before_nodes, before_edges = context.counts()
    builder = context.builder

    simplified_base = context.simplified_hierarchy_permissions(include_inferred_permissions=False)
    member_binding_index = dict(simplified_base.get("member_binding_index") or {})
    iam_members = sorted(member_binding_index.keys())
    workspace_users_rows = [row for row in (context.rows("workspace_users") or []) if isinstance(row, dict)]
    workspace_groups_rows = [row for row in (context.rows("workspace_groups") or []) if isinstance(row, dict)]
    group_membership_rows = [row for row in (context.rows("group_memberships") or []) if isinstance(row, dict)]
    iam_service_accounts_rows = [row for row in (context.rows("iam_service_accounts") or []) if isinstance(row, dict)]
    print(
        "[*] Stage 1 tally: "
        f"users={len(workspace_users_rows)}, "
        f"groups={len(workspace_groups_rows)}, "
        f"iam_members={len(iam_members)}, "
        f"group_memberships={len(group_membership_rows)}, "
        f"service_accounts={len(iam_service_accounts_rows)}"
    )

    hierarchy = context.hierarchy_data()
    hierarchy_rows = context.rows("hierarchy_rows")
    project_scope_by_project_id = {
        str(row.get("project_id") or "").strip(): str(row.get("name") or "").strip()
        for row in hierarchy_rows
        if str(row.get("type") or "").strip().lower() == "project"
        and str(row.get("project_id") or "").strip()
        and str(row.get("name") or "").strip()
    }

    # Input contracts used here:
    # - context.rows("workspace_users"):  Workspace users
    # - context.rows("workspace_groups"): Workspace groups
    # - context.rows("iam_service_accounts"): service account inventory
    # - simplified.member_binding_index:  IAM-derived member keys from allow policy parsing
    # - context.rows("group_memberships"): workspace membership rows

    # 1) Seed workspace users/groups
    _add_workspace_nodes(
        builder,
        workspace_users=workspace_users_rows,
        workspace_groups=workspace_groups_rows,
    )

    # 2) Fill in any remaining IAM principals, including selector-style principals:
    #    - principal://...
    #    - principalSet://...
    _add_iam_member_nodes(builder, iam_members)

    # 3) Add explicit group membership edges
    _add_group_membership_edges(
        builder,
        group_membership_rows,
    )

    # 4) Add inferred domain membership edges when domain nodes exist
    _add_domain_wide_membership_edges(builder)

    # 5) Expand CRM service-account principalSet membership where those principalSets
    #    are already present in IAM members (project/folder/org SA principal sets).
    _add_crm_service_account_principal_set_edges(
        builder,
        iam_service_accounts_rows=iam_service_accounts_rows,
        project_scope_by_project_id=project_scope_by_project_id,
        parent_by_name=hierarchy["parent_by_name"],
    )

    # 6) Workspace super-admins -> CAN_IMPERSONATE / CAN_RESET_PASSWORD over every user.
    #    Add-only: a no-op until Workspace admin-role data has been enumerated.
    _add_admin_role_edges(
        builder,
        admin_roles=[row for row in (context.rows("workspace_admin_roles") or []) if isinstance(row, dict)],
        role_assignments=[row for row in (context.rows("workspace_role_assignments") or []) if isinstance(row, dict)],
        workspace_users=workspace_users_rows,
    )

    # 7) Service accounts with Google Workspace domain-wide delegation -> DOMAIN_WIDE_DELEG
    #    over every user in the tenant (+ a GoogleWorkspaceTenant hub node). Add-only: a
    #    no-op until a SA is proven to hold DWD (workspace_delegations populated).
    _add_domain_wide_delegation_edges(
        builder,
        delegations=[row for row in (context.rows("workspace_delegations") or []) if isinstance(row, dict)],
        workspace_users=workspace_users_rows,
    )

    # 8) Self-join-open groups -> CAN_JOIN from WorkspaceAllAuthenticatedPrincipals
    #    (ALL_IN_DOMAIN_CAN_JOIN) or GCPAllUsers/anonymous (ANYONE_CAN_JOIN). Add-only:
    #    a no-op until group settings are enumerated (enum_group_settings).
    _add_group_join_edges(
        builder,
        group_settings=[row for row in (context.rows("workspace_group_settings") or []) if isinstance(row, dict)],
    )

    # 9) Public / anyone-with-link Google Drive files -> CAN_READ from GCPAllUsers
    #    (anonymous). Add-only: a no-op until Drive files are enumerated (enum_drive).
    _add_drive_share_edges(
        builder,
        drive_files=[row for row in (context.rows("workspace_drive_files") or []) if isinstance(row, dict)],
    )

    after_nodes, after_edges = context.counts()
    return {
        "include_memberships": True,
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
