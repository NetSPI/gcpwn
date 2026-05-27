from __future__ import annotations

"""
Stage 10: principal and membership seeding.

Responsibilities:
- seed Google Workspace user/group nodes
- backfill IAM-only principal nodes not present in Workspace data
- emit explicit group membership edges
- emit inferred domain membership edges when domain nodes exist
"""

from typing import Any, Iterable

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
    return max(1, total // 20)


def _should_log_progress(processed: int, total: int, *, interval: int | None = None) -> bool:
    if total <= 0 or processed <= 0:
        return False
    step = interval if interval is not None else _progress_interval(total)
    return processed == total or processed == 1 or processed % step == 0


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
        if _should_log_progress(index, total_rows):
            print(
                f"[*] {progress_label}: {index}/{total_rows} "
                f"(remaining {max(0, total_rows - index)})"
            )


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
        if _should_log_progress(index, total_rows):
            print(
                f"[*] Group memberships processed: {index}/{total_rows} "
                f"(remaining {max(0, total_rows - index)})"
            )


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
        if _should_log_progress(index, total_members):
            print(
                f"[*] IAM principals processed: {index}/{total_members} "
                f"(remaining {max(0, total_members - index)})"
            )


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

    after_nodes, after_edges = context.counts()
    return {
        "include_memberships": True,
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
