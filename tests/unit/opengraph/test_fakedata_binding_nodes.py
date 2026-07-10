"""Fake-data regression tests for the generic IAM binding modeling family.

Proves the canonical single-grant binding shape survives refactors:
  principal -[HAS_IAM_BINDING]-> GCPIamSimpleBinding-node -[edge]-> target

Asserts:
- The GCPIamSimpleBinding node type is emitted for an ordinary (non-dangerous) grant.
- HAS_IAM_BINDING edge: principal -> binding node.
- include_all=True materializes benign binding nodes that are suppressed otherwise.
- roles/owner collapses to ROLE_OWNER and roles/editor collapses to ROLE_EDITOR.
- DOMAIN_MEMBER_OF: a workspace user whose email suffix matches a domain node
  (seeded as an IAM member) gets a user -> domain edge from stage 1.

Mirrors the harness in test_pipeline_fakedata.py (FakeSession + stage builders).
"""

from __future__ import annotations

from conftest import FakeSession, _edge_kinds, _edges, _node_types, _policy

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph

_BASE_HIERARCHY = [
    {"name": "organizations/111", "type": "organization", "display_name": "corp", "project_id": ""},
    {
        "name": "projects/proj-a",
        "type": "project",
        "display_name": "proj-a",
        "project_id": "proj-a",
        "parent": "organizations/111",
    },
]


def _empty_workspace() -> dict[str, list[dict]]:
    return {
        "iam_allow_policies": [],
        "abstract_tree_hierarchy": list(_BASE_HIERARCHY),
        "iam_service_accounts": [],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }


def _build_iam(tables, **opts):
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions(**opts))
    _run_iam_bindings_stage(ctx)
    return ctx


# --------------------------------------------------------------------------- #
# GCPIamSimpleBinding node + HAS_IAM_BINDING + POLICY_BINDINGS (include_all)
# --------------------------------------------------------------------------- #


def _ordinary_binding_tables() -> dict[str, list[dict]]:
    tables = _empty_workspace()
    # roles/viewer is a benign, non-dangerous, non-collapsed role bound at the project.
    tables["iam_allow_policies"] = [
        {
            "project_id": "proj-a",
            "resource_type": "project",
            "resource_name": "projects/proj-a",
            "policy": _policy(("roles/viewer", ["user:bob@corp.com"])),
        },
    ]
    return tables


def test_benign_binding_node_visible_only_with_include_all():
    # A benign (non-dangerous, non-owner/editor) grant does NOT materialize a binding
    # node by default -- it is only kept when include_all=True. This guards the
    # include_all gating in _emit_iam_binding_edges_from_entries (bindings_to_emit).
    without = _build_iam(_ordinary_binding_tables(), include_all=False)
    assert "GCPIamSimpleBinding" not in set(_node_types(without).values())
    assert "HAS_IAM_BINDING" not in _edge_kinds(without)

    with_all = _build_iam(_ordinary_binding_tables(), include_all=True)
    types = _node_types(with_all)
    binding_nodes = [nid for nid, t in types.items() if t == "GCPIamSimpleBinding"]
    assert binding_nodes, "include_all should materialize the benign viewer binding node"
    # principal -> that binding node via HAS_IAM_BINDING
    has_binding = {(s, d) for s, k, d in _edges(with_all) if k == "HAS_IAM_BINDING"}
    assert any(src == "user:bob@corp.com" and dst in binding_nodes for src, dst in has_binding)


# --------------------------------------------------------------------------- #
# ROLE_OWNER vs ROLE_EDITOR collapse
# --------------------------------------------------------------------------- #


def test_role_owner_and_role_editor_collapse_distinctly():
    tables = _empty_workspace()
    tables["iam_allow_policies"] = [
        {
            "project_id": "proj-a",
            "resource_type": "project",
            "resource_name": "projects/proj-a",
            "policy": _policy(
                ("roles/owner", ["user:alice@corp.com"]),
                ("roles/editor", ["user:carol@corp.com"]),
            ),
        },
    ]
    ctx = _build_iam(tables, include_all=False)
    kinds = _edge_kinds(ctx)
    # owner collapses to ROLE_OWNER, editor collapses to ROLE_EDITOR -- distinct kinds.
    assert "ROLE_OWNER" in kinds
    assert "ROLE_EDITOR" in kinds

    edges = _edges(ctx)
    # owner and editor each route through their own GCPIamSimpleBinding node.
    role_owner_srcs = {s for s, k, _ in edges if k == "ROLE_OWNER"}
    role_editor_srcs = {s for s, k, _ in edges if k == "ROLE_EDITOR"}
    binding_nodes = {nid for nid, t in _node_types(ctx).items() if t == "GCPIamSimpleBinding"}
    assert role_owner_srcs and role_owner_srcs <= binding_nodes
    assert role_editor_srcs and role_editor_srcs <= binding_nodes

    # The respective principals each have a HAS_IAM_BINDING edge into a binding node.
    has_binding_srcs = {s for s, k, _ in edges if k == "HAS_IAM_BINDING"}
    assert "user:alice@corp.com" in has_binding_srcs
    assert "user:carol@corp.com" in has_binding_srcs


# --------------------------------------------------------------------------- #
# Stage 1: DOMAIN_MEMBER_OF (user email suffix -> domain node)
# --------------------------------------------------------------------------- #


def _domain_tables() -> dict[str, list[dict]]:
    tables = _empty_workspace()
    # A domain principal appears as an IAM member, which seeds a domain:<suffix> node
    # in stage 1. The workspace user alice@corp.com should then map into it by suffix.
    tables["iam_allow_policies"] = [
        {
            "project_id": "proj-a",
            "resource_type": "project",
            "resource_name": "projects/proj-a",
            "policy": _policy(("roles/viewer", ["domain:corp.com"])),
        },
    ]
    tables["workspace_users"] = [
        {"email": "alice@corp.com", "user_id": "2"},
    ]
    return tables


def _build_stage1(tables, **opts):
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions(**opts))
    build_users_groups_graph(ctx)
    return ctx


def test_domain_member_of_edge_from_workspace_user_suffix():
    ctx = _build_stage1(_domain_tables())
    types = _node_types(ctx)
    # the domain node exists (seeded from the IAM member domain:corp.com)
    assert types.get("domain:corp.com") == "GCPDomainPrincipal"
    # and the workspace user maps into it by email suffix.
    assert ("user:alice@corp.com", "DOMAIN_MEMBER_OF", "domain:corp.com") in _edges(ctx)


def test_no_domain_node_means_no_domain_member_of():
    # Remove the domain IAM member -> no domain node -> no DOMAIN_MEMBER_OF edge.
    tables = _domain_tables()
    tables["iam_allow_policies"] = []
    ctx = _build_stage1(tables)
    assert "DOMAIN_MEMBER_OF" not in _edge_kinds(ctx)
