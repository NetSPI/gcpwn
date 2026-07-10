"""End-to-end OpenGraph pipeline tests driven by fake SQLite data.

Builds a real OpenGraphBuildContext over a FakeSession (canned get_data rows), runs
the actual stage builders, and asserts the emitted nodes/edges. This catches WIRING
gaps the per-function unit tests miss -- e.g. a table missing from context._ROW_TABLES
(which silently makes context.rows() return [] and a whole edge family disappear).

Covers: identity edges (GOOGLE_MEMBER_OF), the Workspace super-admin edges
(CAN_IMPERSONATE / CAN_RESET_PASSWORD, end-to-end through context.rows), and Workload
Identity Federation edges end-to-end through context.rows. (IAM binding / ROLE_OWNER /
org->project inheritance wiring is covered by test_fakedata_inheritance.py.)
"""

from __future__ import annotations


from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import build_resource_expansion_graph

from conftest import FakeSession, _edge_kinds, _edges, _node_types


# --------------------------------------------------------------------------- #
# Stage 1: identity + Workspace super-admin edges (end-to-end via context.rows)
# --------------------------------------------------------------------------- #


def _identity_tables() -> dict[str, list[dict]]:
    return {
        "iam_allow_policies": [],
        "abstract_tree_hierarchy": [],
        "iam_service_accounts": [],
        "workspace_users": [
            {"email": "admin@corp.com", "user_id": "1"},
            {"email": "alice@corp.com", "user_id": "2"},
            {"email": "bob@corp.com", "user_id": "3"},
        ],
        "workspace_groups": [{"email": "eng@corp.com", "name": "groups/eng"}],
        "workspace_group_memberships": [
            {"group_member": "group:eng@corp.com", "member": "user:alice@corp.com", "source": "workspace_group_memberships"},
        ],
        "workspace_admin_roles": [
            {"role_id": "R_SUPER", "is_super_admin_role": "true"},
            {"role_id": "R_HELP", "is_super_admin_role": "false"},
        ],
        "workspace_role_assignments": [
            {"role_id": "R_SUPER", "assigned_to": "1"},   # admin@corp.com is super-admin
            {"role_id": "R_HELP", "assigned_to": "2"},    # alice is only a helpdesk admin (ignored)
        ],
    }


def _build_stage1(tables, **opts):
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions(**opts))
    build_users_groups_graph(ctx)
    return ctx


def test_group_membership_edge_emitted():
    ctx = _build_stage1(_identity_tables())
    assert ("user:alice@corp.com", "GOOGLE_MEMBER_OF", "group:eng@corp.com") in _edges(ctx)
    types = _node_types(ctx)
    assert types.get("user:alice@corp.com") == "GoogleUser"
    assert types.get("group:eng@corp.com") == "GoogleGroup"


def test_super_admin_edges_emit_end_to_end_through_context_rows():
    # Regression: workspace_admin_roles/role_assignments must be in context._ROW_TABLES,
    # else context.rows() returns [] and these edges silently never appear.
    ctx = _build_stage1(_identity_tables())
    edges = _edges(ctx)
    admin = "user:admin@corp.com"
    for target in ("user:alice@corp.com", "user:bob@corp.com"):
        assert (admin, "CAN_IMPERSONATE", target) in edges
        assert (admin, "CAN_RESET_PASSWORD", target) in edges
    # the helpdesk (non-super) admin gets NO impersonation edges
    assert not any(src == "user:alice@corp.com" and kind == "CAN_IMPERSONATE" for src, kind, _ in edges)


def test_no_workspace_admin_data_means_no_admin_edges():
    tables = _identity_tables()
    tables["workspace_admin_roles"] = []
    tables["workspace_role_assignments"] = []
    ctx = _build_stage1(tables)
    assert "CAN_IMPERSONATE" not in _edge_kinds(ctx)
    assert "CAN_RESET_PASSWORD" not in _edge_kinds(ctx)


# --------------------------------------------------------------------------- #
# Stage 4: Workload Identity Federation (regression for the _ROW_TABLES WIF gap)
# --------------------------------------------------------------------------- #


def test_wif_edges_emit_end_to_end_through_context_rows():
    # Regression: workload_identity_pools/providers must be in context._ROW_TABLES, else
    # context.rows() returns [] in resource expansion and WIF_PROVIDER_IN_POOL (and the
    # rest of the WIF family) silently never emit despite being documented edges.
    pool = "projects/123/locations/global/workloadIdentityPools/mypool"
    provider = f"{pool}/providers/myprovider"
    tables = {
        "iam_allow_policies": [],
        "abstract_tree_hierarchy": [{"name": "projects/proj-a", "type": "project", "project_id": "proj-a"}],
        "iam_service_accounts": [],
        "iam_sa_keys": [],
        "cloudcompute_instances": [],
        "cloudfunctions_functions": [],
        "cloudrun_services": [],
        "cloudrun_jobs": [],
        "workload_identity_pools": [{"name": pool, "pool_id": "mypool", "project_id": "proj-a"}],
        "workload_identity_providers": [
            {"name": provider, "pool_name": pool, "provider_id": "myprovider", "project_id": "proj-a"}
        ],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    build_resource_expansion_graph(ctx)
    assert (f"resource:{provider}", "WIF_PROVIDER_IN_POOL", f"resource:{pool}") in _edges(ctx)
