"""Fake-data tests for principal/resource NODE TYPES that the golden snapshot
doesn't exercise: allUsers / allAuthenticatedUsers pseudo-principals, domain
principals (+ DOMAIN_MEMBER_OF), WIF principalSet members (+ FederatedPrincipalInPool),
and the GCPCloudFunction / GCPSecret resource node types from the priv-esc rules.
All shapes verified empirically against the pipeline.
"""

from __future__ import annotations

import json

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import build_resource_expansion_graph

from conftest import FakeSession, _policy


_TABLE_KEYS = (
    "iam_allow_policies", "iam_roles", "abstract_tree_hierarchy", "iam_service_accounts",
    "iam_sa_keys", "cloudcompute_instances", "cloudfunctions_functions", "cloudrun_services",
    "cloudrun_jobs", "workload_identity_pools", "workload_identity_providers",
    "workspace_users", "workspace_groups", "workspace_group_memberships",
    "workspace_admin_roles", "workspace_role_assignments",
)
_HIER = [{"name": "projects/proj-a", "type": "project", "display_name": "proj-a", "project_id": "proj-a", "parent": ""}]


def _run(extra, *, stage4=False):
    tables = {k: [] for k in _TABLE_KEYS}
    tables["abstract_tree_hierarchy"] = _HIER
    tables.update(extra)
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions(include_all=True))
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    if stage4:
        build_resource_expansion_graph(ctx)
    nodes = {n.node_id: n.node_type for n in ctx.builder.node_map.values()}
    edges = {(e.source_id, e.edge_type, e.destination_id) for e in ctx.builder.edge_map.values()}
    return nodes, edges


def test_alluser_pseudo_principals_get_typed_nodes():
    iam = [{"project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
            "policy": _policy(("roles/editor", ["allUsers", "allAuthenticatedUsers"]))}]
    nodes, _ = _run({"iam_allow_policies": iam})
    assert nodes.get("allUsers") == "GCPAllUsers"
    assert nodes.get("allAuthenticatedUsers") == "GCPAllAuthenticatedUsers"


def test_wif_principalset_member_and_in_pool_edge():
    pool = "projects/123/locations/global/workloadIdentityPools/pool1"
    pset = f"principalSet://iam.googleapis.com/{pool}/*"
    iam = [{"project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
            "policy": _policy(("roles/editor", [pset]))}]
    nodes, edges = _run(
        {"iam_allow_policies": iam, "workload_identity_pools": [{"name": pool, "pool_id": "pool1", "project_id": "proj-a"}]},
        stage4=True,
    )
    assert nodes.get(pset) == "GCPPrincipalSet"
    # Resource node ids are now resource:<leaf>@<project-number>; pool leaf "pool1" @ project 123.
    assert (pset, "FederatedPrincipalInPool", "resource:pool1@123") in edges


def _privesc(permission, resource_type, resource_name):
    role = "projects/proj-a/roles/Custom"
    iam = [
        {"project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
         "policy": _policy((role, ["user:eve@corp.com"]))},
        {"project_id": "proj-a", "resource_type": resource_type, "resource_name": resource_name,
         "policy": _policy(("roles/viewer", ["user:by@corp.com"]))},
    ]
    return {"iam_allow_policies": iam, "iam_roles": [{"name": role, "included_permissions": json.dumps([permission])}]}


def test_cloudfunction_resource_node_type():
    fn = "projects/proj-a/locations/us-central1/functions/fn1"
    nodes, edges = _run(_privesc("cloudfunctions.functions.setIamPolicy", "cloudfunction", fn))
    # Resource node ids are now resource:<leaf>@<project-id>; function leaf "fn1" @ proj-a.
    fn_id = "resource:fn1@proj-a"
    assert nodes.get(fn_id) == "GCPCloudFunction"
    assert any(k == "CAN_MODIFY_CLOUD_RUN_FUNCTION_IAM" and d == fn_id for _, k, d in edges)


def test_secret_resource_node_type():
    secret = "projects/proj-a/secrets/db-password"
    tables = {k: [] for k in _TABLE_KEYS}
    tables["abstract_tree_hierarchy"] = _HIER
    tables.update(_privesc("secretmanager.versions.access", "secrets", secret))
    ctx = OpenGraphBuildContext(
        session=FakeSession(tables),
        options=OpenGraphBuildOptions(
            include_all=True,
            edge_categories=frozenset({"priv_escalation", "sensitive_resource_access"}),
        ),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    nodes = {n.node_id: n.node_type for n in ctx.builder.node_map.values()}
    edges = {(e.source_id, e.edge_type, e.destination_id) for e in ctx.builder.edge_map.values()}
    # Resource node ids are now resource:<leaf>@<project-id>; secret leaf "db-password" @ proj-a.
    secret_id = "resource:db-password@proj-a"
    assert nodes.get(secret_id) == "GCPSecret"
    assert any(k == "CAN_READ_SECRET_DATA" and d == secret_id for _, k, d in edges)
