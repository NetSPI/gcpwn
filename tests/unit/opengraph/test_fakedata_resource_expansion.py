"""Fake-data regression tests for the OpenGraph resource-expansion edge family.

Runs the real stage builders (stage 1 principals -> stage 2 IAM bindings ->
stage 4 resource expansion) over a FakeSession of canned `get_data` rows and
asserts that the resource-expansion edge kinds are emitted. This guards against
a future refactor silently dropping a whole edge family (e.g. a table dropping
out of context._ROW_TABLES, or a section being skipped in stage 4).

Edge kinds covered here:
  - EXISTS_IN_PROJECT          (project -> compute instance topology)
  - EXECUTES_WITH              (compute instance -> attached service account)
  - GCP_SERVICE_ACCOUNT_KEY_FOR(iam_sa_keys key node -> service account)
  - GCP_PRINCIPAL_SET          (serviceAccount -> CRM ServiceAccount principalSet)
  - WIF_PRINCIPAL_IN_POOL      (WIF principal member -> workload identity pool)

Not covered (see module docstring blockers / report): WIF_PROVIDER_IN_POOL,
GCP_FEDERATION_POSSIBLE, and EXISTS_IN_PROJECT for WIF pools/providers. Those
read `workload_identity_pools` / `workload_identity_providers` exclusively
through context.rows(), whose key->table map (_ROW_TABLES) has no entry for
those tables, so the rows always come back empty regardless of get_data data.
"""

from __future__ import annotations

import json

import pytest
from conftest import FakeSession, _edge_kinds, _edges, _node_types

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import (
    build_resource_expansion_graph,
)


# Canonical fake identifiers reused across assertions.
_SA_EMAIL = "sa@proj-a.iam.gserviceaccount.com"
_SA_KEY_NAME = f"projects/proj-a/serviceAccounts/{_SA_EMAIL}/keys/key-123"
_INSTANCE_RESOURCE = "projects/proj-a/zones/us-central1-a/instances/vm1"
_PROJECT_SCOPE = "projects/proj-a"
_WIF_SUBJECT_MEMBER = (
    "principal://iam.googleapis.com/projects/123456/locations/global"
    "/workloadIdentityPools/my-pool/subject/sub-1"
)
_WIF_POOL_RESOURCE = "projects/123456/locations/global/workloadIdentityPools/my-pool"
_CRM_PRINCIPAL_SET = (
    "principalSet://cloudresourcemanager.googleapis.com/projects/proj-a/type/ServiceAccount"
)


def _resource_expansion_tables() -> dict[str, list[dict]]:
    """Representative fake data exercising every supported resource-expansion edge.

    A single project-scope IAM binding carries three member kinds:
      - serviceAccount:<email>   (drives GCP_PRINCIPAL_SET via the CRM principalSet member)
      - the CRM ServiceAccount principalSet (creates the CRM target node)
      - a WIF subject principal    (drives WIF_PRINCIPAL_IN_POOL)
    plus cached service tables for the SA key, the SA inventory, and a compute
    instance attached to the SA.
    """
    policy = json.dumps(
        {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [
                        f"serviceAccount:{_SA_EMAIL}",
                        _CRM_PRINCIPAL_SET,
                        _WIF_SUBJECT_MEMBER,
                    ],
                }
            ]
        }
    )
    return {
        "iam_allow_policies": [
            {
                "project_id": "proj-a",
                "resource_type": "project",
                "resource_name": _PROJECT_SCOPE,
                "policy": policy,
            }
        ],
        "abstract_tree_hierarchy": [
            {
                "name": _PROJECT_SCOPE,
                "type": "project",
                "display_name": "proj-a",
                "project_id": "proj-a",
            }
        ],
        "iam_service_accounts": [
            {"email": _SA_EMAIL, "project_id": "proj-a", "type": "serviceAccount", "name": "sa display"},
        ],
        "iam_sa_keys": [
            {"name": _SA_KEY_NAME, "key_type": "USER_MANAGED", "disabled": False},
        ],
        "cloudcompute_instances": [
            {
                "project_id": "proj-a",
                "name": "vm1",
                "zone": "us-central1-a",
                "status": "RUNNING",
                "service_accounts": json.dumps([{"email": _SA_EMAIL}]),
            }
        ],
    }


@pytest.fixture()
def expansion_context():
    tables = _resource_expansion_tables()
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)   # stage 1: principals + GCP_PRINCIPAL_SET
    _run_iam_bindings_stage(ctx)     # stage 2: IAM bindings (seeds member index)
    build_resource_expansion_graph(ctx)  # stage 4: resource expansion edges
    return ctx


def test_exists_in_project_edge_for_compute_instance(expansion_context):
    edges = _edges(expansion_context)
    project_node = "resource:projects/proj-a"
    instance_node = f"resource:{_INSTANCE_RESOURCE}"
    assert (project_node, "EXISTS_IN_PROJECT", instance_node) in edges
    types = _node_types(expansion_context)
    assert types.get(instance_node) == "GCPComputeInstance"
    assert types.get(project_node) == "GCPProject"


def test_executes_with_edge_instance_to_attached_service_account(expansion_context):
    edges = _edges(expansion_context)
    instance_node = f"resource:{_INSTANCE_RESOURCE}"
    sa_node = f"serviceAccount:{_SA_EMAIL}"
    assert (instance_node, "EXECUTES_WITH", sa_node) in edges
    assert _node_types(expansion_context).get(sa_node) == "GCPServiceAccount"


def test_service_account_key_for_edge(expansion_context):
    edges = _edges(expansion_context)
    key_node = f"service_account_key:{_SA_KEY_NAME}"
    sa_node = f"serviceAccount:{_SA_EMAIL}"
    assert (key_node, "GCP_SERVICE_ACCOUNT_KEY_FOR", sa_node) in edges
    assert _node_types(expansion_context).get(key_node) == "GCPServiceAccountKey"


def test_gcp_principal_set_edge_service_account_to_crm_set(expansion_context):
    edges = _edges(expansion_context)
    sa_node = f"serviceAccount:{_SA_EMAIL}"
    assert (sa_node, "GCP_PRINCIPAL_SET", _CRM_PRINCIPAL_SET) in edges


def test_wif_principal_in_pool_edge(expansion_context):
    edges = _edges(expansion_context)
    pool_node = f"resource:{_WIF_POOL_RESOURCE}"
    assert (_WIF_SUBJECT_MEMBER, "WIF_PRINCIPAL_IN_POOL", pool_node) in edges
    assert _node_types(expansion_context).get(pool_node) == "GCPWorkloadIdentityPool"


def test_no_compute_rows_means_no_executes_with_or_exists_in_project():
    # Drop the compute instance: the compute-driven edges must disappear, proving
    # the edges are data-driven (not spuriously emitted).
    tables = _resource_expansion_tables()
    tables["cloudcompute_instances"] = []
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    build_resource_expansion_graph(ctx)
    kinds = _edge_kinds(ctx)
    assert "EXECUTES_WITH" not in kinds
    # The compute instance's project edge disappears with the compute rows, but an
    # enumerated service account still EXISTS_IN_PROJECT (that edge is SA-driven, not
    # compute-driven -- SAs are seeded as project resources so combo target selection
    # can find them). So assert only the COMPUTE-instance project edge is gone.
    exists_in_project_dests = {
        e.destination_id for e in ctx.builder.edge_map.values() if e.edge_type == "EXISTS_IN_PROJECT"
    }
    assert not any("/instances/" in dest for dest in exists_in_project_dests)
    # The SA-key and WIF edges are independent of compute and still present.
    assert "GCP_SERVICE_ACCOUNT_KEY_FOR" in kinds
    assert "WIF_PRINCIPAL_IN_POOL" in kinds
