"""CAI ingest: synthetic Cloud Asset Inventory records -> mapping -> real OpenGraph pipeline.

Proves `cai_records_to_tables` produces row shapes the unchanged pipeline can build a
graph from (incl. the project-number -> projectId normalization), so `process_og
--cai-file` works without the DB. Asserts the key edge families emerge.
"""

from __future__ import annotations

from gcpwn.modules.gcp.assetinventory.utilities.cai_mapping import cai_records_to_tables
from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import build_resource_expansion_graph


class _CaiSession:
    """A get_data-only session backed by CAI-mapped tables (the CaiFileSource shape)."""

    def __init__(self, tables):
        self._tables = tables

    def get_data(self, table_name, columns="*", conditions=None, *, where=None, params=None):
        return [dict(r) for r in self._tables.get(str(table_name), [])]

    def get_session_data(self, *a, **k):
        return []

    def get_actions(self, *a, **k):
        return {}


# project NUMBER 123456 everywhere in CAI names; projectId is proj-a.
_RECORDS = [
    {"name": "//cloudresourcemanager.googleapis.com/organizations/789",
     "assetType": "cloudresourcemanager.googleapis.com/Organization",
     "resource": {"data": {"displayName": "corp"}}},
    {"name": "//cloudresourcemanager.googleapis.com/folders/456",
     "assetType": "cloudresourcemanager.googleapis.com/Folder",
     "resource": {"data": {"displayName": "eng", "parent": "organizations/789"}}},
    {"name": "//cloudresourcemanager.googleapis.com/projects/123456",
     "assetType": "cloudresourcemanager.googleapis.com/Project",
     "resource": {"data": {"projectId": "proj-a", "name": "proj-a", "parent": "folders/456"}},
     "iamPolicy": {"bindings": [{"role": "roles/owner", "members": ["user:alice@corp.com"]}]}},
    {"name": "//iam.googleapis.com/projects/123456/serviceAccounts/svc@proj-a.iam.gserviceaccount.com",
     "assetType": "iam.googleapis.com/ServiceAccount",
     "resource": {"data": {"email": "svc@proj-a.iam.gserviceaccount.com"}}},
    {"name": "//iam.googleapis.com/projects/123456/serviceAccounts/svc@proj-a.iam.gserviceaccount.com/keys/k1",
     "assetType": "iam.googleapis.com/ServiceAccountKey", "resource": {"data": {}}},
    {"name": "//compute.googleapis.com/projects/123456/zones/us-central1-a/instances/vm1",
     "assetType": "compute.googleapis.com/Instance",
     "resource": {"data": {"serviceAccounts": [{"email": "svc@proj-a.iam.gserviceaccount.com"}]}}},
    {"name": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/pool1",
     "assetType": "iam.googleapis.com/WorkloadIdentityPool", "resource": {"data": {}}},
    {"name": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/pool1/providers/gh",
     "assetType": "iam.googleapis.com/WorkloadIdentityPoolProvider", "resource": {"data": {}}},
]


def _edges(ctx):
    return {(e.source_id, e.edge_type, e.destination_id) for e in ctx.builder.edge_map.values()}


def _nodes(ctx):
    return {n.node_id for n in ctx.builder.node_map.values()}


def test_cai_mapping_normalizes_project_number_to_id():
    tables = cai_records_to_tables(_RECORDS)
    # hierarchy: the project row uses the STRING id, not the number 123456
    proj = [r for r in tables["abstract_tree_hierarchy"] if r["type"] == "project"][0]
    assert proj["name"] == "projects/proj-a" and proj["project_id"] == "proj-a"
    assert proj["parent"] == "folders/456"
    # the project IAM policy resource_name was rewritten off the number too
    pol = [r for r in tables["iam_allow_policies"] if r["resource_type"] == "project"][0]
    assert pol["resource_name"] == "projects/proj-a"
    # SA key + compute instance + WIF names all carry proj-a, never 123456
    assert "123456" not in tables["iam_sa_keys"][0]["name"]
    assert tables["cloudcompute_instances"][0]["name"].startswith("projects/proj-a/")
    assert tables["workload_identity_pools"][0]["project_id"] == "proj-a"


def test_cai_ingest_builds_expected_graph():
    tables = cai_records_to_tables(_RECORDS)
    ctx = OpenGraphBuildContext(
        session=_CaiSession(tables),
        options=OpenGraphBuildOptions(expand_inheritance=True, include_all=True),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    build_resource_expansion_graph(ctx)

    nodes, edges = _nodes(ctx), _edges(ctx)
    # the project node is materialized (it carries the owner binding + resources)
    assert "resource:projects/proj-a" in nodes
    # the owner binding collapses to ROLE_OWNER on the project resource
    assert any(k == "ROLE_OWNER" and d == "resource:projects/proj-a" for _, k, d in edges)
    # alice holds the owner binding
    assert any(s == "user:alice@corp.com" and k == "HAS_IAM_BINDING" for s, k, _ in edges)
    # SA key -> SA edge
    assert any(k == "GCP_SERVICE_ACCOUNT_KEY_FOR" for _, k, _ in edges)
    # WIF provider -> pool edge
    assert ("resource:projects/proj-a/locations/global/workloadIdentityPools/pool1/providers/gh",
            "WIF_PROVIDER_IN_POOL",
            "resource:projects/proj-a/locations/global/workloadIdentityPools/pool1") in edges


def test_process_og_cai_file_end_to_end(tmp_path):
    """`process_og --cai-file <export> --out <dir>` builds + exports a graph with no DB."""
    import json

    from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import run_module

    cai_path = tmp_path / "export.ndjson"
    cai_path.write_text("\n".join(json.dumps(r) for r in _RECORDS), encoding="utf-8")
    out_dir = tmp_path / "out"

    class _StubSession:
        """Minimal session; --out bypasses path resolution and CAI mode skips persist."""

    rc = run_module(["--cai-file", str(cai_path), "--out", str(out_dir), "--include-all"], _StubSession())
    assert rc == 1

    exported = list(out_dir.glob("opengraph_*.json"))
    assert exported, "no graph JSON was exported"
    payload = json.loads(exported[0].read_text(encoding="utf-8"))
    graph = payload.get("graph") or {}
    node_ids = {str(n.get("id") or "") for n in (graph.get("nodes") or [])}
    edge_kinds = {str(e.get("kind") or "") for e in (graph.get("edges") or [])}
    assert "resource:projects/proj-a" in node_ids
    assert "WIF_PROVIDER_IN_POOL" in edge_kinds
    assert "GCP_SERVICE_ACCOUNT_KEY_FOR" in edge_kinds
