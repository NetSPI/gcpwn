"""Fake-data tests for IAM-binding INHERITANCE (expand_inheritance on vs off).

An ancestor-level binding (org or folder) should:
- with expand_inheritance=FALSE: stay attached to the ancestor only (no fan-out,
  no `#src:` provenance suffix, descendant resource nodes not materialized);
- with expand_inheritance=TRUE: fan out to every descendant scope, each getting a
  distinct binding node `...@<descendant>#src:<source>` and its own dangerous edges.

Verified empirically against the pipeline (org->folder->project owner binding).
"""

from __future__ import annotations

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph

from conftest import FakeSession, _policy


_TABLE_KEYS = (
    "iam_allow_policies", "iam_roles", "abstract_tree_hierarchy", "iam_service_accounts",
    "workspace_users", "workspace_groups", "workspace_group_memberships",
    "workspace_admin_roles", "workspace_role_assignments",
)

_HIER = [
    {"name": "organizations/111", "type": "organization", "display_name": "corp", "project_id": "", "parent": ""},
    {"name": "folders/222", "type": "folder", "display_name": "eng", "project_id": "", "parent": "organizations/111"},
    {"name": "projects/proj-a", "type": "project", "display_name": "proj-a", "project_id": "proj-a", "parent": "folders/222"},
]


def _run(iam, *, expand):
    tables = {k: [] for k in _TABLE_KEYS}
    tables["iam_allow_policies"] = iam
    tables["abstract_tree_hierarchy"] = _HIER
    ctx = OpenGraphBuildContext(
        session=FakeSession(tables),
        options=OpenGraphBuildOptions(expand_inheritance=expand, include_all=True),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    nodes = {(n.node_id, n.node_type) for n in ctx.builder.node_map.values()}
    edges = {(e.source_id, e.edge_type, e.destination_id) for e in ctx.builder.edge_map.values()}
    return nodes, edges


_ORG_OWNER = [{
    "project_id": "", "resource_type": "organization", "resource_name": "organizations/111",
    "policy": _policy(("roles/owner", ["user:alice@corp.com"])),
}]


def test_org_binding_without_inheritance_stays_at_org():
    nodes, edges = _run(_ORG_OWNER, expand=False)
    binding_ids = {nid for nid, _ in nodes if nid.startswith("iambinding:")}
    assert binding_ids == {"iambinding:roles/owner@org:111"}
    assert not any("#src:" in nid for nid in binding_ids)
    node_types = {nt for _, nt in nodes}
    # descendant resource nodes are NOT materialized without fan-out
    assert "GCPFolder" not in node_types and "GCPProject" not in node_types
    assert ("iambinding:roles/owner@org:111", "ROLE_OWNER", "resource:organizations/111") in edges
    # no inherited ROLE_OWNER on folder/project
    assert not any(d in ("resource:folders/222", "resource:projects/proj-a") for _, k, d in edges if k == "ROLE_OWNER")


def test_org_binding_with_inheritance_fans_to_folder_and_project():
    nodes, edges = _run(_ORG_OWNER, expand=True)
    binding_ids = {nid for nid, _ in nodes if nid.startswith("iambinding:")}
    assert "iambinding:roles/owner@org:111" in binding_ids
    assert "iambinding:roles/owner@folder:222#src:org:111" in binding_ids
    assert "iambinding:roles/owner@project:proj-a#src:org:111" in binding_ids
    # each descendant scope gets its own ROLE_OWNER edge, with org provenance preserved
    assert ("iambinding:roles/owner@folder:222#src:org:111", "ROLE_OWNER", "resource:folders/222") in edges
    assert ("iambinding:roles/owner@project:proj-a#src:org:111", "ROLE_OWNER", "resource:projects/proj-a") in edges
    assert {"GCPOrganization", "GCPFolder", "GCPProject"} <= {nt for _, nt in nodes}


def test_inheritance_strictly_adds_edges():
    _, off = _run(_ORG_OWNER, expand=False)
    _, on = _run(_ORG_OWNER, expand=True)
    # the off graph's edges are a subset of the on graph's (fan-out only adds)
    assert off <= on
    assert len(on) > len(off)


def test_inherited_binding_carries_both_src_and_cond_suffixes():
    expr = "request.time < timestamp('2025-01-01T00:00:00Z')"
    iam = [{
        "project_id": "", "resource_type": "organization", "resource_name": "organizations/111",
        "policy": _policy(("roles/owner", ["user:alice@corp.com"], {"expression": expr, "title": "t"})),
    }]
    nodes, _ = _run(iam, expand=True)
    cond_bindings = {nid for nid, _ in nodes if nid.startswith("iambinding:") and "#cond:" in nid}
    # org + folder + project, all conditioned
    assert len(cond_bindings) == 3
    # the two inherited descendants keep org provenance AND the condition hash, in order
    inherited = {nid for nid in cond_bindings if "#src:org:111" in nid}
    assert len(inherited) == 2
    assert all("#src:org:111#cond:" in nid for nid in inherited)


def test_folder_binding_inherits_only_to_its_project():
    folder_editor = [{
        "project_id": "", "resource_type": "folder", "resource_name": "folders/222",
        "policy": _policy(("roles/editor", ["group:eng@corp.com"])),
    }]
    nodes, edges = _run(folder_editor, expand=True)
    binding_ids = {nid for nid, _ in nodes if nid.startswith("iambinding:")}
    # folder binding inherits DOWN to the project, but never UP to the org
    assert "iambinding:roles/editor@folder:222" in binding_ids
    assert "iambinding:roles/editor@project:proj-a#src:folder:222" in binding_ids
    assert not any("org:111" in nid for nid in binding_ids)
    assert ("iambinding:roles/editor@project:proj-a#src:folder:222", "ROLE_EDITOR", "resource:projects/proj-a") in edges
