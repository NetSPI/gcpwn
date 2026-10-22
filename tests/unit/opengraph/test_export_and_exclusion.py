"""Tests for service-agent exclusion and export-path resolution.

- `_exclude_service_agent_nodes` drops is_service_agent nodes AND the iam-binding nodes
  that are left with no principal (cascade), without touching reachable structure.
- `_resolve_export_paths` with --out treats it as an output directory and returns the
  single-json path inside it plus that directory as the split dir.
"""

from __future__ import annotations

import types
from pathlib import Path

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import (
    _exclude_service_agent_nodes,
    _resolve_export_paths,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphEdge, OpenGraphNode


def _n(node_id, node_type="GCPResource", **props):
    return OpenGraphNode(node_id=node_id, node_type=node_type, properties=props)


def _e(src, dst, kind="HAS_IAM_BINDING"):
    return OpenGraphEdge(source_id=src, destination_id=dst, edge_type=kind, properties={})


def test_excludes_service_agent_and_cascades_orphan_bindings():
    nodes = [
        _n("user:real@x.com", "GoogleUser"),
        _n("serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com", "GCPServiceAccount", is_service_agent=True),
        _n("iambinding:roles/viewer@project:p", "GCPIamSimpleBinding"),      # only the agent binds here -> orphan
        _n("iambinding:roles/owner@project:p", "GCPIamSimpleBinding"),       # real user binds here -> kept
        _n("resource:p@p", "GCPProject"),
    ]
    edges = [
        _e("serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com", "iambinding:roles/viewer@project:p"),
        _e("iambinding:roles/viewer@project:p", "resource:p@p", "CAN_READ"),
        _e("user:real@x.com", "iambinding:roles/owner@project:p"),
        _e("iambinding:roles/owner@project:p", "resource:p@p", "ROLE_OWNER"),
    ]
    out_nodes, out_edges, stats = _exclude_service_agent_nodes(nodes, edges)
    ids = {n.node_id for n in out_nodes}
    assert "serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com" not in ids  # agent gone
    assert "iambinding:roles/viewer@project:p" not in ids                      # orphan binding cascaded out
    assert "iambinding:roles/owner@project:p" in ids                           # real path intact
    assert "user:real@x.com" in ids and "resource:p@p" in ids
    # viewer binding's outgoing CAN_READ edge is also gone; owner path survives.
    kinds = {(e.source_id, e.edge_type, e.destination_id) for e in out_edges}
    assert ("user:real@x.com", "HAS_IAM_BINDING", "iambinding:roles/owner@project:p") in kinds
    assert all("roles/viewer" not in e.source_id for e in out_edges)
    assert stats["service_agent_nodes_removed"] == 2  # agent + cascaded orphan binding
    assert stats["edges_removed"] == 2


def test_no_service_agents_is_identity():
    nodes = [_n("user:a@x.com", "GoogleUser")]
    edges = []
    out_nodes, out_edges, stats = _exclude_service_agent_nodes(nodes, edges)
    assert out_nodes == nodes and out_edges == edges
    assert stats == {"service_agent_nodes_removed": 0, "edges_removed": 0}


def test_resolve_export_paths_out_is_a_directory(tmp_path):
    out = tmp_path / "my-export"
    args = types.SimpleNamespace(out=str(out))
    single, split_dir = _resolve_export_paths(session=None, args=args)
    assert split_dir == str(out)
    assert out.is_dir()
    assert Path(single).parent == out
    assert Path(single).name.startswith("opengraph_") and Path(single).name.endswith(".json")
