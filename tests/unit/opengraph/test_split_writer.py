"""Tests for the split-JSON writer (`_write_split_outputs`).

The split writer is the most intricate code in process_og (byte-budget banding, per-chunk
border-node re-emission, legacy single-part rename, manifest). These lock in its contract:
every part is a self-contained OpenGraph payload (all edge endpoints present as nodes), a
single-part section gets the legacy `<stem>_<section>.json` name, the manifest totals are
consistent, and a tiny size budget actually produces multiple self-contained parts.
"""

from __future__ import annotations

import json
from pathlib import Path

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _write_split_outputs

_SECTIONS = ["users_groups", "iam_bindings", "inferred_permissions", "resource_expansion"]


def _node(node_id, kinds):
    return {"id": node_id, "kinds": kinds, "properties": {}}


def _edge(start, kind, end):
    return {"start": {"match_by": "id", "value": start}, "end": {"match_by": "id", "value": end}, "kind": kind, "properties": {}}


def _payload(nodes, edges):
    return {"metadata": {"source_kind": "GCPBase"}, "graph": {"nodes": nodes, "edges": edges}}


def _assert_part_self_contained(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    graph = data.get("graph", data)
    node_ids = {n["id"] for n in graph["nodes"]}
    for e in graph["edges"]:
        start = e["start"]["value"] if isinstance(e.get("start"), dict) else e["start"]
        end = e["end"]["value"] if isinstance(e.get("end"), dict) else e["end"]
        assert start in node_ids, f"edge start {start} missing from part {Path(path).name}"
        assert end in node_ids, f"edge end {end} missing from part {Path(path).name}"


def _small_graph():
    nodes = [
        _node("user:alice@x.com", ["GoogleUser"]),
        _node("iambinding:roles/owner@project:p", ["GCPIamSimpleBinding"]),
        _node("resource:p@p", ["GCPProject", "GCPResource"]),
        _node("serviceAccount:svc@p.iam.gserviceaccount.com", ["GCPServiceAccount"]),
    ]
    edges = [
        _edge("user:alice@x.com", "HAS_IAM_BINDING", "iambinding:roles/owner@project:p"),
        _edge("iambinding:roles/owner@project:p", "CAN_MODIFY_PROJECT_IAM", "resource:p@p"),
        _edge("iambinding:roles/owner@project:p", "INFERRED_CAN_IMPERSONATE_SA", "serviceAccount:svc@p.iam.gserviceaccount.com"),
    ]
    return _payload(nodes, edges)


def test_single_part_sections_use_legacy_names_and_are_self_contained(tmp_path):
    base = tmp_path / "graph.json"
    files, manifest_path = _write_split_outputs(
        base_output_path=str(base),
        payload=_small_graph(),
        selected_sections=_SECTIONS,
        max_size_mb=64.0,  # large -> one part per section
        split_output_dir=str(tmp_path),
    )
    parts = [f for f in files if f != manifest_path]
    assert parts, "expected at least one part file"
    for part in parts:
        _assert_part_self_contained(part)
        # Single-part sections are renamed to the legacy <stem>_<section>.json form.
        assert Path(part).name.startswith("graph_") and Path(part).name.endswith(".json")
        assert "_part" not in Path(part).name

    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    # Every edge lands in exactly one section, so section edge counts sum to the total.
    total_edges = sum(sec["edges"] for sec in manifest["sections"].values())
    assert total_edges == 3
    assert manifest["summary"]["files_written"] == len(parts)
    assert manifest["summary"]["sections_written"] == len(manifest["sections"])


def test_tiny_budget_produces_multiple_self_contained_parts(tmp_path):
    # One section, many edges to distinct targets, forced under a tiny size budget.
    nodes = [_node("iambinding:roles/owner@project:p", ["GCPIamSimpleBinding"])]
    edges = []
    for i in range(200):
        tgt = f"resource:big-{i}-{'x' * 200}@p"
        nodes.append(_node(tgt, ["GCPProject", "GCPResource"]))
        edges.append(_edge("iambinding:roles/owner@project:p", "CAN_MODIFY_PROJECT_IAM", tgt))
    base = tmp_path / "graph.json"
    files, manifest_path = _write_split_outputs(
        base_output_path=str(base),
        payload=_payload(nodes, edges),
        selected_sections=["resource_expansion"],
        max_size_mb=0.02,  # ~20KB -> must split
        size_tolerance_mb=0.0,
        split_output_dir=str(tmp_path),
    )
    parts = [f for f in files if f != manifest_path]
    assert len(parts) > 1, "tiny budget should force multiple parts"
    for part in parts:
        _assert_part_self_contained(part)
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    assert manifest["sections"]["resource_expansion"]["edges"] == 200
    assert manifest["sections"]["resource_expansion"]["parts"] == len(parts)
