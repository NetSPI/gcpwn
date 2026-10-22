"""AttackGraph.from_path must flag a partial split-export directory load.

Loading a directory that holds only some of the manifest's section parts otherwise analyzes
as if complete and silently under-reports; a full load must stay quiet.
"""

from __future__ import annotations

import json
from pathlib import Path

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _write_split_outputs
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.model import AttackGraph


def _write_split(tmp_path):
    nodes = [
        {"id": "user:a@x.com", "kinds": ["GoogleUser"], "properties": {}},
        {"id": "iambinding:roles/owner@project:p", "kinds": ["GCPIamSimpleBinding"], "properties": {}},
        {"id": "resource:p@p", "kinds": ["GCPProject", "GCPResource"], "properties": {}},
    ]
    edges = [
        {"start": {"match_by": "id", "value": "user:a@x.com"}, "end": {"match_by": "id", "value": "iambinding:roles/owner@project:p"}, "kind": "HAS_IAM_BINDING", "properties": {}},
        {"start": {"match_by": "id", "value": "iambinding:roles/owner@project:p"}, "end": {"match_by": "id", "value": "resource:p@p"}, "kind": "CAN_MODIFY_PROJECT_IAM", "properties": {}},
    ]
    payload = {"metadata": {"source_kind": "GCPBase"}, "graph": {"nodes": nodes, "edges": edges}}
    out = tmp_path / "split"
    _write_split_outputs(
        base_output_path=str(tmp_path / "graph.json"),
        payload=payload,
        selected_sections=["users_groups", "iam_bindings", "resource_expansion"],
        max_size_mb=64.0,
        split_output_dir=str(out),
    )
    return out


def test_full_split_load_is_quiet(tmp_path, capsys):
    out = _write_split(tmp_path)
    AttackGraph.from_path(out)
    assert "Partial split load" not in capsys.readouterr().err


def test_missing_section_triggers_warning(tmp_path, capsys):
    out = _write_split(tmp_path)
    # Drop one section's part file to simulate a partial/interrupted export.
    removed = next(p for p in out.glob("graph_iam_bindings*.json"))
    removed.unlink()
    AttackGraph.from_path(out)
    err = capsys.readouterr().err
    assert "Partial split load" in err and "iam_bindings" in err


def test_manifest_schema_lists_sections(tmp_path):
    _write_split(tmp_path)
    manifest = next(tmp_path.rglob("*_split_manifest.json"))
    data = json.loads(Path(manifest).read_text(encoding="utf-8"))
    assert set(data["sections"]) <= {"users_groups", "iam_bindings", "resource_expansion"}
