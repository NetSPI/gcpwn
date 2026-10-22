"""paths_to_json must apply the same display cap as the text report and disclose totals.

Previously the text report capped at --max-paths while --json emitted every path, so the
two disagreed on how many paths existed for the same query.
"""

from __future__ import annotations

import json

from gcpwn.modules.opengraph.utilities.helpers.pathfinding.model import AttackGraph
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.render import paths_to_json
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.search import enumerate_paths


def _node(node_id, kind, props=None):
    return {"id": node_id, "kinds": [kind, "GCPResource"], "properties": props or {}}


def _edge(start, end, kind):
    return {"start": {"match_by": "id", "value": start}, "end": {"match_by": "id", "value": end}, "kind": kind, "properties": {}}


def _binding(node_id, role, scope):
    return _node(node_id, "GCPIamSimpleBinding", {"role_name": role, "attached_scope_id": scope, "attached_scope_type": "project"})


def _multi_path_graph():
    # Three principals each own the same project -> three independent paths to resource:proj.
    nodes = [_node("resource:proj", "GCPProject", {"project_id": "proj", "name": "proj"})]
    edges = []
    for who in ("a", "b", "c"):
        b = f"iambinding:roles/owner@project:proj#{who}"
        nodes.append(_node(f"user:{who}@corp.com", "GoogleUser"))
        nodes.append(_binding(b, "roles/owner", "projects/proj"))
        edges.append(_edge(f"user:{who}@corp.com", b, "HAS_IAM_BINDING"))
        edges.append(_edge(b, "resource:proj", "ROLE_OWNER"))
    node_map = {n["id"]: {"id": n["id"], "kinds": n["kinds"], "kind": n["kinds"][0], "properties": n["properties"]} for n in nodes}
    emap = [{"start": e["start"]["value"], "end": e["end"]["value"], "kind": e["kind"], "properties": {}} for e in edges]
    return AttackGraph(node_map, emap)


def test_json_respects_detail_limit_and_reports_totals():
    graph = _multi_path_graph()
    paths, _ = enumerate_paths(graph, {"resource:proj"}, max_depth=6)
    assert len(paths) >= 3

    capped = json.loads(paths_to_json(graph, paths, config={}, query={}, detail_limit=1))
    assert capped["paths_total"] == len(paths)
    assert capped["paths_shown"] == 1
    assert capped["paths_truncated"] is True
    assert len(capped["paths"]) == 1

    full = json.loads(paths_to_json(graph, paths, config={}, query={}, detail_limit=None))
    assert full["paths_total"] == full["paths_shown"] == len(paths)
    assert full["paths_truncated"] is False
