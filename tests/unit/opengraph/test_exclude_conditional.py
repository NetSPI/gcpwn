"""--exclude-conditional drops IAM-condition-scoped edges from traversal (opt-in).

Conditional edges are modeled as unconditional (conditions are not CEL-evaluated), so they
can over-grant. They stay in the graph and are traversed by default; the flag lets a
defender exclude them. A path that exists only through a conditional edge must disappear
when the flag is set, and a non-conditional path must be unaffected.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.pathfinding.model import AttackGraph
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.search import enumerate_paths, shortest_paths


def _graph(conditional: bool):
    nodes = {
        "user:a@x.com": {"id": "user:a@x.com", "kinds": ["GoogleUser"], "kind": "GoogleUser", "properties": {}},
        "iambinding:roles/owner@project:p": {
            "id": "iambinding:roles/owner@project:p",
            "kinds": ["GCPIamSimpleBinding"], "kind": "GCPIamSimpleBinding",
            "properties": {"role_name": "roles/owner", "attached_scope_id": "projects/p"},
        },
        "resource:p": {"id": "resource:p", "kinds": ["GCPProject"], "kind": "GCPProject", "properties": {"project_id": "p"}},
    }
    edges = [
        {"start": "user:a@x.com", "end": "iambinding:roles/owner@project:p", "kind": "HAS_IAM_BINDING",
         "properties": {"conditional": conditional}},
        {"start": "iambinding:roles/owner@project:p", "end": "resource:p", "kind": "ROLE_OWNER", "properties": {}},
    ]
    return AttackGraph(nodes, edges)


def test_conditional_path_present_by_default_absent_when_excluded():
    tgt = {"resource:p"}
    g = _graph(conditional=True)
    assert shortest_paths(g, tgt, max_depth=6)                       # default: traversed
    assert not shortest_paths(g, tgt, max_depth=6, exclude_conditional=True)   # excluded
    found, _ = enumerate_paths(g, tgt, max_depth=6)
    assert found
    found_excl, _ = enumerate_paths(g, tgt, max_depth=6, exclude_conditional=True)
    assert not found_excl


def test_non_conditional_path_unaffected_by_flag():
    tgt = {"resource:p"}
    g = _graph(conditional=False)
    assert shortest_paths(g, tgt, max_depth=6, exclude_conditional=True)
    found, _ = enumerate_paths(g, tgt, max_depth=6, exclude_conditional=True)
    assert found
