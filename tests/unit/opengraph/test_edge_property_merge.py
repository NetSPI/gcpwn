"""`_merge_opengraph_edge_properties` must merge edge properties deterministically.

Used when several contributors collapse onto one edge key (node dedup redirect, and combo
target-edge collisions). List evidence becomes the sorted union; scalar conflicts resolve
to a canonical value; new keys are added. The result must not depend on argument order.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import _merge_opengraph_edge_properties


def test_list_evidence_is_sorted_union():
    a = {"evidence_bindings": ["b", "a"], "roles": ["roles/editor"]}
    b = {"evidence_bindings": ["c", "a"], "roles": ["roles/owner"]}
    out = _merge_opengraph_edge_properties(a, b)
    assert out["evidence_bindings"] == ["a", "b", "c"]
    assert out["roles"] == ["roles/editor", "roles/owner"]


def test_new_keys_added_and_scalar_conflict_is_canonical():
    a = {"status": "VALIDATED", "only_a": 1}
    b = {"status": "PROPOSED", "only_b": 2}
    out = _merge_opengraph_edge_properties(a, b)
    assert out["only_a"] == 1 and out["only_b"] == 2
    # Canonical scalar pick (smaller string form): "PROPOSED" < "VALIDATED".
    assert out["status"] == "PROPOSED"


def test_merge_is_order_independent():
    a = {"evidence_bindings": ["x", "y"], "status": "CONFIRMED", "n": ["1"]}
    b = {"evidence_bindings": ["z"], "status": "AUTHORITATIVE", "n": ["2"]}
    assert _merge_opengraph_edge_properties(a, b) == _merge_opengraph_edge_properties(b, a)


def test_empty_inputs():
    assert _merge_opengraph_edge_properties(None, {"a": 1}) == {"a": 1}
    assert _merge_opengraph_edge_properties({"a": 1}, None) == {"a": 1}
