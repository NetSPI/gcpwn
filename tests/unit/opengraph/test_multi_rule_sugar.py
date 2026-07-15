"""The concise combo-rule authoring form (`subject_groups` + `act_as`).

`_desugar_multi_permission_rule` expands the sugar into the exact verbose
`requires_groups` + `combo_hop` dict the engine consumes, and leaves rules that
already use the verbose form (or `match_paths`) untouched.
"""
from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    _desugar_multi_permission_rule,
)


def test_sugar_expands_to_full_combo_hop_shape():
    out = _desugar_multi_permission_rule("RESET_COMPUTE_STARTUP_SA", {
        "description": "d",
        "subject_groups": [
            {"permissions": ["compute.instances.get", "compute.instances.reset"],
             "target": "computeinstance", "status_in": ["RUNNING"]},
        ],
        "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "target": "service-account"},
        "subject_edge": "CAN_RESET_COMPUTE_WITH_STARTUP_SCRIPT",
        "subject_node": "resource",
        "target_edge": "RESET_COMPUTE_STARTUP_SA",
    })

    # mechanically-implied defaults for the combo shape
    assert out["multi_permission_type"] == "complex"
    assert out["same_scope_required"] is False
    assert out["same_project_required"] is True

    groups = {g["id"]: g for g in out["requires_groups"]}
    assert set(groups) == {"subject_1", "act_as"}
    # resource_scopes_possible = ["project"] + target
    assert groups["subject_1"]["resource_scopes_possible"] == ["project", "computeinstance"]
    assert groups["act_as"]["resource_scopes_possible"] == ["project", "service-account"]
    assert groups["subject_1"]["target_selector"] == {
        "mode": "resource_types", "resource_types": ["computeinstance"], "status_in": ["RUNNING"]}

    hop = out["combo_hop"]["hops"][0]
    assert out["combo_hop"]["edge_to_target"] == "RESET_COMPUTE_STARTUP_SA"
    assert out["combo_hop"]["target_from_groups"] == ["act_as"]      # the pivot
    assert hop["edge_from_subject"] == "CAN_RESET_COMPUTE_WITH_STARTUP_SCRIPT"
    assert hop["node_mode"] == "resource"
    assert hop["from_groups"] == ["subject_1"]                       # every subject group feeds the hop


def test_sugar_supports_multiple_subject_groups():
    out = _desugar_multi_permission_rule("CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA", {
        "subject_groups": [
            {"permissions": ["cloudfunctions.functions.create"], "target": "cloudfunction"},
            {"permissions": ["cloudfunctions.functions.call"], "target": "cloudfunction"},
        ],
        "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "target": "service-account"},
        "subject_edge": "CAN_CREATE_DEPLOY_INVOKE_CLOUDFUNCTION",
        "subject_node": "capability",
    })
    assert out["combo_hop"]["hops"][0]["from_groups"] == ["subject_1", "subject_2"]
    assert out["combo_hop"]["hops"][0]["node_mode"] == "capability"
    # target_edge omitted -> defaults to the rule name
    assert out["combo_hop"]["edge_to_target"] == "CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA"


def test_verbose_rule_passes_through_untouched():
    verbose = {
        "multi_permission_type": "complex",
        "requires_groups": [{"id": "g", "permissions": ["x"]}],
        "combo_hop": {"edge_to_target": "E", "hops": []},
    }
    assert _desugar_multi_permission_rule("R", verbose) is verbose


def test_match_paths_rule_is_left_for_the_full_parser():
    rule = {"match_paths": [{"id": "p", "requires_groups": []}],
            "subject_groups": [{"permissions": ["x"]}], "act_as": {"permissions": ["y"]}}
    # sugar keys present but match_paths wins -> untouched (no accidental double-expansion)
    assert _desugar_multi_permission_rule("R", rule) is rule
