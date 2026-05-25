from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    _normalized_rule,
    expand_multi_permission_rules,
)


def test_key_expand_multi_permission_rule_paths_into_variants() -> None:
    raw_rules = {
        "COMPUTE_STARTUP_FLOW": {
            "description": "demo",
            "edge_type": "COMPUTE_STARTUP_FLOW",
            "match_paths": [
                {
                    "id": "running_reset",
                    "requires_all": [
                        "compute.instances.setMetadata",
                        "compute.instances.reset",
                    ],
                    "target_selector": {
                        "mode": "resource_types",
                        "resource_types": ["computeinstance"],
                        "status_in": ["RUNNING"],
                    },
                },
                {
                    "id": "stopped_start",
                    "requires_all": [
                        "compute.instances.setMetadata",
                        "compute.instances.start",
                    ],
                    "target_selector": {
                        "mode": "resource_types",
                        "resource_types": ["computeinstance"],
                        "status_in": ["STOPPED", "TERMINATED"],
                    },
                },
            ],
        }
    }

    expanded = expand_multi_permission_rules(raw_rules)

    assert sorted(expanded.keys()) == [
        "COMPUTE_STARTUP_FLOW__running_reset",
        "COMPUTE_STARTUP_FLOW__stopped_start",
    ]
    assert expanded["COMPUTE_STARTUP_FLOW__running_reset"]["rule_name"] == "COMPUTE_STARTUP_FLOW"
    assert expanded["COMPUTE_STARTUP_FLOW__running_reset"]["edge_type"] == "COMPUTE_STARTUP_FLOW"
    assert expanded["COMPUTE_STARTUP_FLOW__running_reset"]["rule_variant_id"] == "running_reset"


def test_key_normalized_rule_uses_rule_name_override_for_variant_rules() -> None:
    normalized = _normalized_rule(
        "COMPUTE_STARTUP_FLOW__running_reset",
        {
            "rule_name": "COMPUTE_STARTUP_FLOW",
            "rule_variant_id": "running_reset",
            "edge_type": "COMPUTE_STARTUP_FLOW",
            "requires_all": [
                "compute.instances.setMetadata",
                "compute.instances.reset",
            ],
            "target_selector": {
                "mode": "resource_types",
                "resource_types": ["computeinstance"],
                "status_in": ["RUNNING"],
            },
        },
    )

    assert normalized["name"] == "COMPUTE_STARTUP_FLOW"
    assert normalized["edge_type"] == "COMPUTE_STARTUP_FLOW"
    assert normalized["rule_variant_id"] == "running_reset"
