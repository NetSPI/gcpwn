from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphBuilder
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
    ScopeResourceIndexes,
    _normalized_rule,
)
from gcpwn.modules.opengraph.utilities.stage_2_policy_bindings import (
    _binding_rule_permission_map_coverage,
    build_iam_bindings_multi_permission_graph,
)

from conftest import make_binding_entry


class _BuilderContext:
    def __init__(self, *, entries: list[BindingPlusScopeEntry], unsupported_rule_names: list[str] | None = None) -> None:
        self.builder = OpenGraphBuilder()
        allow_resources = [
            {
                "resource_name": "projects/demo-project/zones/us-central1-c/instances/demo-vm",
                "resource_type": "computeinstance",
                "display_name": "demo-vm",
                "project_id": "demo-project",
                "status": "RUNNING",
            },
            {
                "resource_name": "projects/demo-project/serviceAccounts/sa-runner@demo-project.iam.gserviceaccount.com",
                "resource_type": "service-account",
                "display_name": "sa-runner",
                "project_id": "demo-project",
            },
        ]
        by_project: dict[str, list[dict[str, str]]] = {"demo-project": list(allow_resources)}
        by_project_type: dict[str, dict[str, list[dict[str, str]]]] = {
            "demo-project": {
                "computeinstance": [allow_resources[0]],
                "service-account": [allow_resources[1]],
            }
        }
        self._scope_indexes = ScopeResourceIndexes(
            project_scope_by_project_id={"demo-project": "projects/demo-project"},
            project_id_by_scope_name={"projects/demo-project": "demo-project"},
            known_project_ids={"demo-project"},
            allow_resources=allow_resources,
            allow_resources_by_project=by_project,
            allow_resources_by_project_type=by_project_type,
        )
        self._artifacts = {
            "resolved_bindings_composite": list(entries),
            "iam_bindings_base_state": {"seed": "ok"},
            "binding_unsupported_rule_names": list(unsupported_rule_names or []),
        }

    def hierarchy_data(self) -> dict[str, dict[str, str]]:
        return {
            "scope_type_by_name": {"projects/demo-project": "project"},
            "scope_display_by_name": {"projects/demo-project": "demo-project"},
            "parent_by_name": {},
        }

    def scope_resource_indexes(self) -> ScopeResourceIndexes:
        return self._scope_indexes

    def get_artifact(self, key: str, default=None):
        return self._artifacts.get(key, default)

    def set_artifact(self, key: str, value):
        self._artifacts[key] = value

    def counts(self) -> tuple[int, int]:
        return len(self.builder.node_map), len(self.builder.edge_map)


def test_key_permission_map_coverage_marks_rule_unsupported_when_permission_missing() -> None:
    normalized_single = (
        _normalized_rule(
            "TEST_EDGE",
            {
                "edge_type": "TEST_EDGE",
                "requires_any": ["test.permission.present", "test.permission.missing"],
            },
        ),
    )
    coverage = _binding_rule_permission_map_coverage(
        permission_to_roles={"test.permission.present": ["roles/test.role"]},
        single_rules=normalized_single,
        multi_rules=(),
    )

    assert coverage["unsupported_rule_count"] == 1
    assert "TEST_EDGE" in coverage["unsupported_rule_names"]
    assert "test.permission.missing" in coverage["unmapped_permissions"]


def test_key_multi_binding_builder_skips_unsupported_rule_names() -> None:
    matching_permissions = {
        "compute.instances.get",
        "compute.instances.setMetadata",
        "compute.instances.reset",
        "iam.serviceAccounts.actAs",
    }
    entries = [
        make_binding_entry(
            role_name="roles/editor",
            permissions=matching_permissions,
        )
    ]

    supported_context = _BuilderContext(entries=entries, unsupported_rule_names=[])
    supported_stats = build_iam_bindings_multi_permission_graph(supported_context)
    assert any(edge.edge_type == "RESET_COMPUTE_STARTUP_SA" for edge in supported_context.builder.edge_map.values())
    assert supported_stats["dangerous_edges_emitted"] >= 1

    blocked_context = _BuilderContext(entries=entries, unsupported_rule_names=["RESET_COMPUTE_STARTUP_SA"])
    blocked_stats = build_iam_bindings_multi_permission_graph(blocked_context)
    assert not any(edge.edge_type == "RESET_COMPUTE_STARTUP_SA" for edge in blocked_context.builder.edge_map.values())
    assert blocked_stats["dangerous_edges_emitted"] <= supported_stats["dangerous_edges_emitted"]
