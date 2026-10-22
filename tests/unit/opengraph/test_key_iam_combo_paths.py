from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphBuilder, node_to_opengraph
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    ScopeResourceIndexes,
    _emit_iam_binding_edges_from_entries,
)

from conftest import make_binding_entry


class _TestContext:
    def __init__(
        self,
        *,
        allow_resources: list[dict[str, str]] | None = None,
        resource_sa_by_name: dict[str, list[str]] | None = None,
    ) -> None:
        resources = [dict(resource) for resource in (allow_resources or [])]
        by_project: dict[str, list[dict[str, str]]] = {}
        by_project_type: dict[str, dict[str, list[dict[str, str]]]] = {}
        for resource in resources:
            project_id = str(resource.get("project_id") or "").strip()
            if not project_id:
                continue
            by_project.setdefault(project_id, []).append(resource)
            resource_type = str(resource.get("resource_type") or "").strip().lower()
            if resource_type:
                by_project_type.setdefault(project_id, {}).setdefault(resource_type, []).append(resource)

        self.builder = OpenGraphBuilder()
        self._scope_indexes = ScopeResourceIndexes(
            project_scope_by_project_id={"demo-project": "projects/demo-project"},
            project_id_by_scope_name={"projects/demo-project": "demo-project"},
            known_project_ids={"demo-project"},
            allow_resources=resources,
            allow_resources_by_project=by_project,
            allow_resources_by_project_type=by_project_type,
            resource_sa_by_name=dict(resource_sa_by_name or {}),
        )

    def hierarchy_data(self) -> dict[str, dict[str, str]]:
        return {
            "scope_type_by_name": {"projects/demo-project": "project"},
            "scope_display_by_name": {"projects/demo-project": "demo-project"},
            "parent_by_name": {},
        }

    def scope_resource_indexes(self) -> ScopeResourceIndexes:
        return self._scope_indexes


def _test_combo_hop_rule() -> dict:
    return {
        "name": "TEST_COMBO_HOP_RULE",
        "description": "Unit test rule for combo hop emission.",
        "edge_type": "CAN_ATTACH_SERVICE_ACCOUNT",
        "multi_permission_type": "complex",
        "same_scope_required": False,
        "same_project_required": True,
        "requires_groups": [
            {
                "id": "compute_create_group",
                "permissions": ["compute.instances.create"],
                "resource_scopes_possible": ["project"],
            },
            {
                "id": "sa_actas_group",
                "permissions": ["iam.serviceAccounts.actAs"],
                "resource_scopes_possible": ["project", "service-account"],
                "target_selector": {
                    "mode": "resource_types",
                    "resource_types": ["service-account"],
                },
            },
        ],
        "combo_hop": {
            "edge_to_target": "CAN_ATTACH_SERVICE_ACCOUNT",
            "target_from_groups": ["sa_actas_group"],
            "hops": [
                {
                    "edge_from_subject": "CAN_CREATE_COMPUTE",
                    "node_mode": "capability",
                    "from_groups": ["compute_create_group"],
                    "node_label": "Create Compute Instance Capability",
                }
            ],
        },
    }


def test_key_combo_rule_does_not_emit_partial_chain_without_targets() -> None:
    context = _TestContext(allow_resources=[])
    entries = [
        make_binding_entry(
            binding_suffix="create",
            role_name="roles/compute.instanceAdmin.v1",
            permissions={"compute.instances.create"},
        ),
        make_binding_entry(
            binding_suffix="actas",
            role_name="roles/iam.serviceAccountUser",
            permissions={"iam.serviceAccounts.actAs"},
        ),
    ]

    stats = _emit_iam_binding_edges_from_entries(
        context,
        entries=entries,
        include_all=False,
        dangerous_rules=[_test_combo_hop_rule()],
        pass_name="dangerous",
    )

    assert stats["dangerous_edges_emitted"] == 0
    assert not any(node_id.startswith("combo_iambinding@") for node_id in context.builder.node_map.keys())
    assert not any(edge.edge_type == "CAN_CREATE_COMPUTE" for edge in context.builder.edge_map.values())
    assert not any(edge.edge_type == "CAN_ATTACH_SERVICE_ACCOUNT" for edge in context.builder.edge_map.values())


def test_key_combo_rule_uses_short_multi_binding_display_name() -> None:
    context = _TestContext(
        allow_resources=[
            {
                "resource_name": "projects/demo-project/serviceAccounts/sa-runner@demo-project.iam.gserviceaccount.com",
                "resource_type": "service-account",
                "display_name": "sa-runner",
                "project_id": "demo-project",
            }
        ]
    )
    entries = [
        make_binding_entry(
            binding_suffix="create",
            role_name="roles/compute.instanceAdmin.v1",
            permissions={"compute.instances.create"},
        ),
        make_binding_entry(
            binding_suffix="actas",
            role_name="roles/iam.serviceAccountUser",
            permissions={"iam.serviceAccounts.actAs"},
        ),
    ]

    stats = _emit_iam_binding_edges_from_entries(
        context,
        entries=entries,
        include_all=False,
        dangerous_rules=[_test_combo_hop_rule()],
        pass_name="dangerous",
    )

    combo_nodes = [
        node
        for node in context.builder.node_map.values()
        if str(node.node_id or "").startswith("combo_iambinding@") and str(node.node_type or "") == "GCPIamMultiBinding"
    ]
    assert len(combo_nodes) == 1

    exported_combo = node_to_opengraph(combo_nodes[0])
    assert exported_combo["kinds"][0] == "GCPIamMultiBinding"

    display_name = str((exported_combo.get("properties") or {}).get("display_name") or "")
    assert display_name.startswith("Combo TEST_COMBO_HOP_RULE @")
    assert "user:alice@example.com" not in display_name

    assert any(edge.edge_type == "CAN_CREATE_COMPUTE" for edge in context.builder.edge_map.values())
    assert any(edge.edge_type == "CAN_ATTACH_SERVICE_ACCOUNT" for edge in context.builder.edge_map.values())
    assert stats["combo_bindings_emitted"] == 1


_INSTANCE = "projects/demo-project/zones/us-central1-a/instances/vm1"
_SA_ENUM = "projects/demo-project/serviceAccounts/actasable@demo-project.iam.gserviceaccount.com"
_SA_ENUM_EMAIL = "actasable@demo-project.iam.gserviceaccount.com"
_SA_NODE_SECRET = "nodeonly@demo-project.iam.gserviceaccount.com"


def _reset_resource_rule() -> dict:
    """via=resource RESET-style rule: reset perm on a compute instance + actAs pivot.

    Mirrors RESET_COMPUTE_STARTUP_SA: the terminal SA is the instance's OWN attached
    SA, which must be gated by whether the principal can actAs THAT SA.
    """
    return {
        "name": "TEST_RESET_RESOURCE_RULE",
        "description": "Unit rule for via=resource terminal actAs gating.",
        "edge_type": "CAN_RESET_COMPUTE",
        "multi_permission_type": "complex",
        "same_project_required": True,
        "requires_groups": [
            {
                "id": "reset_group",
                "permissions": ["compute.instances.reset", "compute.instances.setMetadata"],
                "resource_scopes_possible": ["project", "computeinstance"],
                "target_selector": {"mode": "resource_types", "resource_types": ["computeinstance"]},
            },
            {
                "id": "sa_actas_group",
                "permissions": ["iam.serviceAccounts.actAs"],
                "resource_scopes_possible": ["project", "service-account"],
                "target_selector": {"mode": "resource_types", "resource_types": ["service-account"]},
            },
        ],
        "combo_hop": {
            "edge_to_target": "RESET_COMPUTE_STARTUP_SA",
            "target_from_groups": ["sa_actas_group"],
            "hops": [
                {
                    "edge_from_subject": "CAN_RESET_COMPUTE",
                    "node_mode": "resource",
                    "from_groups": ["reset_group"],
                    "node_label": "Reset Compute Instance",
                }
            ],
        },
    }


def _reset_entries() -> list:
    return [
        make_binding_entry(
            binding_suffix="reset",
            role_name="roles/compute.instanceAdmin.v1",
            permissions={"compute.instances.reset", "compute.instances.setMetadata"},
        ),
        make_binding_entry(
            binding_suffix="actas",
            role_name="roles/iam.serviceAccountUser",
            permissions={"iam.serviceAccounts.actAs"},
        ),
    ]


def _instance_and_sa_resources() -> list[dict[str, str]]:
    return [
        {"resource_name": _INSTANCE, "resource_type": "computeinstance",
         "display_name": "vm1", "project_id": "demo-project"},
        {"resource_name": _SA_ENUM, "resource_type": "service-account",
         "display_name": "actasable", "project_id": "demo-project"},
    ]


def _run_reset(instance_sa_email: str):
    context = _TestContext(
        allow_resources=_instance_and_sa_resources(),
        resource_sa_by_name={_INSTANCE: [instance_sa_email]},
    )
    _emit_iam_binding_edges_from_entries(
        context,
        entries=_reset_entries(),
        include_all=False,
        dangerous_rules=[_reset_resource_rule()],
        pass_name="dangerous",
    )
    return [
        (edge.source_id, edge.destination_id)
        for edge in context.builder.edge_map.values()
        if edge.edge_type == "RESET_COMPUTE_STARTUP_SA"
    ]


def test_reset_resource_terminal_emits_when_principal_can_actas_instance_sa() -> None:
    # The instance runs as an SA the project-scoped actAs can reach (it is an
    # enumerated service-account resource): the terminal edge MUST be emitted.
    terminal = _run_reset(_SA_ENUM_EMAIL)
    assert any(dst.endswith("actasable@demo-project.iam.gserviceaccount.com") for _src, dst in terminal), terminal


def test_reset_resource_terminal_suppressed_when_actas_excludes_instance_sa() -> None:
    # The instance runs as an SA that is NOT actAs-able by the principal (not an
    # enumerated SA resource the project-scoped actAs fan-out reaches): no edge is
    # drawn claiming theft of an SA the attacker cannot impersonate (finding #5).
    terminal = _run_reset(_SA_NODE_SECRET)
    assert not any(dst.endswith("nodeonly@demo-project.iam.gserviceaccount.com") for _src, dst in terminal), terminal
