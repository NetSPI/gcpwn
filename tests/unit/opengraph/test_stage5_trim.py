"""Regression coverage for stage 5 (final allowlist trim).

Stage 5 is the only destructive pass that runs on the SHIPPED graph in default
mode, and the pipeline golden runs with include_all=True (which skips trim), so
without this file the trim passes are unguarded. Two things are locked here:

1. Each trim pass removes exactly what it documents (behavioral lock).
2. A well-formed combo privilege-escalation chain
   (SA principal -HAS_COMBO_BINDING-> GCPIamMultiBinding -hop-> CAP -> SA target)
   SURVIVES the full trim. This is the regression for the "combo edge matched in
   stage 2 but disappeared from the final graph" class of bug: none of the four
   passes should touch a complete combo chain.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    OpenGraphBuilder,
    OpenGraphEdge,
    OpenGraphNode,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
    ScopeResourceIndexes,
    _emit_iam_binding_edges_from_entries,
)
from gcpwn.modules.opengraph.utilities.stage_5_allowlist_trim import (
    apply_final_allowlist_trims,
    trim_isolated_service_accounts,
    trim_non_escalation_simple_bindings,
    trim_orphan_implied_bindings,
    trim_service_account_binding_islands,
)


def _n(node_id, node_type, **props):
    return OpenGraphNode(node_id=node_id, node_type=node_type, properties=dict(props))


def _e(source_id, edge_type, destination_id, **props):
    return OpenGraphEdge(
        source_id=source_id, destination_id=destination_id, edge_type=edge_type, properties=dict(props)
    )


# --------------------------------------------------------------------------- #
# Per-pass behavioral locks
# --------------------------------------------------------------------------- #


def test_trim_isolated_service_accounts_removes_only_zero_incident_sa():
    connected_sa = "serviceAccount:live@proj.iam.gserviceaccount.com"
    isolated_sa = "serviceAccount:orphan@proj.iam.gserviceaccount.com"
    nodes = [
        _n(connected_sa, "GCPServiceAccount"),
        _n(isolated_sa, "GCPServiceAccount"),
        _n("user:a@x.com", "GCPUser"),
    ]
    edges = [_e("user:a@x.com", "CAN_IMPERSONATE_SA", connected_sa)]
    pruned_nodes, _pruned_edges, stats = trim_isolated_service_accounts(nodes, edges)
    ids = {n.node_id for n in pruned_nodes}
    assert connected_sa in ids
    assert isolated_sa not in ids
    assert stats["isolated_service_accounts_removed"] == 1


def test_trim_non_escalation_simple_bindings_keeps_pe_bindings():
    nodes = [
        _n("iambinding:pe@project:p", "GCPIamSimpleBinding", privilege_escalation=True),
        _n("iambinding:noise@project:p", "GCPIamSimpleBinding", privilege_escalation=False),
    ]
    pruned_nodes, _pruned_edges, stats = trim_non_escalation_simple_bindings(nodes, [])
    ids = {n.node_id for n in pruned_nodes}
    assert "iambinding:pe@project:p" in ids
    assert "iambinding:noise@project:p" not in ids
    assert stats["non_escalation_simple_bindings_removed"] == 1


def test_trim_orphan_implied_bindings_removes_dangling_implied_node():
    nodes = [_n("implied-iambinding:x@project:p", "GCPIamSimpleBinding", inferred=True)]
    edges = [_e("user:a@x.com", "HasImpliedPermissions", "implied-iambinding:x@project:p")]
    pruned_nodes, pruned_edges, stats = trim_orphan_implied_bindings(nodes, edges)
    assert not pruned_nodes
    assert not pruned_edges
    assert stats["implied_bindings_removed"] == 1


def test_trim_service_account_binding_islands_removes_dead_end_pair():
    sa = "serviceAccount:island@proj.iam.gserviceaccount.com"
    binding = "iambinding:roles/x@project:p"
    nodes = [_n(sa, "GCPServiceAccount"), _n(binding, "GCPIamSimpleBinding")]
    edges = [_e(sa, "HAS_IAM_BINDING", binding)]
    pruned_nodes, _pruned_edges, stats = trim_service_account_binding_islands(nodes, edges)
    assert not pruned_nodes
    assert stats["pairs_removed"] == 1


# --------------------------------------------------------------------------- #
# Combo chain survives the full trim (the open-bug regression)
# --------------------------------------------------------------------------- #

_ATTACKER = "serviceAccount:attacker@demo-project.iam.gserviceaccount.com"
_TARGET_SA = "projects/demo-project/serviceAccounts/victim@demo-project.iam.gserviceaccount.com"


def _sa_entry(*, role_name, permissions, binding_suffix):
    return BindingPlusScopeEntry(
        principal_id=_ATTACKER,
        expanded_from_convenience_member="",
        binding_composite_id=f"iambinding:{role_name}@project:demo-project#{binding_suffix}",
        role_name=role_name,
        permissions=frozenset(permissions),
        attached_scope_name="projects/demo-project",
        attached_scope_type="project",
        attached_scope_display="demo-project",
        source_scope_name="projects/demo-project",
        source_scope_type="project",
        source_scope_display="demo-project",
        effective_scope_name="projects/demo-project",
        effective_scope_type="project",
        effective_scope_display="demo-project",
        project_id="demo-project",
        inherited=False,
        source="unit_test",
        condition_expr_raw="",
        condition_hash="",
        condition_option_id="",
        condition_option_summary="",
        condition_services=frozenset(),
        condition_resource_types=frozenset(),
        condition_name_prefixes=frozenset(),
        condition_name_equals=frozenset(),
    )


class _ComboContext:
    def __init__(self, allow_resources):
        resources = [dict(r) for r in allow_resources]
        by_project = {}
        by_project_type = {}
        for r in resources:
            pid = str(r.get("project_id") or "").strip()
            if not pid:
                continue
            by_project.setdefault(pid, []).append(r)
            rt = str(r.get("resource_type") or "").strip().lower()
            if rt:
                by_project_type.setdefault(pid, {}).setdefault(rt, []).append(r)
        self.builder = OpenGraphBuilder()
        self._scope_indexes = ScopeResourceIndexes(
            project_scope_by_project_id={"demo-project": "projects/demo-project"},
            project_id_by_scope_name={"projects/demo-project": "demo-project"},
            known_project_ids={"demo-project"},
            allow_resources=resources,
            allow_resources_by_project=by_project,
            allow_resources_by_project_type=by_project_type,
            resource_sa_by_name={},
        )

    def hierarchy_data(self):
        return {
            "scope_type_by_name": {"projects/demo-project": "project"},
            "scope_display_by_name": {"projects/demo-project": "demo-project"},
            "parent_by_name": {},
        }

    def scope_resource_indexes(self):
        return self._scope_indexes


def _combo_hop_rule():
    return {
        "name": "TEST_CREATE_COMPUTE_AS_SA",
        "description": "Unit combo rule: create a VM as a target SA.",
        "edge_type": "CREATE_COMPUTE_INSTANCE_AS_SA",
        "multi_permission_type": "complex",
        "same_scope_required": False,
        "same_project_required": True,
        "requires_groups": [
            {
                "id": "create_group",
                "permissions": ["compute.instances.create"],
                "resource_scopes_possible": ["project"],
            },
            {
                "id": "actas_group",
                "permissions": ["iam.serviceAccounts.actAs"],
                "resource_scopes_possible": ["project", "service-account"],
                "target_selector": {"mode": "resource_types", "resource_types": ["service-account"]},
            },
        ],
        "combo_hop": {
            "edge_to_target": "CREATE_COMPUTE_INSTANCE_AS_SA",
            "target_from_groups": ["actas_group"],
            "hops": [
                {
                    "edge_from_subject": "CAN_CREATE_COMPUTE",
                    "node_mode": "capability",
                    "from_groups": ["create_group"],
                    "node_label": "Create Compute Instance Capability",
                }
            ],
        },
    }


def _build_combo_graph():
    context = _ComboContext(
        allow_resources=[
            {
                "resource_name": _TARGET_SA,
                "resource_type": "service-account",
                "display_name": "victim",
                "project_id": "demo-project",
            }
        ]
    )
    entries = [
        _sa_entry(
            role_name="roles/compute.instanceAdmin.v1",
            permissions={"compute.instances.create"},
            binding_suffix="create",
        ),
        _sa_entry(
            role_name="roles/iam.serviceAccountUser",
            permissions={"iam.serviceAccounts.actAs"},
            binding_suffix="actas",
        ),
    ]
    _emit_iam_binding_edges_from_entries(
        context,
        entries=entries,
        include_all=False,
        dangerous_rules=[_combo_hop_rule()],
        pass_name="dangerous",
    )
    return context


def test_combo_pe_chain_is_emitted_before_trim():
    """Sanity: the combo chain (HAS_COMBO_BINDING + both hop edges) exists pre-trim."""
    context = _build_combo_graph()
    kinds = {e.edge_type for e in context.builder.edge_map.values()}
    assert "HAS_COMBO_BINDING" in kinds
    assert "CAN_CREATE_COMPUTE" in kinds
    assert "CREATE_COMPUTE_INSTANCE_AS_SA" in kinds


def test_combo_pe_chain_survives_full_trim():
    """The open-bug regression: a well-formed SA-attacker combo chain must NOT be
    removed by any trim pass. The final CREATE_COMPUTE_INSTANCE_AS_SA edge and the
    GCPIamMultiBinding node both survive apply_final_allowlist_trims."""
    context = _build_combo_graph()
    nodes = list(context.builder.node_map.values())
    edges = list(context.builder.edge_map.values())

    pruned_nodes, pruned_edges, _stats = apply_final_allowlist_trims(nodes, edges)

    surviving_kinds = {e.edge_type for e in pruned_edges}
    assert "HAS_COMBO_BINDING" in surviving_kinds, "attacker->combo binding edge was trimmed"
    assert "CAN_CREATE_COMPUTE" in surviving_kinds, "combo->capability hop was trimmed"
    assert "CREATE_COMPUTE_INSTANCE_AS_SA" in surviving_kinds, "capability->target-SA edge was trimmed"

    surviving_node_types = {n.node_type for n in pruned_nodes}
    assert "GCPIamMultiBinding" in surviving_node_types, "combo binding node was trimmed"
