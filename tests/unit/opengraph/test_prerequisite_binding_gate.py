"""Regression test for the `prerequisite_binding: source_must_hold_custom_role` gate.

UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS is only a real escalation for a principal who already
holds a binding to a CUSTOM role; updating a custom role only benefits its holders. The
gate in `_matches_for_group` drops the match for a principal who holds only predefined
roles (otherwise the edge fires for anyone with iam.roles.update -- a false positive).
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
    _matches_for_group,
)


def _entry(role_name: str, permissions: set[str]) -> BindingPlusScopeEntry:
    return BindingPlusScopeEntry(
        principal_id="serviceAccount:atk@proj-a.iam.gserviceaccount.com",
        expanded_from_convenience_member="",
        binding_composite_id=f"iambinding:{role_name}@project:proj-a",
        role_name=role_name,
        permissions=frozenset(permissions),
        attached_scope_name="projects/proj-a",
        attached_scope_type="project",
        attached_scope_display="proj-a",
        source_scope_name="projects/proj-a",
        source_scope_type="project",
        source_scope_display="proj-a",
        effective_scope_name="projects/proj-a",
        effective_scope_type="project",
        effective_scope_display="proj-a",
        project_id="proj-a",
        inherited=False,
        source="direct_api",
        condition_expr_raw="",
        condition_hash="",
        condition_option_id="default",
        condition_option_summary="",
        condition_services=frozenset(),
        condition_resource_types=frozenset(),
        condition_name_prefixes=frozenset(),
        condition_name_equals=frozenset(),
    )


_RULE = {
    "name": "UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS",
    "edge_type": "UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS",
    "prerequisite_binding": "source_must_hold_custom_role",
    "requires_all": {"iam.roles.update"},
    "combine_across_bindings": False,
}


def test_gate_drops_principal_holding_only_predefined_roles():
    entries = [_entry("roles/iam.admin", {"iam.roles.update"})]
    assert _matches_for_group(_RULE, entries) == []


def test_gate_allows_principal_holding_a_custom_role():
    entries = [_entry("projects/proj-a/roles/MyCustom", {"iam.roles.update"})]
    assert _matches_for_group(_RULE, entries) != []


def test_without_prerequisite_a_predefined_holder_matches():
    rule = {k: v for k, v in _RULE.items() if k != "prerequisite_binding"}
    entries = [_entry("roles/iam.admin", {"iam.roles.update"})]
    assert _matches_for_group(rule, entries) != []
