"""Well-formedness guard for the og_defined_edges.json rule file itself.

test_rule_schema.py proves the PARSER desugars correct input. This file proves
the shipped RULE FILE contains only valid shapes, so a mis-authored edge fails
at commit time instead of silently dropping its act_as pivot in a live run.

The format is discriminated by field presence:
  - simple edge  -> top-level `permissions` + `on`      -> GCPIamSimpleBinding
  - combo edge   -> `requires` array (+ optional `act_as`) -> GCPIamMultiBinding

_desugar_multi_permission_rule only desugars a combo when BOTH `requires` (list)
and `act_as` (dict) are present; an edge authored with top-level `permissions`
AND an `act_as` block has its `act_as` silently ignored. That exact shape shipped
7 broken edges once. These assertions reject it.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.constants import (
    load_privilege_escalation_rules,
)

_VIA_VALUES = {"capability", "resource"}


def _iter_edges():
    """Yield (category, edge_name, rule_dict) for every leaf edge rule, across
    the full category/service nesting, using the same loader the pipeline uses."""
    single_rules, multi_rules, _collapsed = load_privilege_escalation_rules(categories=None)
    for name, rule in (single_rules or {}).items():
        yield ("single", name, rule)
    for name, rule in (multi_rules or {}).items():
        yield ("multi", name, rule)


def test_no_combo_edge_uses_the_single_perm_shape():
    """An edge with an act_as pivot MUST use the `requires` array shape, or the
    desugarer ignores act_as and the SA-impersonation hop is never emitted."""
    offenders = []
    for _kind, name, rule in _iter_edges():
        if not isinstance(rule, dict):
            continue
        has_act_as = isinstance(rule.get("act_as"), dict)
        has_requires = isinstance(rule.get("requires"), list)
        has_top_permissions = "permissions" in rule and "requires" not in rule
        if has_act_as and not has_requires:
            offenders.append(name)
        if has_act_as and has_top_permissions:
            offenders.append(name)
    assert not offenders, (
        "edges declare act_as with the single-perm `permissions` shape; act_as is "
        f"silently dropped. Convert to the `requires` array form: {sorted(set(offenders))}"
    )


def test_no_edge_mixes_both_shapes():
    """`permissions` (top-level) and `requires` are mutually exclusive discriminators."""
    offenders = [
        name
        for _kind, name, rule in _iter_edges()
        if isinstance(rule, dict) and "permissions" in rule and "requires" in rule
    ]
    assert not offenders, f"edges set both top-level `permissions` and `requires`: {sorted(set(offenders))}"


def test_via_values_are_known():
    offenders = [
        (name, rule.get("via"))
        for _kind, name, rule in _iter_edges()
        if isinstance(rule, dict) and rule.get("via") is not None and str(rule.get("via")) not in _VIA_VALUES
    ]
    assert not offenders, f"edges declare an unknown `via` value (expected {_VIA_VALUES}): {offenders}"


def test_every_edge_has_at_least_one_permission():
    """Every rule must name at least one permission somewhere, or it can never match."""
    offenders = []
    for _kind, name, rule in _iter_edges():
        if not isinstance(rule, dict):
            continue
        perms = list(rule.get("permissions") or [])
        for group in rule.get("requires") or []:
            if isinstance(group, dict):
                perms.extend(group.get("permissions") or [])
        if not perms:
            offenders.append(name)
    assert not offenders, f"edges name no permissions at all (can never match): {sorted(set(offenders))}"
