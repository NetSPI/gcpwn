from __future__ import annotations

from typing import Any

from gcpwn.core.utils.module_helpers import load_mapping_data

# Edge rules are loaded from a dedicated data file so contributors can add
# paths without editing code.  The file is organised into named categories;
# callers may filter to a subset via the `categories` parameter.
_DEFINED_EDGES_FILE = "og_defined_edges.json"

# Top-level keys that are not rule categories.
_NON_CATEGORY_KEYS: frozenset[str] = frozenset({"_schema", "collapsed_role_edges"})


def _as_rule_mapping(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, dict[str, Any]] = {}
    for raw_name, raw_rule in value.items():
        name = str(raw_name or "").strip()
        if not name or not isinstance(raw_rule, dict):
            continue
        output[name] = dict(raw_rule)
    return output


def _as_collapsed_role_mapping(value: Any) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, dict[str, str]] = {}
    for raw_role, raw_rule in value.items():
        role_name = str(raw_role or "").strip()
        if not role_name or not isinstance(raw_rule, dict):
            continue
        edge_type = str(raw_rule.get("edge_type") or "").strip()
        if not edge_type:
            continue
        output[role_name] = {
            "edge_type": edge_type,
            "description": str(raw_rule.get("description") or "").strip(),
        }
    return output


def load_privilege_escalation_rules(
    categories: "frozenset[str] | None" = None,
) -> "tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, str]]]":
    """Load edge rule mappings from og_defined_edges.json.

    Args:
        categories: frozenset of category names to include (e.g.
            ``frozenset({"priv_escalation"})``).  ``None`` or empty frozenset
            includes every category (backward-compatible default used by
            module-level initialisation and tests).

    Returns:
        ``(single_rules, multi_rules, collapsed_role_edges)`` — single_rules
        have only ``permissions``; multi_rules have ``requires``.
    """
    payload = load_mapping_data(_DEFINED_EDGES_FILE, kind="json")
    if not isinstance(payload, dict):
        return {}, {}, {}

    # Legacy flat layout ("rules" key) — still supported transparently.
    if "rules" in payload:
        all_raw = _as_rule_mapping(payload.get("rules"))
    else:
        # Category layout: merge rules from every matching category.
        all_raw: dict[str, dict[str, Any]] = {}
        for key, val in payload.items():
            if key in _NON_CATEGORY_KEYS:
                continue
            if categories and key not in categories:
                continue
            if isinstance(val, dict):
                all_raw.update(_as_rule_mapping(val))

    single_rules = {n: r for n, r in all_raw.items() if not r.get("requires")}
    multi_rules = {n: r for n, r in all_raw.items() if r.get("requires")}
    return (
        single_rules,
        multi_rules,
        _as_collapsed_role_mapping(payload.get("collapsed_role_edges")),
    )
