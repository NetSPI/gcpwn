from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable


def collect_rule_events(
    *,
    entries: list[Any],
    rules: list[dict[str, Any]],
    matches_for_group: Callable[[dict[str, Any], list[Any]], list[dict[str, Any]]],
    normalize_binding_permission_map: Callable[[dict[str, Any] | None], dict[str, list[str]]],
    normalized_token_list: Callable[[Any], list[str]],
    progress_callback: Callable[[int, int, int], None] | None = None,
    group_progress_callback: Callable[[int, int, int, int, int, str], None] | None = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    total_rules = len(rules or [])
    matched_events = 0
    grouped_entries_by_rule_shape: dict[tuple[bool, bool], list[list[Any]]] = {}
    for rule_index, rule in enumerate(rules, start=1):
        same_scope_required = bool(rule.get("same_scope_required", True))
        same_project_required = bool(rule.get("same_project_required", False))
        group_key = (same_scope_required, same_project_required)
        grouped_entries = grouped_entries_by_rule_shape.get(group_key)
        if grouped_entries is None:
            groups: dict[tuple[str, str, str, str, str], list[Any]] = defaultdict(list)
            for entry in entries:
                groups[
                    (
                        entry.principal_id,
                        entry.effective_scope_name if same_scope_required else "",
                        entry.effective_scope_type if same_scope_required else "",
                        entry.condition_option_id,
                        entry.project_id if same_project_required else "",
                    )
                ].append(entry)
            grouped_entries = list(groups.values())
            grouped_entries_by_rule_shape[group_key] = grouped_entries

        total_groups = len(grouped_entries)
        for group_index, group_entries in enumerate(grouped_entries, start=1):
            matches = matches_for_group(rule, group_entries)
            for match in matches:
                contributors = list(match.get("contributors") or [])
                if not contributors:
                    continue
                matched_permissions = set(match.get("matched_permissions") or ())
                matched_roles = {entry.role_name for entry in contributors}
                contributor_permission_map = normalize_binding_permission_map(match.get("contributor_permission_map"))
                evidence_bindings = sorted(set(entry.binding_composite_id for entry in contributors)) or sorted(contributor_permission_map.keys())
                emission_mode = str(match.get("emission_mode") or "binding").strip().lower()
                emission_mode = emission_mode if emission_mode in {"binding", "combo"} else "binding"

                events.append(
                    {
                        "rule_name": str(rule.get("name") or ""),
                        "rule_description": str(rule.get("description") or "").strip(),
                        "edge_type": str(rule.get("edge_type") or "POLICY_BINDINGS"),
                        "target_selector": rule.get("target_selector") or {},
                        "contributors": contributors,
                        "matched_permissions": matched_permissions,
                        "matched_roles": matched_roles,
                        "evidence_bindings": evidence_bindings,
                        "combine_across_bindings": bool(match.get("combine_across_bindings", False)),
                        "emission_mode": emission_mode,
                        "contributor_permission_map": contributor_permission_map,
                        "matched_group_contributors": {
                            str(group_id): normalized_token_list(binding_ids)
                            for group_id, binding_ids in (
                                (match.get("matched_group_contributors") or {}).items()
                                if isinstance(match.get("matched_group_contributors"), dict)
                                else ()
                            )
                        },
                        "matched_group_permissions": {
                            str(group_id): normalized_token_list(permissions)
                            for group_id, permissions in (
                                (match.get("matched_group_permissions") or {}).items()
                                if isinstance(match.get("matched_group_permissions"), dict)
                                else ()
                            )
                        },
                        "requires_groups": list(rule.get("requires_groups") or []),
                        "multi_permission_type": str(rule.get("multi_permission_type") or "simple").strip().lower() or "simple",
                        "combo_hop": rule.get("combo_hop") or {},
                        "targets_from_permissions": set(rule.get("targets_from_permissions") or ()),
                        "privilege_escalation": True,
                    }
                )
                matched_events += 1
            if group_progress_callback:
                group_progress_callback(
                    rule_index,
                    total_rules,
                    group_index,
                    total_groups,
                    matched_events,
                    str(rule.get("name") or f"rule_{rule_index}"),
                )
        if progress_callback:
            progress_callback(rule_index, total_rules, matched_events)
    return events


def collect_owner_baseline_events(
    *,
    entries: list[Any],
    collapsed_dangerous_role_rules: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    baseline_role_rules = ("roles/owner", "roles/editor")
    events: list[dict[str, Any]] = []
    for role_name in baseline_role_rules:
        role_rule = dict(collapsed_dangerous_role_rules.get(role_name) or {})
        edge_type = str(
            role_rule.get("edge_type")
            or ("ROLE_OWNER" if role_name == "roles/owner" else "ROLE_EDITOR")
        ).strip() or ("ROLE_OWNER" if role_name == "roles/owner" else "ROLE_EDITOR")
        description = str(role_rule.get("description") or "").strip()
        role_entries = [entry for entry in entries if str(entry.role_name or "").strip() == role_name]
        for entry in role_entries:
            events.append(
                {
                    "rule_name": edge_type,
                    "rule_description": description,
                    "edge_type": edge_type,
                    "target_selector": {},
                    "contributors": [entry],
                    "matched_permissions": set(),
                    "matched_roles": {entry.role_name},
                    "evidence_bindings": [entry.binding_composite_id],
                    "combine_across_bindings": False,
                    "emission_mode": "binding",
                    "contributor_permission_map": {entry.binding_composite_id: []},
                    "matched_group_contributors": {},
                    "matched_group_permissions": {},
                    "requires_groups": [],
                    "multi_permission_type": "simple",
                    "combo_hop": {},
                    "targets_from_permissions": set(),
                    "privilege_escalation": False,
                    "scope_only": True,
                }
            )
    return events
