from __future__ import annotations

from typing import Any, Callable

from gcpwn.core.utils.module_helpers import normalize_str_set


def ensure_subject_state(role_subject_state: dict[str, dict[str, dict[str, Any]]], entry: Any) -> dict[str, Any]:
    role_state = role_subject_state.setdefault(entry.role_name, {})
    subject_state = role_state.setdefault(
        entry.principal_id,
        {
            "principal_id": entry.principal_id,
            "principal_member": entry.principal_id,
            "role_name": entry.role_name,
            "role_permissions": set(),
            "binding_ids": set(),
            "bindings": {},
            "destinations": {},
        },
    )
    subject_state["role_permissions"].update(entry.permissions)
    subject_state["binding_ids"].add(entry.binding_composite_id)
    binding_state = subject_state["bindings"].setdefault(
        entry.binding_composite_id,
        {
            "binding_id": entry.binding_composite_id,
            "attached_scope_id": entry.attached_scope_name,
            "attached_scope_type": entry.attached_scope_type,
            "attached_scope_display": entry.attached_scope_display,
            "source_scope_id": entry.source_scope_name,
            "source_scope_type": entry.source_scope_type,
            "source_scope_display": entry.source_scope_display,
            "inherited": bool(entry.inherited),
            "condition_hash": entry.condition_hash,
            "conditional": bool(entry.condition_hash),
            "condition_summary": (
                entry.condition_expr_raw[:240]
                if entry.condition_expr_raw
                else entry.condition_option_summary
            ),
            "privilege_escalation": False,
        },
    )
    if entry.condition_option_id:
        binding_state.setdefault("condition_option_ids", set()).add(entry.condition_option_id)
    if entry.expanded_from_convenience_member:
        binding_state.setdefault("expanded_from_convenience_members", set()).add(entry.expanded_from_convenience_member)
    return subject_state


def record_destination(
    *,
    role_subject_state: dict[str, dict[str, dict[str, Any]]],
    entry: Any,
    edge_type: str,
    rule_name: str,
    rule_description: str,
    matched_permissions: Any,
    evidence_bindings: Any,
    target_id: str,
    target_name: str,
    target_type: str,
    privilege_escalation: bool,
) -> None:
    subject_state = ensure_subject_state(role_subject_state, entry)
    binding_state = subject_state["bindings"].get(entry.binding_composite_id)
    if binding_state is not None:
        binding_state["privilege_escalation"] = bool(binding_state["privilege_escalation"] or privilege_escalation)
    dest_key = (target_id, edge_type, entry.condition_option_id)
    destination = subject_state["destinations"].setdefault(
        dest_key,
        {
            "target_node_id": target_id,
            "target_resource_id": target_name,
            "target_resource_type": target_type,
            "effective_scope_id": entry.effective_scope_name,
            "effective_scope_type": entry.effective_scope_type,
            "effective_scope_display": entry.effective_scope_display,
            "project_id": entry.project_id,
            "inherited": False,
            "conditional": False,
            "condition_option_ids": set(),
            "condition_hashes": set(),
            "condition_services": set(),
            "condition_resource_types": set(),
            "condition_name_prefixes": set(),
            "condition_name_equals": set(),
            "edge_types": set(),
            "rule_names": set(),
            "rule_descriptions": set(),
            "matched_permissions": set(),
            "evidence_bindings": set(),
            "attached_scope_ids": set(),
            "attached_scope_types": set(),
            "sources": set(),
            "privilege_escalation": False,
        },
    )
    destination["inherited"] = bool(destination["inherited"] or entry.inherited)
    destination["conditional"] = bool(destination["conditional"] or entry.condition_hash)
    destination["privilege_escalation"] = bool(destination["privilege_escalation"] or privilege_escalation)
    if entry.condition_option_id:
        destination["condition_option_ids"].add(entry.condition_option_id)
    if entry.condition_hash:
        destination["condition_hashes"].add(entry.condition_hash)
    destination["condition_services"].update(entry.condition_services)
    destination["condition_resource_types"].update(entry.condition_resource_types)
    destination["condition_name_prefixes"].update(entry.condition_name_prefixes)
    destination["condition_name_equals"].update(entry.condition_name_equals)
    destination["edge_types"].add(str(edge_type or "").strip())
    destination["rule_names"].add(str(rule_name or "").strip())
    if str(rule_description or "").strip():
        destination["rule_descriptions"].add(str(rule_description).strip())
    destination["matched_permissions"].update(normalize_str_set(list(matched_permissions or ())))
    destination["evidence_bindings"].update(normalize_str_set(list(evidence_bindings or ())))
    destination["attached_scope_ids"].add(entry.attached_scope_name)
    destination["attached_scope_types"].add(entry.attached_scope_type)
    destination["sources"].add(entry.source)


def serialize_role_subject_state(
    *,
    role_subject_state: dict[str, dict[str, dict[str, Any]]],
    normalized_token_list: Callable[[Any], list[str]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    serialized_roles: dict[str, Any] = {}
    flat_role_subject_destinations: list[dict[str, Any]] = []
    conditional_paths: list[dict[str, Any]] = []
    seen_conditional_paths: set[tuple[str, str, str, str]] = set()
    destination_list_fields = (
        "condition_option_ids",
        "condition_hashes",
        "condition_services",
        "condition_resource_types",
        "condition_name_prefixes",
        "condition_name_equals",
        "edge_types",
        "rule_names",
        "rule_descriptions",
        "matched_permissions",
        "evidence_bindings",
        "attached_scope_ids",
        "attached_scope_types",
        "sources",
    )
    conditional_path_list_fields = (
        "edge_types",
        "rule_names",
        "rule_descriptions",
        "condition_option_ids",
        "condition_hashes",
        "condition_services",
        "condition_resource_types",
        "condition_name_prefixes",
        "condition_name_equals",
    )
    for role_name in sorted(role_subject_state.keys()):
        subjects = role_subject_state.get(role_name, {})
        serialized_subjects: dict[str, Any] = {}
        for principal_id in sorted(subjects.keys()):
            subject_bucket = subjects.get(principal_id, {})
            destinations = subject_bucket.get("destinations", {})
            serialized_destinations: list[dict[str, Any]] = []
            for dest_key in sorted(destinations.keys(), key=lambda value: (str(value[1]), str(value[0]), str(value[2]))):
                destination = destinations.get(dest_key) or {}
                serialized_destination = {
                    "effective_scope_id": str(destination.get("effective_scope_id") or ""),
                    "effective_scope_type": str(destination.get("effective_scope_type") or ""),
                    "effective_scope_display": str(destination.get("effective_scope_display") or ""),
                    "project_id": str(destination.get("project_id") or ""),
                    "inherited": bool(destination.get("inherited", False)),
                    "conditional": bool(destination.get("conditional", False)),
                    "target_node_id": str(destination.get("target_node_id") or ""),
                    "target_resource_id": str(destination.get("target_resource_id") or ""),
                    "target_resource_type": str(destination.get("target_resource_type") or ""),
                    "privilege_escalation": bool(destination.get("privilege_escalation", False)),
                }
                serialized_destination.update(
                    {
                        field_name: normalized_token_list(destination.get(field_name))
                        for field_name in destination_list_fields
                    }
                )
                serialized_destinations.append(serialized_destination)
                flat_role_subject_destinations.append(
                    {
                        "role_name": role_name,
                        "principal_id": str(subject_bucket.get("principal_id") or principal_id),
                        "principal_member": str(subject_bucket.get("principal_member") or ""),
                        **serialized_destination,
                    }
                )
                if bool(serialized_destination.get("conditional")):
                    evidence_bindings = list(serialized_destination.get("evidence_bindings") or [])
                    if not evidence_bindings:
                        evidence_bindings = [""]
                    for binding_id in evidence_bindings:
                        dedupe_key = (
                            str(subject_bucket.get("principal_id") or principal_id),
                            str(binding_id or ""),
                            str(serialized_destination.get("target_resource_id") or ""),
                            ",".join(serialized_destination.get("condition_option_ids") or []),
                        )
                        if dedupe_key in seen_conditional_paths:
                            continue
                        seen_conditional_paths.add(dedupe_key)
                        conditional_path = {
                            "principal_id": str(subject_bucket.get("principal_id") or principal_id),
                            "principal_member": str(subject_bucket.get("principal_member") or ""),
                            "role_name": role_name,
                            "binding_id": str(binding_id or ""),
                            "target_resource_id": str(serialized_destination.get("target_resource_id") or ""),
                            "target_resource_type": str(serialized_destination.get("target_resource_type") or ""),
                            "effective_scope_id": str(serialized_destination.get("effective_scope_id") or ""),
                            "effective_scope_type": str(serialized_destination.get("effective_scope_type") or ""),
                        }
                        conditional_path.update(
                            {
                                field_name: list(serialized_destination.get(field_name) or [])
                                for field_name in conditional_path_list_fields
                            }
                        )
                        conditional_paths.append(conditional_path)
            serialized_subjects[principal_id] = {
                "principal_id": str(subject_bucket.get("principal_id") or principal_id),
                "principal_member": str(subject_bucket.get("principal_member") or ""),
                "role_name": role_name,
                "role_permissions": normalized_token_list(subject_bucket.get("role_permissions")),
                "binding_ids": normalized_token_list(subject_bucket.get("binding_ids")),
                "bindings": [
                    {
                        key: (normalized_token_list(value) if isinstance(value, set) else value)
                        for key, value in binding.items()
                    }
                    for binding in (
                        subject_bucket.get("bindings", {}).get(binding_id)
                        for binding_id in normalized_token_list(subject_bucket.get("binding_ids"))
                    )
                    if isinstance(binding, dict)
                ],
                "destinations": serialized_destinations,
            }
        serialized_roles[role_name] = {"subjects": serialized_subjects}
    return serialized_roles, flat_role_subject_destinations, conditional_paths
