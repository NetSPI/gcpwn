from __future__ import annotations

from typing import Any

from gcpwn.core.utils.module_helpers import load_mapping_data

# IAM dangerous (privilege escalation/lateral movement) edge rules are loaded
# from a dedicated data file so contributors can add paths without editing code.
_PRIVILEGE_ESCALATION_RULES_MAPPING_FILE = "og_privilege_escalation_paths.json"


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


def load_privilege_escalation_rules() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    """
    Load privilege-escalation rule mappings from disk.

    Callers that need hot-reload behavior in long-lived CLI sessions should
    use this helper instead of relying on module-import-time globals.
    """
    payload = load_mapping_data(_PRIVILEGE_ESCALATION_RULES_MAPPING_FILE, kind="json")
    if not isinstance(payload, dict):
        return {}, {}, {}
    return (
        _as_rule_mapping(payload.get("single_permission_rules")),
        _as_rule_mapping(payload.get("multi_permission_rules")),
        _as_collapsed_role_mapping(payload.get("collapsed_role_edges")),
    )
