from __future__ import annotations

import json
from functools import lru_cache
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from gcpwn.core.utils.module_helpers import extract_path_tail, load_mapping_data, parse_json_value, split_path_tokens
from gcpwn.modules.opengraph.utilities.helpers.graph.normalization import (
    RESOURCE_TOKEN_TO_NODE_TYPE,
    normalize_resource_type_token,
    normalized_token_list,
)

@dataclass(frozen=True)
class OpenGraphNode:
    """In-memory OpenGraph node model used during pipeline assembly."""
    node_id: str
    node_type: str
    properties: Dict[str, Any]


@dataclass(frozen=True)
class OpenGraphEdge:
    """In-memory OpenGraph edge model used during pipeline assembly."""
    source_id: str
    destination_id: str
    edge_type: str
    properties: Dict[str, Any]

def principal_node_id(member: str) -> str:
    """
    Normalize principal/member identifiers into one canonical token format.

    Example:
    - input:  "users:alice@example.com"
    - output: "user:alice@example.com"
    """
    # Canonical principal/member ID normalizer used throughout OpenGraph.
    #
    # Examples:
    # - "users:alice@example.com"            -> "user:alice@example.com"
    # - "service_account:sa@p.iam.gserviceaccount.com" -> "serviceAccount:sa@p.iam.gserviceaccount.com"
    # - "project_editor:my-proj"             -> "projectEditor:my-proj"
    # - "all_users"                          -> "allUsers"
    # - "all_authenticated_users"            -> "allAuthenticatedUsers"
    token = str(member or "").strip()
    if not token:
        return ""

    lowered = token.lower()
    if lowered.startswith("deleted:"):
        return ""
    if lowered in {"all_users", "allusers"}:
        return "allUsers"
    if lowered in {"all_authenticated_users", "allauthenticatedusers"}:
        return "allAuthenticatedUsers"
    if ":" not in token:
        return token

    prefix, rest = token.split(":", 1)
    mapped = {
        "service_account": "serviceAccount",
        "serviceaccount": "serviceAccount",
        "service-account": "serviceAccount",
        "user": "user",
        "users": "user",
        "group": "group",
        "groups": "group",
        "domain": "domain",
        "domains": "domain",
        "project_owner": "projectOwner",
        "projectowner": "projectOwner",
        "project-owner": "projectOwner",
        "project_editor": "projectEditor",
        "projecteditor": "projectEditor",
        "project-editor": "projectEditor",
        "project_viewer": "projectViewer",
        "projectviewer": "projectViewer",
        "project-viewer": "projectViewer",
    }.get(prefix.strip().lower())
    if not mapped:
        return token
    return f"{mapped}:{rest.strip()}"


def principal_display_name(member: str) -> str:
    """Return a user-facing principal label (usually the right side of prefix:value)."""
    token = principal_node_id(member)
    if not token:
        return ""
    if token in {"allUsers", "allAuthenticatedUsers"}:
        return token
    if token.startswith("principal://") or token.startswith("principalSet://"):
        return token
    if ":" not in token:
        return token
    _prefix, value = token.split(":", 1)
    cleaned = value.split("?", 1)[0].strip()
    return cleaned or token


def principal_type(member: str) -> str:
    """Map a canonical principal token to the OpenGraph node type."""
    value = principal_node_id(member)

    if value.startswith("principalSet://"):
        return "GCPPrincipalSet"
    if value.startswith("user:"):
        return "GoogleUser"
    if value.startswith("serviceAccount:"):
        return "GCPServiceAccount"
    if value.startswith("group:"):
        return "GoogleGroup"
    if value.startswith("domain:"):
        return "GCPDomainPrincipal"
    if value == "allUsers":
        return "GCPAllUsers"
    if value == "allAuthenticatedUsers":
        return "GCPAllAuthenticatedUsers"
    if value.startswith(("projectOwner:", "projectEditor:", "projectViewer:")):
        return "GCPConvenienceMember"
    return "GCPPrincipal"


def resource_node_id(name: str) -> str:
    """Build canonical resource node ID from resource name/path."""
    return f"resource:{name}"


def resource_leaf_name(resource_name: str) -> str:
    """Return the tail segment of a resource path for display and matching."""
    token = str(resource_name or "").strip()
    if not token:
        return ""
    return extract_path_tail(token, default=token)


def resource_location_token(resource_name: str) -> str:
    """Extract location/region/zone token from a resource path when present."""
    token = str(resource_name or "").strip()
    if not token:
        return ""
    parts = split_path_tokens(token, separator="/", drop_empty=True)
    lowered = [str(part or "").strip().lower() for part in parts]
    for idx, part in enumerate(lowered):
        if part in {"locations", "regions", "zones"} and idx + 1 < len(parts):
            return str(parts[idx + 1] or "").strip()
    return ""


def resource_display_label(
    resource_name: str,
    *,
    resource_type: str = "",
    project_id: str = "",
) -> str:
    """
    Human-friendly node label for resources.

    Project preference:
    - Use project_id as the primary display token when available.
    - If the backing project resource leaf is numeric (project number), append
      it for context: "<project_id> (<project_number>)".
    """
    token = str(resource_name or "").strip()
    leaf = resource_leaf_name(token) or token
    kind = str(resource_type or "").strip().lower()
    project_token = str(project_id or "").strip()

    is_project = kind == "project" or (not kind and token.startswith("projects/"))
    if is_project and project_token:
        if leaf and project_token.lower() != leaf.lower():
            return f"{project_token} ({leaf})"
        return project_token

    return leaf


def is_convenience_member(member: str) -> bool:
    """Detect GCP convenience members (projectOwner/projectEditor/projectViewer)."""
    token = principal_node_id(member)
    return token.startswith(("projectOwner:", "projectEditor:", "projectViewer:"))


_SERVICE_AGENT_PATTERNS_MAPPING_FILE = "og_service_agent_patterns.json"
_SERVICE_AGENT_PLACEHOLDERS: tuple[tuple[str, str], ...] = (
    ("PROJECT_NUMBER", r"\d+"),
    ("FOLDER_NUMBER", r"\d+"),
    ("ORGANIZATION_NUMBER", r"\d+"),
    ("IDENTIFIER", r"[a-z0-9-]+"),
)
_SERVICE_AGENT_ROLE_REGEX = re.compile(r"^roles\/[a-z0-9_.-]*serviceagent[a-z0-9_.-]*$", re.IGNORECASE)


def _compile_service_agent_regex(template: str) -> re.Pattern[str]:
    """Compile a service-agent template string into a concrete email-matching regex."""
    escaped = re.escape(str(template or "").strip())
    for placeholder, replacement in _SERVICE_AGENT_PLACEHOLDERS:
        escaped = escaped.replace(re.escape(placeholder), replacement)
    return re.compile(rf"^{escaped}$", re.IGNORECASE)


@lru_cache(maxsize=1)
def _service_agent_matchers() -> list[tuple[re.Pattern[str], str]]:
    """Load and cache compiled service-agent matchers from mapping JSON."""
    try:
        payload = load_mapping_data(_SERVICE_AGENT_PATTERNS_MAPPING_FILE, kind="json")
    except Exception:
        return []
    if not isinstance(payload, list):
        return []

    seen_templates: set[str] = set()
    matchers: list[tuple[re.Pattern[str], str]] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        template = str(row.get("pattern") or "").strip()
        if not template or template in seen_templates:
            continue
        seen_templates.add(template)
        try:
            matcher = _compile_service_agent_regex(template)
        except re.error:
            continue
        matchers.append((matcher, template))
    return matchers


def service_account_agent_metadata(email: str) -> dict[str, Any]:
    """
    Classify service-account emails that look like Google-managed service agents.
    Matching uses the static, hardcoded pattern inventory in
    `gcpwn/mappings/og_service_agent_patterns.json`.
    """
    token = str(email or "").strip().lower()
    if not token:
        return {"is_service_agent": False, "service_agent_pattern": ""}

    for matcher, template in _service_agent_matchers():
        if matcher.match(token):
            return {"is_service_agent": True, "service_agent_pattern": template}

    return {"is_service_agent": False, "service_agent_pattern": ""}


def role_agent_metadata(role_name: str) -> dict[str, Any]:
    """
    Classify IAM role identifiers that look like service-agent roles.

    Examples that should match:
    - roles/cloudfunctions.serviceAgent
    - roles/firebase.managementServiceAgent
    """
    token = str(role_name or "").strip()
    if not token:
        return {"service_agent_role": False}
    return {"service_agent_role": bool(_SERVICE_AGENT_ROLE_REGEX.match(token))}


def principal_member_properties(member: str) -> dict[str, Any]:
    """
    Common principal-node properties. Includes service-agent classification for
    serviceAccount:* members.
    """
    token = principal_node_id(member)
    friendly_name = principal_display_name(token)
    props: dict[str, Any] = {
        "member": token,
        "name": friendly_name or token,
        "display_name": friendly_name or token,
    }
    if token.startswith("deleted:"):
        props["deleted"] = True
    if token.startswith("serviceAccount:"):
        email = token.split(":", 1)[1].strip().lower()
        if email:
            props["email"] = email
            props.update(service_account_agent_metadata(email))
    return props


def gcp_resource_node_type(resource_type: str | None) -> str:
    """
    Map GCPwn resource_type tokens (iam_allow_policies.resource_type)
    to nicer OpenGraph node types.
    """
    token = normalize_resource_type_token(resource_type)
    if not token:
        return "GCPResource"
    if token in RESOURCE_TOKEN_TO_NODE_TYPE:
        return RESOURCE_TOKEN_TO_NODE_TYPE[token]
    return f"GCP{token.title()}"


class OpenGraphBuilder:
    """Small in-memory graph builder with node merge and edge de-duplication."""

    def __init__(self) -> None:
        """Initialize empty node/edge maps keyed for fast de-duplication."""
        self.node_map: Dict[str, OpenGraphNode] = {}
        self.edge_map: Dict[Tuple[str, str, str], OpenGraphEdge] = {}

    @staticmethod
    def _prefer_node_type(existing: str, incoming: str) -> str:
        """
        Prefer the more-specific node type when we learn it later.

        Example:
          - a principal may be created as GCPPrincipal first, then upgraded to
            GoogleUser / GoogleGroup / GCPServiceAccount when the member prefix is known.
        """
        existing = str(existing or "").strip()
        incoming = str(incoming or "").strip()
        if not existing:
            return incoming
        if not incoming or existing == incoming:
            return existing

        generic = {"GCPPrincipal", "GCPResource"}
        if existing in generic and incoming not in generic:
            return incoming
        return existing

    @staticmethod
    def _merge_nested_dict_missing(existing_value: dict[str, Any], incoming_value: dict[str, Any]) -> dict[str, Any]:
        """Merge nested dict fields without overwriting already-populated values."""
        merged = dict(existing_value or {})
        for key, value in (incoming_value or {}).items():
            if key not in merged:
                if value not in (None, "", [], {}):
                    merged[key] = value
                continue
            existing_child = merged.get(key)
            if isinstance(existing_child, dict) and isinstance(value, dict):
                merged[key] = OpenGraphBuilder._merge_nested_dict_missing(existing_child, value)
        return merged

    def add_node(self, node_id: str, node_type: str, **properties: Any) -> None:
        """Insert or merge a node; preserves existing values unless missing."""
        if node_id in self.node_map:
            existing = self.node_map[node_id]
            merged = dict(existing.properties)
            for key, value in properties.items():
                if key not in merged and value not in (None, "", [], {}):
                    merged[key] = value
                    continue
                if (
                    key in merged
                    and isinstance(merged.get(key), dict)
                    and isinstance(value, dict)
                ):
                    merged[key] = self._merge_nested_dict_missing(
                        dict(merged.get(key) or {}),
                        value,
                    )
            chosen_type = self._prefer_node_type(existing.node_type, node_type)
            self.node_map[node_id] = OpenGraphNode(node_id=node_id, node_type=chosen_type, properties=merged)
            return
        self.node_map[node_id] = OpenGraphNode(node_id=node_id, node_type=node_type, properties=properties)

    def add_edge(self, source_id: str, destination_id: str, edge_type: str, **properties: Any) -> None:
        """Insert edge if unseen; duplicate (src, kind, dst) edges are ignored."""
        key = (source_id, edge_type, destination_id)
        if key in self.edge_map:
            return
        self.edge_map[key] = OpenGraphEdge(
            source_id=source_id,
            destination_id=destination_id,
            edge_type=edge_type,
            properties=properties,
        )


PRINCIPAL_KINDS = {
    "GCPAllUsers",
    "GCPAllAuthenticatedUsers",
    "GoogleUser",
    "GoogleGroup",
    "GCPServiceAccount",
    "GCPDomainPrincipal",
    "GCPConvenienceMember",
    "GCPPrincipal",
}

IAM_BINDING_KINDS = {
    "GCPIamBinding",
    "GCPIamGrant",
    "GCPIamSimpleBinding",
    "GCPIamMultiBinding",
}

def _standardize(value: Any, *, flatten: bool = False):
    """
    Normalize export values into stable, serializable primitives.

    When flatten=True, nested dicts are flattened to dotted keys.
    """
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None

    if flatten:
        result = {}
        stack = [("", value)]
        while stack:
            key_prefix, current = stack.pop()
            if not isinstance(current, dict):
                continue
            for raw_key in sorted(current.keys(), key=lambda x: str(x)):
                raw_val = current.get(raw_key)
                key = str(raw_key).strip()
                if not key:
                    continue
                full_key = f"{key_prefix}.{key}" if key_prefix else key
                if isinstance(raw_val, dict):
                    stack.append((full_key, raw_val))
                    continue
                normalized = _standardize(raw_val)
                if normalized is not None:
                    result[full_key] = normalized
        return {k: result[k] for k in sorted(result.keys())}

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        normalized = {}
        for raw_key in sorted(value.keys(), key=lambda x: str(x)):
            key = str(raw_key).strip()
            if not key:
                continue
            child = _standardize(value.get(raw_key))
            if child is not None:
                normalized[key] = child
        return normalized or None
    if isinstance(value, list):
        if not value:
            return []
        normalized = []
        for item in value:
            if isinstance(item, str):
                item = item.strip()
                if not item:
                    continue
            if isinstance(item, (bool, int, float, str)):
                normalized.append(item)
                continue
            continue
        return normalized
    return None


def _collect_contributing_binding_permission_map(trimmed: dict[str, Any]) -> dict[str, list[str]]:
    """Collect/normalize binding->permissions attribution from map and flattened export forms."""
    output: dict[str, list[str]] = {}

    raw_map = trimmed.get("contributing_binding_permission_map")
    if isinstance(raw_map, dict):
        for binding_id, permissions in sorted(raw_map.items(), key=lambda item: str(item[0] or "").strip()):
            binding_token = str(binding_id or "").strip()
            if not binding_token:
                continue
            output[binding_token] = normalized_token_list(permissions)

    # Export normalization may flatten nested dicts into dotted keys:
    # contributing_binding_permission_map.<binding_id> = [perm1, perm2]
    for key, value in list(trimmed.items()):
        token = str(key or "").strip()
        if not token.startswith("contributing_binding_permission_map."):
            continue
        binding_token = token.split(".", 1)[1].strip()
        if not binding_token:
            continue
        merged = set(output.get(binding_token, []))
        merged.update(normalized_token_list(value))
        output[binding_token] = sorted(merged)

    return {
        binding_id: normalized_token_list(permissions)
        for binding_id, permissions in sorted(output.items(), key=lambda item: item[0])
    }


def _permission_source_summary_lines(
    *,
    binding_ids: list[str],
    permission_map: dict[str, list[str]],
) -> list[str]:
    """Render readable per-binding permission attribution summary lines."""
    if not binding_ids and not permission_map:
        return []

    lines: list[str] = []
    for binding_id in sorted(set(binding_ids) | set(permission_map.keys())):
        permissions = normalized_token_list(permission_map.get(binding_id, []))
        if permissions:
            lines.append(f"{binding_id}: {', '.join(permissions)}")
        else:
            lines.append(f"{binding_id}: [permission attribution unavailable]")
    return lines


def _normalized_permission_attribution(
    trimmed: dict[str, Any],
) -> dict[str, list[str]]:
    """Build normalized permission attribution fields used in exported graph payloads."""
    permission_source_map = _collect_contributing_binding_permission_map(trimmed)
    permission_source_bindings = normalized_token_list(trimmed.get("evidence_bindings"))
    if not permission_source_bindings:
        permission_source_bindings = normalized_token_list(trimmed.get("contributing_binding_ids"))
    if not permission_source_bindings and permission_source_map:
        permission_source_bindings = sorted(permission_source_map.keys())

    permissions_required_by_rule = normalized_token_list(trimmed.get("matched_permissions"))
    permissions_granted_from_bindings = normalized_token_list(trimmed.get("contributing_permissions"))
    if not permissions_granted_from_bindings and permission_source_map:
        permissions_granted_from_bindings = normalized_token_list(
            permission
            for permissions in permission_source_map.values()
            for permission in permissions
        )
    if not permissions_granted_from_bindings:
        permissions_granted_from_bindings = list(permissions_required_by_rule)

    permission_source_summary = _permission_source_summary_lines(
        binding_ids=permission_source_bindings,
        permission_map=permission_source_map,
    )

    return {
        "permissions_required_by_rule": permissions_required_by_rule,
        "permissions_granted_from_bindings": permissions_granted_from_bindings,
        "permission_source_bindings": permission_source_bindings,
        "permission_source_summary": permission_source_summary,
        "effective_permissions": permissions_required_by_rule or permissions_granted_from_bindings,
    }


def _trim_export_properties(props: dict[str, Any], *, node_id: str = "") -> dict[str, Any]:
    """Remove redundant/noisy export properties and preserve high-value attribution fields."""
    trimmed = dict(props or {})

    # Prefer one lineage key for simpler graph payloads.
    if isinstance(trimmed.get("contributing_binding_ids"), list):
        if not isinstance(trimmed.get("evidence_bindings"), list) or not trimmed.get("evidence_bindings"):
            trimmed["evidence_bindings"] = list(trimmed.get("contributing_binding_ids") or [])
        trimmed.pop("contributing_binding_ids", None)
    contributing_roles = trimmed.get("contributing_roles")
    if isinstance(contributing_roles, list):
        if not isinstance(trimmed.get("matched_roles"), list) or not trimmed.get("matched_roles"):
            trimmed["matched_roles"] = list(contributing_roles or [])
        trimmed.pop("contributing_roles", None)
    if (
        isinstance(contributing_roles, list)
        and isinstance(trimmed.get("matched_roles"), list)
        and list(trimmed.get("matched_roles") or []) == list(contributing_roles or [])
    ):
        trimmed.pop("matched_roles", None)

    binding_display = str(trimmed.get("binding_display") or "").strip()
    display_name = str(trimmed.get("display_name") or "").strip()
    if binding_display:
        if not display_name or display_name == str(node_id or "").strip() or display_name == str(trimmed.get("name") or "").strip():
            trimmed["display_name"] = binding_display
        trimmed.pop("binding_display", None)

    permission_attribution = _normalized_permission_attribution(trimmed)
    for field_name in (
        "permissions_required_by_rule",
        "permissions_granted_from_bindings",
        "permission_source_bindings",
        "permission_source_summary",
    ):
        values = permission_attribution.get(field_name) or []
        if values:
            trimmed[field_name] = values

    effective_permissions = permission_attribution.get("effective_permissions") or []
    if isinstance(effective_permissions, list) and effective_permissions:
        trimmed["single_permission"] = len(effective_permissions) == 1
        if len(effective_permissions) == 1:
            permission_value = effective_permissions[0]
            trimmed["permission"] = permission_value
    trimmed.pop("matched_permissions", None)
    trimmed.pop("contributing_permissions", None)
    trimmed.pop("evidence_bindings", None)
    trimmed.pop("contributing_binding_ids", None)
    if (
        str(trimmed.get("collapsed_edge_description") or "").strip()
        and str(trimmed.get("collapsed_edge_description") or "").strip()
        == str(trimmed.get("rule_description") or "").strip()
    ):
        trimmed.pop("collapsed_edge_description", None)

    if not bool(trimmed.get("inherited")):
        if trimmed.get("source_scope_id") == trimmed.get("attached_scope_id"):
            trimmed.pop("source_scope_id", None)
        if trimmed.get("source_scope_type") == trimmed.get("attached_scope_type"):
            trimmed.pop("source_scope_type", None)
        if trimmed.get("source_scope_display") == trimmed.get("attached_scope_display"):
            trimmed.pop("source_scope_display", None)

    if str(trimmed.get("binding_origin") or "").strip().lower() == "direct" and trimmed.get("inherited") is False:
        trimmed.pop("inherited", None)
    trimmed.pop("direct_attached_scope", None)
    trimmed.pop("is_convenience_member", None)
    trimmed.pop("contributing_binding_permission_map", None)
    return trimmed


def _order_export_properties(props: dict[str, Any]) -> dict[str, Any]:
    """Move boolean flags to the end of property dict for easier human scanning."""
    ordered = dict(props or {})
    non_boolean_items = [(key, value) for key, value in ordered.items() if not isinstance(value, bool)]
    boolean_items = [(key, value) for key, value in ordered.items() if isinstance(value, bool)]
    return dict(non_boolean_items + boolean_items)


def _node_kinds(node_type: str | None) -> list[str]:
    """Map internal node_type to exported kinds list with generic fallback kind."""
    token = str(node_type or "").strip()
    if not token:
        return ["GCPUnknown"]

    if token in PRINCIPAL_KINDS or token.endswith("Principal") or token.startswith("Google"):
        kinds = [token]
        if token != "GCPPrincipal":
            kinds.append("GCPPrincipal")
        return kinds[:3]

    if token.startswith("GCP"):
        kinds = [token]
        if token != "GCPResource":
            kinds.append("GCPResource")
        return kinds[:3]

    return ["GCPUnknown"]


def _normalize_resourcedata_value(value: Any) -> Any:
    """Normalize arbitrary resourcedata values to stable primitives/dicts/lists."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        token = value.strip()
        if not token:
            return None
        parsed = parse_json_value(token, default=None)
        if isinstance(parsed, (dict, list)):
            return _normalize_resourcedata_value(parsed)
        return token
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for raw_key in sorted(value.keys(), key=lambda x: str(x)):
            key = str(raw_key).strip()
            if not key:
                continue
            normalized = _normalize_resourcedata_value(value.get(raw_key))
            if normalized is not None:
                output[key] = normalized
        return output or None
    if isinstance(value, list):
        output: list[Any] = []
        for item in value:
            normalized = _normalize_resourcedata_value(item)
            if normalized is not None:
                output.append(normalized)
        return output or None
    return None


def _resource_resourcedata_from_props(raw_props: dict[str, Any]) -> dict[str, Any]:
    """Build baseline nested `resourcedata` payload from non-resourcedata properties."""
    payload: dict[str, Any] = {}
    for raw_key in sorted((raw_props or {}).keys(), key=lambda x: str(x)):
        key = str(raw_key).strip()
        if not key or key == "resourcedata" or key.startswith("resourcedata."):
            continue
        normalized = _normalize_resourcedata_value(raw_props.get(raw_key))
        if normalized is not None:
            payload[key] = normalized
    return payload


def _flatten_resourcedata_value(value: Any, *, prefix: str, output: dict[str, Any]) -> None:
    """Flatten nested resourcedata into dotted key form (resourcedata.*)."""
    if isinstance(value, dict):
        for raw_key in sorted(value.keys(), key=lambda x: str(x)):
            key = str(raw_key).strip()
            if not key:
                continue
            child_prefix = f"{prefix}.{key}" if prefix else key
            _flatten_resourcedata_value(value.get(raw_key), prefix=child_prefix, output=output)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            child_prefix = f"{prefix}.{index}" if prefix else str(index)
            _flatten_resourcedata_value(item, prefix=child_prefix, output=output)
        return
    normalized = _normalize_resourcedata_value(value)
    if normalized is not None and prefix:
        output[prefix] = normalized


def node_to_opengraph(node: OpenGraphNode) -> dict[str, Any]:
    """
    Convert in-memory node to final OpenGraph JSON shape.

    Includes export hygiene (flattening, dedupe, attribution normalization).
    """
    raw_props = dict(node.properties or {})
    is_resource_node = str(node.node_id or "").startswith("resource:")
    if is_resource_node:
        has_flat_resourcedata = any(str(key or "").startswith("resourcedata.") for key in raw_props.keys())
        if not has_flat_resourcedata and "resourcedata" not in raw_props:
            baseline_resourcedata = _resource_resourcedata_from_props(raw_props)
            if baseline_resourcedata:
                raw_props["resourcedata"] = baseline_resourcedata
        raw_resourcedata = raw_props.get("resourcedata")
        if isinstance(raw_resourcedata, (dict, list)):
            flattened_resourcedata: dict[str, Any] = {}
            _flatten_resourcedata_value(raw_resourcedata, prefix="resourcedata", output=flattened_resourcedata)
            for key, value in flattened_resourcedata.items():
                raw_props.setdefault(key, value)
            raw_props.pop("resourcedata", None)
    props = _standardize(raw_props, flatten=True)
    if not isinstance(props, dict):
        props = {}
    if is_resource_node and str(props.get("resourcedata.status") or "").strip():
        props.pop("status", None)

    if not props.get("name"):
        props["name"] = str(raw_props.get("name") or node.node_id)

    kinds = _node_kinds(node.node_type)

    # Export hygiene for principal nodes:
    # - drop `member` when it duplicates node id
    # - drop `name` when it duplicates `display_name`
    # Keep these internally during build-time, but trim redundant output in final JSON.
    if any(kind in PRINCIPAL_KINDS for kind in kinds):
        member_value = str(props.get("member") or "").strip()
        if member_value and member_value == str(node.node_id or "").strip():
            props.pop("member", None)
        name_value = str(props.get("name") or "").strip()
        display_value = str(props.get("display_name") or "").strip()
        if name_value and display_value and name_value == display_value:
            props.pop("name", None)
    elif any(kind in IAM_BINDING_KINDS for kind in kinds):
        props.pop("member", None)
        if str(props.get("display_name") or "").strip():
            props.pop("name", None)

    props = _trim_export_properties(props, node_id=node.node_id)
    props = {k: v for k, v in props.items() if v is not None and str(k).strip().lower() != "objectid"}
    props = _order_export_properties(props)

    return {
        "id": node.node_id,
        "kinds": kinds,
        "properties": props or None,
    }


def _sanitize_edge_kind(kind: str | None) -> str:
    """Normalize edge kind to Graph-safe token (fallback: RELATED_TO)."""
    value = str(kind or "").strip()
    if not value:
        return "RELATED_TO"
    cleaned = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in value)
    cleaned = cleaned.strip("_")
    return cleaned or "RELATED_TO"


def edge_to_opengraph(edge: OpenGraphEdge) -> dict[str, Any]:
    """Convert in-memory edge to final OpenGraph JSON shape with normalized properties."""
    raw_props = dict(edge.properties or {})
    if isinstance(raw_props.get("edge_inner_properties"), dict):
        merged = {"edge_category": raw_props.get("edge_category")}
        merged.update(dict(raw_props.get("edge_inner_properties") or {}))
        props = _standardize(merged, flatten=True)
    else:
        props = _standardize(raw_props, flatten=True)
    if not isinstance(props, dict):
        props = {}
    props = _trim_export_properties(props, node_id=edge.source_id)
    props = {k: v for k, v in props.items() if v is not None}
    props = _order_export_properties(props)

    return {
        "start": {"match_by": "id", "value": edge.source_id},
        "end": {"match_by": "id", "value": edge.destination_id},
        "kind": _sanitize_edge_kind(edge.edge_type),
        "properties": props or None,
    }


def persist_opengraph(session, nodes: List[OpenGraphNode], edges: List[OpenGraphEdge], *, clear_existing: bool = False) -> None:
    """
    Persist generated OpenGraph nodes/edges into SQLite backing tables.

    Typical use:
    - default run: append/update per node/edge key
    - with `clear_existing=True` (module `--reset`): replace prior graph snapshot
    """
    node_type_by_id = {node.node_id: node.node_type for node in nodes}

    if clear_existing:
        session.data_master.service_cursor.execute(
            'DELETE FROM "opengraph_nodes" WHERE workspace_id = ?',
            (session.workspace_id,),
        )
        session.data_master.service_cursor.execute(
            'DELETE FROM "opengraph_edges" WHERE workspace_id = ?',
            (session.workspace_id,),
        )
        session.data_master.service_conn.commit()

    for node in nodes:
        node_props = dict(node.properties or {})
        if not str(node_props.get("name") or "").strip():
            node_props["name"] = str(node_props.get("display_name") or node.node_id)
        if not str(node_props.get("display_name") or "").strip():
            node_props["display_name"] = str(node_props.get("name") or node.node_id)
        session.insert_data(
            "opengraph_nodes",
            {
                "node_id": node.node_id,
                "node_type": node.node_type,
                "name": str(node_props.get("name") or ""),
                "display_name": str(node_props.get("display_name") or ""),
                "properties_json": json.dumps(node_props, ensure_ascii=False, sort_keys=True),
            },
            if_column_matches=["node_id"],
        )

    for edge in edges:
        session.insert_data(
            "opengraph_edges",
            {
                "source_id": edge.source_id,
                "destination_id": edge.destination_id,
                "edge_type": edge.edge_type,
                "source_type": node_type_by_id.get(edge.source_id, ""),
                "destination_type": node_type_by_id.get(edge.destination_id, ""),
                "properties_json": json.dumps(edge.properties, ensure_ascii=False, sort_keys=True),
                "evidence_source": str(edge.properties.get("source") or ""),
            },
            if_column_matches=["source_id", "destination_id", "edge_type"],
        )
