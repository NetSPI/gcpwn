from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from itertools import combinations
from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.modules.opengraph.utilities.helpers.graph.constants import (
    load_privilege_escalation_rules,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_aggregation_helpers import (
    ensure_subject_state,
    record_destination,
    serialize_role_subject_state,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_event_helpers import (
    collect_owner_baseline_events,
    collect_rule_events,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    OpenGraphEdge,
    OpenGraphBuilder,
    OpenGraphNode,
    gcp_resource_node_type,
    principal_member_properties,
    principal_type,
    role_agent_metadata,
    resource_display_label,
    resource_location_token,
    resource_node_id,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.normalization import (
    canonical_scope_type,
    normalized_token_frozenset,
    normalized_token_list,
)


# Permission prefix -> canonical Google API service (used by conditional narrowing).
_PERMISSION_SERVICE_PREFIX_MAP: tuple[tuple[str, str], ...] = (
    ("resourcemanager.", "cloudresourcemanager.googleapis.com"),
    ("compute.", "compute.googleapis.com"),
    ("storage.", "storage.googleapis.com"),
    ("cloudfunctions.", "cloudfunctions.googleapis.com"),
    ("iam.", "iam.googleapis.com"),
    ("secretmanager.", "secretmanager.googleapis.com"),
    ("cloudkms.", "cloudkms.googleapis.com"),
    ("run.", "run.googleapis.com"),
    ("artifactregistry.", "artifactregistry.googleapis.com"),
    ("pubsub.", "pubsub.googleapis.com"),
    ("servicedirectory.", "servicedirectory.googleapis.com"),
    ("spanner.", "spanner.googleapis.com"),
    ("cloudtasks.", "cloudtasks.googleapis.com"),
)

# Permission prefix -> canonical full resource type(s) used by IAM Conditions.
_PERMISSION_RESOURCE_TYPE_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("resourcemanager.organizations.", ("cloudresourcemanager.googleapis.com/Organization",)),
    ("resourcemanager.folders.", ("cloudresourcemanager.googleapis.com/Folder",)),
    ("resourcemanager.projects.", ("cloudresourcemanager.googleapis.com/Project",)),
    ("compute.instances.", ("compute.googleapis.com/Instance",)),
    ("storage.buckets.", ("storage.googleapis.com/Bucket",)),
    ("storage.objects.", ("storage.googleapis.com/Object",)),
    ("cloudfunctions.functions.", ("cloudfunctions.googleapis.com/CloudFunction",)),
    ("iam.serviceAccounts.", ("iam.googleapis.com/ServiceAccount",)),
    ("iam.serviceAccountKeys.", ("iam.googleapis.com/ServiceAccountKey",)),
    ("iam.roles.", ("iam.googleapis.com/Role",)),
    ("secretmanager.secrets.", ("secretmanager.googleapis.com/Secret",)),
    ("secretmanager.versions.", ("secretmanager.googleapis.com/SecretVersion",)),
    ("cloudkms.keyRings.", ("cloudkms.googleapis.com/KeyRing",)),
    ("cloudkms.cryptoKeys.", ("cloudkms.googleapis.com/CryptoKey",)),
    ("run.services.", ("run.googleapis.com/Service",)),
    ("run.jobs.", ("run.googleapis.com/Job",)),
    ("artifactregistry.repositories.", ("artifactregistry.googleapis.com/Repository",)),
    ("pubsub.topics.", ("pubsub.googleapis.com/Topic",)),
    ("pubsub.subscriptions.", ("pubsub.googleapis.com/Subscription",)),
    ("pubsub.snapshots.", ("pubsub.googleapis.com/Snapshot",)),
    ("pubsub.schemas.", ("pubsub.googleapis.com/Schema",)),
    ("servicedirectory.namespaces.", ("servicedirectory.googleapis.com/Namespace",)),
    ("servicedirectory.services.", ("servicedirectory.googleapis.com/Service",)),
    ("spanner.instances.", ("spanner.googleapis.com/Instance",)),
    ("spanner.databases.", ("spanner.googleapis.com/Database",)),
    ("cloudtasks.queues.", ("cloudtasks.googleapis.com/Queue",)),
)

# Internal resource_type token -> owning Google API service.
_RESOURCE_TYPE_TO_SERVICE: dict[str, str] = {
    "org": "cloudresourcemanager.googleapis.com",
    "folder": "cloudresourcemanager.googleapis.com",
    "project": "cloudresourcemanager.googleapis.com",
    "computeinstance": "compute.googleapis.com",
    "bucket": "storage.googleapis.com",
    "cloudfunction": "cloudfunctions.googleapis.com",
    "service-account": "iam.googleapis.com",
    "secrets": "secretmanager.googleapis.com",
    "kmskeyring": "cloudkms.googleapis.com",
    "kmscryptokey": "cloudkms.googleapis.com",
    "cloudrunservice": "run.googleapis.com",
    "cloudrunjob": "run.googleapis.com",
    "artifactregistryrepo": "artifactregistry.googleapis.com",
    "pubsubtopic": "pubsub.googleapis.com",
    "pubsubsubscription": "pubsub.googleapis.com",
    "pubsubschema": "pubsub.googleapis.com",
    "pubsubsnapshot": "pubsub.googleapis.com",
    "servicedirectorynamespace": "servicedirectory.googleapis.com",
    "servicedirectoryservice": "servicedirectory.googleapis.com",
    "spannerinstance": "spanner.googleapis.com",
    "spannerdatabase": "spanner.googleapis.com",
    "cloudtasksqueue": "cloudtasks.googleapis.com",
}

# Internal resource_type token -> canonical full resource type(s).
_RESOURCE_TYPE_TO_FULL_TYPE: dict[str, tuple[str, ...]] = {
    "org": ("cloudresourcemanager.googleapis.com/Organization",),
    "folder": ("cloudresourcemanager.googleapis.com/Folder",),
    "project": ("cloudresourcemanager.googleapis.com/Project",),
    "computeinstance": ("compute.googleapis.com/Instance",),
    "bucket": ("storage.googleapis.com/Bucket",),
    "cloudfunction": ("cloudfunctions.googleapis.com/CloudFunction",),
    "service-account": ("iam.googleapis.com/ServiceAccount",),
    "secrets": ("secretmanager.googleapis.com/Secret",),
    "kmskeyring": ("cloudkms.googleapis.com/KeyRing",),
    "kmscryptokey": ("cloudkms.googleapis.com/CryptoKey",),
    "cloudrunservice": ("run.googleapis.com/Service",),
    "cloudrunjob": ("run.googleapis.com/Job",),
    "artifactregistryrepo": ("artifactregistry.googleapis.com/Repository",),
    "pubsubtopic": ("pubsub.googleapis.com/Topic",),
    "pubsubsubscription": ("pubsub.googleapis.com/Subscription",),
    "pubsubsnapshot": ("pubsub.googleapis.com/Snapshot",),
    "pubsubschema": ("pubsub.googleapis.com/Schema",),
    "servicedirectorynamespace": ("servicedirectory.googleapis.com/Namespace",),
    "servicedirectoryservice": ("servicedirectory.googleapis.com/Service",),
    "spannerinstance": ("spanner.googleapis.com/Instance",),
    "spannerdatabase": ("spanner.googleapis.com/Database",),
    "cloudtasksqueue": ("cloudtasks.googleapis.com/Queue",),
}

_PREFERRED_RULE_RESOURCE_TOKENS: frozenset[str] = frozenset(
    {
        "org",
        "folder",
        "project",
        "computeinstance",
        "bucket",
        "cloudfunction",
        "service-account",
        "secrets",
        "kmskeyring",
        "kmscryptokey",
        "kmskeyversion",
        "cloudrunservice",
        "cloudrunjob",
        "artifactregistryrepo",
        "pubsubtopic",
        "pubsubsubscription",
        "pubsubsnapshot",
        "pubsubschema",
        "servicedirectorynamespace",
        "servicedirectoryservice",
        "spannerinstance",
        "spannerdatabase",
        "cloudtasksqueue",
        "cloudsqlinstance",
        "bigquerydataset",
        "bigquerytable",
        "bigqueryroutine",
    }
)

_COLLAPSED_DANGEROUS_ROLE_EDGE_RULES: dict[str, dict[str, str]] = {
    "roles/owner": {
        "edge_type": "ROLE_OWNER",
        "description": (
            "Collapsed dangerous-path edge for owner role grants. "
            "See dangerous_rule_names and dangerous_rule_descriptions for collapsed rule details."
        ),
    },
    "roles/editor": {
        "edge_type": "ROLE_EDITOR",
        "description": (
            "Collapsed dangerous-path edge for editor role grants. "
            "See dangerous_rule_names and dangerous_rule_descriptions for collapsed rule details."
        ),
    },
}
_single_rules_raw, _multi_rules_raw, _collapsed_rules_raw = load_privilege_escalation_rules()
for _role_name, _rule_data in dict(_collapsed_rules_raw or {}).items():
    role_name = str(_role_name or "").strip()
    if not role_name or not isinstance(_rule_data, dict):
        continue
    edge_type = str(_rule_data.get("edge_type") or "").strip()
    if not edge_type:
        continue
    _COLLAPSED_DANGEROUS_ROLE_EDGE_RULES[role_name] = {
        "edge_type": edge_type,
        "description": str(_rule_data.get("description") or "").strip(),
    }


@dataclass(frozen=True)
class BindingPlusScopeEntry:
    """Resolved IAM binding-composite row shared between the base and advanced passes."""

    principal_id: str
    expanded_from_convenience_member: str
    binding_composite_id: str
    role_name: str
    permissions: frozenset[str]
    attached_scope_name: str
    attached_scope_type: str
    attached_scope_display: str
    source_scope_name: str
    source_scope_type: str
    source_scope_display: str
    effective_scope_name: str
    effective_scope_type: str
    effective_scope_display: str
    project_id: str
    inherited: bool
    source: str
    condition_expr_raw: str
    condition_hash: str
    condition_option_id: str
    condition_option_summary: str
    condition_services: frozenset[str]
    condition_resource_types: frozenset[str]
    condition_name_prefixes: frozenset[str]
    condition_name_equals: frozenset[str]




@dataclass(frozen=True)
class ScopeResourceIndexes:
    """Shared scope/resource lookup bundle consumed by both IAM graph passes."""

    project_scope_by_project_id: dict[str, str]
    project_id_by_scope_name: dict[str, str]
    known_project_ids: set[str]
    allow_resources: list[dict[str, str]]
    allow_resources_by_project: dict[str, list[dict[str, str]]]
    allow_resources_by_project_type: dict[str, dict[str, list[dict[str, str]]]]


def canonical_scope_type_for_bindings(scope_type: str | None, scope_name: str | None) -> str:
    return canonical_scope_type(scope_type, scope_name)

def _scope_leaf(scope_name: str) -> str:
    token = str(scope_name or "").strip()
    if not token:
        return ""
    return extract_path_tail(token, default=token)


def _role_display_name(role_name: str) -> str:
    """
    Keep built-in roles as-is (roles/owner) but shorten custom-role paths.
    Example: projects/my-proj/roles/CustomRole704 -> CustomRole704
    """
    token = str(role_name or "").strip()
    if not token:
        return ""
    if "/roles/" in token and not token.startswith("roles/"):
        return _scope_leaf(token)
    return token


def parse_scoped_resource_key(
    resource_key: str,
    *,
    known_project_ids: set[str] | None = None,
) -> tuple[str, str, str] | None:
    token = str(resource_key or "").strip()
    if not token or ":" not in token:
        return None

    base = token
    project_id = ""
    maybe_base, sep, suffix = token.rpartition("@")
    suffix_token = str(suffix or "").strip()
    if sep and ":" in maybe_base and suffix_token:
        if known_project_ids is None or suffix_token in known_project_ids:
            base = maybe_base
            project_id = suffix_token
    if ":" not in base:
        return None

    scope_type, scope_name = base.split(":", 1)
    scope_type = canonical_scope_type_for_bindings(str(scope_type or "").strip(), str(scope_name or "").strip())
    scope_name = str(scope_name or "").strip()
    if not scope_type or not scope_name:
        return None
    return scope_type, scope_name, project_id


def binding_scope_token(scope_type: str, scope_name: str, *, project_id: str = "") -> str:
    """Build a compact binding scope token, preferring project_id for project scopes."""
    canonical_type = canonical_scope_type_for_bindings(scope_type, scope_name)
    if canonical_type == "project":
        project_token = str(project_id or "").strip()
        if project_token:
            return f"project:{project_token}"
    return f"{canonical_type}:{_scope_leaf(scope_name)}"


def binding_origin_from_entry(entry: BindingPlusScopeEntry) -> str:
    return "inherited" if bool(entry.inherited) else "direct"


def binding_family_id_for_entry(entry: BindingPlusScopeEntry) -> str:
    attached_scope_ref = binding_scope_token(
        entry.attached_scope_type,
        entry.attached_scope_name,
        project_id=entry.project_id,
    )
    family_id = f"iambinding:{entry.role_name}@{attached_scope_ref}"
    if entry.condition_hash:
        family_id = f"{family_id}#cond:{entry.condition_hash}"
    return family_id


def existing_binding_rule_targets(builder) -> set[tuple[str, str, str]]:
    """
    Return {(principal_id, edge_type, destination_id)} already proven by
    explicit IAM/combo bindings in the current graph.
    """
    grant_owner: dict[str, str] = {}
    for edge in builder.edge_map.values():
        if edge.edge_type in {"HAS_IAM_BINDING", "HAS_COMBO_BINDING"}:
            grant_owner[str(edge.destination_id or "").strip()] = str(edge.source_id or "").strip()

    proven: set[tuple[str, str, str]] = set()
    for edge in builder.edge_map.values():
        source_id = str(edge.source_id or "").strip()
        owner = grant_owner.get(source_id)
        if not owner:
            continue
        destination_id = str(edge.destination_id or "").strip()
        edge_type = str(edge.edge_type or "").strip()
        proven.add((owner, edge_type, destination_id))

        if edge_type in {"ROLE_OWNER", "ROLE_EDITOR"}:
            properties = dict(edge.properties or {})
            wrapped_types = normalized_token_list(
                list(properties.get("dangerous_edge_types") or [])
                + list(properties.get("dangerous_rule_names") or [])
            )
            for wrapped_type in wrapped_types:
                proven.add((owner, wrapped_type, destination_id))
    return proven


def _normalize_binding_permission_map(
    contribution_map: dict[str, Iterable[str]] | None,
) -> dict[str, list[str]]:
    return {
        grant_key: normalized_token_list(permissions)
        for grant_id, permissions in (contribution_map or {}).items()
        if (grant_key := str(grant_id or "").strip())
    }


def _normalized_rule(name: str, raw_rule: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize one privilege-escalation rule into the shared matcher contract.

    Rule authors primarily define:
    - `requires_any` / `requires_all` / `requires_groups`
    - `target_selector`
    - optional combo controls (`same_scope_required`, `same_project_required`,
      `combo_hop`, `targets_from_permission`).
    """

    def _list_or_empty(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    def _selector_or_empty(raw_selector_value: Any) -> dict[str, Any]:
        selector: dict[str, Any] = {}
        if isinstance(raw_selector_value, dict):
            mode = str(raw_selector_value.get("mode") or "").strip().lower()
            if mode == "resource_types":
                selector = {
                    "mode": "resource_types",
                    "resource_types": {
                        canonical
                        for item in _list_or_empty(raw_selector_value.get("resource_types"))
                        if str(item).strip()
                        if (canonical := canonical_scope_type_for_bindings(str(item).strip().lower(), "")) in _PREFERRED_RULE_RESOURCE_TOKENS
                    },
                    "status_in": {
                        str(item).strip().upper()
                        for item in _list_or_empty(raw_selector_value.get("status_in"))
                        if str(item).strip()
                    },
                }
        return selector

    requires_groups: list[dict[str, Any]] = []
    seen_group_ids: set[str] = set()
    for index, raw_group in enumerate(raw_rule.get("requires_groups") or []):
        default_group_id = f"group_{index + 1}"
        group_id = default_group_id
        permissions: set[str] = set()
        group_resource_scopes_possible: set[str] = set()
        group_attached_scope_types: set[str] = set()
        group_target_selector: dict[str, Any] = {}

        if isinstance(raw_group, dict):
            group_id = str(raw_group.get("id") or raw_group.get("group_id") or default_group_id).strip() or default_group_id
            raw_permissions = (
                raw_group.get("permissions")
                or raw_group.get("requires_any")
                or raw_group.get("requires")
                or []
            )
            permissions = set(_list_or_empty(raw_permissions))
            single_permission = str(raw_group.get("permission") or "").strip()
            if single_permission:
                permissions.add(single_permission)
            group_resource_scopes_possible = {
                canonical
                for token in normalized_token_list(raw_group.get("resource_scopes_possible"))
                if str(token).strip()
                if (canonical := canonical_scope_type_for_bindings(token, "")) in _PREFERRED_RULE_RESOURCE_TOKENS
            }
            group_attached_scope_types = {
                canonical
                for token in _list_or_empty(raw_group.get("attached_scope_types"))
                if str(token).strip()
                if (canonical := canonical_scope_type_for_bindings(token, "")) in _PREFERRED_RULE_RESOURCE_TOKENS
            }
            group_target_selector = _selector_or_empty(raw_group.get("target_selector"))
        else:
            permissions = set(_list_or_empty(raw_group))

        if not permissions:
            continue
        if group_id in seen_group_ids:
            suffix = 2
            while f"{group_id}_{suffix}" in seen_group_ids:
                suffix += 1
            group_id = f"{group_id}_{suffix}"
        seen_group_ids.add(group_id)
        requires_groups.append(
            {
                "id": group_id,
                "permissions": permissions,
                "resource_scopes_possible": group_resource_scopes_possible,
                "attached_scope_types": group_attached_scope_types,
                "target_selector": group_target_selector,
            }
        )

    selector = _selector_or_empty(raw_rule.get("target_selector"))
    raw_multi_permission_type = str(raw_rule.get("multi_permission_type") or "").strip().lower()
    if raw_multi_permission_type not in {"simple", "complex"}:
        raw_multi_permission_type = "complex" if isinstance(raw_rule.get("combo_hop"), dict) else "simple"

    raw_combo_hop = raw_rule.get("combo_hop")
    combo_hop: dict[str, Any] = {}
    if isinstance(raw_combo_hop, dict):
        edge_to = str(raw_combo_hop.get("edge_to_target") or "").strip()
        normalized_hops: list[dict[str, Any]] = []

        raw_hops = raw_combo_hop.get("hops")
        if isinstance(raw_hops, list):
            for hop_index, raw_hop in enumerate(raw_hops):
                if not isinstance(raw_hop, dict):
                    continue
                edge_from_subject = str(raw_hop.get("edge_from_subject") or "").strip()
                if not edge_from_subject:
                    continue
                hop_mode = (
                    str(raw_hop.get("node_mode") or raw_hop.get("intermediate_node_mode") or "capability").strip().lower()
                    or "capability"
                )
                if hop_mode not in {"capability", "resource"}:
                    hop_mode = "capability"
                raw_from_group = raw_hop.get("from_groups")
                if raw_from_group is None:
                    raw_from_group = raw_hop.get("from_group")
                if raw_from_group is None:
                    raw_from_group = raw_hop.get("intermediate_from_group")
                from_groups: set[str] = set()
                if isinstance(raw_from_group, str):
                    if token := str(raw_from_group).strip():
                        from_groups.add(token)
                elif isinstance(raw_from_group, list):
                    from_groups = set(_list_or_empty(raw_from_group))
                normalized_hops.append(
                    {
                        "id": str(raw_hop.get("id") or f"hop_{hop_index + 1}").strip() or f"hop_{hop_index + 1}",
                        "edge_from_subject": edge_from_subject,
                        "node_mode": hop_mode,
                        "from_groups": from_groups,
                        "selector": _selector_or_empty(
                            raw_hop.get("selector")
                            if raw_hop.get("selector") is not None
                            else raw_hop.get("intermediate_selector")
                        ),
                        "node_type": str(raw_hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability",
                        "node_label": str(raw_hop.get("node_label") or str(name)).strip() or str(name),
                    }
                )

        if not normalized_hops:
            edge_from_subject = str(raw_combo_hop.get("edge_from_subject") or "").strip()
            if edge_from_subject:
                hop_mode = (
                    str(raw_combo_hop.get("intermediate_node_mode") or raw_combo_hop.get("node_mode") or "capability").strip().lower()
                    or "capability"
                )
                if hop_mode not in {"capability", "resource"}:
                    hop_mode = "capability"
                raw_intermediate_from_group = raw_combo_hop.get("intermediate_from_group")
                from_groups: set[str] = set()
                if isinstance(raw_intermediate_from_group, str):
                    if token := str(raw_intermediate_from_group).strip():
                        from_groups.add(token)
                elif isinstance(raw_intermediate_from_group, list):
                    from_groups = set(_list_or_empty(raw_intermediate_from_group))
                normalized_hops = [
                    {
                        "id": "hop_1",
                        "edge_from_subject": edge_from_subject,
                        "node_mode": hop_mode,
                        "from_groups": from_groups,
                        "selector": _selector_or_empty(raw_combo_hop.get("intermediate_selector")),
                        "node_type": str(raw_combo_hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability",
                        "node_label": str(raw_combo_hop.get("node_label") or str(name)).strip() or str(name),
                    }
                ]

        raw_target_from_group = raw_combo_hop.get("target_from_group")
        if raw_target_from_group is None:
            raw_target_from_group = raw_combo_hop.get("target_from_groups")
        target_from_groups: set[str] = set()
        if isinstance(raw_target_from_group, str):
            if token := str(raw_target_from_group).strip():
                target_from_groups.add(token)
        elif isinstance(raw_target_from_group, list):
            target_from_groups = set(_list_or_empty(raw_target_from_group))

        if normalized_hops and edge_to:
            combo_hop = {
                "edge_to_target": edge_to,
                "hops": normalized_hops,
                "target_from_groups": target_from_groups,
                "target_selector": _selector_or_empty(raw_combo_hop.get("target_selector")),
            }
    raw_targets_from_permission = raw_rule.get("targets_from_permission")
    targets_from_permissions: set[str] = set()
    if isinstance(raw_targets_from_permission, str):
        token = str(raw_targets_from_permission).strip()
        if token:
            targets_from_permissions.add(token)
    elif isinstance(raw_targets_from_permission, list):
        targets_from_permissions = set(_list_or_empty(raw_targets_from_permission))

    normalized_rule_name = str(raw_rule.get("rule_name") or name).strip() or str(name)
    return {
        "name": normalized_rule_name,
        "description": str(raw_rule.get("description") or "").strip(),
        "edge_type": str(raw_rule.get("edge_type") or normalized_rule_name),
        "rule_variant_id": str(raw_rule.get("rule_variant_id") or "").strip(),
        "target_selector": selector,
        "multi_permission_type": raw_multi_permission_type,
        "requires_any": set(_list_or_empty(raw_rule.get("requires_any"))),
        "requires_all": set(_list_or_empty(raw_rule.get("requires_all"))),
        "requires_groups": requires_groups,
        "resource_scopes_possible": {
            canonical
            for token in normalized_token_list(raw_rule.get("resource_scopes_possible"))
            if str(token).strip()
            if (canonical := canonical_scope_type_for_bindings(token, "")) in _PREFERRED_RULE_RESOURCE_TOKENS
        },
        "attached_scope_types": {
            canonical
            for token in _list_or_empty(raw_rule.get("attached_scope_types"))
            if str(token).strip()
            if (canonical := canonical_scope_type_for_bindings(token, "")) in _PREFERRED_RULE_RESOURCE_TOKENS
        },
        "same_scope_required": bool(raw_rule.get("same_scope_required", True)),
        "same_project_required": bool(raw_rule.get("same_project_required", False)),
        "combine_across_bindings": bool(raw_rule.get("combine_across_bindings", True)),
        "combo_hop": combo_hop if raw_multi_permission_type == "complex" else {},
        "targets_from_permissions": targets_from_permissions,
    }


def expand_single_permission_rules(raw_rules: dict[str, dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    """Translate `permission` shorthand rules into matcher-ready `requires_any` rules."""
    expanded: dict[str, dict[str, Any]] = {}
    for name, raw_rule in (raw_rules or {}).items():
        if not isinstance(raw_rule, dict):
            continue
        permission = str(raw_rule.get("permission") or "").strip()
        if not permission:
            continue
        rule_copy = {key: value for key, value in raw_rule.items() if key != "permission"}
        if not rule_copy.get("requires_any"):
            rule_copy["requires_any"] = [permission]
        rule_copy.setdefault("combine_across_bindings", False)
        expanded[str(name)] = rule_copy
    return expanded


def expand_multi_permission_rules(raw_rules: dict[str, dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    """
    Expand optional multi-permission path variants into matcher-ready rules.

    Supported top-level shape:
      RULE_NAME:
        edge_type: ...
        description: ...
        match_paths:
          - id: path_a
            requires_all: [...]
            target_selector: {...}
          - id: path_b
            requires_all: [...]
            target_selector: {...}

    Each path becomes an internal rule variant while preserving the external
    rule name/edge semantics via `rule_name` and `edge_type`.
    """
    expanded: dict[str, dict[str, Any]] = {}
    for raw_name, raw_rule in (raw_rules or {}).items():
        base_name = str(raw_name or "").strip()
        if not base_name or not isinstance(raw_rule, dict):
            continue
        raw_paths = raw_rule.get("match_paths")
        if not isinstance(raw_paths, list) or not raw_paths:
            expanded[base_name] = dict(raw_rule)
            continue

        base_rule = dict(raw_rule)
        base_rule.pop("match_paths", None)
        base_edge_type = str(base_rule.get("edge_type") or base_name).strip() or base_name
        for index, raw_path in enumerate(raw_paths):
            if not isinstance(raw_path, dict):
                continue
            variant_id = str(raw_path.get("id") or f"path_{index + 1}").strip() or f"path_{index + 1}"
            variant_rule = dict(base_rule)
            variant_rule.update(
                {
                    key: value
                    for key, value in raw_path.items()
                    if key not in {"id"}
                }
            )
            variant_rule.setdefault("edge_type", base_edge_type)
            variant_rule.setdefault("rule_name", base_name)
            variant_rule["rule_variant_id"] = variant_id
            expanded[f"{base_name}__{variant_id}"] = variant_rule
    return expanded


def load_normalized_dangerous_rules_by_family() -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    """
    Load dangerous IAM rules and return canonicalized single/multi families.

    This is the shared normalization entrypoint used across OpenGraph stages
    to avoid duplicating load+expand+normalize logic in each stage module.
    """
    single_rules_raw, multi_rules_raw, _collapsed_rules = load_privilege_escalation_rules()
    single_rules = tuple(
        _normalized_rule(str(name), raw_rule)
        for name, raw_rule in expand_single_permission_rules(single_rules_raw).items()
        if isinstance(raw_rule, dict)
    )
    multi_rules = tuple(
        _normalized_rule(str(name), raw_rule)
        for name, raw_rule in expand_multi_permission_rules(multi_rules_raw).items()
        if isinstance(raw_rule, dict)
    )
    return single_rules, multi_rules


def _requirement_permissions(rule: dict[str, Any]) -> set[str]:
    group_permissions: set[str] = set()
    for raw_group in (rule.get("requires_groups", []) or []):
        if isinstance(raw_group, dict):
            group_permissions.update(set(raw_group.get("permissions") or ()))
        else:
            group_permissions.update(set(raw_group or ()))
    return (
        set(rule.get("requires_any", set()))
        | set(rule.get("requires_all", set()))
        | group_permissions
    )


def _permission_service(permission: str) -> str:
    token = str(permission or "").strip()
    if not token:
        return ""
    for prefix, service in _PERMISSION_SERVICE_PREFIX_MAP:
        if token.startswith(prefix):
            return service
    return ""


def _services_for_permissions(permissions: Iterable[str]) -> set[str]:
    return {
        service
        for permission in (permissions or ())
        if (service := _permission_service(str(permission or "")))
    }


def _permission_resource_types(permission: str) -> set[str]:
    token = str(permission or "").strip()
    if not token:
        return set()
    for prefix, resource_types in _PERMISSION_RESOURCE_TYPE_MAP:
        if token.startswith(prefix):
            return set(resource_types or ())
    return set()


def _resource_types_for_permissions(permissions: Iterable[str]) -> set[str]:
    return {
        resource_type
        for permission in (permissions or ())
        for resource_type in _permission_resource_types(str(permission or ""))
    }


def _match_rule_against_permissions(rule: dict[str, Any], permissions: set[str]) -> tuple[bool, set[str], dict[str, set[str]]]:
    seen_perms = set(permissions or ())
    requires_all = set(rule.get("requires_all", set()))
    if requires_all and (requires_all - seen_perms):
        return False, set(), {}

    requires_any = set(rule.get("requires_any", set()))
    any_match = requires_any.intersection(seen_perms)
    if requires_any and not any_match:
        return False, set(), {}

    requires_groups = list(rule.get("requires_groups", []) or [])
    matched: set[str] = set(requires_all)
    matched.update(any_match)
    matched_group_permissions: dict[str, set[str]] = {}
    if requires_groups:
        for index, raw_group in enumerate(requires_groups):
            if isinstance(raw_group, dict):
                group_permissions = set(raw_group.get("permissions") or ())
                group_id = str(raw_group.get("id") or f"group_{index + 1}").strip() or f"group_{index + 1}"
            else:
                group_permissions = set(raw_group or ())
                group_id = f"group_{index + 1}"
            if not group_permissions:
                continue
            overlap = group_permissions.intersection(seen_perms)
            if not overlap:
                return False, set(), {}
            matched.update(overlap)
            matched_group_permissions[group_id] = set(overlap)

    if not (requires_all or requires_any or requires_groups):
        return False, set(), {}
    return True, matched, matched_group_permissions


def _matches_for_group(rule: dict[str, Any], entries: list[BindingPlusScopeEntry]) -> list[dict[str, Any]]:
    # Matching order matters for advanced multi-permission rules:
    # 1) first see whether one resolved binding-composite entry already satisfies the rule
    # 2) only if no single entry works, search across multiple entries for combos
    if not entries:
        return []
    valid_resource_scopes_possible = set(rule.get("resource_scopes_possible", set()))
    valid_attached_scope_types = set(rule.get("attached_scope_types", set()))
    eligible_entries = [
        entry
        for entry in entries
        if (
            (not valid_resource_scopes_possible or entry.effective_scope_type in valid_resource_scopes_possible)
            and (not valid_attached_scope_types or entry.attached_scope_type in valid_attached_scope_types)
        )
    ]
    if not eligible_entries:
        return []

    rule_required_permissions = _requirement_permissions(rule)
    rule_required_services = _services_for_permissions(rule_required_permissions)
    rule_required_resource_types = _resource_types_for_permissions(rule_required_permissions)

    representative_by_grant: dict[str, BindingPlusScopeEntry] = {}
    perms_by_grant: dict[str, set[str]] = {}
    for entry in eligible_entries:
        condition_services = set(entry.condition_services)
        condition_resource_types = set(entry.condition_resource_types)
        if condition_services and rule_required_services and not condition_services.intersection(rule_required_services):
            filtered_permissions: set[str] = set()
        elif condition_resource_types and rule_required_resource_types and not condition_resource_types.intersection(rule_required_resource_types):
            filtered_permissions = set()
        else:
            if condition_services:
                filtered_permissions = {
                    permission
                    for permission in entry.permissions
                    if not (service := _permission_service(permission)) or service in condition_services
                }
            else:
                filtered_permissions = set(entry.permissions)
            if condition_resource_types:
                filtered_permissions = {
                    permission
                    for permission in filtered_permissions
                    if not (permission_resource_types := _permission_resource_types(permission))
                    or permission_resource_types.intersection(condition_resource_types)
                }
        grant_id = str(entry.binding_composite_id or "").strip()
        if not grant_id:
            continue
        representative_by_grant.setdefault(grant_id, entry)
        perms_by_grant.setdefault(grant_id, set()).update(filtered_permissions)
    if not perms_by_grant:
        return []

    normalized_group_defs: list[dict[str, Any]] = []
    for index, raw_group in enumerate(rule.get("requires_groups", []) or []):
        if isinstance(raw_group, dict):
            group_id = str(raw_group.get("id") or f"group_{index + 1}").strip() or f"group_{index + 1}"
            group_permissions = set(raw_group.get("permissions") or ())
            group_scope_types = set(raw_group.get("resource_scopes_possible") or ())
            group_attached_scope_types = set(raw_group.get("attached_scope_types") or ())
        else:
            group_id = f"group_{index + 1}"
            group_permissions = set(raw_group or ())
            group_scope_types = set()
            group_attached_scope_types = set()
        if not group_permissions:
            continue
        normalized_group_defs.append(
            {
                "id": group_id,
                "permissions": group_permissions,
                "resource_scopes_possible": group_scope_types,
                "attached_scope_types": group_attached_scope_types,
            }
        )

    def _entry_matches_group_constraints(entry: BindingPlusScopeEntry, group_def: dict[str, Any]) -> bool:
        valid_effective_scope_types = set(group_def.get("resource_scopes_possible") or ())
        if valid_effective_scope_types and entry.effective_scope_type not in valid_effective_scope_types:
            return False
        valid_attached_scope_types_local = set(group_def.get("attached_scope_types") or ())
        if valid_attached_scope_types_local and entry.attached_scope_type not in valid_attached_scope_types_local:
            return False
        return True

    def _group_contribution_for_grants(
        grant_ids: Iterable[str],
    ) -> tuple[bool, dict[str, list[str]], dict[str, list[str]]]:
        if not normalized_group_defs:
            return True, {}, {}
        normalized_grants = normalized_token_list(grant_ids)
        contributors_by_group: dict[str, list[str]] = {}
        permissions_by_group: dict[str, list[str]] = {}
        for group_def in normalized_group_defs:
            group_id = str(group_def.get("id") or "").strip()
            if not group_id:
                continue
            group_permissions = set(group_def.get("permissions") or ())
            if not group_permissions:
                continue
            group_contributors: set[str] = set()
            group_matched_permissions: set[str] = set()
            for grant_id in normalized_grants:
                representative = representative_by_grant.get(grant_id)
                if representative is None:
                    continue
                if not _entry_matches_group_constraints(representative, group_def):
                    continue
                overlaps = set(perms_by_grant.get(grant_id, set())).intersection(group_permissions)
                if not overlaps:
                    continue
                group_contributors.add(grant_id)
                group_matched_permissions.update(overlaps)
            if not group_contributors:
                return False, {}, {}
            contributors_by_group[group_id] = sorted(group_contributors)
            permissions_by_group[group_id] = sorted(group_matched_permissions)
        return True, contributors_by_group, permissions_by_group

    def _permission_map_for(grant_ids: Iterable[str], matched_permissions: set[str]) -> dict[str, list[str]]:
        mapped: dict[str, list[str]] = {}
        for grant_id in normalized_token_list(grant_ids):
            perms = set(perms_by_grant.get(grant_id, set()))
            contributing = sorted(perms.intersection(matched_permissions)) if matched_permissions else sorted(perms)
            if not contributing:
                contributing = sorted(perms)
            mapped[grant_id] = contributing
        return mapped

    single_matches: list[dict[str, Any]] = []
    # If one binding grant already satisfies the rule, emit from the standard
    # IAM binding node path (no COMBO_IAMBINDING node). This applies to
    # broad roles like roles/owner and roles/editor as well.
    single_match_emission_mode = "binding"
    for grant_id in sorted(perms_by_grant.keys()):
        perms = perms_by_grant.get(grant_id, set())
        ok, matched, matched_group_permissions = _match_rule_against_permissions(rule, perms)
        if not ok:
            continue
        group_ok, matched_group_contributors, group_permissions_from_entries = _group_contribution_for_grants([grant_id])
        if not group_ok:
            continue
        for group_id, permissions in matched_group_permissions.items():
            if not permissions:
                continue
            existing = set(group_permissions_from_entries.get(group_id, []))
            existing.update(permissions)
            group_permissions_from_entries[group_id] = sorted(existing)
        single_matches.append(
            {
                "contributors": [representative_by_grant[grant_id]],
                "matched_permissions": matched,
                "combine_across_bindings": False,
                "emission_mode": single_match_emission_mode,
                "contributor_permission_map": _permission_map_for([grant_id], matched),
                "matched_group_contributors": matched_group_contributors,
                "matched_group_permissions": group_permissions_from_entries,
            }
        )

    if single_matches or not bool(rule.get("combine_across_bindings", True)):
        return single_matches

    candidate_grant_ids = sorted(perms_by_grant.keys())
    if len(candidate_grant_ids) < 2:
        return []
    max_candidates = 12
    max_combos = 32
    candidate_grant_ids = candidate_grant_ids[:max_candidates]

    minimal_combo_sets: list[frozenset[str]] = []
    combo_matches: list[dict[str, Any]] = []

    for size in range(2, len(candidate_grant_ids) + 1):
        for grant_tuple in combinations(candidate_grant_ids, size):
            grant_set = frozenset(grant_tuple)
            if any(existing.issubset(grant_set) for existing in minimal_combo_sets):
                continue
            union_permissions: set[str] = set()
            for grant_id in grant_tuple:
                union_permissions.update(perms_by_grant.get(grant_id, set()))
            ok, matched, matched_group_permissions = _match_rule_against_permissions(rule, union_permissions)
            if not ok:
                continue
            group_ok, matched_group_contributors, group_permissions_from_entries = _group_contribution_for_grants(grant_tuple)
            if not group_ok:
                continue
            for group_id, permissions in matched_group_permissions.items():
                if not permissions:
                    continue
                existing = set(group_permissions_from_entries.get(group_id, []))
                existing.update(permissions)
                group_permissions_from_entries[group_id] = sorted(existing)

            keep_indices = [idx for idx, existing in enumerate(minimal_combo_sets) if not grant_set.issubset(existing)]
            minimal_combo_sets = [minimal_combo_sets[idx] for idx in keep_indices]
            combo_matches = [combo_matches[idx] for idx in keep_indices]
            minimal_combo_sets.append(grant_set)
            combo_contributors = [representative_by_grant[grant_id] for grant_id in sorted(grant_set)]
            combo_roles = {
                str(entry.role_name or "").strip()
                for entry in combo_contributors
                if str(entry.role_name or "").strip()
            }
            combo_matches.append(
                {
                    "contributors": combo_contributors,
                    "matched_permissions": matched,
                    "combine_across_bindings": True,
                    # If every contributing grant is still the same role, emit
                    # via normal IAM binding path instead of creating combo node.
                    "emission_mode": "binding" if len(combo_roles) <= 1 else "combo",
                    "contributor_permission_map": _permission_map_for(grant_set, matched),
                    "matched_group_contributors": matched_group_contributors,
                    "matched_group_permissions": group_permissions_from_entries,
                }
            )
            if len(combo_matches) >= max_combos:
                break
        if len(combo_matches) >= max_combos:
            break

    return combo_matches


def _edge_properties_from_entry(
    *,
    entry: BindingPlusScopeEntry,
    rule_name: str,
    rule_description: str = "",
    matched_permissions: Iterable[str],
    matched_roles: Iterable[str],
    evidence_bindings: Iterable[str],
    combine_across_bindings: bool,
    privilege_escalation: bool,
    contributing_binding_permission_map: dict[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    binding_origin = binding_origin_from_entry(entry)
    binding_family_id = binding_family_id_for_entry(entry)
    normalized_contribution_map = _normalize_binding_permission_map(contributing_binding_permission_map)
    contributing_permissions: set[str] = set()
    for permissions in normalized_contribution_map.values():
        contributing_permissions.update(permissions)

    matched_permissions_set = set(normalized_token_list(matched_permissions))
    if not contributing_permissions:
        contributing_permissions = set(matched_permissions_set)
    evidence_bindings_set = normalized_token_list(evidence_bindings)
    output = {
        "principal_member": entry.principal_id,
        "role_name": entry.role_name,
        "binding_origin": binding_origin,
        "binding_family_id": binding_family_id,
        "attached_scope_id": entry.attached_scope_name,
        "attached_scope_type": entry.attached_scope_type,
        "attached_scope_display": entry.attached_scope_display,
        "source_scope_id": entry.source_scope_name,
        "source_scope_type": entry.source_scope_type,
        "source_scope_display": entry.source_scope_display,
        "effective_scope_id": entry.effective_scope_name,
        "effective_scope_type": entry.effective_scope_type,
        "effective_scope_display": entry.effective_scope_display,
        "inherited": bool(entry.inherited),
        "conditional": bool(entry.condition_hash),
        "condition_expr_raw": entry.condition_expr_raw,
        "condition_hash": entry.condition_hash,
        "condition_summary": (entry.condition_expr_raw[:240] if entry.condition_expr_raw else entry.condition_option_summary),
        "condition_option_id": entry.condition_option_id,
        "condition_option_summary": entry.condition_option_summary,
        "condition_services": normalized_token_list(entry.condition_services),
        "condition_resource_types": normalized_token_list(entry.condition_resource_types),
        "condition_name_prefixes": normalized_token_list(entry.condition_name_prefixes),
        "condition_name_equals": normalized_token_list(entry.condition_name_equals),
        "rule_name": rule_name,
        "matched_permissions": normalized_token_list(matched_permissions_set),
        "matched_roles": normalized_token_list(matched_roles),
        "evidence_bindings": evidence_bindings_set,
        "contributing_permissions": normalized_token_list(contributing_permissions),
        "contributing_binding_permission_map": normalized_contribution_map,
        "combine_across_bindings": bool(combine_across_bindings),
        "privilege_escalation": bool(privilege_escalation),
        "project_id": entry.project_id,
        "source": entry.source,
        "expanded_from_convenience_member": entry.expanded_from_convenience_member,
    }
    description = str(rule_description or "").strip()
    if description:
        output["rule_description"] = description
    return output


def _collapsed_dangerous_role_edge_type(entry: BindingPlusScopeEntry, *, privilege_escalation: bool) -> tuple[str, str]:
    if not privilege_escalation:
        return "", ""
    rule = _COLLAPSED_DANGEROUS_ROLE_EDGE_RULES.get(str(entry.role_name or "").strip(), {})
    return (
        str(rule.get("edge_type") or "").strip(),
        str(rule.get("description") or "").strip(),
    )


# Keep owner/editor collapsed for baseline dangerous-role edges, but do not
# collapse multi-permission workflow edges. Otherwise owner/editor cannot
# visibly feed capability/multi-hop paths.
_NO_COLLAPSE_MULTI_PERMISSION_EDGE_TYPES: frozenset[str] = frozenset(
    {
        "CAN_CREATE_DEPLOY_INVOKE_CLOUDFUNCTION",
        "CAN_UPDATE_DEPLOY_INVOKE_CLOUDFUNCTION",
        "CAN_CREATE_CLOUDSCHEDULER_JOB",
        "CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
        "UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
        "CREATE_CLOUDSCHEDULER_JOB_AS_SA",
    }
)


def _merge_edge_properties(existing_props: dict[str, Any] | None, new_props: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(existing_props or {})
    for key, incoming in dict(new_props or {}).items():
        if incoming in (None, "", [], {}):
            continue
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(incoming, dict):
            if key == "contributing_binding_permission_map":
                merged_map = {
                    str(grant_id): normalized_token_list(permissions)
                    for grant_id, permissions in current.items()
                    if str(grant_id or "").strip()
                }
                for grant_id, permissions in incoming.items():
                    grant_key = str(grant_id or "").strip()
                    if not grant_key:
                        continue
                    merged_map[grant_key] = normalized_token_list(
                        list(merged_map.get(grant_key, [])) + list(permissions or [])
                    )
                merged[key] = merged_map
                continue
        if isinstance(current, list) and isinstance(incoming, list):
            merged[key] = normalized_token_list(list(current) + list(incoming))
            continue
        if isinstance(current, bool) and isinstance(incoming, bool):
            merged[key] = bool(current or incoming)
            continue
        if key not in merged or merged.get(key) in (None, "", [], {}):
            merged[key] = incoming
    return merged


def _matches_condition_resource_filters(entry: BindingPlusScopeEntry, *, resource_name: str, resource_type: str) -> bool:
    resource_token = str(resource_name or "").strip()
    if entry.condition_name_equals and resource_token not in entry.condition_name_equals:
        return False
    if entry.condition_name_prefixes and not any(resource_token.startswith(prefix) for prefix in entry.condition_name_prefixes):
        return False
    if entry.condition_services:
        service = str(_RESOURCE_TYPE_TO_SERVICE.get(str(resource_type or "").strip().lower(), "")).strip()
        if service and service not in entry.condition_services:
            return False
    if entry.condition_resource_types:
        full_types = set(_RESOURCE_TYPE_TO_FULL_TYPE.get(str(resource_type or "").strip().lower(), ()))
        if full_types and not full_types.intersection(entry.condition_resource_types):
            return False
    return True


def _scope_ancestors(scope_name: str, parent_by_name: dict[str, str]) -> set[str]:
    out: set[str] = set()
    cursor = str(scope_name or "").strip()
    while cursor:
        parent = str(parent_by_name.get(cursor) or "").strip()
        if not parent or parent in out:
            break
        out.add(parent)
        cursor = parent
    return out


def _scope_contains_resource(
    *,
    effective_scope_name: str,
    effective_scope_type: str,
    resource_name: str,
    resource_project_id: str,
    parent_by_name: dict[str, str],
    project_scope_by_project_id: dict[str, str],
    project_id_by_scope_name: dict[str, str],
    scope_ancestor_cache: dict[str, set[str]] | None = None,
) -> bool:
    def _ancestors(scope: str) -> set[str]:
        scope_token = str(scope or "").strip()
        if not scope_token:
            return set()
        if scope_ancestor_cache is None:
            return _scope_ancestors(scope_token, parent_by_name)
        cached = scope_ancestor_cache.get(scope_token)
        if cached is None:
            cached = _scope_ancestors(scope_token, parent_by_name)
            scope_ancestor_cache[scope_token] = cached
        return cached

    effective_scope = str(effective_scope_name or "").strip()
    if not effective_scope:
        return False
    resource_token = str(resource_name or "").strip()
    if resource_token and resource_token == effective_scope:
        return True

    effective_type = canonical_scope_type_for_bindings(effective_scope_type, effective_scope)
    if effective_type == "project":
        effective_project_id = str(project_id_by_scope_name.get(effective_scope) or "").strip() or _scope_leaf(effective_scope)
        return bool(resource_project_id and resource_project_id == effective_project_id)

    if effective_type not in {"org", "folder"}:
        return False

    if resource_token and effective_scope in _ancestors(resource_token):
        return True

    if resource_project_id:
        project_scope = str(project_scope_by_project_id.get(resource_project_id) or "").strip()
        if project_scope:
            if project_scope == effective_scope:
                return True
            if effective_scope in _ancestors(project_scope):
                return True
    return False


def _target_candidates_for_entry(
    *,
    entry: BindingPlusScopeEntry,
    selector: dict[str, Any],
    allow_resources: list[dict[str, str]],
    allow_resources_by_project: dict[str, list[dict[str, str]]],
    allow_resources_by_project_type: dict[str, dict[str, list[dict[str, str]]]],
    parent_by_name: dict[str, str],
    project_scope_by_project_id: dict[str, str],
    project_id_by_scope_name: dict[str, str],
    scope_ancestor_cache: dict[str, set[str]] | None = None,
) -> list[dict[str, str]]:
    mode = str(selector.get("mode") or "").strip().lower()
    if mode != "resource_types":
        return []
    if canonical_scope_type_for_bindings(entry.effective_scope_type, entry.effective_scope_name) != "project":
        return []

    selected_types = _selector_resource_types(selector)
    selected_statuses = {
        str(token or "").strip().upper()
        for token in (selector.get("status_in") or set())
        if str(token or "").strip()
    }
    effective_project_id = str(project_id_by_scope_name.get(entry.effective_scope_name) or "").strip() or _scope_leaf(entry.effective_scope_name)
    project_scoped_pool = bool(effective_project_id)
    if project_scoped_pool:
        if selected_types:
            scoped_type_map = allow_resources_by_project_type.get(effective_project_id, {})
            candidate_pool = [
                resource
                for token in selected_types
                for resource in scoped_type_map.get(token, [])
            ]
        else:
            candidate_pool = allow_resources_by_project.get(effective_project_id, [])
    else:
        candidate_pool = allow_resources

    out: list[dict[str, str]] = []
    for resource in candidate_pool:
        resource_name = str(resource.get("resource_name") or "").strip()
        resource_type = str(resource.get("resource_type") or "").strip().lower()
        if not resource_name or (selected_types and resource_type not in selected_types):
            continue
        if selected_statuses:
            status_token = str(resource.get("status") or resource.get("state") or "").strip().upper()
            if not status_token or status_token not in selected_statuses:
                continue
        if not project_scoped_pool and not _scope_contains_resource(
            effective_scope_name=entry.effective_scope_name,
            effective_scope_type=entry.effective_scope_type,
            resource_name=resource_name,
            resource_project_id=str(resource.get("project_id") or "").strip(),
            parent_by_name=parent_by_name,
            project_scope_by_project_id=project_scope_by_project_id,
            project_id_by_scope_name=project_id_by_scope_name,
            scope_ancestor_cache=scope_ancestor_cache,
        ):
            continue
        if not _matches_condition_resource_filters(entry, resource_name=resource_name, resource_type=resource_type):
            continue
        out.append(resource)

    return out


def _selector_resource_types(selector: dict[str, Any]) -> set[str]:
    raw_tokens = selector.get("resource_types") or set()
    return {
        canonical_scope_type_for_bindings(str(token or "").strip().lower(), "")
        for token in raw_tokens
        if str(token or "").strip()
    }


def _scope_target_matches_selector(
    *,
    scope_target: dict[str, str],
    selector: dict[str, Any],
) -> bool:
    mode = str(selector.get("mode") or "").strip().lower()
    if mode != "resource_types":
        return True
    selected_types = _selector_resource_types(selector)
    if not selected_types:
        return False
    target_name = str(scope_target.get("resource_name") or "").strip()
    target_type = canonical_scope_type_for_bindings(
        str(scope_target.get("resource_type") or "").strip().lower(),
        target_name,
    )
    return target_type in selected_types


def _effective_scope_target(
    *,
    entry: BindingPlusScopeEntry,
    scope_display_by_name: dict[str, str],
    scope_type_by_name: dict[str, str],
) -> dict[str, str]:
    return {
        "resource_name": entry.effective_scope_name,
        "resource_type": scope_type_by_name.get(entry.effective_scope_name, entry.effective_scope_type),
        "display_name": scope_display_by_name.get(entry.effective_scope_name, entry.effective_scope_display),
        "project_id": entry.project_id,
    }


def _emit_subject_binding(
    builder: OpenGraphBuilder,
    *,
    entry: BindingPlusScopeEntry,
    privilege_escalation: bool,
) -> None:
    principal_props = principal_member_properties(entry.principal_id)
    builder.add_node(entry.principal_id, principal_type(entry.principal_id), **principal_props)
    attached_scope_ref = binding_scope_token(
        entry.attached_scope_type,
        entry.attached_scope_name,
        project_id=entry.project_id,
    )
    role_display_name = _role_display_name(entry.role_name)
    binding_display = f"{role_display_name} @ {attached_scope_ref}"
    if entry.condition_hash:
        binding_display = f"{binding_display} [cond]"
    binding_origin = binding_origin_from_entry(entry)
    binding_family_id = binding_family_id_for_entry(entry)
    builder.add_node(
        entry.binding_composite_id,
        "GCPIamSimpleBinding",
        role_name=entry.role_name,
        binding_origin=binding_origin,
        binding_family_id=binding_family_id,
        **role_agent_metadata(entry.role_name),
        attached_scope_id=entry.attached_scope_name,
        attached_scope_type=entry.attached_scope_type,
        attached_scope_display=entry.attached_scope_display or attached_scope_ref,
        source_scope_id=entry.source_scope_name,
        source_scope_type=entry.source_scope_type,
        source_scope_display=entry.source_scope_display,
        conditional=bool(entry.condition_hash),
        condition_expr_raw=entry.condition_expr_raw,
        condition_hash=entry.condition_hash,
        condition_summary=(entry.condition_expr_raw[:240] if entry.condition_expr_raw else entry.condition_option_summary),
        inherited=bool(entry.inherited),
        source=entry.source,
        binding_display=binding_display,
        role_display_name=role_display_name,
        member=entry.principal_id,
        expanded_from_convenience_member=entry.expanded_from_convenience_member,
        privilege_escalation=bool(privilege_escalation),
    )
    builder.add_edge(
        entry.principal_id,
        entry.binding_composite_id,
        "HAS_IAM_BINDING",
        source=entry.source,
        role_name=entry.role_name,
        binding_origin=binding_origin,
        binding_family_id=binding_family_id,
        attached_scope_id=entry.attached_scope_name,
        attached_scope_type=entry.attached_scope_type,
        source_scope_id=entry.source_scope_name,
        source_scope_type=entry.source_scope_type,
        condition_hash=entry.condition_hash,
        conditional=bool(entry.condition_hash),
        inherited=bool(entry.inherited),
        expanded_from_convenience_member=entry.expanded_from_convenience_member or None,
        privilege_escalation=bool(privilege_escalation),
    )


def _combo_scope_info(contributors: Iterable[BindingPlusScopeEntry]) -> dict[str, Any]:
    contributor_list = [entry for entry in contributors if isinstance(entry, BindingPlusScopeEntry)]
    scope_ids = sorted(set(str(entry.effective_scope_name or "").strip() for entry in contributor_list if str(entry.effective_scope_name or "").strip()))
    scope_types = normalized_token_list(
        canonical_scope_type_for_bindings(str(entry.effective_scope_type or "").strip(), str(entry.effective_scope_name or "").strip())
        for entry in contributor_list
        if str(entry.effective_scope_name or "").strip()
    )
    scope_displays = normalized_token_list(
        str(entry.effective_scope_display or "").strip()
        for entry in contributor_list
        if str(entry.effective_scope_display or "").strip()
    )
    if len(scope_ids) == 1:
        effective_scope_id = scope_ids[0]
        effective_scope_type = scope_types[0] if scope_types else "resource"
        effective_scope_display = scope_displays[0] if scope_displays else _scope_leaf(effective_scope_id)
        effective_scope_project_id = ""
        if effective_scope_type == "project":
            effective_scope_project_id = next(
                (
                    str(entry.project_id or "").strip()
                    for entry in contributor_list
                    if str(entry.effective_scope_name or "").strip() == effective_scope_id
                    and str(entry.project_id or "").strip()
                ),
                "",
            )
        effective_scope_token = binding_scope_token(
            effective_scope_type,
            effective_scope_id,
            project_id=effective_scope_project_id,
        )
    else:
        effective_scope_id = "MULTI_SCOPE"
        effective_scope_type = "mixed"
        effective_scope_display = "Multiple Effective Scopes"
        effective_scope_token = "mixed"
    return {
        "effective_scope_id": effective_scope_id,
        "effective_scope_type": effective_scope_type,
        "effective_scope_display": effective_scope_display,
        "effective_scope_token": effective_scope_token,
        "effective_scope_ids": scope_ids,
        "effective_scope_types": scope_types,
        "effective_scope_displays": scope_displays,
    }


def _combo_binding_id(
    *,
    subject_id: str,
    rule_name: str,
    effective_scope_token: str,
    contributing_binding_ids: Iterable[str],
    condition_hashes: Iterable[str],
    source_scope_ids: Iterable[str],
) -> tuple[str, str]:
    payload = json.dumps(
        {
            "subject_id": str(subject_id or "").strip(),
            "rule_name": str(rule_name or "").strip(),
            "effective_scope_token": str(effective_scope_token or "").strip(),
            "contributing_binding_ids": normalized_token_list(contributing_binding_ids),
            "condition_hashes": normalized_token_list(condition_hashes),
            "source_scope_ids": normalized_token_list(source_scope_ids),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    combo_hash = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
    # Keep IDs compact/readable: subject identity is still included in the hash
    # payload above, so uniqueness/isolation are preserved without embedding the
    # full principal string in the visible node ID.
    node_id = f"combo_iambinding:{rule_name}@{effective_scope_token}#{combo_hash}"
    return node_id, combo_hash


def _emit_subject_combo_binding(
    builder: OpenGraphBuilder,
    *,
    subject_entry: BindingPlusScopeEntry,
    combo_binding_id: str,
    combo_hash: str,
    rule_name: str,
    rule_description: str = "",
    scope_info: dict[str, Any],
    contributing_binding_ids: Iterable[str],
    contributing_roles: Iterable[str],
    contributing_permissions: Iterable[str],
    contributing_binding_permission_map: dict[str, Iterable[str]] | None,
    condition_hashes: Iterable[str],
    condition_summaries: Iterable[str],
    source_scope_ids: Iterable[str],
    source_scope_types: Iterable[str],
    inherited: bool,
) -> None:
    principal_props = principal_member_properties(subject_entry.principal_id)
    builder.add_node(subject_entry.principal_id, principal_type(subject_entry.principal_id), **principal_props)
    normalized_contribution_map = _normalize_binding_permission_map(contributing_binding_permission_map)
    effective_scope_display = str(scope_info.get("effective_scope_display") or "").strip()
    effective_scope_id = str(scope_info.get("effective_scope_id") or "").strip()
    combo_binding_display = f"Combo {rule_name}"
    if effective_scope_display or effective_scope_id:
        combo_binding_display = f"{combo_binding_display} @ {effective_scope_display or effective_scope_id}"
    combo_binding_display = f"{combo_binding_display} #{combo_hash[:6]}"

    builder.add_node(
        combo_binding_id,
        "GCPIamMultiBinding",
        binding_kind="combo",
        binding_origin="combo",
        binding_family_id=combo_binding_id,
        role_name=f"combo:{rule_name}",
        **role_agent_metadata(f"combo:{rule_name}"),
        binding_display=combo_binding_display,
        combo_id=combo_hash,
        rule_name=rule_name,
        rule_description=str(rule_description or "").strip(),
        subject_id=subject_entry.principal_id,
        subject_display=subject_entry.principal_id,
        effective_scope_id=str(scope_info.get("effective_scope_id") or ""),
        effective_scope_type=str(scope_info.get("effective_scope_type") or ""),
        effective_scope_display=str(scope_info.get("effective_scope_display") or ""),
        effective_scope_ids=normalized_token_list(scope_info.get("effective_scope_ids") or []),
        effective_scope_types=normalized_token_list(scope_info.get("effective_scope_types") or []),
        effective_scope_displays=normalized_token_list(scope_info.get("effective_scope_displays") or []),
        contributing_binding_ids=normalized_token_list(contributing_binding_ids),
        contributing_roles=normalized_token_list(contributing_roles),
        contributing_permissions=normalized_token_list(contributing_permissions),
        contributing_binding_permission_map=normalized_contribution_map,
        conditional=bool(condition_hashes),
        condition_hashes=normalized_token_list(condition_hashes),
        condition_summaries=normalized_token_list(condition_summaries),
        inherited=bool(inherited),
        source_scope_ids=normalized_token_list(source_scope_ids),
        source_scope_types=normalized_token_list(source_scope_types),
        privilege_escalation=True,
    )
    builder.add_edge(
        subject_entry.principal_id,
        combo_binding_id,
        "HAS_COMBO_BINDING",
        rule_name=rule_name,
        binding_origin="combo",
        binding_family_id=combo_binding_id,
        rule_description=str(rule_description or "").strip(),
        combo_id=combo_hash,
        effective_scope_id=str(scope_info.get("effective_scope_id") or ""),
        effective_scope_type=str(scope_info.get("effective_scope_type") or ""),
        effective_scope_ids=normalized_token_list(scope_info.get("effective_scope_ids") or []),
        contributing_binding_ids=normalized_token_list(contributing_binding_ids),
        contributing_roles=normalized_token_list(contributing_roles),
        contributing_permissions=normalized_token_list(contributing_permissions),
        condition_hashes=normalized_token_list(condition_hashes),
        inherited=bool(inherited),
        privilege_escalation=True,
    )


def _emit_binding_target_edge(
    builder: OpenGraphBuilder,
    *,
    entry: BindingPlusScopeEntry,
    edge_type: str,
    target: dict[str, str],
    rule_name: str,
    rule_description: str = "",
    matched_permissions: Iterable[str],
    matched_roles: Iterable[str],
    evidence_bindings: Iterable[str],
    combine_across_bindings: bool,
    privilege_escalation: bool,
    contributing_binding_permission_map: dict[str, Iterable[str]] | None = None,
) -> tuple[bool, str, str, str]:
    target_name = str(target.get("resource_name") or "").strip()
    target_type = str(target.get("resource_type") or "").strip()
    if not target_name:
        return False, "", "", ""
    target_project_id = str(target.get("project_id") or "").strip() or entry.project_id
    target_status = str(target.get("status") or target.get("state") or "").strip().upper()
    target_label = resource_display_label(
        target_name,
        resource_type=target_type,
        project_id=target_project_id,
    )
    target_region = resource_location_token(target_name)
    target_id = resource_node_id(target_name)
    builder.add_node(
        target_id,
        gcp_resource_node_type(target_type),
        name=target_label,
        display_name=target_label,
        resource_name=target_name,
        region=target_region,
        project_id=target_project_id,
        resource_type=target_type,
        status=target_status or None,
    )
    collapsed_edge_type = ""
    collapsed_edge_description = ""
    if str(edge_type or "").strip() not in _NO_COLLAPSE_MULTI_PERMISSION_EDGE_TYPES:
        collapsed_edge_type, collapsed_edge_description = _collapsed_dangerous_role_edge_type(
            entry,
            privilege_escalation=privilege_escalation,
        )
    actual_edge_type = collapsed_edge_type or edge_type
    edge_rule_name = actual_edge_type if actual_edge_type != edge_type else rule_name
    edge_rule_description = (
        collapsed_edge_description
        if collapsed_edge_type and collapsed_edge_description
        else rule_description
    )
    props = _edge_properties_from_entry(
        entry=entry,
        rule_name=edge_rule_name,
        rule_description=edge_rule_description,
        matched_permissions=matched_permissions,
        matched_roles=matched_roles,
        evidence_bindings=evidence_bindings,
        combine_across_bindings=combine_across_bindings,
        privilege_escalation=privilege_escalation,
        contributing_binding_permission_map=contributing_binding_permission_map,
    )
    if actual_edge_type != edge_type:
        props["collapsed_role_edge"] = True
        props["collapsed_role_name"] = str(entry.role_name or "").strip()
        props["dangerous_rule_names"] = normalized_token_list([rule_name])
        props["dangerous_edge_types"] = normalized_token_list([edge_type])
        if str(rule_description or "").strip():
            props["dangerous_rule_descriptions"] = normalized_token_list([rule_description])
        if str(collapsed_edge_description or "").strip():
            props["collapsed_edge_description"] = str(collapsed_edge_description).strip()
    props["target_resource_id"] = target_name
    props["target_resource_type"] = target_type
    edge_key = (entry.binding_composite_id, actual_edge_type, target_id)
    existing_edge = builder.edge_map.get(edge_key)
    if existing_edge is not None:
        if actual_edge_type != edge_type:
            builder.edge_map[edge_key] = OpenGraphEdge(
                source_id=existing_edge.source_id,
                destination_id=existing_edge.destination_id,
                edge_type=existing_edge.edge_type,
                properties=_merge_edge_properties(existing_edge.properties, props),
            )
        return False, actual_edge_type, target_id, target_name
    builder.add_edge(entry.binding_composite_id, target_id, actual_edge_type, **props)
    return True, actual_edge_type, target_id, target_name


def _emit_combo_target_edge(
    builder: OpenGraphBuilder,
    *,
    combo_binding_id: str,
    source_node_id: str,
    subject_entry: BindingPlusScopeEntry,
    edge_type: str,
    target: dict[str, str],
    rule_name: str,
    rule_description: str = "",
    matched_permissions: Iterable[str],
    matched_roles: Iterable[str],
    evidence_bindings: Iterable[str],
    contributing_binding_permission_map: dict[str, Iterable[str]] | None,
    scope_info: dict[str, Any],
    condition_hashes: Iterable[str],
    condition_summaries: Iterable[str],
    source_scope_ids: Iterable[str],
    source_scope_types: Iterable[str],
    inherited: bool,
    binding_origin: str = "combo",
    match_mode: str = "combo",
) -> tuple[bool, str, str]:
    target_name = str(target.get("resource_name") or "").strip()
    target_type = str(target.get("resource_type") or "").strip()
    if not target_name:
        return False, "", ""
    target_project_id = str(target.get("project_id") or "").strip() or subject_entry.project_id
    target_status = str(target.get("status") or target.get("state") or "").strip().upper()
    target_label = resource_display_label(
        target_name,
        resource_type=target_type,
        project_id=target_project_id,
    )
    target_region = resource_location_token(target_name)
    target_id = resource_node_id(target_name)
    builder.add_node(
        target_id,
        gcp_resource_node_type(target_type),
        name=target_label,
        display_name=target_label,
        resource_name=target_name,
        region=target_region,
        project_id=target_project_id,
        resource_type=target_type,
        status=target_status or None,
    )
    normalized_contribution_map = _normalize_binding_permission_map(contributing_binding_permission_map)
    contributing_permissions: set[str] = set()
    for permissions in normalized_contribution_map.values():
        contributing_permissions.update(permissions)
    if not contributing_permissions:
        contributing_permissions.update(normalized_token_list(matched_permissions))
    props: dict[str, Any] = {
        "principal_member": subject_entry.principal_id,
        "rule_name": rule_name,
        "binding_origin": str(binding_origin or "combo"),
        "binding_family_id": combo_binding_id,
        "match_mode": str(match_mode or "combo"),
        "combine_across_bindings": True,
        "matched_permissions": normalized_token_list(matched_permissions),
        "matched_roles": normalized_token_list(matched_roles),
        "evidence_bindings": normalized_token_list(evidence_bindings),
        "contributing_permissions": normalized_token_list(contributing_permissions),
        "contributing_binding_permission_map": normalized_contribution_map,
        "effective_scope_id": str(scope_info.get("effective_scope_id") or ""),
        "effective_scope_type": str(scope_info.get("effective_scope_type") or ""),
        "effective_scope_display": str(scope_info.get("effective_scope_display") or ""),
        "effective_scope_ids": normalized_token_list(scope_info.get("effective_scope_ids") or []),
        "effective_scope_types": normalized_token_list(scope_info.get("effective_scope_types") or []),
        "source_scope_ids": normalized_token_list(source_scope_ids),
        "source_scope_types": normalized_token_list(source_scope_types),
        "conditional": bool(condition_hashes),
        "condition_hashes": normalized_token_list(condition_hashes),
        "condition_summaries": normalized_token_list(condition_summaries),
        "inherited": bool(inherited),
        "privilege_escalation": True,
        "project_id": subject_entry.project_id,
        "source": subject_entry.source,
        "target_resource_id": target_name,
        "target_resource_type": target_type,
    }
    if str(rule_description or "").strip():
        props["rule_description"] = str(rule_description).strip()
    edge_key = (source_node_id, edge_type, target_id)
    existed = edge_key in builder.edge_map
    builder.add_edge(source_node_id, target_id, edge_type, **props)
    return (not existed), target_id, target_name


def _emit_combo_capability_hop(
    builder: OpenGraphBuilder,
    *,
    combo_binding_id: str,
    rule_name: str,
    rule_description: str = "",
    scope_info: dict[str, Any],
    combo_hop: dict[str, Any],
) -> tuple[str, bool]:
    """
    Emit an optional intermediate capability node for combo rules:
      combo_binding -(edge_from_subject)-> capability_node -(edge_to_target)-> target
    """
    node_label = str(combo_hop.get("node_label") or rule_name).strip() or rule_name
    node_type = str(combo_hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability"
    scope_id = str(scope_info.get("effective_scope_id") or "").strip()
    scope_type = canonical_scope_type_for_bindings(
        str(scope_info.get("effective_scope_type") or "").strip(),
        scope_id,
    )
    scope_project_id = str(scope_info.get("effective_scope_project_id") or "").strip()
    scope_token = binding_scope_token(scope_type, scope_id, project_id=scope_project_id)
    hop_id = str(combo_hop.get("id") or "hop_1").strip() or "hop_1"
    capability_node_id = f"capability:{str(rule_name or '').strip()}@{scope_token}:{hop_id}"
    builder.add_node(
        capability_node_id,
        node_type,
        name=node_label,
        display_name=node_label,
        rule_name=rule_name,
        rule_description=str(rule_description or "").strip(),
        effective_scope_id=str(scope_info.get("effective_scope_id") or ""),
        effective_scope_type=str(scope_info.get("effective_scope_type") or ""),
        effective_scope_display=str(scope_info.get("effective_scope_display") or ""),
    )

    edge_type = str(combo_hop.get("edge_from_subject") or "").strip()
    if not edge_type:
        return capability_node_id, False
    edge_key = (combo_binding_id, edge_type, capability_node_id)
    existed = edge_key in builder.edge_map
    builder.add_edge(
        combo_binding_id,
        capability_node_id,
        edge_type,
        rule_name=rule_name,
        rule_description=str(rule_description or "").strip(),
        match_mode="combo_hop",
        privilege_escalation=True,
    )
    return capability_node_id, (not existed)


def _emit_iam_binding_edges_from_entries(
    context,
    *,
    entries: list[BindingPlusScopeEntry] | None = None,
    include_all: bool = False,
    dangerous_rules: Iterable[dict[str, Any]] | None = None,
    pass_name: str = "base",
) -> dict[str, Any]:
    """
    Turn resolved BindingPlusScopeEntry rows into graph edges.

    Important: this function does not parse raw IAM policy JSON. It assumes the
    caller already resolved:
    - attached/effective/source scope metadata
    - inheritance fan-out
    - conditional narrowing

    Example input:
      entries=[BindingPlusScopeEntry(...), BindingPlusScopeEntry(...)]
      dangerous_rules=[{"name":"CAN_READ_SECRET_DATA", ...}]

    Example output:
      {
        "dangerous_edges_emitted": 2,
        "bindings_emitted": 1,
        "aggregation": {"roles": {...}},
        "runtime": {"resolved_bindings_composite": [BindingPlusScopeEntry(...)]},
      }

    Single vs multi-permission behavior:
    - Single-permission pass: caller supplies single-permission rules. A binding
      contributes if it satisfies that rule's required permission pattern, and
      one or more dangerous edges are emitted from matching contributor bindings.
    - Multi-permission pass: caller supplies combo rules. The matcher builds
      grouped evidence (`matched_group_contributors`) and checks whether each
      required permission-group/role-group requirement is satisfied. If yes, it
      emits the configured combo output (binding-mode and/or combo capability
      node mode), including contributor evidence metadata.
    - This function emits all matching rules it sees for the current pass; it
      does not stop at the first match.
    """
    builder = context.builder
    hierarchy = context.hierarchy_data() or {}
    scope_resource_indexes = context.scope_resource_indexes()
    dangerous_rule_mode = str(pass_name or "base").strip().lower()
    rules = list(dangerous_rules or ())
    scope_type_by_name = hierarchy.get("scope_type_by_name") or {}
    scope_display_by_name = hierarchy.get("scope_display_by_name") or {}
    parent_by_name = hierarchy.get("parent_by_name") or {}
    entries = list(entries or [])
    rule_progress_label = (
        "single-permission rules checked"
        if dangerous_rule_mode == "base"
        else "multi-permission combo rules checked"
        if dangerous_rule_mode == "advanced"
        else "rules checked"
    )

    role_subject_state: dict[str, dict[str, dict[str, Any]]] = {}

    if not entries:
        return {
            "entries_total": 0,
            "rules_total": len(rules),
            "dangerous_rule_mode": dangerous_rule_mode,
            "dangerous_edges_emitted": 0,
            "combo_bindings_emitted": 0,
            "bindings_composite_with_dangerous_edges": 0,
            "bindings_with_dangerous_edges": 0,
            "aggregation": {
                "roles": {},
                "rule_matches": [],
                "combo_rule_matches": [],
                "flat_role_subject_destinations": [],
            },
            "runtime": {
                "resolved_bindings_composite": entries,
            },
        }

    def _print_rule_scan_progress(processed_rules: int, total_rules: int, matched_events: int) -> None:
        if total_rules <= 0:
            return
        message = (
            f"[*] Stage 2 {rule_progress_label}: {processed_rules}/{total_rules} "
            f"(matched_events={matched_events})"
        )
        if sys.stdout.isatty():
            print(f"\r{message}", end="", flush=True)
            if processed_rules == total_rules:
                print("")
            return
        print(message)

    dangerous_events = collect_rule_events(
        entries=entries,
        rules=rules,
        matches_for_group=_matches_for_group,
        normalize_binding_permission_map=_normalize_binding_permission_map,
        normalized_token_list=normalized_token_list,
        progress_callback=_print_rule_scan_progress,
    )
    owner_baseline_events = collect_owner_baseline_events(
        entries=entries,
        collapsed_dangerous_role_rules=_COLLAPSED_DANGEROUS_ROLE_EDGE_RULES,
    )
    all_events = list(dangerous_events) + list(owner_baseline_events)

    bindings_with_dangerous_edges: set[str] = {
        contributor.binding_composite_id
        for event in dangerous_events
        for contributor in (event.get("contributors") or [])
        if isinstance(contributor, BindingPlusScopeEntry)
    }
    owner_grants: set[str] = {
        entry.binding_composite_id for entry in entries if str(entry.role_name or "").strip() == "roles/owner"
    }
    all_binding_ids = {entry.binding_composite_id for entry in entries}
    bindings_to_emit = all_binding_ids if include_all else (bindings_with_dangerous_edges | owner_grants)

    emitted_bindings: set[str] = set()
    bindings_with_direct_dangerous_edges: set[str] = set()
    for entry in entries:
        if entry.binding_composite_id not in bindings_to_emit or entry.binding_composite_id in emitted_bindings:
            continue
        _emit_subject_binding(
            builder,
            entry=entry,
            privilege_escalation=entry.binding_composite_id in bindings_with_dangerous_edges,
        )
        subject_state = ensure_subject_state(role_subject_state, entry)
        binding_state = subject_state["bindings"].get(entry.binding_composite_id)
        if binding_state is not None:
            binding_state["privilege_escalation"] = bool(
                binding_state["privilege_escalation"] or (entry.binding_composite_id in bindings_with_dangerous_edges)
            )
        emitted_bindings.add(entry.binding_composite_id)

    rule_match_records: list[dict[str, Any]] = []
    combo_rule_match_records: list[dict[str, Any]] = []
    emitted_combo_bindings: set[str] = set()

    def _emit_events(events: list[dict[str, Any]]) -> int:
        emitted_dangerous = 0
        scope_ancestor_cache: dict[str, set[str]] = {}
        for event in events:
            contributors = list(event.get("contributors") or [])
            matched_permissions = set(event.get("matched_permissions") or ())
            matched_roles = set(event.get("matched_roles") or ())
            evidence_bindings = list(event.get("evidence_bindings") or ())
            edge_type = str(event.get("edge_type") or "POLICY_BINDINGS")
            rule_name = str(event.get("rule_name") or "")
            rule_description = str(event.get("rule_description") or "").strip()
            selector = event.get("target_selector") or {}
            combo_hop = event.get("combo_hop") or {}
            targets_from_permissions = set(event.get("targets_from_permissions") or ())
            privilege_escalation = bool(event.get("privilege_escalation", False))
            emission_mode = str(event.get("emission_mode") or "binding").strip().lower()
            if emission_mode not in {"binding", "combo"}:
                emission_mode = "binding"
            combine_across_bindings = bool(event.get("combine_across_bindings", False))
            contributor_permission_map = event.get("contributor_permission_map") or {}
            scope_only = bool(event.get("scope_only", False))
            multi_permission_type = str(event.get("multi_permission_type") or "simple").strip().lower() or "simple"
            if multi_permission_type not in {"simple", "complex"}:
                multi_permission_type = "simple"
            matched_group_contributors_raw = event.get("matched_group_contributors") or {}
            matched_group_contributors = {
                str(group_id): normalized_token_list(binding_ids)
                for group_id, binding_ids in (
                    matched_group_contributors_raw.items() if isinstance(matched_group_contributors_raw, dict) else ()
                )
            }
            requires_groups = list(event.get("requires_groups") or [])
            group_definitions_by_id: dict[str, dict[str, Any]] = {}
            for index, raw_group in enumerate(requires_groups):
                if not isinstance(raw_group, dict):
                    continue
                group_id = str(raw_group.get("id") or f"group_{index + 1}").strip() or f"group_{index + 1}"
                group_definitions_by_id[group_id] = raw_group
            contributors_by_binding_id = {
                str(contributor.binding_composite_id): contributor
                for contributor in contributors
                if isinstance(contributor, BindingPlusScopeEntry) and str(contributor.binding_composite_id).strip()
            }

            def _emit_and_record_for_contributor(
                *,
                contributor: BindingPlusScopeEntry,
                target: dict[str, str],
            ) -> int:
                added, emitted_edge_type, target_id, target_name = _emit_binding_target_edge(
                    builder,
                    entry=contributor,
                    edge_type=edge_type,
                    target=target,
                    rule_name=rule_name,
                    rule_description=rule_description,
                    matched_permissions=matched_permissions,
                    matched_roles=matched_roles,
                    evidence_bindings=evidence_bindings,
                    combine_across_bindings=combine_across_bindings,
                    privilege_escalation=privilege_escalation,
                    contributing_binding_permission_map={
                        contributor.binding_composite_id: list(contributor_permission_map.get(contributor.binding_composite_id) or [])
                    },
                )
                if not target_id:
                    return 0
                record_destination(
                    role_subject_state=role_subject_state,
                    entry=contributor,
                    edge_type=emitted_edge_type or edge_type,
                    rule_name=rule_name,
                    rule_description=rule_description,
                    matched_permissions=matched_permissions,
                    evidence_bindings=evidence_bindings,
                    target_id=target_id,
                    target_name=target_name,
                    target_type=str(target.get("resource_type") or "").strip(),
                    privilege_escalation=privilege_escalation,
                )
                resolved_edge_type = str(emitted_edge_type or edge_type).strip()
                if privilege_escalation or resolved_edge_type in {"ROLE_OWNER", "ROLE_EDITOR"}:
                    bindings_with_direct_dangerous_edges.add(contributor.binding_composite_id)
                return 1 if added else 0

            def _collect_targets_for_contributor(
                contributor: BindingPlusScopeEntry,
                *,
                include_fanout: bool,
                selector_override: dict[str, Any] | None = None,
            ) -> dict[tuple[str, str, str], dict[str, str]]:
                targets: dict[tuple[str, str, str], dict[str, str]] = {}
                active_selector = selector_override if isinstance(selector_override, dict) else selector

                scope_target = _effective_scope_target(
                    entry=contributor,
                    scope_display_by_name=scope_display_by_name,
                    scope_type_by_name=scope_type_by_name,
                )
                if _scope_target_matches_selector(scope_target=scope_target, selector=active_selector):
                    scope_key = (
                        str(scope_target.get("resource_name") or "").strip(),
                        str(scope_target.get("resource_type") or "").strip(),
                        str(scope_target.get("project_id") or "").strip(),
                    )
                    if scope_key[0]:
                        targets[scope_key] = scope_target

                if not include_fanout:
                    return targets

                for target in _target_candidates_for_entry(
                    entry=contributor,
                    selector=active_selector,
                    allow_resources=scope_resource_indexes.allow_resources,
                    allow_resources_by_project=scope_resource_indexes.allow_resources_by_project,
                    allow_resources_by_project_type=scope_resource_indexes.allow_resources_by_project_type,
                    parent_by_name=parent_by_name,
                    project_scope_by_project_id=scope_resource_indexes.project_scope_by_project_id,
                    project_id_by_scope_name=scope_resource_indexes.project_id_by_scope_name,
                    scope_ancestor_cache=scope_ancestor_cache,
                ):
                    target_key = (
                        str(target.get("resource_name") or "").strip(),
                        str(target.get("resource_type") or "").strip(),
                        str(target.get("project_id") or "").strip(),
                    )
                    if target_key[0]:
                        targets[target_key] = target
                return targets

            def _contributors_for_group_ids(group_ids: Iterable[str]) -> list[BindingPlusScopeEntry]:
                selected: dict[str, BindingPlusScopeEntry] = {}
                for group_id in normalized_token_list(group_ids):
                    for binding_id in matched_group_contributors.get(group_id, []):
                        contributor = contributors_by_binding_id.get(binding_id)
                        if contributor is None:
                            continue
                        selected[binding_id] = contributor
                return list(selected.values())

            def _selector_for_group(group_id: str) -> dict[str, Any]:
                group_def = group_definitions_by_id.get(str(group_id or "").strip()) or {}
                selector_value = group_def.get("target_selector") if isinstance(group_def, dict) else {}
                return selector_value if isinstance(selector_value, dict) else {}

            def _snapshot_graph_mutation_state() -> tuple[set[str], set[tuple[str, str, str]], set[str], int]:
                return (
                    set(builder.node_map.keys()),
                    set(builder.edge_map.keys()),
                    set(emitted_combo_bindings),
                    len(combo_rule_match_records),
                )

            def _rollback_graph_mutation_state(snapshot: tuple[set[str], set[tuple[str, str, str]], set[str], int]) -> None:
                node_ids_before, edge_keys_before, combo_ids_before, combo_match_len_before = snapshot
                for edge_key in [key for key in list(builder.edge_map.keys()) if key not in edge_keys_before]:
                    builder.edge_map.pop(edge_key, None)
                for node_id in [key for key in list(builder.node_map.keys()) if key not in node_ids_before]:
                    builder.node_map.pop(node_id, None)
                emitted_combo_bindings.clear()
                emitted_combo_bindings.update(combo_ids_before)
                del combo_rule_match_records[combo_match_len_before:]

            def _normalized_combo_hops(combo_hop_config: dict[str, Any]) -> list[dict[str, Any]]:
                raw_hops = combo_hop_config.get("hops")
                hops: list[dict[str, Any]] = []
                if isinstance(raw_hops, list):
                    for hop_index, raw_hop in enumerate(raw_hops):
                        if not isinstance(raw_hop, dict):
                            continue
                        edge_from_subject = str(raw_hop.get("edge_from_subject") or "").strip()
                        if not edge_from_subject:
                            continue
                        hop_mode = str(raw_hop.get("node_mode") or raw_hop.get("intermediate_node_mode") or "capability").strip().lower()
                        if hop_mode not in {"capability", "resource"}:
                            hop_mode = "capability"
                        from_groups = set(
                            normalized_token_list(
                                raw_hop.get("from_groups")
                                or raw_hop.get("from_group")
                                or raw_hop.get("intermediate_from_group")
                                or []
                            )
                        )
                        hops.append(
                            {
                                "id": str(raw_hop.get("id") or f"hop_{hop_index + 1}").strip() or f"hop_{hop_index + 1}",
                                "edge_from_subject": edge_from_subject,
                                "node_mode": hop_mode,
                                "from_groups": from_groups,
                                "selector": raw_hop.get("selector") if isinstance(raw_hop.get("selector"), dict) else {},
                                "node_type": str(raw_hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability",
                                "node_label": str(raw_hop.get("node_label") or rule_name).strip() or rule_name,
                            }
                        )
                if hops:
                    return hops
                edge_from_subject = str(combo_hop_config.get("edge_from_subject") or "").strip()
                if not edge_from_subject:
                    return []
                hop_mode = str(combo_hop_config.get("intermediate_node_mode") or "capability").strip().lower()
                if hop_mode not in {"capability", "resource"}:
                    hop_mode = "capability"
                return [
                    {
                        "id": "hop_1",
                        "edge_from_subject": edge_from_subject,
                        "node_mode": hop_mode,
                        "from_groups": set(
                            normalized_token_list(
                                combo_hop_config.get("from_groups")
                                or combo_hop_config.get("intermediate_from_group")
                                or []
                            )
                        ),
                        "selector": (
                            combo_hop_config.get("selector")
                            if isinstance(combo_hop_config.get("selector"), dict)
                            else {}
                        )
                        or (
                            combo_hop_config.get("intermediate_selector")
                            if isinstance(combo_hop_config.get("intermediate_selector"), dict)
                            else {}
                        ),
                        "node_type": str(combo_hop_config.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability",
                        "node_label": str(combo_hop_config.get("node_label") or rule_name).strip() or rule_name,
                    }
                ]

            contributors_in_scope: list[tuple[BindingPlusScopeEntry, set[str]]] = []
            if privilege_escalation and isinstance(combo_hop, dict) and combo_hop:
                for contributor in contributors:
                    if contributor.binding_composite_id not in bindings_to_emit:
                        continue
                    contributing_perms = set(
                        normalized_token_list(contributor_permission_map.get(contributor.binding_composite_id) or [])
                    )
                    if not contributing_perms:
                        contributing_perms = set(contributor.permissions)
                    if targets_from_permissions and not contributing_perms.intersection(targets_from_permissions):
                        continue
                    contributors_in_scope.append((contributor, contributing_perms))

            # Reduce combo-node churn:
            # if all contributors are the same role, emit via the simple-binding
            # path instead of creating a dedicated combo binding node.
            if emission_mode == "combo" and privilege_escalation:
                active_contributors = [contributor for contributor, _ in contributors_in_scope] or list(contributors)
                distinct_roles = {
                    str(contributor.role_name or "").strip()
                    for contributor in active_contributors
                    if isinstance(contributor, BindingPlusScopeEntry) and str(contributor.role_name or "").strip()
                }
                if len(distinct_roles) <= 1:
                    emission_mode = "binding"

            rule_match_records.append(
                {
                    "rule_name": rule_name,
                    "rule_description": rule_description,
                    "edge_type": edge_type,
                    "target_selector": selector,
                    "principal_ids": normalized_token_list(entry.principal_id for entry in contributors),
                    "effective_scope_ids": normalized_token_list(entry.effective_scope_name for entry in contributors),
                    "effective_scope_types": normalized_token_list(entry.effective_scope_type for entry in contributors),
                    "matched_permissions": normalized_token_list(matched_permissions),
                    "matched_roles": normalized_token_list(matched_roles),
                    "evidence_bindings": normalized_token_list(evidence_bindings),
                    "combine_across_bindings": combine_across_bindings,
                    "emission_mode": emission_mode,
                    "contributor_permission_map": contributor_permission_map,
                    "matched_group_contributors": matched_group_contributors,
                    "targets_from_permissions": normalized_token_list(targets_from_permissions),
                    "privilege_escalation": privilege_escalation,
                }
            )

            if emission_mode == "combo" and privilege_escalation:
                if not contributors:
                    continue
                mutation_snapshot = _snapshot_graph_mutation_state()
                combo_branch_emitted = 0
                pending_destination_records: list[dict[str, Any]] = []
                pending_combo_records: list[dict[str, Any]] = []

                subject_entry = sorted(
                    contributors,
                    key=lambda item: (str(item.binding_composite_id or ""), str(item.attached_scope_name or ""), str(item.role_name or "")),
                )[0]
                scope_info = _combo_scope_info(contributors)
                condition_hashes = normalized_token_list(
                    str(entry.condition_hash or "").strip()
                    for entry in contributors
                    if str(entry.condition_hash or "").strip()
                )
                condition_summaries = normalized_token_list(
                    str((entry.condition_expr_raw[:240] if entry.condition_expr_raw else entry.condition_option_summary) or "").strip()
                    for entry in contributors
                    if str((entry.condition_expr_raw[:240] if entry.condition_expr_raw else entry.condition_option_summary) or "").strip()
                )
                source_scope_ids = normalized_token_list(
                    str(entry.source_scope_name or "").strip()
                    for entry in contributors
                    if str(entry.source_scope_name or "").strip()
                )
                source_scope_types = normalized_token_list(
                    str(entry.source_scope_type or "").strip()
                    for entry in contributors
                    if str(entry.source_scope_type or "").strip()
                )
                inherited = any(bool(entry.inherited) for entry in contributors)
                combo_binding_id, combo_hash = _combo_binding_id(
                    subject_id=subject_entry.principal_id,
                    rule_name=rule_name,
                    effective_scope_token=str(scope_info.get("effective_scope_token") or "mixed"),
                    contributing_binding_ids=evidence_bindings,
                    condition_hashes=condition_hashes,
                    source_scope_ids=source_scope_ids,
                )
                if combo_binding_id not in emitted_combo_bindings:
                    _emit_subject_combo_binding(
                        builder,
                        subject_entry=subject_entry,
                        combo_binding_id=combo_binding_id,
                        combo_hash=combo_hash,
                        rule_name=rule_name,
                        rule_description=rule_description,
                        scope_info=scope_info,
                        contributing_binding_ids=evidence_bindings,
                        contributing_roles=matched_roles,
                        contributing_permissions=matched_permissions,
                        contributing_binding_permission_map=contributor_permission_map,
                        condition_hashes=condition_hashes,
                        condition_summaries=condition_summaries,
                        source_scope_ids=source_scope_ids,
                        source_scope_types=source_scope_types,
                        inherited=inherited,
                    )
                    emitted_combo_bindings.add(combo_binding_id)

                # Make combo contribution explicit: simple binding -> combo binding.
                for contributor in contributors:
                    builder.add_edge(
                        contributor.binding_composite_id,
                        combo_binding_id,
                        "CONTRIBUTES_TO_COMBO",
                        rule_name=rule_name,
                        rule_description=str(rule_description or "").strip(),
                        privilege_escalation=True,
                    )

                combo_hops = _normalized_combo_hops(combo_hop if isinstance(combo_hop, dict) else {})
                combo_target_edge_type = str(combo_hop.get("edge_to_target") or edge_type).strip() or edge_type
                target_group_ids = normalized_token_list(combo_hop.get("target_from_groups") or [])
                group_target_contributors = _contributors_for_group_ids(target_group_ids)
                target_source_contributors = (
                    group_target_contributors
                    or [contributor for contributor, _ in contributors_in_scope]
                    or list(contributors)
                )
                current_source_node_ids: set[str] = {combo_binding_id}
                complete_chain = True

                for hop_index, hop in enumerate(combo_hops):
                    hop_edge_type = str(hop.get("edge_from_subject") or edge_type).strip() or edge_type
                    hop_mode = str(hop.get("node_mode") or "capability").strip().lower()
                    if hop_mode not in {"capability", "resource"}:
                        hop_mode = "capability"
                    hop_from_groups = set(normalized_token_list(hop.get("from_groups") or []))
                    hop_group_contributors = _contributors_for_group_ids(hop_from_groups)
                    hop_contributors = hop_group_contributors or target_source_contributors or list(contributors)
                    default_hop_group_selector = {}
                    if len(hop_from_groups) == 1:
                        default_hop_group_selector = _selector_for_group(next(iter(hop_from_groups)))
                    hop_selector = (
                        hop.get("selector")
                        if isinstance(hop.get("selector"), dict)
                        else {}
                    ) or default_hop_group_selector or selector
                    next_source_node_ids: set[str] = set()
                    hop_edge_seen = False

                    if hop_mode == "capability":
                        for source_node_id in sorted(current_source_node_ids):
                            capability_hop_id = str(hop.get("id") or f"hop_{hop_index + 1}").strip() or f"hop_{hop_index + 1}"
                            scope_token = binding_scope_token(
                                str(scope_info.get("effective_scope_type") or "resource").strip(),
                                str(scope_info.get("effective_scope_id") or "").strip(),
                                project_id=str(scope_info.get("effective_scope_project_id") or "").strip(),
                            )
                            capability_node_id = f"capability:{str(rule_name or '').strip()}@{scope_token}:{capability_hop_id}"
                            node_label = str(hop.get("node_label") or rule_name).strip() or rule_name
                            node_type = str(hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability"
                            builder.add_node(
                                capability_node_id,
                                node_type,
                                name=node_label,
                                display_name=node_label,
                                rule_name=rule_name,
                                rule_description=str(rule_description or "").strip(),
                                effective_scope_id=str(scope_info.get("effective_scope_id") or ""),
                                effective_scope_type=str(scope_info.get("effective_scope_type") or ""),
                                effective_scope_display=str(scope_info.get("effective_scope_display") or ""),
                            )
                            edge_key = (source_node_id, hop_edge_type, capability_node_id)
                            existed = edge_key in builder.edge_map
                            builder.add_edge(
                                source_node_id,
                                capability_node_id,
                                hop_edge_type,
                                rule_name=rule_name,
                                rule_description=str(rule_description or "").strip(),
                                match_mode="combo_hop",
                                privilege_escalation=True,
                            )
                            hop_edge_seen = True
                            if not existed:
                                combo_branch_emitted += 1
                            next_source_node_ids.add(capability_node_id)
                    else:
                        hop_targets: dict[tuple[str, str, str], dict[str, str]] = {}
                        for contributor in hop_contributors:
                            hop_targets.update(
                                _collect_targets_for_contributor(
                                    contributor,
                                    include_fanout=True,
                                    selector_override=hop_selector,
                                )
                            )
                        if not hop_targets:
                            complete_chain = False
                            current_source_node_ids = set()
                            break
                        for source_node_id in sorted(current_source_node_ids):
                            for hop_target in hop_targets.values():
                                hop_target_name = str(hop_target.get("resource_name") or "").strip()
                                if source_node_id == resource_node_id(hop_target_name):
                                    continue
                                added, hop_target_id, _ = _emit_combo_target_edge(
                                    builder,
                                    combo_binding_id=combo_binding_id,
                                    source_node_id=source_node_id,
                                    subject_entry=subject_entry,
                                    edge_type=hop_edge_type,
                                    target=hop_target,
                                    rule_name=rule_name,
                                    rule_description=rule_description,
                                    matched_permissions=matched_permissions,
                                    matched_roles=matched_roles,
                                    evidence_bindings=evidence_bindings,
                                    contributing_binding_permission_map=contributor_permission_map,
                                    scope_info=scope_info,
                                    condition_hashes=condition_hashes,
                                    condition_summaries=condition_summaries,
                                    source_scope_ids=source_scope_ids,
                                    source_scope_types=source_scope_types,
                                    inherited=inherited,
                                    match_mode=f"combo_hop_resource_step_{hop_index + 1}",
                                )
                                if hop_target_id:
                                    hop_edge_seen = True
                                    next_source_node_ids.add(hop_target_id)
                                if added:
                                    combo_branch_emitted += 1
                    if not hop_edge_seen or not next_source_node_ids:
                        complete_chain = False
                        current_source_node_ids = set()
                        break
                    current_source_node_ids = set(next_source_node_ids)

                if not complete_chain or not current_source_node_ids or not target_source_contributors:
                    _rollback_graph_mutation_state(mutation_snapshot)
                    continue

                default_target_group_selector = {}
                if len(target_group_ids) == 1:
                    default_target_group_selector = _selector_for_group(target_group_ids[0])
                hop_target_selector = (
                    combo_hop.get("target_selector")
                    if isinstance(combo_hop.get("target_selector"), dict)
                    else {}
                ) or default_target_group_selector or selector

                combo_targets: dict[tuple[str, str, str], dict[str, str]] = {}
                for contributor in target_source_contributors:
                    combo_targets.update(
                        _collect_targets_for_contributor(
                            contributor,
                            include_fanout=True,
                            selector_override=hop_target_selector,
                        )
                    )

                final_target_edge_seen = False
                for source_node_id in sorted(current_source_node_ids):
                    for target in combo_targets.values():
                        target_name_for_self_check = str(target.get("resource_name") or "").strip()
                        if source_node_id == resource_node_id(target_name_for_self_check):
                            continue
                        added, target_id, target_name = _emit_combo_target_edge(
                            builder,
                            combo_binding_id=combo_binding_id,
                            source_node_id=source_node_id,
                            subject_entry=subject_entry,
                            edge_type=combo_target_edge_type,
                            target=target,
                            rule_name=rule_name,
                            rule_description=rule_description,
                            matched_permissions=matched_permissions,
                            matched_roles=matched_roles,
                            evidence_bindings=evidence_bindings,
                            contributing_binding_permission_map=contributor_permission_map,
                            scope_info=scope_info,
                            condition_hashes=condition_hashes,
                            condition_summaries=condition_summaries,
                            source_scope_ids=source_scope_ids,
                            source_scope_types=source_scope_types,
                            inherited=inherited,
                        )
                        if not target_id:
                            continue
                        final_target_edge_seen = True
                        if not added:
                            continue
                        for contributor in contributors:
                            pending_destination_records.append(
                                {
                                    "entry": contributor,
                                    "edge_type": combo_target_edge_type,
                                    "rule_name": rule_name,
                                    "rule_description": rule_description,
                                    "matched_permissions": matched_permissions,
                                    "evidence_bindings": evidence_bindings,
                                    "target_id": target_id,
                                    "target_name": target_name,
                                    "target_type": str(target.get("resource_type") or "").strip(),
                                    "privilege_escalation": True,
                                }
                            )
                        pending_combo_records.append(
                            {
                                "combo_binding_id": combo_binding_id,
                                "combo_id": combo_hash,
                                "rule_name": rule_name,
                                "rule_description": rule_description,
                                "edge_type": combo_target_edge_type,
                                "principal_id": subject_entry.principal_id,
                                "principal_member": subject_entry.principal_id,
                                "effective_scope_id": str(scope_info.get("effective_scope_id") or ""),
                                "effective_scope_type": str(scope_info.get("effective_scope_type") or ""),
                                "effective_scope_ids": normalized_token_list(scope_info.get("effective_scope_ids")),
                                "target_node_id": target_id,
                                "target_resource_id": target_name,
                                "target_resource_type": str(target.get("resource_type") or "").strip(),
                                "contributing_binding_ids": normalized_token_list(evidence_bindings),
                                "contributing_roles": normalized_token_list(matched_roles),
                                "contributing_permissions": normalized_token_list(matched_permissions),
                                "contributing_binding_permission_map": contributor_permission_map,
                                "condition_hashes": condition_hashes,
                                "inherited": inherited,
                            }
                        )
                        combo_branch_emitted += 1

                if not final_target_edge_seen:
                    _rollback_graph_mutation_state(mutation_snapshot)
                    continue

                for pending_record in pending_destination_records:
                    record_destination(role_subject_state=role_subject_state, **pending_record)
                combo_rule_match_records.extend(pending_combo_records)
                emitted_dangerous += combo_branch_emitted
                continue

            if emission_mode == "binding" and privilege_escalation and isinstance(combo_hop, dict) and combo_hop:
                normalized_binding_hops = _normalized_combo_hops(combo_hop)
                primary_hop = normalized_binding_hops[0] if normalized_binding_hops else {}
                hop_mode = str(primary_hop.get("node_mode") or combo_hop.get("intermediate_node_mode") or "capability").strip().lower()
                if hop_mode not in {"capability", "resource"}:
                    hop_mode = "capability"
                target_group_ids = normalized_token_list(combo_hop.get("target_from_groups") or [])
                default_target_group_selector = {}
                if len(target_group_ids) == 1:
                    default_target_group_selector = _selector_for_group(target_group_ids[0])
                resolved_target_selector = (
                    combo_hop.get("target_selector")
                    if isinstance(combo_hop.get("target_selector"), dict)
                    else {}
                ) or default_target_group_selector or selector
                for contributor, _ in contributors_in_scope:
                    mutation_snapshot = _snapshot_graph_mutation_state()
                    binding_branch_emitted = 0
                    final_target_edge_seen = False
                    pending_destination_records: list[dict[str, Any]] = []

                    scope_info = _combo_scope_info([contributor])
                    condition_hashes = normalized_token_list(
                        [str(contributor.condition_hash or "").strip()] if str(contributor.condition_hash or "").strip() else []
                    )
                    condition_summaries = normalized_token_list(
                        [
                            str(
                                (contributor.condition_expr_raw[:240] if contributor.condition_expr_raw else contributor.condition_option_summary)
                                or ""
                            ).strip()
                        ]
                    )
                    source_scope_ids = normalized_token_list([str(contributor.source_scope_name or "").strip()])
                    source_scope_types = normalized_token_list([str(contributor.source_scope_type or "").strip()])

                    combo_target_edge_type = str(combo_hop.get("edge_to_target") or edge_type).strip() or edge_type
                    contribution_map_for_binding = {
                        contributor.binding_composite_id: list(contributor_permission_map.get(contributor.binding_composite_id) or [])
                    }

                    if hop_mode == "resource":
                        intermediate_selector = (
                            primary_hop.get("selector")
                            if isinstance(primary_hop.get("selector"), dict)
                            else (
                                combo_hop.get("intermediate_selector")
                                if isinstance(combo_hop.get("intermediate_selector"), dict)
                                else {}
                            )
                        )
                        hop_target_selector = (
                            combo_hop.get("target_selector")
                            if isinstance(combo_hop.get("target_selector"), dict)
                            else {}
                        ) or resolved_target_selector
                        intermediate_targets = _collect_targets_for_contributor(
                            contributor,
                            include_fanout=not scope_only,
                            selector_override=intermediate_selector,
                        )
                        if not intermediate_targets:
                            _rollback_graph_mutation_state(mutation_snapshot)
                            continue
                        edge_from_type = str(combo_hop.get("edge_from_subject") or edge_type).strip() or edge_type
                        intermediate_source_ids: set[str] = set()
                        for intermediate_target in intermediate_targets.values():
                            added, intermediate_target_id, _ = _emit_combo_target_edge(
                                builder,
                                combo_binding_id=contributor.binding_composite_id,
                                source_node_id=contributor.binding_composite_id,
                                subject_entry=contributor,
                                edge_type=edge_from_type,
                                target=intermediate_target,
                                rule_name=rule_name,
                                rule_description=rule_description,
                                matched_permissions=matched_permissions,
                                matched_roles=matched_roles,
                                evidence_bindings=[contributor.binding_composite_id],
                                contributing_binding_permission_map=contribution_map_for_binding,
                                scope_info=scope_info,
                                condition_hashes=condition_hashes,
                                condition_summaries=condition_summaries,
                                source_scope_ids=source_scope_ids,
                                source_scope_types=source_scope_types,
                                inherited=bool(contributor.inherited),
                                binding_origin=binding_origin_from_entry(contributor),
                                match_mode="binding_combo_hop_resource_intermediate",
                            )
                            if intermediate_target_id:
                                intermediate_source_ids.add(intermediate_target_id)
                                bindings_with_direct_dangerous_edges.add(contributor.binding_composite_id)
                            if added:
                                binding_branch_emitted += 1
                        if not intermediate_source_ids:
                            _rollback_graph_mutation_state(mutation_snapshot)
                            continue
                        grant_targets = _collect_targets_for_contributor(
                            contributor,
                            include_fanout=not scope_only,
                            selector_override=hop_target_selector,
                        )
                        for source_node_id in sorted(intermediate_source_ids):
                            for target in grant_targets.values():
                                if source_node_id == resource_node_id(str(target.get("resource_name") or "").strip()):
                                    continue
                                added, target_id, target_name = _emit_combo_target_edge(
                                    builder,
                                    combo_binding_id=contributor.binding_composite_id,
                                    source_node_id=source_node_id,
                                    subject_entry=contributor,
                                    edge_type=combo_target_edge_type,
                                    target=target,
                                    rule_name=rule_name,
                                    rule_description=rule_description,
                                    matched_permissions=matched_permissions,
                                    matched_roles=matched_roles,
                                    evidence_bindings=[contributor.binding_composite_id],
                                    contributing_binding_permission_map=contribution_map_for_binding,
                                    scope_info=scope_info,
                                    condition_hashes=condition_hashes,
                                    condition_summaries=condition_summaries,
                                    source_scope_ids=source_scope_ids,
                                    source_scope_types=source_scope_types,
                                    inherited=bool(contributor.inherited),
                                    binding_origin=binding_origin_from_entry(contributor),
                                    match_mode="binding_combo_hop_resource_target",
                                )
                                if not target_id:
                                    continue
                                final_target_edge_seen = True
                                if not added:
                                    continue
                                pending_destination_records.append(
                                    {
                                        "entry": contributor,
                                        "edge_type": combo_target_edge_type,
                                        "rule_name": rule_name,
                                        "rule_description": rule_description,
                                        "matched_permissions": matched_permissions,
                                        "evidence_bindings": [contributor.binding_composite_id],
                                        "target_id": target_id,
                                        "target_name": target_name,
                                        "target_type": str(target.get("resource_type") or "").strip(),
                                        "privilege_escalation": True,
                                    }
                                )
                                binding_branch_emitted += 1
                        if not final_target_edge_seen:
                            _rollback_graph_mutation_state(mutation_snapshot)
                            continue
                        for pending_record in pending_destination_records:
                            record_destination(role_subject_state=role_subject_state, **pending_record)
                        emitted_dangerous += binding_branch_emitted
                        continue

                    combo_target_source_id, hop_added = _emit_combo_capability_hop(
                        builder,
                        combo_binding_id=contributor.binding_composite_id,
                        rule_name=rule_name,
                        rule_description=rule_description,
                        scope_info=scope_info,
                        combo_hop={
                            **combo_hop,
                            "edge_from_subject": str(primary_hop.get("edge_from_subject") or combo_hop.get("edge_from_subject") or ""),
                            "id": str(primary_hop.get("id") or combo_hop.get("id") or "hop_1"),
                            "node_type": str(primary_hop.get("node_type") or combo_hop.get("node_type") or "GCPIamCapability"),
                            "node_label": str(primary_hop.get("node_label") or combo_hop.get("node_label") or rule_name),
                        },
                    )
                    if hop_added:
                        binding_branch_emitted += 1
                    hop_edge_type = str(primary_hop.get("edge_from_subject") or combo_hop.get("edge_from_subject") or "").strip()
                    hop_edge_present = bool(
                        hop_edge_type
                        and (contributor.binding_composite_id, hop_edge_type, combo_target_source_id) in builder.edge_map
                    )
                    if not hop_edge_present:
                        _rollback_graph_mutation_state(mutation_snapshot)
                        continue

                    grant_targets = _collect_targets_for_contributor(
                        contributor,
                        include_fanout=not scope_only,
                        selector_override=resolved_target_selector,
                    )

                    for target in grant_targets.values():
                        added, target_id, target_name = _emit_combo_target_edge(
                            builder,
                            combo_binding_id=contributor.binding_composite_id,
                            source_node_id=combo_target_source_id,
                            subject_entry=contributor,
                            edge_type=combo_target_edge_type,
                            target=target,
                            rule_name=rule_name,
                            rule_description=rule_description,
                            matched_permissions=matched_permissions,
                            matched_roles=matched_roles,
                            evidence_bindings=[contributor.binding_composite_id],
                            contributing_binding_permission_map=contribution_map_for_binding,
                            scope_info=scope_info,
                            condition_hashes=condition_hashes,
                            condition_summaries=condition_summaries,
                            source_scope_ids=source_scope_ids,
                            source_scope_types=source_scope_types,
                            inherited=bool(contributor.inherited),
                            binding_origin=binding_origin_from_entry(contributor),
                            match_mode="binding_combo_hop",
                        )
                        if not target_id:
                            continue
                        final_target_edge_seen = True
                        bindings_with_direct_dangerous_edges.add(contributor.binding_composite_id)
                        if not added:
                            continue
                        pending_destination_records.append(
                            {
                                "entry": contributor,
                                "edge_type": combo_target_edge_type,
                                "rule_name": rule_name,
                                "rule_description": rule_description,
                                "matched_permissions": matched_permissions,
                                "evidence_bindings": [contributor.binding_composite_id],
                                "target_id": target_id,
                                "target_name": target_name,
                                "target_type": str(target.get("resource_type") or "").strip(),
                                "privilege_escalation": True,
                            }
                        )
                        binding_branch_emitted += 1
                    if not final_target_edge_seen:
                        _rollback_graph_mutation_state(mutation_snapshot)
                        continue
                    for pending_record in pending_destination_records:
                        record_destination(role_subject_state=role_subject_state, **pending_record)
                    emitted_dangerous += binding_branch_emitted
                continue

            for contributor in contributors:
                if contributor.binding_composite_id not in bindings_to_emit:
                    continue

                contributor_targets = _collect_targets_for_contributor(
                    contributor,
                    include_fanout=not scope_only,
                )
                for target in contributor_targets.values():
                    emitted_count = _emit_and_record_for_contributor(
                        contributor=contributor,
                        target=target,
                    )
                    if not emitted_count:
                        continue
                    if privilege_escalation:
                        emitted_dangerous += emitted_count
        return emitted_dangerous

    dangerous_edges_emitted = _emit_events(all_events)
    combo_bindings_emitted = len(emitted_combo_bindings)

    # Only mark simple binding nodes as privilege-escalation when they emit
    # direct dangerous edges from that binding node (not merely combo contribution).
    for binding_id in emitted_bindings:
        node = builder.node_map.get(binding_id)
        if node is None:
            continue
        props = dict(node.properties)
        props["privilege_escalation"] = binding_id in bindings_with_direct_dangerous_edges
        builder.node_map[binding_id] = OpenGraphNode(node_id=node.node_id, node_type=node.node_type, properties=props)
    for role_state in role_subject_state.values():
        if not isinstance(role_state, dict):
            continue
        for subject_state in role_state.values():
            if not isinstance(subject_state, dict):
                continue
            binding_states = subject_state.get("bindings")
            if not isinstance(binding_states, dict):
                continue
            for binding_id, binding_state in binding_states.items():
                if not isinstance(binding_state, dict):
                    continue
                binding_state["privilege_escalation"] = binding_id in bindings_with_direct_dangerous_edges

    serialized_roles, flat_role_subject_destinations, conditional_paths = serialize_role_subject_state(
        role_subject_state=role_subject_state,
        normalized_token_list=normalized_token_list,
    )

    return {
        "entries_total": len(entries),
        "rules_total": len(rules),
        "dangerous_rule_mode": dangerous_rule_mode,
        "dangerous_edges_emitted": dangerous_edges_emitted,
        "combo_bindings_emitted": combo_bindings_emitted,
        "bindings_composite_total": len(all_binding_ids),
        "bindings_composite_emitted": len(bindings_to_emit),
        "bindings_composite_with_dangerous_edges": len(bindings_with_direct_dangerous_edges),
        "bindings_total": len(all_binding_ids),
        "bindings_emitted": len(bindings_to_emit),
        "bindings_with_dangerous_edges": len(bindings_with_direct_dangerous_edges),
        "aggregation": {
            "roles": serialized_roles,
            "rule_matches": rule_match_records,
            "combo_rule_matches": combo_rule_match_records,
            "flat_role_subject_destinations": flat_role_subject_destinations,
            "conditional_paths": conditional_paths,
        },
        "runtime": {
            "resolved_bindings_composite": entries,
        },
    }
