from __future__ import annotations

"""
Shared IAM-binding -> OpenGraph edge emitters and the dangerous-rule matcher.

This module turns already-resolved IAM binding rows (BindingPlusScopeEntry) into the
principal -> binding -> resource topology of the graph, and matches them against the
privilege-escalation rule set to emit dangerous-path edges.

Authorization-fidelity routing (the reason the graph is shaped this way):
every grant is modeled as principal -[HAS_IAM_BINDING]-> binding-node -[edge]-> resource,
NOT as a direct principal -> resource edge. The intermediate binding node carries
role@scope, condition, and inheritance metadata so the exact authorization that proves a
path is never lost when edges are de-duplicated or collapsed.

Single vs combo pairing:
- "single"/simple bindings: one BindingPlusScopeEntry already satisfies a rule. Emitted
  via _emit_subject_binding (GCPIamSimpleBinding) + _emit_binding_target_edge.
- "combo"/multi bindings: several distinct-role bindings TOGETHER satisfy a rule. A
  GCPIamMultiBinding node is created (_emit_subject_combo_binding) and wired to the
  principal via -[HAS_COMBO_BINDING]->. Combo target edges hang off the combo node via
  _emit_combo_target_edge / capability hops. If all contributors share one role the combo
  collapses back to the simple-binding path to avoid redundant combo nodes.

Edge kind contract (do not rename without updating wiki + export):
  HAS_IAM_BINDING          principal -> GCPIamSimpleBinding
  HAS_COMBO_BINDING principal -> GCPIamMultiBinding (combo)
  HasImpliedPermissions principal -> implied GCPIamSimpleBinding (inferred stage)
  ROLE_OWNER/ROLE_EDITOR  collapsed dangerous edges for owner/editor roles
  per-rule edge kinds come from the `edge_type` (single) or `edge` (combo) field in
  og_defined_edges.json
"""

import hashlib
import json
import sys
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Iterable

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
    _merge_opengraph_edge_properties,
    canonical_target_node_ref,
    cap_update_node_id,
    gcp_resource_node_type,
    principal_member_properties,
    principal_type,
    role_agent_metadata,
    resource_display_label,
    resource_leaf_name,
    resource_location_token,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.normalization import (
    canonical_scope_type,
    normalized_token_list,
)


from gcpwn.modules.opengraph.utilities.helpers.graph.iam_permission_taxonomy import (
    _RESOURCE_TYPE_TO_SERVICE,
    _RESOURCE_TYPE_TO_FULL_TYPE,
    _PREFERRED_RULE_RESOURCE_TOKENS,
    _permission_service,
    _services_for_permissions,
    _permission_resource_types,
    _resource_types_for_permissions,
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
_, _, _collapsed_rules_raw = load_privilege_escalation_rules()
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


@dataclass(frozen=True, slots=True)
class BindingPlusScopeEntry:
    """
    One fully-resolved (principal, role, scope, condition) IAM grant -- the emitter's unit.

    This is the contract between the policy-resolution stage and the edge emitters: by the
    time an entry exists, attached/effective/source scopes, inheritance fan-out, convenience-
    member expansion, and condition narrowing are all already computed. binding_composite_id
    is the stable id used for the GCPIamSimpleBinding node and as the de-dup key throughout
    the matcher. Frozen so entries are hashable and safely shared across the base (single-
    permission) and advanced (combo) passes without copying.
    """

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
    resource_sa_by_name: dict[str, list[str]]
    project_oslogin_by_project_id: dict[str, bool | None] = field(default_factory=dict)


def canonical_scope_type_for_bindings(scope_type: str | None, scope_name: str | None) -> str:
    return canonical_scope_type(scope_type, scope_name)

def _scope_leaf(scope_name: str) -> str:
    # Identical to core_helpers.resource_leaf_name (both delegate to extract_path_tail).
    return resource_leaf_name(scope_name)


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
    # A binding node can be the destination of HAS_IAM_BINDING edges from SEVERAL
    # members (one per principal in a multi-member binding). Map each binding node
    # to the SET of all its members, not just the last-seen one, so the dedup guard
    # proves the direct edge for every member (otherwise INFERRED_<X> duplicates of
    # the other members' direct <X> edges are not suppressed).
    grant_owner: dict[str, set[str]] = {}
    for edge in builder.edge_map.values():
        if edge.edge_type in {"HAS_IAM_BINDING", "HAS_COMBO_BINDING"}:
            grant_owner.setdefault(str(edge.destination_id or "").strip(), set()).add(
                str(edge.source_id or "").strip()
            )

    proven: set[tuple[str, str, str]] = set()
    for edge in builder.edge_map.values():
        source_id = str(edge.source_id or "").strip()
        owners = grant_owner.get(source_id)
        if not owners:
            continue
        destination_id = str(edge.destination_id or "").strip()
        edge_type = str(edge.edge_type or "").strip()
        wrapped_types: list[str] = []
        if edge_type in {"ROLE_OWNER", "ROLE_EDITOR"}:
            properties = dict(edge.properties or {})
            wrapped_types = normalized_token_list(
                list(properties.get("dangerous_edge_types") or [])
                + list(properties.get("dangerous_rule_names") or [])
            )
        for owner in owners:
            if not owner:
                continue
            proven.add((owner, edge_type, destination_id))
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
                # Carry the resource-metadata gate through normalization. Without this,
                # require_node_sa / require_workload_pool / require_active_execution
                # (desugared into resource_metadata_require) are silently dropped here,
                # making those gates no-ops in the matching path.
                metadata_require = raw_selector_value.get("resource_metadata_require")
                if isinstance(metadata_require, dict) and metadata_require:
                    selector["resource_metadata_require"] = dict(metadata_require)
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
            group_id = str(raw_group.get("id") or default_group_id).strip() or default_group_id
            permissions = set(_list_or_empty(raw_group.get("permissions")))
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
                hop_mode = str(raw_hop.get("node_mode") or "capability").strip().lower() or "capability"
                if hop_mode not in {"capability", "resource"}:
                    hop_mode = "capability"
                raw_from_group = raw_hop.get("from_groups")
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
                        "selector": _selector_or_empty(raw_hop.get("selector")),
                        "node_type": str(raw_hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability",
                        "node_label": str(raw_hop.get("node_label") or str(name)).strip() or str(name),
                    }
                )

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
                "requires_resource_exists": bool(raw_combo_hop.get("requires_resource_exists", False)),
                "capability_resource_type": str(raw_combo_hop.get("capability_resource_type") or "").strip(),
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
        "example_command": str(raw_rule.get("example_command") or "").strip(),
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
        "via": str(raw_rule.get("via") or "").strip().lower(),
        "include_all_only": bool(raw_rule.get("include_all_only", False)),
        "target_requires_permissions": list(_list_or_empty(raw_rule.get("target_requires_permissions"))),
        # Confidence tier (VALIDATED / CONFIRMED / PROPOSED); surfaced onto emitted edges so
        # attack-path output can rank live-validated edges above theoretical ones.
        "status": str(raw_rule.get("status") or "").strip().upper(),
        # Extra precondition a source principal must satisfy before the edge is real
        # (e.g. source_must_hold_custom_role for UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS).
        "prerequisite_binding": str(raw_rule.get("prerequisite_binding") or "").strip(),
    }


def expand_single_permission_rules(raw_rules: dict[str, dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    """Translate `permissions` (or legacy `permission`) shorthand into matcher-ready `requires_any` rules.

    New form:  permissions: [str, ...]   # always a list
               on: "resource-type"       # optional; expands to target_selector
    Legacy:    permission: str           # still accepted for backward compat
    """
    expanded: dict[str, dict[str, Any]] = {}
    for name, raw_rule in (raw_rules or {}).items():
        if not isinstance(raw_rule, dict):
            continue
        # Resolve permission list: new `permissions` list, or legacy singular `permission`.
        perms = raw_rule.get("permissions")
        if isinstance(perms, list):
            perms = [str(p).strip() for p in perms if str(p).strip()]
        elif isinstance(perms, str) and perms.strip():
            perms = [perms.strip()]
        else:
            legacy = str(raw_rule.get("permission") or "").strip()
            perms = [legacy] if legacy else []
        if not perms:
            continue
        rule_copy = {
            key: value for key, value in raw_rule.items()
            if key not in {"permission", "permissions", "on",
                           "resource_scopes_possible", "require_node_sa",
                           "require_workload_pool", "require_active_execution"}
        }
        # `on: "type"` shorthand -> target_selector (skip if target_selector already present)
        on_type = str(raw_rule.get("on") or "").strip()
        if on_type and not rule_copy.get("target_selector"):
            selector: dict[str, Any] = {"mode": "resource_types", "resource_types": [on_type]}
            # require_node_sa: true → only match clusters with a non-default SA on at least
            # one node pool (populated during index build from gke_node_pools rows).
            if raw_rule.get("require_node_sa"):
                selector["resource_metadata_require"] = {"has_node_sa": True}
            # require_workload_pool: true → only match clusters with Workload Identity enabled
            # (workload_pool column non-empty in gke_clusters, propagated as has_workload_pool).
            elif raw_rule.get("require_workload_pool"):
                selector["resource_metadata_require"] = {"has_workload_pool": True}
            # require_active_execution: true → only match jobs that have at least one
            # currently running execution (running_count > 0 from cloudrun_job_executions).
            elif raw_rule.get("require_active_execution"):
                selector["resource_metadata_require"] = {"has_active_execution": True}
            rule_copy["target_selector"] = selector
        if not rule_copy.get("requires_any"):
            rule_copy["requires_any"] = perms
        rule_copy.setdefault("combine_across_bindings", False)
        expanded[str(name)] = rule_copy
    return expanded


def _desugar_multi_permission_rule(name: str, raw_rule: dict[str, Any]) -> dict[str, Any]:
    """Compact authoring form for the common 2-hop shape: N `requires` permission groups
    + one `act_as` pivot -> capability/resource node -> service-account target.

    New (preferred) form:
        NAME:
          requires:
            - { permissions: [...], on: computeinstance, status_in: [RUNNING] }
          act_as: { permissions: [iam.serviceAccounts.actAs], on: service-account }
          edge: CAN_...          # edge emitted from binding -> intermediate node
          via: resource          # capability|resource (default: capability)
          # rule key IS the final edge name; no target_edge needed

    Legacy form (still accepted):
        NAME:
          subject_groups: [...]  # same as requires
          act_as: {...}
          subject_edge: CAN_...  # same as edge
          subject_node: resource # same as via
          target_edge: NAME      # redundant with rule key; ignored

    Expands into `requires_groups` + `combo_hop` that the engine consumes.
    Passes through untouched when verbose keys (requires_groups/combo_hop/match_paths)
    are already present.
    """
    if not isinstance(raw_rule, dict):
        return raw_rule
    # Accept both new ("requires") and legacy ("subject_groups") keys.
    requires = raw_rule.get("requires") or raw_rule.get("subject_groups")
    act_as = raw_rule.get("act_as")
    if not isinstance(requires, list) or not isinstance(act_as, dict):
        return raw_rule
    if raw_rule.get("requires_groups") or raw_rule.get("combo_hop") or raw_rule.get("match_paths"):
        return raw_rule  # already in verbose form — leave it to the full parser

    def _group(group_id: str, spec: dict[str, Any]) -> dict[str, Any]:
        # Accept both "on" (new) and "target" (legacy) for the resource type.
        target = str(spec.get("on") or spec.get("target") or "").strip()
        group: dict[str, Any] = {
            "id": group_id,
            "permissions": list(spec.get("permissions") or []),
            "resource_scopes_possible": ["project"] + ([target] if target and target != "project" else []),
        }
        if target:
            selector: dict[str, Any] = {"mode": "resource_types", "resource_types": [target]}
            status_in = spec.get("status_in")
            if isinstance(status_in, list) and status_in:
                selector["status_in"] = list(status_in)
            metadata_require = spec.get("resource_metadata_require")
            if isinstance(metadata_require, dict) and metadata_require:
                selector["resource_metadata_require"] = dict(metadata_require)
            group["target_selector"] = selector
        return group

    subject_ids: list[str] = []
    groups: list[dict[str, Any]] = []
    for index, spec in enumerate(requires):
        spec = spec if isinstance(spec, dict) else {}
        group_id = str(spec.get("id") or f"subject_{index + 1}").strip() or f"subject_{index + 1}"
        subject_ids.append(group_id)
        groups.append(_group(group_id, spec))
    act_as_id = str(act_as.get("id") or "act_as").strip() or "act_as"
    groups.append(_group(act_as_id, act_as))

    # Accept "via" (new) or "subject_node" (legacy); default: capability.
    node_mode = str(raw_rule.get("via") or raw_rule.get("subject_node") or "capability").strip().lower() or "capability"
    if node_mode not in {"capability", "resource"}:
        node_mode = "capability"
    # Final edge: always the rule key (target_edge is redundant in the new form).
    edge_to = str(raw_rule.get("edge_type") or "").strip() or str(name or "").strip()
    # Subject edge: "edge" (new) or "subject_edge" (legacy).
    subject_edge = str(raw_rule.get("edge") or raw_rule.get("subject_edge") or "").strip()

    expanded = {
        key: value
        for key, value in raw_rule.items()
        if key not in {"requires", "subject_groups", "act_as",
                       "edge", "subject_edge", "via", "subject_node", "target_edge"}
    }
    # description and example_command are passed through from raw_rule above
    expanded.setdefault("multi_permission_type", "complex")
    expanded.setdefault("same_scope_required", False)
    # GCP enforces iam.disableCrossProjectServiceAccountUsage by default: Cloud Run/Build/
    # Scheduler all reject SAs from a different project unless the org policy is explicitly
    # disabled.  Default True (same-project paths only); --cross-project overrides at runtime.
    expanded.setdefault("same_project_required", True)
    expanded["requires_groups"] = groups
    # For resource-mode hops the intermediate node IS the real GCP resource (the compute
    # instance, Cloud Run service, etc.), so we must filter candidates with the subject
    # group's target_selector (which carries resource_types and status_in).  Without this
    # the hop inherits an empty selector that falls back to the scope (project) target,
    # causing rules like RESET_COMPUTE_STARTUP_SA to fire on STOPPED instances.
    hop_selector: dict[str, Any] = {}
    if node_mode == "resource":
        for sid in subject_ids:
            subject_group_def = next((g for g in groups if g.get("id") == sid), {})
            candidate = dict(subject_group_def.get("target_selector") or {})
            if candidate:
                hop_selector = candidate
                break
    expanded["combo_hop"] = {
        "edge_to_target": edge_to,
        "target_from_groups": [act_as_id],
        "requires_resource_exists": bool(raw_rule.get("requires_resource_exists", False)),
        "capability_resource_type": str(raw_rule.get("capability_resource_type") or "").strip(),
        "hops": [
            {
                "edge_from_subject": subject_edge,
                "node_mode": node_mode,
                "from_groups": list(subject_ids),
                "selector": hop_selector,
            }
        ],
    }
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
        raw_rule = _desugar_multi_permission_rule(base_name, raw_rule)
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


def load_normalized_dangerous_rules_by_family(
    categories: "frozenset[str] | None" = None,
) -> "tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]":
    """Load dangerous IAM rules and return canonicalized single/multi families.

    Args:
        categories: forwarded to ``load_privilege_escalation_rules``; ``None``
            or empty frozenset loads every category.  Pass the value from
            ``OpenGraphBuildOptions.edge_categories`` (converting an empty
            frozenset to ``None``) to respect per-run category filtering.
    """
    single_rules_raw, multi_rules_raw, _collapsed_rules = load_privilege_escalation_rules(
        categories=categories or None
    )
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
            if not group_permissions.issubset(seen_perms):
                return False, set(), {}
            overlap = group_permissions.intersection(seen_perms)
            matched.update(overlap)
            matched_group_permissions[group_id] = set(overlap)

    if not (requires_all or requires_any or requires_groups):
        return False, set(), {}
    return True, matched, matched_group_permissions


_SA_EMAIL_SUFFIX = ".iam.gserviceaccount.com"


def _sa_home_project_from_email(email: str) -> str:
    """Home project encoded in a service-account email, or "" if the domain doesn't name it.

    ``x@PROJECT.iam.gserviceaccount.com`` -> PROJECT; ``PROJECT@appspot.gserviceaccount.com``
    -> PROJECT. Compute-default (``developer.gserviceaccount.com``) emails carry a project
    NUMBER, not id, so they return "" and the caller falls back to the recorded project id."""
    token = str(email or "").strip()
    token = token.split("/serviceAccounts/")[-1]
    if token.startswith("serviceAccount:"):
        token = token.split(":", 1)[1]
    if "@" not in token:
        return ""
    local, _, domain = token.partition("@")
    if domain.endswith(_SA_EMAIL_SUFFIX):
        return domain[: -len(_SA_EMAIL_SUFFIX)]
    if domain == "appspot.gserviceaccount.com" and local:
        return local
    return ""


def _sa_home_project(entry: "BindingPlusScopeEntry") -> str:
    """Home project of a service-account-scoped binding contributor.

    The SA email encodes its true home project, which is the project whose
    ``iam.disableCrossProjectServiceAccountUsage`` policy governs cross-project impersonation
    -- authoritative even when the binding row's ``project_id`` was stamped from the
    actor/resource side. Falls back to the recorded ``project_id`` for SA domains that don't
    name the project."""
    return _sa_home_project_from_email(str(getattr(entry, "attached_scope_name", "") or "")) or str(
        getattr(entry, "project_id", "") or ""
    ).strip()


def _condition_summary(entry: "BindingPlusScopeEntry") -> str:
    """Readable condition summary for an entry: the (truncated) raw CEL expression, or the
    stored option summary when there is no raw expression."""
    raw = entry.condition_expr_raw
    return raw[:240] if raw else entry.condition_option_summary


def _combo_evidence(entries: list["BindingPlusScopeEntry"]) -> dict[str, Any]:
    """Shared evidence bundle for combo/combo-hop emission: scope info, condition hashes +
    summaries, source scopes, and inherited flag over a set of contributing entries.
    normalized_token_list drops empty tokens + dedups, so a single-entry call matches the
    old per-site literals exactly."""
    return {
        "scope_info": _combo_scope_info(entries),
        "condition_hashes": normalized_token_list(str(e.condition_hash or "").strip() for e in entries),
        "condition_summaries": normalized_token_list(str(_condition_summary(e) or "").strip() for e in entries),
        "source_scope_ids": normalized_token_list(str(e.source_scope_name or "").strip() for e in entries),
        "source_scope_types": normalized_token_list(str(e.source_scope_type or "").strip() for e in entries),
        "inherited": any(bool(e.inherited) for e in entries),
    }


def _matches_for_group(rule: dict[str, Any], entries: list[BindingPlusScopeEntry]) -> list[dict[str, Any]]:
    """
    Match one dangerous rule against a group of co-scoped binding entries.

    Returns a list of match records (each with contributors, matched permissions, an
    emission_mode of "binding" or "combo", and per-grant permission attribution). The
    ordering is deliberate and load-bearing:
    1) try whether a SINGLE binding grant already satisfies the rule -> emit via the
       simple-binding path (emission_mode="binding"), including broad roles like
       owner/editor;
    2) only if no single grant works AND the rule allows combine_across_bindings, search
       small unions of grants for a combo match -> emission_mode="combo" (or "binding"
       when every contributor is still the same role).
    Combo search is bounded (max_candidates/max_combos) and keeps only minimal grant sets
    to avoid combinatorial blowup. IAM-condition narrowing is applied per grant before
    matching so conditionally-scoped permissions don't over-grant.
    """
    # Matching order matters for advanced multi-permission rules:
    # 1) first see whether one resolved binding-composite entry already satisfies the rule
    # 2) only if no single entry works, search across multiple entries for combos
    if not entries:
        return []

    # Precondition gate: UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS (prerequisite_binding ==
    # "source_must_hold_custom_role") is only a real escalation for a principal who already
    # holds a binding to a CUSTOM role (project/org-scoped role def) -- updating a custom role
    # only benefits its holders. Without this, the edge fires for anyone with iam.roles.update
    # (a false-positive privesc). Custom roles carry a project/organization-scoped role name;
    # predefined roles are "roles/<name>".
    if str(rule.get("prerequisite_binding") or "").strip() == "source_must_hold_custom_role":
        if not any(
            str(getattr(entry, "role_name", "") or "").strip().startswith(("projects/", "organizations/"))
            for entry in entries
        ):
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

    # For complex combo rules (actAs-pivot PE edges), primitive owner/editor grants
    # are represented exclusively by the collapsed ROLE_OWNER/ROLE_EDITOR edges, and
    # the event layer already drops any combo whose contributors are all owner/editor.
    # Keeping them in the matcher is not just redundant: a single owner grant satisfies
    # the whole rule, so the single-match path returns it and short-circuits the combo
    # search — suppressing legitimate non-owner combos (e.g. batch.jobsEditor +
    # serviceAccountUser). This is the --expand-inherited false-negative: org-level
    # roles/owner inherited into a project-scope group silently drops every CREATE_*_AS_SA
    # combo for that principal. Exclude owner/editor so the real combos are always
    # discovered, in both default and --expand-inherited builds.
    if isinstance(rule.get("combo_hop"), dict) and rule.get("combo_hop"):
        primitive_grant_ids = [
            grant_id
            for grant_id, representative in representative_by_grant.items()
            if str(representative.role_name or "").strip().split("_withcond_")[0]
            in {"roles/owner", "roles/editor"}
        ]
        for grant_id in primitive_grant_ids:
            perms_by_grant.pop(grant_id, None)
            representative_by_grant.pop(grant_id, None)
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
    # Restrict to grants that contribute at least one required permission so that
    # principals with many grants don't push relevant grants past max_candidates.
    if rule_required_permissions:
        candidate_grant_ids = [
            gid for gid in candidate_grant_ids
            if perms_by_grant.get(gid, set()).intersection(rule_required_permissions)
        ]
        if len(candidate_grant_ids) < 2:
            return []

    # --- actAs target fan-out (CREATE_*_AS_SA / act_as-pivot combos) --------------
    # A combo_hop rule pairs a CREATE-side capability with impersonation of N target SAs.
    # Choosing a target SA is independent (a fan-out), NOT a subset to combine, so folding
    # the N actAs grants into the generic subset search makes it look exponential and the
    # max_candidates=12 cut then drops targets past 12 (edges that are never generated).
    # Here the CREATE side keeps the bounded combination search while EVERY eligible target
    # grant is attached to the match, so one combo node fans out to all N targets (linear).
    # Generic combos with no act_as pivot fall through to the unchanged search below.
    combo_hop_cfg = rule.get("combo_hop") if isinstance(rule.get("combo_hop"), dict) else {}
    target_group_ids = (
        set(normalized_token_list(combo_hop_cfg.get("target_from_groups") or []))
        if combo_hop_cfg
        else set()
    )
    target_group_defs = [g for g in normalized_group_defs if str(g.get("id")) in target_group_ids]
    non_target_group_defs = [g for g in normalized_group_defs if str(g.get("id")) not in target_group_ids]

    def _grant_contributes_to_any(grant_id: str, group_defs: list[dict[str, Any]]) -> bool:
        representative = representative_by_grant.get(grant_id)
        if representative is None:
            return False
        grant_perms = perms_by_grant.get(grant_id, set())
        for group_def in group_defs:
            if _entry_matches_group_constraints(representative, group_def) and grant_perms.intersection(
                set(group_def.get("permissions") or ())
            ):
                return True
        return False

    if target_group_ids and target_group_defs and non_target_group_defs:
        target_grant_ids = sorted(
            gid for gid in candidate_grant_ids if _grant_contributes_to_any(gid, target_group_defs)
        )
        create_candidate_ids = sorted(
            gid for gid in candidate_grant_ids if _grant_contributes_to_any(gid, non_target_group_defs)
        )
        if not target_grant_ids or not create_candidate_ids:
            return []
        # Bound ONLY the create side; every target grant is kept so the combo fans out to all
        # N impersonation targets without truncation.
        create_candidate_ids = create_candidate_ids[:max_candidates]
        target_union_permissions: set[str] = set()
        for gid in target_grant_ids:
            target_union_permissions.update(perms_by_grant.get(gid, set()))

        minimal_create_sets: list[frozenset[str]] = []
        combo_matches = []
        for size in range(1, len(create_candidate_ids) + 1):
            for grant_tuple in combinations(create_candidate_ids, size):
                create_set = frozenset(grant_tuple)
                if any(existing.issubset(create_set) for existing in minimal_create_sets):
                    continue
                union_permissions = set(target_union_permissions)
                for grant_id in grant_tuple:
                    union_permissions.update(perms_by_grant.get(grant_id, set()))
                ok, matched, matched_group_permissions = _match_rule_against_permissions(rule, union_permissions)
                if not ok:
                    continue
                full_grant_ids = list(grant_tuple) + target_grant_ids
                group_ok, matched_group_contributors, group_permissions_from_entries = _group_contribution_for_grants(full_grant_ids)
                if not group_ok:
                    continue
                for group_id, permissions in matched_group_permissions.items():
                    if not permissions:
                        continue
                    existing = set(group_permissions_from_entries.get(group_id, []))
                    existing.update(permissions)
                    group_permissions_from_entries[group_id] = sorted(existing)
                keep_indices = [idx for idx, existing in enumerate(minimal_create_sets) if not create_set.issubset(existing)]
                minimal_create_sets = [minimal_create_sets[idx] for idx in keep_indices]
                combo_matches = [combo_matches[idx] for idx in keep_indices]
                minimal_create_sets.append(create_set)
                combo_contributors = [
                    representative_by_grant[grant_id] for grant_id in sorted(set(full_grant_ids))
                ]
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
                        "emission_mode": "binding" if len(combo_roles) <= 1 else "combo",
                        "contributor_permission_map": _permission_map_for(set(full_grant_ids), matched),
                        "matched_group_contributors": matched_group_contributors,
                        "matched_group_permissions": group_permissions_from_entries,
                    }
                )
                if len(combo_matches) >= max_combos:
                    break
            if len(combo_matches) >= max_combos:
                break
        return combo_matches

    candidate_grant_ids = candidate_grant_ids[:max_candidates]

    minimal_combo_sets: list[frozenset[str]] = []
    combo_matches = []

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
        "condition_summary": _condition_summary(entry),
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
        "ActAsServiceAccount",
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


def _resource_metadata_filter_passes(
    resource: dict[str, Any],
    metadata_require: dict[str, Any],
    *,
    project_oslogin_by_project_id: dict[str, bool | None],
) -> bool:
    """Return True only if the resource satisfies every key in metadata_require.

    Currently supports:
      enable_oslogin: true  — instance-level metadata_enable_os_login, with project-level fallback.
        If neither instance nor project has it set (or the value is False), the filter fails.
        Defaults to False (do not graph the edge) when data is absent.
    """
    for key, required_value in metadata_require.items():
        if key == "enable_oslogin":
            rd = resource.get("resourcedata") or {}
            instance_flag = rd.get("metadata_enable_os_login")
            if instance_flag is True or instance_flag == 1:
                effective = True
            elif instance_flag is False or instance_flag == 0:
                effective = False
            else:
                # No instance-level override — fall back to project setting.
                project_id = str(resource.get("project_id") or "").strip()
                proj_flag = project_oslogin_by_project_id.get(project_id)
                effective = bool(proj_flag) if proj_flag is not None else False
            if bool(effective) != bool(required_value):
                return False
        elif key == "has_node_sa":
            rd = resource.get("resourcedata") or {}
            if bool(rd.get("has_node_sa")) != bool(required_value):
                return False
        elif key == "has_active_execution":
            if bool(resource.get("has_active_execution")) != bool(required_value):
                return False
        elif key == "is_cf_build_capable":
            if bool(resource.get("is_cf_build_capable")) != bool(required_value):
                return False
        # Unknown metadata filter keys: skip silently (forward-compat).
    return True


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
    project_oslogin_by_project_id: dict[str, bool | None] | None = None,
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
            # Normalize GCP provider-specific status values to conceptual states
            # GCP Compute Engine uses TERMINATED for stopped instances
            _STATUS_NORM = {"TERMINATED": "STOPPED"}
            status_token = _STATUS_NORM.get(status_token, status_token)
            if not status_token or status_token not in selected_statuses:
                continue
        metadata_require = selector.get("resource_metadata_require")
        if isinstance(metadata_require, dict) and metadata_require:
            if not _resource_metadata_filter_passes(
                resource,
                metadata_require,
                project_oslogin_by_project_id=project_oslogin_by_project_id or {},
            ):
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
    """
    Emit the principal node, the GCPIamSimpleBinding node, and the HAS_IAM_BINDING edge.

    This is the canonical single-grant shape: principal -[HAS_IAM_BINDING]-> binding-node.
    The binding node id is entry.binding_composite_id and it carries the full role@scope
    fidelity (role_name, attached/source scope, condition, inheritance, binding_family_id)
    so downstream resource edges hang off it rather than off the principal. Resource
    target edges are added separately by _emit_binding_target_edge using this same
    binding node as their source.
    """
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
        condition_summary=_condition_summary(entry),
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
        # Consumers (capability-hop emission) recompute the scope token and need the
        # project id; without it a project-scoped combo loses its project in the token.
        "effective_scope_project_id": effective_scope_project_id if len(scope_ids) == 1 else "",
        "effective_scope_ids": scope_ids,
        "effective_scope_types": scope_types,
        "effective_scope_displays": scope_displays,
    }


def _cap_capability_node_id(
    resource_type: str,
    scope_token: str,
    rule_name: str,
    hop_id: str,
    target_id: str,
) -> str:
    """Build a compact capability node id: ``cap:new:<restype>@<scope>#<hash8>``.

    The hash encodes (rule_name, scope_token, hop_id, target_id) so the ID is
    deterministic per target SA — different SAs get different nodes; the same SA
    always maps to the same node (dedup across contributors).
    """
    res = (resource_type or "resource").strip() or "resource"
    payload = f"{rule_name}|{scope_token}|{hop_id}|{target_id}"
    h = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
    return f"cap:new:{res}@{scope_token}#{h}"


def _combo_binding_id(
    *,
    subject_id: str,
    rule_name: str,
    effective_scope_token: str,
    contributing_binding_ids: Iterable[str],
    condition_hashes: Iterable[str],
    source_scope_ids: Iterable[str],
    effective_scope_ids: Iterable[str] = (),
) -> tuple[str, str]:
    """
    Compute the stable id (and short hash) for a combo (GCPIamMultiBinding) node.

    Returns (node_id, combo_hash). The visible id is
    `combo_iambinding:<rule>@<scope_token>#<hash>` for readability, but the hash is taken
    over the full payload INCLUDING subject identity and the contributing binding ids, so
    distinct subjects/evidence never collide onto one combo node even though the subject
    string is not embedded in the visible id. Deterministic: same inputs -> same id, which
    is what lets repeated emits de-duplicate via emitted_combo_bindings.
    """
    payload = json.dumps(
        {
            "subject_id": str(subject_id or "").strip(),
            "rule_name": str(rule_name or "").strip(),
            "effective_scope_token": str(effective_scope_token or "").strip(),
            "contributing_binding_ids": normalized_token_list(contributing_binding_ids),
            "condition_hashes": normalized_token_list(condition_hashes),
            "source_scope_ids": normalized_token_list(source_scope_ids),
            # Include the concrete effective-scope set so distinct multi-scope combos (which
            # all share the opaque "mixed" token) never collapse onto one node id. Without
            # this, combos resolving through different scope sets dedup together and the
            # shared subject->combo edge records one combo's scope/evidence nondeterministically.
            "effective_scope_ids": normalized_token_list(effective_scope_ids),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    combo_hash = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
    # Keep IDs compact/readable: subject identity is still included in the hash
    # payload above, so uniqueness/isolation are preserved without embedding the
    # full principal string in the visible node ID.
    node_id = f"combo_iambinding@{effective_scope_token}#{combo_hash}"
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
    """
    Emit the GCPIamMultiBinding (combo) node and the subject's HAS_COMBO_BINDING edge.

    Combo nodes represent a privilege-escalation path that only exists because SEVERAL
    bindings (typically different roles) combine. This emits principal
    -[HAS_COMBO_BINDING]-> combo-node carrying the union evidence: contributing binding
    ids, contributing roles/permissions, the per-binding permission attribution map,
    condition hashes, and effective-scope info (possibly MULTI_SCOPE). Target resource
    edges hang off this combo node via _emit_combo_target_edge, preserving authorization
    fidelity instead of drawing a bare principal -> resource edge.
    """
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


def _register_target_node(
    builder: OpenGraphBuilder,
    target: dict[str, str],
    *,
    fallback_project_id: str,
    node_id_override: str | None = None,
) -> tuple[str, str, str, str, str]:
    """Create/merge the TARGET resource node shared by the single-grant and combo edge
    emitters. Returns (target_id, target_name, target_type, target_project_id, target_status);
    an empty target_name signals no target (caller bails). A service-account target collapses
    onto its serviceAccount:<email> principal node (canonical_target_node_ref); node_id_override
    pins the id for via=resource combo hops (the cap:UPDATE clone)."""
    target_name = str(target.get("resource_name") or "").strip()
    target_type = str(target.get("resource_type") or "").strip()
    if not target_name:
        return "", "", "", "", ""
    target_project_id = str(target.get("project_id") or "").strip() or fallback_project_id
    target_status = str(target.get("status") or target.get("state") or "").strip().upper()
    target_label = resource_display_label(
        target_name,
        resource_type=target_type,
        project_id=target_project_id,
    )
    target_region = resource_location_token(target_name)
    target_id, target_node_kind = canonical_target_node_ref(target_name, target_type)
    if node_id_override:
        target_id = node_id_override
    builder.add_node(
        target_id,
        target_node_kind,
        name=target_label,
        display_name=target_label,
        resource_name=target_name,
        region=target_region,
        project_id=target_project_id,
        resource_type=target_type,
        status=target_status or None,
    )
    return target_id, target_name, target_type, target_project_id, target_status


def _emit_cap_hop(
    builder: OpenGraphBuilder,
    *,
    source_node_id: str,
    cap_resource_type: str,
    scope_token: str,
    hop_id: str,
    target_sa_node_id: str,
    node_type: str,
    node_label: str,
    edge_type: str,
    match_mode: str,
    rule_name: str,
    rule_description: str,
    scope_info: dict[str, Any],
) -> tuple[str, bool]:
    """Create (or reuse) the per-target capability node and the source->cap edge for a combo
    hop. The cap node is keyed by target SA so all principals reaching that SA via this rule
    and scope share one node. Returns (cap_node_id, edge_already_existed); the existed flag is
    captured BEFORE add_edge (add_edge is first-write-wins) so callers can drive their
    'already emitted' dedup correctly."""
    cap_node_id = _cap_capability_node_id(cap_resource_type, scope_token, rule_name, hop_id, target_sa_node_id)
    builder.add_node(
        cap_node_id,
        node_type,
        name=node_label,
        display_name=node_label,
        rule_name=rule_name,
        rule_description=str(rule_description or "").strip(),
        effective_scope_id=str(scope_info.get("effective_scope_id") or ""),
        effective_scope_type=str(scope_info.get("effective_scope_type") or ""),
        effective_scope_display=str(scope_info.get("effective_scope_display") or ""),
    )
    existed = (source_node_id, edge_type, cap_node_id) in builder.edge_map
    builder.add_edge(
        source_node_id,
        cap_node_id,
        edge_type,
        rule_name=rule_name,
        rule_description=str(rule_description or "").strip(),
        match_mode=match_mode,
        privilege_escalation=True,
    )
    return cap_node_id, existed


def _emit_binding_target_edge(
    builder: OpenGraphBuilder,
    *,
    entry: BindingPlusScopeEntry,
    edge_type: str,
    target: dict[str, str],
    rule_name: str,
    rule_description: str = "",
    example_command: str = "",
    matched_permissions: Iterable[str],
    matched_roles: Iterable[str],
    evidence_bindings: Iterable[str],
    combine_across_bindings: bool,
    privilege_escalation: bool,
    contributing_binding_permission_map: dict[str, Iterable[str]] | None = None,
    status: str = "",
) -> tuple[bool, str, str, str]:
    """
    Emit (or merge) the binding-node -> resource edge for a single-grant dangerous path.

    Source is the contributor's simple binding node (entry.binding_composite_id); the
    resource node is created/merged here and the edge carries the rule + permission
    attribution (_edge_properties_from_entry).

    Dangerous-role collapsing: for broad roles (owner/editor) the rule edge_type is
    collapsed to ROLE_OWNER/ROLE_EDITOR (unless the edge type is in the
    _NO_COLLAPSE_MULTI_PERMISSION_EDGE_TYPES set), and the original rule name/edge type
    are folded into dangerous_rule_names/dangerous_edge_types on the edge. Because
    add_edge is first-write-wins, a collapse onto an already-present edge is applied by
    rewriting builder.edge_map directly.

    Returns (added_new_edge, actual_edge_type, target_node_id, target_resource_name);
    added is False when the edge already existed (or a merge occurred) and ("","","")
    when there is no target name.
    """
    target_id, target_name, target_type, target_project_id, target_status = _register_target_node(
        builder, target, fallback_project_id=entry.project_id
    )
    if not target_name:
        return False, "", "", ""
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
    if str(example_command or "").strip():
        props["example_command"] = str(example_command).strip()
    if str(status or "").strip():
        props["status"] = str(status).strip().upper()
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
    example_command: str = "",
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
    target_node_id_override: str | None = None,
    status: str = "",
) -> tuple[bool, str, str]:
    """
    Emit a combo/multi-permission edge from a given source node to a resource target.

    Used for every hop of a combo path: combo-node -> capability -> ... -> resource, as
    well as the final combo-node -> resource edge. `source_node_id` is whatever the
    current hop source is (the combo binding node, a capability node, or a prior resource
    node), which is why this is parameterized separately from the subject. The resource
    node is created/merged and the edge records the union combo evidence (matched perms/
    roles, contributing binding permission map, effective/source scope, conditions) plus
    `match_mode` so the hop's role in the chain is recoverable.

    `target_node_id_override`: when set, the node is registered under this id instead of
    the canonical `resource:<name>` id.  Used for `via=resource` combo hops where the
    intermediate node is the cap:UPDATE clone rather than the real resource node.

    Returns (added_new_edge, target_node_id, target_resource_name); added is False when
    the edge already existed and ("","") when there is no target name.
    """
    target_id, target_name, target_type, target_project_id, target_status = _register_target_node(
        builder, target, fallback_project_id=subject_entry.project_id, node_id_override=target_node_id_override
    )
    if not target_name:
        return False, "", ""
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
    if str(example_command or "").strip():
        props["example_command"] = str(example_command).strip()
    if str(status or "").strip():
        props["status"] = str(status).strip().upper()
    edge_key = (source_node_id, edge_type, target_id)
    existing = builder.edge_map.get(edge_key)
    if existing is not None:
        # add_edge is first-write-wins, so when several contributors produce the SAME combo
        # edge (same source node, edge kind, target) with different evidence, the later ones
        # would be dropped and their evidence lost. Merge deterministically instead (sorted
        # union of list evidence, canonical scalars) so the surviving edge reflects all
        # contributors regardless of emission order. Mirrors the dedup-redirect merge.
        builder.edge_map[edge_key] = OpenGraphEdge(
            source_id=existing.source_id,
            destination_id=existing.destination_id,
            edge_type=existing.edge_type,
            properties=_merge_opengraph_edge_properties(existing.properties, props),
        )
        return False, target_id, target_name
    builder.add_edge(source_node_id, target_id, edge_type, **props)
    return True, target_id, target_name


def _filter_targets_requiring_perms(
    grant_targets: dict[tuple[str, str, str], dict[str, str]],
    *,
    required_perms: "frozenset[str] | set[str]",
    project_id: str,
    sa_project_perms_index: dict[str, dict[str, "frozenset[str]"]],
) -> dict[tuple[str, str, str], dict[str, str]]:
    """Keep only target SAs that actually hold `required_perms` (rule `target_requires_permissions`).

    Applies to BOTH the single-grant (binding-mode) and the combo/MULTI_SCOPE emission
    paths, so a rule like CREATE_VERTEX_KFP_JOB_AS_SA never draws an edge to a target SA
    that lacks the precondition permission (e.g. aiplatform.metadataStores.get) regardless
    of which emission branch builds it.
    """
    if not required_perms:
        return grant_targets
    required = set(required_perms)
    proj_sa_perms = sa_project_perms_index.get(str(project_id or "").strip(), {})

    def _target_holds(target: dict[str, str]) -> bool:
        email = str(target.get("resource_name") or "").strip()
        if not email:
            return False
        # sa_project_perms_index is keyed by the grantee's PRINCIPAL id (serviceAccount:<email>),
        # not the bare SA email, so look the target up in that form (fall back to the bare email
        # for any non-SA target). A target SA may also live in a different project than the acting
        # grant, so consult its own home project's index as well.
        rtype = str(target.get("resource_type") or "").strip()
        principal = (
            email if email.startswith("serviceAccount:")
            else (f"serviceAccount:{email}" if rtype == "service-account" else email)
        )
        perms: "frozenset[str] | set[str]" = (
            proj_sa_perms.get(principal) or proj_sa_perms.get(email) or frozenset()
        )
        if not required.issubset(perms):
            home_project = _sa_home_project_from_email(email)
            if home_project:
                home_perms = sa_project_perms_index.get(home_project, {})
                perms = home_perms.get(principal) or home_perms.get(email) or perms
        return required.issubset(perms)

    return {key: target for key, target in grant_targets.items() if _target_holds(target)}


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
    # Sort entries into a stable, total order before any grouping/matching. Downstream,
    # collect_rule_events groups entries into (principal, scope, condition, project) buckets
    # in iteration order and _matches_for_group keeps the first entry seen per grant as the
    # representative; combo nodes then record properties (effective_scope_ids, combo_id) from
    # whichever match landed first. If the incoming order is nondeterministic (it is derived
    # from sets/dicts upstream), those recorded properties churn run-to-run even though node
    # ids and reachability are stable. A deterministic sort makes the whole build byte-reproducible.
    entries = sorted(
        (entries or []),
        key=lambda e: (
            str(getattr(e, "principal_id", "") or ""),
            str(getattr(e, "binding_composite_id", "") or ""),
            str(getattr(e, "effective_scope_name", "") or ""),
            str(getattr(e, "attached_scope_name", "") or ""),
            str(getattr(e, "role_name", "") or ""),
            str(getattr(e, "condition_option_id", "") or ""),
        ),
    )

    # Index of (project_id -> sa_email -> set[permissions]) for target_requires_permissions checks.
    sa_project_perms_index: dict[str, dict[str, frozenset[str]]] = {}
    for _entry in entries:
        _pid = str(_entry.project_id or "").strip()
        _principal = str(_entry.principal_id or "").strip()
        if _pid and _principal and _entry.permissions:
            if _pid not in sa_project_perms_index:
                sa_project_perms_index[_pid] = {}
            existing = sa_project_perms_index[_pid].get(_principal, frozenset())
            sa_project_perms_index[_pid][_principal] = existing | _entry.permissions

    rule_progress_label = (
        "single-permission rules checked"
        if dangerous_rule_mode == "base"
        else "multi-permission combo rules checked"
        if dangerous_rule_mode == "advanced"
        else "rules checked"
    )

    role_subject_state: dict[str, dict[str, dict[str, Any]]] = {}
    # The role/subject/destination aggregation below is reporting-only (no consumer reads it;
    # iam_bindings_*_state is merely presence-checked) and is the dominant memory sink + a big
    # slowdown in this pass. Skip building it unless explicitly requested. Guarded so the graph
    # output is unchanged: edge/node emission and bindings_with_direct_dangerous_edges do not
    # depend on role_subject_state / rule_match_records / combo_rule_match_records.
    build_aggregation = bool(getattr(getattr(context, "options", None), "build_aggregation", False))

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

    progress_line_length = 0

    def _write_inline_progress(message: str) -> None:
        nonlocal progress_line_length
        text = str(message or "")
        padding = ""
        if progress_line_length > len(text):
            padding = " " * (progress_line_length - len(text))
        sys.stdout.write(f"\r{text}{padding}")
        sys.stdout.flush()
        progress_line_length = len(text)

    def _finalize_inline_progress() -> None:
        nonlocal progress_line_length
        if progress_line_length > 0:
            sys.stdout.write("\n")
            sys.stdout.flush()
            progress_line_length = 0

    def _print_rule_scan_progress(processed_rules: int, total_rules: int, matched_events: int) -> None:
        if total_rules <= 0:
            return
        message = (
            f"[*] Stage 2 {rule_progress_label}: {processed_rules}/{total_rules} "
            f"(matched_events={matched_events})"
        )
        _write_inline_progress(message)

    def _print_rule_group_scan_progress(
        processed_rules: int,
        total_rules: int,
        processed_groups: int,
        total_groups: int,
        matched_events: int,
        rule_name: str,
    ) -> None:
        if total_groups <= 0:
            return
        # Emit group-scan status only when a rule fully completes to avoid
        # consoles that render carriage-return updates as many new lines.
        if processed_groups != total_groups:
            return
        rule_label = str(rule_name or "").strip() or f"rule_{processed_rules}"
        if len(rule_label) > 56:
            rule_label = f"{rule_label[:53]}..."
        message = (
            f"[*] Stage 2 {rule_progress_label}: rule {processed_rules}/{total_rules} "
            f"[{rule_label}] groups {processed_groups}/{total_groups} "
            f"(matched_events={matched_events})"
        )
        _write_inline_progress(message)

    # Announce the phase before the (silent) setup below — sorting, the permission
    # index, the cross-project scan and the first grouping all run over every grant,
    # which on a large graph is a multi-second gap before the first per-rule tick.
    # Without this, the advanced/combo pass looks hung right after the single pass.
    # The count is rules EVALUATED, not edge kinds graphed: a few rules (resource-only
    # setIamPolicy) are matched so owner/editor fan-out works, then their edges are
    # trimmed from the default graph — call that out so the count is not mistaken for
    # the number of edge kinds in the output.
    _rules_note = ""
    if dangerous_rule_mode == "base" and not bool(
        getattr(getattr(context, "options", None), "include_resource_iam", False)
    ):
        from gcpwn.modules.opengraph.utilities.helpers.graph.constants import load_resource_iam_edge_types

        _resource_only = load_resource_iam_edge_types()
        _n_hidden = sum(
            1 for _r in rules if str(_r.get("edge_type") or _r.get("name") or "") in _resource_only
        )
        if _n_hidden:
            _rules_note = (
                f" ({_n_hidden} resource-only setIamPolicy rule(s) matched but hidden from the "
                f"default graph; --include-resource-iam to keep)"
            )
    print(
        f"[*] Stage 2 {rule_progress_label.replace(' checked', '')}: "
        f"{len(rules)} rules over {len(entries)} resolved grants...{_rules_note}"
    )

    _opts = getattr(context, "options", None)
    _cross_project = bool(getattr(_opts, "cross_project", False))
    _cross_project_sa_projects: frozenset[str] = getattr(_opts, "cross_project_sa_projects", frozenset()) or frozenset()
    # Hint: when cross-project actAs is OFF (the safe default matching
    # iam.disableCrossProjectServiceAccountUsage), surface that real cross-project
    # impersonation grants exist and are being suppressed, so an operator in a looser tenant
    # knows to re-run with --cross-sa-project-allowed. Precise for SA actors (project encoded
    # in the email); user/group actors carry no project and are skipped. Emitted once, on the
    # combo (advanced) pass -- cross-project actAs only matters for CREATE_*_AS_SA combos.
    if not _cross_project and dangerous_rule_mode != "base":
        _xproj_targets: set[str] = set()
        for _e in entries:
            if str(getattr(_e, "attached_scope_type", "") or "") != "service-account":
                continue
            if not any("serviceAccounts.actAs" in p for p in getattr(_e, "permissions", ()) or ()):
                continue
            _actor_proj = _sa_home_project_from_email(str(getattr(_e, "principal_id", "") or ""))
            _sa_proj = _sa_home_project(_e)
            if _actor_proj and _sa_proj and _actor_proj != _sa_proj:
                _xproj_targets.add(_sa_proj)
        if _xproj_targets:
            sys.stderr.write(
                f"[!] {len(_xproj_targets)} service-account home-project(s) have cross-project "
                "actAs grants that are SUPPRESSED by default (iam.disableCrossProjectServiceAccountUsage). "
                "If that org policy is disabled in this tenant, re-run with "
                "--cross-sa-project-allowed <projects> to graph those paths.\n"
            )
    # Emit events in a stable, total order. _emit_events is first-write-wins per combo-node
    # id / edge key, so when several events collapse onto one shared combo node (e.g. a
    # via=resource combo fanning to many targets), the event that lands first fixes the
    # recorded properties (effective_scope_ids, combo_id, permission_source_summary). A
    # canonical event order makes that choice deterministic and the export byte-reproducible.
    def _event_sort_key(event: dict[str, Any]) -> tuple:
        contributors = event.get("contributors") or []
        return (
            str(event.get("rule_name") or ""),
            str(event.get("emission_mode") or ""),
            tuple(sorted(str(b) for b in (event.get("evidence_bindings") or []))),
            tuple(sorted(str(getattr(c, "binding_composite_id", "") or "") for c in contributors)),
            tuple(sorted(str(getattr(c, "effective_scope_name", "") or "") for c in contributors)),
            tuple(sorted(str(getattr(c, "principal_id", "") or "") for c in contributors)),
        )

    def _filter_cross_project_events(evs):
        # Post-filter cross-project combo events when a specific SA-project allowlist is given.
        # iam.disableCrossProjectServiceAccountUsage is a project-level policy on the SA's HOME
        # project; only SA home-projects in the allowlist should yield cross-project edges.
        if not (_cross_project and _cross_project_sa_projects):
            return evs
        filtered_events = []
        for _ev in evs:
            if _ev.get("emission_mode") != "combo":
                filtered_events.append(_ev)
                continue
            _contribs = _ev.get("contributors") or []
            _project_ids = {c.project_id for c in _contribs if getattr(c, "project_id", None)}
            if len(_project_ids) <= 1:
                filtered_events.append(_ev)
                continue
            _sa_projects = {
                proj
                for c in _contribs
                if str(getattr(c, "attached_scope_type", "") or "") == "service-account"
                and (proj := _sa_home_project(c))
            }
            if not _sa_projects:
                filtered_events.append(_ev)
            elif _sa_projects & _cross_project_sa_projects:
                filtered_events.append(_ev)
        return filtered_events

    _grouped_cache: dict = {}

    def _collect_filtered(rule_subset):
        return _filter_cross_project_events(collect_rule_events(
            entries=entries,
            rules=rule_subset,
            matches_for_group=_matches_for_group,
            normalize_binding_permission_map=_normalize_binding_permission_map,
            normalized_token_list=normalized_token_list,
            progress_callback=_print_rule_scan_progress,
            group_progress_callback=_print_rule_group_scan_progress,
            cross_project=_cross_project,
            grouped_cache=_grouped_cache,
        ))

    owner_baseline_events = collect_owner_baseline_events(
        entries=entries,
        collapsed_dangerous_role_rules=_COLLAPSED_DANGEROUS_ROLE_EDGE_RULES,
    )

    # --low-memory: stream the (heavy) combo pass rule-by-rule so the full combo-event set is
    # never resident at once. A cheap prepass first computes the COMPLETE dangerous-binding id
    # set (the binding-node loop + _emit_events read it up front); then the per-rule events are
    # re-collected, emitted and discarded one rule at a time in the emission phase below. Output
    # is byte-identical: combo/capability node ids are rule-scoped (no cross-rule node sharing),
    # so cross-rule emission order is irrelevant, and the export re-sorts everything.
    #
    # The base (single-permission) pass is deliberately NOT streamed. It is not emission-order
    # independent, so per-rule streaming would diverge from a normal run (verified):
    #   1. owner/editor collapse: a dangerous single-perm rule matching a roles/owner|editor
    #      binding is rewritten to a ROLE_OWNER/ROLE_EDITOR edge (_emit_binding_target_edge). Two
    #      different single-perm rules then collide on one (binding, ROLE_OWNER, target) key and
    #      _merge_edge_properties keeps the FIRST writer's scalar props (status/example_command).
    #      Non-stream sorts all events globally (_event_sort_key, rule_name-first) -> one winner;
    #      per-rule streaming emits in rule-list order -> a different winner.
    #   2. node-id collapse: resource target node ids are resource:<leaf>@<project>, so two
    #      different-typed resources with the same leaf name in a project collide on one node id,
    #      each created by a different rule's event -> first-writer (order-dependent) sets the type.
    # The aggregation fix above already removed the dominant base-pass memory sink, so streaming
    # the base pass is not worth a non-byte-identical graph.
    _stream_combo = (
        bool(getattr(getattr(context, "options", None), "low_memory", False))
        and dangerous_rule_mode == "advanced"
    )
    all_events = None
    if _stream_combo:
        bindings_with_dangerous_edges = set()
        for _r in rules:
            _pre = _collect_filtered([_r])
            for _ev in _pre:
                for _c in (_ev.get("contributors") or []):
                    if isinstance(_c, BindingPlusScopeEntry):
                        bindings_with_dangerous_edges.add(_c.binding_composite_id)
            del _pre
        if rules:
            _finalize_inline_progress()
    else:
        dangerous_events = _collect_filtered(rules)
        if rules:
            _finalize_inline_progress()
        # Compute this FIRST, from dangerous_events alone -- owner-baseline contributors are also
        # BindingPlusScopeEntry, so merging them in before this would leak owner binding ids in.
        bindings_with_dangerous_edges = {
            contributor.binding_composite_id
            for event in dangerous_events
            for contributor in (event.get("contributors") or [])
            if isinstance(contributor, BindingPlusScopeEntry)
        }
        # Merge owner-baseline IN PLACE + sort in place (avoids list()/sorted() copies).
        all_events = dangerous_events
        all_events.extend(owner_baseline_events)
        owner_baseline_events = None
        all_events.sort(key=_event_sort_key)
    owner_grants: set[str] = {
        entry.binding_composite_id for entry in entries if str(entry.role_name or "").strip() == "roles/owner"
    }
    all_binding_ids = {entry.binding_composite_id for entry in entries}
    bindings_to_emit = all_binding_ids if include_all else (bindings_with_dangerous_edges | owner_grants)

    emitted_binding_nodes: set[str] = set()
    bindings_with_direct_dangerous_edges: set[str] = set()
    for entry in entries:
        if entry.binding_composite_id not in bindings_to_emit:
            continue
        pe_flag = entry.binding_composite_id in bindings_with_dangerous_edges
        if entry.binding_composite_id not in emitted_binding_nodes:
            _emit_subject_binding(builder, entry=entry, privilege_escalation=pe_flag)
            emitted_binding_nodes.add(entry.binding_composite_id)
        else:
            # Binding node already exists — wire this principal's HAS_IAM_BINDING edge
            principal_props = principal_member_properties(entry.principal_id)
            builder.add_node(entry.principal_id, principal_type(entry.principal_id), **principal_props)
            builder.add_edge(
                entry.principal_id,
                entry.binding_composite_id,
                "HAS_IAM_BINDING",
                source=entry.source,
                role_name=entry.role_name,
                binding_origin=binding_origin_from_entry(entry),
                binding_family_id=binding_family_id_for_entry(entry),
                attached_scope_id=entry.attached_scope_name,
                attached_scope_type=entry.attached_scope_type,
                source_scope_id=entry.source_scope_name,
                source_scope_type=entry.source_scope_type,
                condition_hash=entry.condition_hash,
                conditional=bool(entry.condition_hash),
                inherited=bool(entry.inherited),
                expanded_from_convenience_member=entry.expanded_from_convenience_member or None,
                privilege_escalation=bool(pe_flag),
            )
        if build_aggregation:
            subject_state = ensure_subject_state(role_subject_state, entry)
            binding_state = subject_state["bindings"].get(entry.binding_composite_id)
            if binding_state is not None:
                binding_state["privilege_escalation"] = bool(
                    binding_state["privilege_escalation"] or pe_flag
                )
        emitted_binding_nodes.add(entry.binding_composite_id)

    rule_match_records: list[dict[str, Any]] = []
    combo_rule_match_records: list[dict[str, Any]] = []
    emitted_combo_bindings: set[str] = set()

    def _emit_events(events: list[dict[str, Any]]) -> int:
        emitted_dangerous = 0
        scope_ancestor_cache: dict[str, set[str]] = {}
        _emit_total = len(events)
        _emit_label = (
            "multi-permission combo"
            if dangerous_rule_mode == "advanced"
            else "single-permission"
            if dangerous_rule_mode == "base"
            else "dangerous"
        )
        for _emit_index, event in enumerate(events, start=1):
            # Emitting combo/capability fan-out over a large event set is the slow,
            # otherwise-silent tail of the advanced pass; tick an inline counter so a
            # big graph does not look hung between the rule scan and the final counts.
            if _emit_total and (_emit_index % 200 == 0 or _emit_index == _emit_total):
                _write_inline_progress(
                    f"[*] Stage 2 emitting {_emit_label} edges: {_emit_index}/{_emit_total} "
                    f"(edges={emitted_dangerous})"
                )
            contributors = list(event.get("contributors") or [])
            matched_permissions = set(event.get("matched_permissions") or ())
            matched_roles = set(event.get("matched_roles") or ())
            evidence_bindings = list(event.get("evidence_bindings") or ())
            edge_type = str(event.get("edge_type") or "HAS_IAM_BINDING")
            rule_name = str(event.get("rule_name") or "")
            rule_description = str(event.get("rule_description") or "").strip()
            example_command = str(event.get("example_command") or "").strip()
            selector = event.get("target_selector") or {}
            combo_hop = event.get("combo_hop") or {}
            target_requires_permissions = set(event.get("target_requires_permissions") or ())
            rule_status = str(event.get("status") or "").strip()
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
            # Every field is now copied into locals above and `event` is not read again this
            # iteration, so drop the list's reference to the dict -- it (and its sub-containers)
            # can be freed as the loop advances instead of the whole event set surviving to the
            # last iteration while the full graph is already built. (The `event` local still
            # holds it for the rest of this iteration.)
            events[_emit_index - 1] = None
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
                    example_command=example_command,
                    status=rule_status,
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
                if build_aggregation:
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
                    project_oslogin_by_project_id=scope_resource_indexes.project_oslogin_by_project_id,
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
                                "capability_resource_type": str(raw_hop.get("capability_resource_type") or combo_hop_config.get("capability_resource_type") or "").strip(),
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
                        "capability_resource_type": str(combo_hop_config.get("capability_resource_type") or "").strip(),
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

            if build_aggregation:
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
                _evidence = _combo_evidence(contributors)
                scope_info = _evidence["scope_info"]
                condition_hashes = _evidence["condition_hashes"]
                condition_summaries = _evidence["condition_summaries"]
                source_scope_ids = _evidence["source_scope_ids"]
                source_scope_types = _evidence["source_scope_types"]
                inherited = _evidence["inherited"]
                combo_binding_id, combo_hash = _combo_binding_id(
                    subject_id=subject_entry.principal_id,
                    rule_name=rule_name,
                    effective_scope_token=str(scope_info.get("effective_scope_token") or "mixed"),
                    contributing_binding_ids=evidence_bindings,
                    condition_hashes=condition_hashes,
                    source_scope_ids=source_scope_ids,
                    effective_scope_ids=scope_info.get("effective_scope_ids") or [],
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

                combo_hops = _normalized_combo_hops(combo_hop if isinstance(combo_hop, dict) else {})
                combo_target_edge_type = str(combo_hop.get("edge_to_target") or "RunsAs").strip() or "RunsAs"
                target_group_ids = normalized_token_list(combo_hop.get("target_from_groups") or [])
                group_target_contributors = _contributors_for_group_ids(target_group_ids)
                target_source_contributors = (
                    group_target_contributors
                    or [contributor for contributor, _ in contributors_in_scope]
                    or list(contributors)
                )
                current_source_node_ids: set[str] = {combo_binding_id}
                complete_chain = True
                resource_name_by_node_id: dict[str, str] = {}
                last_hop_was_resource = False
                _deferred_cap_hop_meta: dict[str, Any] = {}

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
                        # Gate: for rules that require an existing resource (UPDATE attacks),
                        # confirm at least one resource of the required type exists in scope.
                        # CREATE attacks skip this gate (resource need not pre-exist).
                        if bool(combo_hop.get("requires_resource_exists")):
                            # Collect resource selectors from all hop subject groups (handles
                            # rules with multiple subject groups, e.g. UPDATE_AND_INVOKE_CF).
                            _hop_resource_selectors = [
                                _selector_for_group(gid)
                                for gid in hop_from_groups
                                if _selector_for_group(gid).get("resource_types")
                            ] or ([default_hop_group_selector] if default_hop_group_selector.get("resource_types") else [])
                            if _hop_resource_selectors:
                                existence_pool: dict[tuple[str, str, str], dict[str, str]] = {}
                                for _sel in _hop_resource_selectors:
                                    for _contributor in hop_contributors:
                                        existence_pool.update(
                                            _collect_targets_for_contributor(
                                                _contributor,
                                                include_fanout=True,
                                                selector_override=_sel,
                                            )
                                        )
                                if not existence_pool:
                                    complete_chain = False
                                    current_source_node_ids = set()
                                    break
                        # Defer cap node creation to the terminal section, keying by target SA
                        # rather than source node. Multiple principals targeting the same SA
                        # through the same rule then share one cap node instead of each
                        # getting a private duplicate.
                        _cap_hop_id = str(hop.get("id") or f"hop_{hop_index + 1}").strip() or f"hop_{hop_index + 1}"
                        _cap_node_label = str(hop.get("node_label") or rule_name).strip() or rule_name
                        _cap_res_type = str(hop.get("capability_resource_type") or "").strip()
                        _deferred_cap_hop_meta = {
                            "hop_id": _cap_hop_id,
                            "node_label": _cap_node_label,
                            "resource_type": _cap_res_type,
                            "node_type": (
                                gcp_resource_node_type(_cap_res_type)
                                if _cap_res_type
                                else (str(hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability")
                            ),
                            "edge_type": hop_edge_type,
                        }
                        next_source_node_ids = set(current_source_node_ids)
                        hop_edge_seen = bool(next_source_node_ids)
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
                                if source_node_id == canonical_target_node_ref(hop_target_name, hop_target.get("resource_type"))[0]:
                                    continue
                                # Route via=resource hops to a rule-specific cap:UPDATE clone
                                # so that (a) the actual resource node stays a dead end and
                                # (b) two different rules on the same resource never share an
                                # intermediate node — which would let BloodHound traverse
                                # rule_A → cap:UPDATE:res → rule_B_edge → SA as a false path.
                                _hop_override = cap_update_node_id(hop_target_name, rule_name) if hop_mode == "resource" and hop_target_name else None
                                added, hop_target_id, _ = _emit_combo_target_edge(
                                    builder,
                                    combo_binding_id=combo_binding_id,
                                    source_node_id=source_node_id,
                                    subject_entry=subject_entry,
                                    edge_type=hop_edge_type,
                                    target=hop_target,
                                    rule_name=rule_name,
                                    rule_description=rule_description,
                                    example_command=example_command,
                                    status=rule_status,
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
                                    target_node_id_override=_hop_override,
                                )
                                if hop_target_id:
                                    hop_edge_seen = True
                                    next_source_node_ids.add(hop_target_id)
                                    if hop_mode == "resource":
                                        resource_name_by_node_id[hop_target_id] = hop_target_name
                                if added:
                                    combo_branch_emitted += 1
                    if not hop_edge_seen or not next_source_node_ids:
                        complete_chain = False
                        current_source_node_ids = set()
                        break
                    current_source_node_ids = set(next_source_node_ids)
                    last_hop_was_resource = (hop_mode == "resource")

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
                    _c_targets = _collect_targets_for_contributor(
                        contributor,
                        include_fanout=True,
                        selector_override=hop_target_selector,
                    )
                    # Apply target_requires_permissions on the combo/MULTI_SCOPE path too
                    # (the single-grant branch filters at its own grant_targets); without
                    # this, a rule's precondition leaks through mixed-scope capability nodes.
                    _c_targets = _filter_targets_requiring_perms(
                        _c_targets,
                        required_perms=target_requires_permissions,
                        project_id=contributor.project_id,
                        sa_project_perms_index=sa_project_perms_index,
                    )
                    combo_targets.update(_c_targets)
                # Node ids of the SAs the principal can actually actAs (the act_as group's
                # satisfied targets). For via=resource rules the terminal SA is the resource's
                # OWN attached SA, but we must only claim theft of that SA when the principal
                # holds actAs on THAT SA -- not merely actAs on some other SA in scope.
                _actas_target_node_ids = {
                    canonical_target_node_ref(str(t.get("resource_name") or ""), t.get("resource_type"))[0]
                    for t in combo_targets.values()
                }

                final_target_edge_seen = False
                for source_node_id in sorted(current_source_node_ids):
                    if last_hop_was_resource:
                        # For via=resource paths, the terminal SA is the resource's own
                        # attached SA (from enumerated data), gated to the SAs the principal
                        # can actAs so an edge is not drawn to an instance SA the attacker
                        # cannot actually impersonate.
                        _res_name = resource_name_by_node_id.get(source_node_id, "")
                        _node_targets: list[dict[str, str]] = [
                            {"resource_name": _sa_email, "resource_type": "service-account", "project_id": ""}
                            for _sa_email in scope_resource_indexes.resource_sa_by_name.get(_res_name, [])
                            if canonical_target_node_ref(_sa_email, "service-account")[0] in _actas_target_node_ids
                        ]
                    else:
                        _node_targets = list(combo_targets.values())
                    # Compute scope token once per source iteration for cap node IDs.
                    _terminal_scope_token = binding_scope_token(
                        str(scope_info.get("effective_scope_type") or "resource").strip(),
                        str(scope_info.get("effective_scope_id") or "").strip(),
                        project_id=str(scope_info.get("effective_scope_project_id") or "").strip(),
                    ) if _deferred_cap_hop_meta else ""
                    for target in _node_targets:
                        target_name_for_self_check = str(target.get("resource_name") or "").strip()
                        target_sa_node_id, _ = canonical_target_node_ref(target_name_for_self_check, target.get("resource_type"))
                        if source_node_id == target_sa_node_id:
                            continue
                        if _deferred_cap_hop_meta:
                            # Create/get a cap node keyed by target SA — shared across all
                            # principals that can reach the same SA via this rule and scope.
                            _cap_node_id, _src_cap_existed = _emit_cap_hop(
                                builder,
                                source_node_id=source_node_id,
                                cap_resource_type=_deferred_cap_hop_meta["resource_type"],
                                scope_token=_terminal_scope_token,
                                hop_id=_deferred_cap_hop_meta["hop_id"],
                                target_sa_node_id=target_sa_node_id,
                                node_type=_deferred_cap_hop_meta["node_type"],
                                node_label=_deferred_cap_hop_meta["node_label"],
                                edge_type=_deferred_cap_hop_meta["edge_type"],
                                match_mode="combo_hop",
                                rule_name=rule_name,
                                rule_description=rule_description,
                                scope_info=scope_info,
                            )
                            _emission_source = _cap_node_id
                        else:
                            _emission_source = source_node_id
                            _src_cap_existed = True
                        added, target_id, target_name = _emit_combo_target_edge(
                            builder,
                            combo_binding_id=combo_binding_id,
                            source_node_id=_emission_source,
                            subject_entry=subject_entry,
                            edge_type=combo_target_edge_type,
                            target=target,
                            rule_name=rule_name,
                            rule_description=rule_description,
                            example_command=example_command,
                            status=rule_status,
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
                        if not added and _src_cap_existed:
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

                if build_aggregation:
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
                if hop_mode == "capability" and bool(combo_hop.get("requires_resource_exists")):
                    _bm_from_groups = set(normalized_token_list(primary_hop.get("from_groups") or []))
                    _bm_selectors = [
                        _selector_for_group(gid)
                        for gid in _bm_from_groups
                        if _selector_for_group(gid).get("resource_types")
                    ]
                    if _bm_selectors:
                        _bm_pool: dict[tuple[str, str, str], dict[str, str]] = {}
                        for _bm_sel in _bm_selectors:
                            for _bm_contributor, _ in contributors_in_scope:
                                _bm_pool.update(
                                    _collect_targets_for_contributor(
                                        _bm_contributor,
                                        include_fanout=True,
                                        selector_override=_bm_sel,
                                    )
                                )
                        if not _bm_pool:
                            continue
                for contributor, _ in contributors_in_scope:
                    mutation_snapshot = _snapshot_graph_mutation_state()
                    binding_branch_emitted = 0
                    final_target_edge_seen = False
                    pending_destination_records: list[dict[str, Any]] = []

                    _evidence = _combo_evidence([contributor])
                    scope_info = _evidence["scope_info"]
                    condition_hashes = _evidence["condition_hashes"]
                    condition_summaries = _evidence["condition_summaries"]
                    source_scope_ids = _evidence["source_scope_ids"]
                    source_scope_types = _evidence["source_scope_types"]

                    combo_target_edge_type = str(combo_hop.get("edge_to_target") or "RunsAs").strip() or "RunsAs"
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
                        edge_from_type = str(primary_hop.get("edge_from_subject") or combo_hop.get("edge_from_subject") or edge_type).strip() or edge_type
                        intermediate_source_ids: set[str] = set()
                        intermediate_node_to_resource_name: dict[str, str] = {}
                        for intermediate_target in intermediate_targets.values():
                            _int_res_name_pre = str(intermediate_target.get("resource_name") or "").strip()
                            # Route via=resource combo hops to a rule-specific cap:UPDATE node so
                            # the actual resource node stays a dead end and different rules never
                            # share an intermediate node.
                            _cap_override = cap_update_node_id(_int_res_name_pre, rule_name) if _int_res_name_pre else None
                            added, intermediate_target_id, _ = _emit_combo_target_edge(
                                builder,
                                combo_binding_id=contributor.binding_composite_id,
                                source_node_id=contributor.binding_composite_id,
                                subject_entry=contributor,
                                edge_type=edge_from_type,
                                target=intermediate_target,
                                rule_name=rule_name,
                                rule_description=rule_description,
                                example_command=example_command,
                                status=rule_status,
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
                                target_node_id_override=_cap_override,
                            )
                            if intermediate_target_id:
                                intermediate_source_ids.add(intermediate_target_id)
                                bindings_with_direct_dangerous_edges.add(contributor.binding_composite_id)
                                _int_res_name = str(intermediate_target.get("resource_name") or "").strip()
                                intermediate_node_to_resource_name[intermediate_target_id] = _int_res_name
                            if added:
                                binding_branch_emitted += 1
                        if not intermediate_source_ids:
                            _rollback_graph_mutation_state(mutation_snapshot)
                            continue
                        # SAs this contributor can actually actAs (act_as group targets); the
                        # via=resource terminal must only reach an instance's attached SA when
                        # the principal holds actAs on THAT SA.
                        _binding_actas_node_ids = {
                            canonical_target_node_ref(str(t.get("resource_name") or ""), t.get("resource_type"))[0]
                            for t in _collect_targets_for_contributor(
                                contributor,
                                include_fanout=True,
                                selector_override=hop_target_selector,
                            ).values()
                        }
                        for source_node_id in sorted(intermediate_source_ids):
                            # For via=resource hop_mode, the terminal SA is the resource's own
                            # attached SA, gated to the SAs the principal can actAs (prevents
                            # claiming theft of an instance SA the attacker cannot impersonate).
                            _binding_res_name = intermediate_node_to_resource_name.get(source_node_id, "")
                            _binding_sa_list = scope_resource_indexes.resource_sa_by_name.get(_binding_res_name, [])
                            grant_targets: dict[tuple[str, str, str], dict[str, str]] = {
                                ("service-account", _sa_email, ""): {
                                    "resource_name": _sa_email,
                                    "resource_type": "service-account",
                                    "project_id": "",
                                }
                                for _sa_email in _binding_sa_list
                                if canonical_target_node_ref(_sa_email, "service-account")[0] in _binding_actas_node_ids
                            }
                            for target in grant_targets.values():
                                if source_node_id == canonical_target_node_ref(str(target.get("resource_name") or "").strip(), target.get("resource_type"))[0]:
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
                                    example_command=example_command,
                                    status=rule_status,
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
                        if build_aggregation:
                            for pending_record in pending_destination_records:
                                record_destination(role_subject_state=role_subject_state, **pending_record)
                        emitted_dangerous += binding_branch_emitted
                        continue

                    # Collect targets before creating cap nodes so cap nodes can be keyed
                    # by target SA rather than by contributor — multiple contributors
                    # targeting the same SA then share one cap node.
                    hop_edge_type = str(primary_hop.get("edge_from_subject") or combo_hop.get("edge_from_subject") or "").strip()
                    if not hop_edge_type:
                        _rollback_graph_mutation_state(mutation_snapshot)
                        continue

                    grant_targets = _collect_targets_for_contributor(
                        contributor,
                        include_fanout=not scope_only,
                        selector_override=resolved_target_selector,
                    )
                    grant_targets = _filter_targets_requiring_perms(
                        grant_targets,
                        required_perms=target_requires_permissions,
                        project_id=contributor.project_id,
                        sa_project_perms_index=sa_project_perms_index,
                    )
                    if not grant_targets:
                        _rollback_graph_mutation_state(mutation_snapshot)
                        continue

                    # Cap node metadata (constant across all targets for this contributor).
                    _b_hop_id = str(primary_hop.get("id") or combo_hop.get("id") or "hop_1").strip() or "hop_1"
                    _b_node_label = str(primary_hop.get("node_label") or combo_hop.get("node_label") or rule_name).strip() or rule_name
                    _b_cap_res_type = str(primary_hop.get("capability_resource_type") or combo_hop.get("capability_resource_type") or "").strip()
                    _b_node_type = (
                        gcp_resource_node_type(_b_cap_res_type)
                        if _b_cap_res_type
                        else (str(primary_hop.get("node_type") or combo_hop.get("node_type") or "GCPIamCapability").strip() or "GCPIamCapability")
                    )
                    _b_scope_id = str(scope_info.get("effective_scope_id") or "").strip()
                    _b_scope_type = canonical_scope_type_for_bindings(
                        str(scope_info.get("effective_scope_type") or "").strip(), _b_scope_id
                    )
                    _b_scope_token = binding_scope_token(
                        _b_scope_type, _b_scope_id,
                        project_id=str(scope_info.get("effective_scope_project_id") or "").strip(),
                    )

                    for target in grant_targets.values():
                        _b_target_name = str(target.get("resource_name") or "").strip()
                        _b_target_sa_node_id, _ = canonical_target_node_ref(_b_target_name, target.get("resource_type"))

                        # Create/get cap node keyed by target SA (shared across all contributors
                        # that target the same SA through this rule and scope).
                        _b_cap_node_id, _b_hop_existed = _emit_cap_hop(
                            builder,
                            source_node_id=contributor.binding_composite_id,
                            cap_resource_type=_b_cap_res_type,
                            scope_token=_b_scope_token,
                            hop_id=_b_hop_id,
                            target_sa_node_id=_b_target_sa_node_id,
                            node_type=_b_node_type,
                            node_label=_b_node_label,
                            edge_type=hop_edge_type,
                            match_mode="binding_combo_hop",
                            rule_name=rule_name,
                            rule_description=rule_description,
                            scope_info=scope_info,
                        )

                        added, target_id, target_name = _emit_combo_target_edge(
                            builder,
                            combo_binding_id=contributor.binding_composite_id,
                            source_node_id=_b_cap_node_id,
                            subject_entry=contributor,
                            edge_type=combo_target_edge_type,
                            target=target,
                            rule_name=rule_name,
                            rule_description=rule_description,
                            example_command=example_command,
                            status=rule_status,
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
                        if not added and _b_hop_existed:
                            continue
                        if not _b_hop_existed:
                            binding_branch_emitted += 1
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
                        if added:
                            binding_branch_emitted += 1
                    if not final_target_edge_seen:
                        _rollback_graph_mutation_state(mutation_snapshot)
                        continue
                    if build_aggregation:
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

    if _stream_combo:
        # Re-collect and emit one rule at a time, discarding each rule's events immediately, so
        # the full combo-event set never co-exists. bindings_to_emit was already computed from the
        # complete prepass set above, so _emit_events sees the final value. Owner-baseline events
        # are emitted last (their edges never share keys with combo edges, and the export re-sorts).
        dangerous_edges_emitted = 0
        for _r in rules:
            _evs = _collect_filtered([_r])
            _evs.sort(key=_event_sort_key)
            dangerous_edges_emitted += _emit_events(_evs)
            del _evs
        if owner_baseline_events:
            owner_baseline_events.sort(key=_event_sort_key)
            dangerous_edges_emitted += _emit_events(owner_baseline_events)
    else:
        dangerous_edges_emitted = _emit_events(all_events)
    _finalize_inline_progress()
    combo_bindings_emitted = len(emitted_combo_bindings)

    # Mark simple binding nodes as privilege-escalation when they emit direct dangerous
    # edges from that binding node.  Use OR so a prior pass's True is never downgraded:
    # the single-perm pass may have already set pe=True for a binding that appears only
    # as a combo contributor in this (multi-perm) pass.
    for binding_id in emitted_binding_nodes:
        node = builder.node_map.get(binding_id)
        if node is None:
            continue
        props = dict(node.properties)
        props["privilege_escalation"] = bool(props.get("privilege_escalation")) or (binding_id in bindings_with_direct_dangerous_edges)
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
