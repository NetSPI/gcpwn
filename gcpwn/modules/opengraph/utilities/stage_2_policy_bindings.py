from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from gcpwn.core.utils.hierarchy import descendants as _descendants
from gcpwn.core.utils.module_helpers import load_mapping_data, parse_string_list
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import principal_node_id
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_conditionals import ConditionOption, StatementConditionalsEngine
from gcpwn.modules.opengraph.utilities.helpers.graph.normalization import normalized_token_frozenset
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
    ScopeResourceIndexes,
    _emit_iam_binding_edges_from_entries,
    canonical_scope_type_for_bindings,
    load_normalized_dangerous_rules_by_family,
    _requirement_permissions,
    _scope_leaf,
    binding_scope_token,
)


DEFAULT_PERMISSION_ROLE_MAP_FILE = "og_permission_to_roles_map.json"
_DANGEROUS_RULES_BY_FAMILY_ARTIFACT = "dangerous_rules_by_family"
_RESULT_STAT_KEYS = (
    "dangerous_edges_emitted",
    "combo_bindings_emitted",
    "bindings_composite_total",
    "bindings_composite_emitted",
    "bindings_total",
    "bindings_emitted",
    "entries_total",
    "rules_total",
)
_DEFAULT_CONDITION_OPTION = ConditionOption(
    option_id="default",
    expression="",
    narrowed_prefixes=[],
    narrowed_equals=[],
    narrowed_services=[],
    narrowed_resource_types=[],
    unresolved=False,
    filter_summary="",
)


def _progress_interval(total: int) -> int:
    if total <= 0:
        return 1
    return max(1, total // 100)


def _should_emit_progress(processed: int, total: int, *, interval: int | None = None) -> bool:
    if total <= 0 or processed <= 0:
        return False
    step = interval if interval is not None else _progress_interval(total)
    return processed == 1 or processed == total or processed % step == 0


def _print_stage2_progress_inline(
    *,
    processed_members: int,
    total_members: int,
    processed_resources: int,
    total_resources: int,
    processed_binding_records: int,
    total_binding_records: int,
    force: bool = False,
) -> None:
    if total_members <= 0 and total_resources <= 0 and total_binding_records <= 0:
        return
    should_emit = force or any(
        (
            _should_emit_progress(processed_members, total_members),
            _should_emit_progress(processed_resources, total_resources),
            _should_emit_progress(processed_binding_records, total_binding_records),
        )
    )
    if not should_emit:
        return
    message = (
        "[*] Stage 2 progress: "
        f"members {processed_members}/{total_members}, "
        f"resources {processed_resources}/{total_resources}, "
        f"binding_records {processed_binding_records}/{total_binding_records}"
    )
    if sys.stdout.isatty():
        print(f"\r{message}", end="", flush=True)
        if force:
            print("")
        return
    print(message)


@dataclass(frozen=True)
class _ScopedExpansionContext:
    conditional_evaluation: bool
    conditionals: StatementConditionalsEngine
    expand_inheritance: bool
    children_by_parent: dict[str, list[str]]
    scope_type_by_name: dict[str, str]
    scope_display_by_name: dict[str, str]
    project_id_by_scope: dict[str, str]
# Load the static permission->roles mapping that drives role permission expansion.
# This is a required repo mapping; fail fast if the payload is malformed.
def _load_permission_to_roles() -> dict[str, list[str]]:
    payload = load_mapping_data(DEFAULT_PERMISSION_ROLE_MAP_FILE, kind="json")
    if not isinstance(payload, dict):
        raise ValueError(
            f"{DEFAULT_PERMISSION_ROLE_MAP_FILE} must be a JSON object of "
            "permission -> [roles]."
        )
    output: dict[str, list[str]] = {}
    for permission, roles in payload.items():
        if not isinstance(permission, str) or not permission:
            raise ValueError(f"Invalid permission key in {DEFAULT_PERMISSION_ROLE_MAP_FILE}: {permission!r}")
        if not isinstance(roles, list) or any(not isinstance(role, str) or not role for role in roles):
            raise ValueError(
                f"Invalid role list for permission {permission!r} in {DEFAULT_PERMISSION_ROLE_MAP_FILE}"
            )
        output[permission] = roles
    return output


# Compare rule-required permissions against the permission->role map and record
# which rules/permissions are currently unsupported by the local mapping data.
def _binding_rule_permission_map_coverage(
    *,
    permission_to_roles: dict[str, list[str]] | None,
    single_rules: Iterable[dict[str, Any]],
    multi_rules: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    known_permissions = {permission for permission in (permission_to_roles or {}).keys() if permission}
    unsupported_rule_names: set[str] = set()
    unmapped_permissions: set[str] = set()
    unsupported_rules: list[dict[str, Any]] = []

    def _collect_rule(rule: dict[str, Any], *, family: str) -> None:
        required_permissions = sorted({permission for permission in _requirement_permissions(rule) if permission})
        if not required_permissions:
            return
        missing_permissions = [permission for permission in required_permissions if permission not in known_permissions]
        if not missing_permissions:
            return
        rule_name = str(rule.get("name") or "").strip() or str(rule.get("edge_type") or "").strip() or "<unnamed_rule>"
        unsupported_rule_names.add(rule_name)
        unmapped_permissions.update(missing_permissions)
        record = {
            "family": family,
            "rule_name": rule_name,
            "edge_type": str(rule.get("edge_type") or "").strip() or rule_name,
            "missing_permissions": missing_permissions,
            "required_permissions": required_permissions,
        }
        variant_id = str(rule.get("rule_variant_id") or "").strip()
        if variant_id:
            record["rule_variant_id"] = variant_id
        unsupported_rules.append(record)

    for rule in single_rules or ():
        if isinstance(rule, dict):
            _collect_rule(rule, family="single")
    for rule in multi_rules or ():
        if isinstance(rule, dict):
            _collect_rule(rule, family="multi")

    return {
        "known_permission_count": len(known_permissions),
        "unsupported_rule_count": len(unsupported_rules),
        "unsupported_rule_names": sorted(unsupported_rule_names),
        "unmapped_permissions": sorted(unmapped_permissions),
        "unsupported_rules": unsupported_rules,
    }


# Load normalized dangerous-rule families once and cache on context for reuse
# across coverage + base + advanced emit passes.
def _dangerous_rules_by_family(context) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    cached = context.get_artifact(_DANGEROUS_RULES_BY_FAMILY_ARTIFACT)
    if isinstance(cached, tuple) and len(cached) == 2:
        return cached
    rules = load_normalized_dangerous_rules_by_family()
    context.set_artifact(_DANGEROUS_RULES_BY_FAMILY_ARTIFACT, rules)
    return rules


# Produce a short stable hash for IAM condition payloads so binding node IDs
# remain deterministic for conditioned vs non-conditioned variants.
def _condition_hash(condition: Any) -> str:
    if not condition:
        return ""
    if isinstance(condition, dict):
        expression = str(condition.get("expression") or "").strip()
        if expression:
            return hashlib.sha1(expression.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
        payload = json.dumps(condition, sort_keys=True, ensure_ascii=False)
    else:
        payload = str(condition)
    if not payload:
        return ""
    return hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]


# Build a deterministic IAM-binding node ID from role + effective scope (+source
# scope and condition hash when needed to avoid accidental node collapse).
def _binding_composite_id(
    *,
    role_name: str,
    attached_scope_token: str,
    source_scope_token: str = "",
    condition_hash: str,
) -> str:
    binding_composite_id = f"iambinding:{role_name}@{attached_scope_token}"
    # Keep inherited fan-out rows distinct from direct rows at the same effective
    # scope so direct + inherited bindings do not collapse into a single binding node.
    if source_scope_token and source_scope_token != attached_scope_token:
        binding_composite_id = f"{binding_composite_id}#src:{source_scope_token}"
    if condition_hash:
        binding_composite_id = f"{binding_composite_id}#cond:{condition_hash}"
    return binding_composite_id


# Return all descendant scopes of a root scope using a breadth-first traversal.
# Used for org/folder inheritance fan-out.
# Invert permission->roles mapping into role->permissions for quick role lookup
# during binding expansion.
def _invert_permission_to_roles(permission_to_roles: dict[str, list[str]] | None) -> dict[str, set[str]]:
    output: dict[str, set[str]] = defaultdict(set)
    for permission, roles in (permission_to_roles or {}).items():
        for role in roles:
            output[role].add(permission)
    return output


# Parse custom role rows into role->permissions so custom roles merge cleanly
# with predefined mapping data.
def _custom_role_permissions(iam_roles_rows: Iterable[dict[str, Any]] | None) -> dict[str, set[str]]:
    output: dict[str, set[str]] = {}
    for row in iam_roles_rows or []:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        permissions = set(parse_string_list(row.get("included_permissions"), fallback_to_single=True))
        if permissions:
            output[name] = permissions
    return output


# Build and cache reusable scope/resource indexes used by downstream IAM stages.
# This stitches hierarchy data with observed IAM resources and compute runtime
# state so selector expansion has a complete target set.
def build_scope_and_resource_indexes(
    *,
    hierarchy_data: dict[str, Any] | None,
    flattened_member_rows: Iterable[dict[str, Any]] | None = None,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None = None,
    service_account_rows: Iterable[dict[str, Any]] | None = None,
) -> ScopeResourceIndexes:
    """Build reusable scope/resource indexes from hierarchy + flattened IAM member rows.

    ``service_account_rows`` (and, like compute instances, other enumerated inventories)
    seed the resource index so multi-permission combo rules that select a target by
    resource type -- e.g. the ``iam.serviceAccounts.actAs`` target of a "create X as SA"
    combo -- can find every enumerated service account, not only the ones that happen to
    have their OWN allow-policy binding. Without this, such combos silently never fire.
    """
    hierarchy = hierarchy_data or {}
    scope_project_by_name = hierarchy["scope_project_by_name"] if hierarchy else {}
    scope_display_by_name = hierarchy["scope_display_by_name"] if hierarchy else {}
    scope_type_by_name = hierarchy["scope_type_by_name"] if hierarchy else {}
    known_project_ids = set(hierarchy["known_project_ids"]) if hierarchy else set()
    project_id_by_scope_name: dict[str, str] = {}
    project_scope_by_project_id: dict[str, str] = {}

    for scope_name, scope_type in scope_type_by_name.items():
        token = str(scope_name or "").strip()
        if not token or canonical_scope_type_for_bindings(str(scope_type or ""), token) != "project":
            continue
        project_id = str(scope_project_by_name.get(token) or "").strip() or _scope_leaf(token)
        if not project_id:
            continue
        known_project_ids.add(project_id)
        project_id_by_scope_name[token] = project_id
        project_scope_by_project_id[project_id] = token

    allow_resources: list[dict[str, str]] = []
    seen_resources: set[tuple[str, str, str]] = set()
    for row in flattened_member_rows or []:
        resource_name = str(row.get("name") or "").strip()
        if not resource_name:
            continue
        resource_type = canonical_scope_type_for_bindings(str(row.get("type") or "").strip(), resource_name)
        resolved_project_id = str(row.get("project_id") or "").strip()
        if resource_type == "project":
            resolved_project_id = (
                resolved_project_id or project_id_by_scope_name.get(resource_name, "") or _scope_leaf(resource_name)
            )
            if resolved_project_id:
                known_project_ids.add(resolved_project_id)
                project_scope_by_project_id.setdefault(resolved_project_id, resource_name)
                project_id_by_scope_name.setdefault(resource_name, resolved_project_id)
        resource_key_tuple = (resource_name, resource_type, resolved_project_id)
        if resource_key_tuple in seen_resources:
            continue
        seen_resources.add(resource_key_tuple)
        allow_resources.append(
            {
                "resource_name": resource_name,
                "resource_type": resource_type,
                "display_name": str(row.get("display_name") or "").strip()
                or str(scope_display_by_name.get(resource_name) or ""),
                "project_id": resolved_project_id,
            }
        )

    # Enrich compute instance resources with runtime status from cached
    # cloudcompute_instances rows so rule selectors can reason about
    # start/reset viability by instance state.
    # Also ensure compute instances exist as selector targets even when
    # no per-instance IAM policy rows were cached.
    compute_status_by_resource_name: dict[str, str] = {}
    for row in cloudcompute_instances_rows or []:
        project_id = str(row.get("project_id") or "").strip()
        instance_name = str(row.get("name") or "").strip()
        zone = str(row.get("zone") or "").strip()
        if "/" in zone:
            zone = _scope_leaf(zone)
        status = str(row.get("status") or row.get("state") or "").strip().upper()
        if status:
            if project_id and instance_name and zone:
                full_name = f"projects/{project_id}/zones/{zone}/instances/{instance_name}"
                compute_status_by_resource_name[full_name] = status
            if instance_name:
                compute_status_by_resource_name.setdefault(instance_name, status)

        if not (project_id and instance_name):
            continue
        resource_name = f"projects/{project_id}/zones/{zone}/instances/{instance_name}" if zone else instance_name
        resource_key_tuple = (resource_name, "computeinstance", project_id)
        if resource_key_tuple in seen_resources:
            continue
        seen_resources.add(resource_key_tuple)
        allow_resources.append(
            {
                "resource_name": resource_name,
                "resource_type": "computeinstance",
                "display_name": instance_name,
                "project_id": project_id,
            }
        )

    for resource in allow_resources:
        if str(resource.get("resource_type") or "").strip().lower() != "computeinstance":
            continue
        resource_name = str(resource.get("resource_name") or "").strip()
        if not resource_name:
            continue
        status = compute_status_by_resource_name.get(resource_name)
        if not status and "/" in resource_name:
            status = compute_status_by_resource_name.get(_scope_leaf(resource_name))
        if status:
            resource["status"] = status

    # Ensure every ENUMERATED service account is a selectable combo target (resource_type
    # "service-account", keyed by email like allow-policy SA rows) even when the SA has no
    # IAM policy of its own -- otherwise actAs-target combos never fire against it.
    for row in service_account_rows or []:
        email = str(row.get("email") or "").strip()
        if not email:
            name = str(row.get("name") or "").strip()
            email = _scope_leaf(name) if name else ""
        if not email:
            continue
        project_id = str(row.get("project_id") or "").strip()
        resource_key_tuple = (email, "service-account", project_id)
        if resource_key_tuple in seen_resources:
            continue
        seen_resources.add(resource_key_tuple)
        allow_resources.append(
            {
                "resource_name": email,
                "resource_type": "service-account",
                "display_name": email,
                "project_id": project_id,
            }
        )

    allow_resources_by_project: dict[str, list[dict[str, str]]] = defaultdict(list)
    allow_resources_by_project_type: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for resource in allow_resources:
        project_key = str(resource.get("project_id") or "").strip()
        if not project_key:
            continue
        resource_type = str(resource.get("resource_type") or "").strip().lower()
        allow_resources_by_project[project_key].append(resource)
        if resource_type:
            allow_resources_by_project_type[project_key][resource_type].append(resource)

    return ScopeResourceIndexes(
        project_scope_by_project_id=project_scope_by_project_id,
        project_id_by_scope_name=project_id_by_scope_name,
        known_project_ids=known_project_ids,
        allow_resources=allow_resources,
        allow_resources_by_project={k: list(v) for k, v in allow_resources_by_project.items()},
        allow_resources_by_project_type={
            project_id: {resource_type: list(resources) for resource_type, resources in type_map.items()}
            for project_id, type_map in allow_resources_by_project_type.items()
        },
    )


# Build a consistent stats payload for base/advanced IAM dangerous-edge passes.
def _result_payload(
    *,
    before_nodes: int,
    before_edges: int,
    binding_result: dict[str, object],
    defaults: dict[str, object] | None = None,
) -> dict[str, object]:
    defaults = dict(defaults or {})
    after_nodes, after_edges = binding_result.get("_counts", (before_nodes, before_edges))
    payload: dict[str, object] = {
        **defaults,
        "dangerous_rule_mode": str(binding_result.get("dangerous_rule_mode") or defaults.get("dangerous_rule_mode") or ""),
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
    payload.update(
        {
            key: int(binding_result.get(key, defaults.get(key, 0)))
            for key in _RESULT_STAT_KEYS
        }
    )
    return payload


def _emit_binding_pass(
    context,
    *,
    rules: tuple[dict[str, Any], ...],
    include_all: bool,
    pass_name: str,
    artifact_prefix: str,
    defaults: dict[str, object] | None = None,
) -> dict[str, object]:
    before_nodes, before_edges = context.counts()
    resolved_entries = context.get_artifact("resolved_bindings_composite")
    binding_result = dict(
        _emit_iam_binding_edges_from_entries(
            context,
            entries=resolved_entries if isinstance(resolved_entries, list) else [],
            include_all=include_all,
            dangerous_rules=rules,
            pass_name=pass_name,
        )
    )
    context.set_artifact(f"{artifact_prefix}_state", binding_result.get("aggregation") or {})
    context.set_artifact(f"{artifact_prefix}_runtime", binding_result.get("runtime") or {})
    after_nodes, after_edges = context.counts()
    binding_result["_counts"] = (after_nodes, after_edges)
    return _result_payload(
        before_nodes=before_nodes,
        before_edges=before_edges,
        binding_result=binding_result,
        defaults=defaults,
    )


# Emit single-permission IAM dangerous-rule edges from resolved binding entries.
def build_iam_bindings_single_permissions(context) -> dict[str, object]:
    unsupported_rule_names = {
        rule_name
        for rule_name in (context.get_artifact("binding_unsupported_rule_names") or [])
        if rule_name
    }
    single_rules, _multi_rules = _dangerous_rules_by_family(context)
    rules = tuple(rule for rule in single_rules if rule.get("name") not in unsupported_rule_names)

    return _emit_binding_pass(
        context,
        rules=rules,
        include_all=bool(context.options.include_all),
        pass_name="base",
        artifact_prefix="iam_bindings_base",
        defaults={
            "include_all": bool(context.options.include_all),
            "expand_inheritance": bool(context.options.expand_inheritance),
            "conditional_evaluation": bool(context.options.conditional_evaluation),
            "dangerous_rule_mode": "base",
        },
    )


# Emit multi-permission/combo IAM dangerous-rule edges from resolved entries.
def build_iam_bindings_multi_permission_graph(context) -> dict[str, object]:
    before_nodes, before_edges = context.counts()
    base_state_present = bool(context.get_artifact("iam_bindings_base_state"))
    resolved_entries = context.get_artifact("resolved_bindings_composite")
    reused_base_entries = isinstance(resolved_entries, list) and bool(resolved_entries)

    unsupported_rule_names = {
        rule_name
        for rule_name in (context.get_artifact("binding_unsupported_rule_names") or [])
        if rule_name
    }
    _single_rules, multi_rules = _dangerous_rules_by_family(context)
    rules = tuple(rule for rule in multi_rules if rule.get("name") not in unsupported_rule_names)
    if not rules:
        return _result_payload(
            before_nodes=before_nodes,
            before_edges=before_edges,
            binding_result={"dangerous_rule_mode": "advanced", "_counts": (before_nodes, before_edges)},
            defaults={
                "base_state_present": base_state_present,
                "reused_base_entries": reused_base_entries,
            },
        )

    return _emit_binding_pass(
        context,
        rules=rules,
        include_all=False,
        pass_name="advanced",
        artifact_prefix="iam_bindings_advanced",
        defaults={
            "dangerous_rule_mode": "advanced",
            "base_state_present": base_state_present,
            "reused_base_entries": reused_base_entries,
        },
    )


# Expand one logical binding into concrete BindingPlusScopeEntry rows.
# Fan-out dimensions:
# - inheritance: org/folder grants can apply to descendant scopes
# - conditions: one condition can evaluate into multiple narrowed options
#
# For each resulting effective scope + condition option, emit one entry with
# source/effective scope metadata and condition selector metadata.
#
# Mini example (no inheritance, no condition fan-out):
# Input:
# - role_token="roles/storage.objectViewer"
# - attached_scope="projects/123456789012"
# - attached_type="project"
# - effective_scopes => ["projects/123456789012"]
# - option_list => [default]
#
# Output appended to `entries` (count = 1):
# - BindingPlusScopeEntry(
#     role_name="roles/storage.objectViewer",
#     attached_scope_name="projects/123456789012",
#     effective_scope_name="projects/123456789012",
#     inherited=False,
#     condition_option_id="default",
#     ...
#   )
#
# Mini example (folder inheritance + 2 condition options):
# Input:
# - attached_scope="folders/456789012345"
# - attached_type="folder"
# - descendants => ["projects/a", "projects/b"]
# - option_list => ["opt_1", "opt_2"]
#
# Output appended to `entries` (count = 6):
# - 3 scopes (folder + 2 descendant projects) x 2 options
# - Each row gets a unique binding_composite_id suffix when needed and
#   carries the specific condition option metadata for that row.
def _append_scoped_binding_entries(
    *,
    entries: list[BindingPlusScopeEntry],
    common_entry_fields: dict[str, Any],
    binding_ctx: dict[str, Any],
    expansion: _ScopedExpansionContext,
) -> None:
    attached_scope = binding_ctx["attached_scope"]
    attached_type = binding_ctx["attached_type"]
    role_token = binding_ctx["role_token"]
    project_id = binding_ctx["project_id"]
    cond_hash = binding_ctx["cond_hash"]
    attached_scope_ref = binding_ctx["attached_scope_ref"]
    source_scope_display = binding_ctx["source_scope_display"]
    condition_dict = binding_ctx["condition_dict"]
    condition_expr_raw = str(condition_dict.get("expression") or "").strip() if isinstance(condition_dict, dict) else ""

    effective_scopes = [attached_scope]
    if expansion.expand_inheritance and attached_type in {"org", "folder"}:
        effective_scopes.extend(_descendants(expansion.children_by_parent, attached_scope))

    option_list: list[ConditionOption] = (
        expansion.conditionals.evaluate_options(condition_dict)
        if expansion.conditional_evaluation
        else [_DEFAULT_CONDITION_OPTION]
    )
    static_entry_fields = {
        "source_scope_name": attached_scope,
        "source_scope_type": attached_type,
        "source_scope_display": source_scope_display,
        "source": "iam_allow_policies",
        "condition_expr_raw": condition_expr_raw,
        "condition_hash": cond_hash,
    }

    for option in option_list:
        option_scopes = (
            expansion.conditionals.narrow_with_option(effective_scopes, option)
            if expansion.conditional_evaluation
            else effective_scopes
        )
        option_fields = {
            "condition_option_id": str(option.option_id or "default"),
            "condition_option_summary": str(option.filter_summary or ""),
            "condition_services": normalized_token_frozenset(option.narrowed_services),
            "condition_resource_types": normalized_token_frozenset(option.narrowed_resource_types),
            "condition_name_prefixes": normalized_token_frozenset(option.narrowed_prefixes),
            "condition_name_equals": normalized_token_frozenset(option.narrowed_equals),
        }

        for effective_scope in option_scopes:
            effective_scope_type = expansion.scope_type_by_name.get(effective_scope, attached_type)
            effective_scope_display = expansion.scope_display_by_name.get(effective_scope) or _scope_leaf(effective_scope)
            entry_project_id = expansion.project_id_by_scope.get(effective_scope) or project_id
            emitted_scope_ref = binding_scope_token(
                effective_scope_type,
                effective_scope,
                project_id=entry_project_id,
            )
            entries.append(
                BindingPlusScopeEntry(
                    **common_entry_fields,
                    **static_entry_fields,
                    **option_fields,
                    binding_composite_id=_binding_composite_id(
                        role_name=role_token,
                        attached_scope_token=emitted_scope_ref,
                        source_scope_token=attached_scope_ref,
                        condition_hash=cond_hash,
                    ),
                    attached_scope_name=effective_scope,
                    attached_scope_type=effective_scope_type,
                    attached_scope_display=effective_scope_display,
                    effective_scope_name=effective_scope,
                    effective_scope_type=effective_scope_type,
                    effective_scope_display=effective_scope_display,
                    project_id=entry_project_id,
                    inherited=effective_scope != attached_scope,
                )
            )


# Expand raw IAM binding rows into normalized BindingPlusScopeEntry objects,
# including inheritance fan-out and condition option narrowing.
def _section_build_binding_entries(
    *,
    context,
    scope_resource_indexes: ScopeResourceIndexes,
    member_binding_index: dict[str, Any],
    role_to_permissions: dict[str, set[str]],
    expand_inheritance: bool,
    conditional_evaluation: bool,
) -> list[BindingPlusScopeEntry]:
    # Convert canonical `binding_records` rows into normalized
    # BindingPlusScopeEntry rows.
    #
    # Example input record (from member_binding_index[*][*]["binding_records"]):
    # {
    #   "role_name": "roles/storage.objectViewer",
    #   "attached_scope_type": "project",
    #   "attached_scope_name": "projects/123456789012",
    #   "project_id": "my-project",
    #   "condition": {"expression": "resource.name.startsWith('projects/_/buckets/prod-')"},
    #   "record_origin": "direct" | "convenience",
    #   "derived_from": "projectViewer:my-project"  # convenience-only
    # }
    #
    # Example output entries:
    # - 1 direct entry for project scope (when no inheritance/condition fan-out)
    # - N entries when:
    #   - org/folder inheritance expands to descendant scopes, and/or
    #   - condition evaluation yields multiple narrowed options.
    hierarchy = context.hierarchy_data()
    scope_type_by_name = hierarchy["scope_type_by_name"]
    scope_display_by_name = hierarchy["scope_display_by_name"]
    conditionals = StatementConditionalsEngine(enabled=conditional_evaluation)
    entries: list[BindingPlusScopeEntry] = []
    expansion = _ScopedExpansionContext(
        conditional_evaluation=conditional_evaluation,
        conditionals=conditionals,
        expand_inheritance=expand_inheritance,
        children_by_parent=hierarchy["children_by_parent"],
        scope_type_by_name=scope_type_by_name,
        scope_display_by_name=scope_display_by_name,
        project_id_by_scope=scope_resource_indexes.project_id_by_scope_name,
    )
    total_members = len(member_binding_index)
    total_resources = 0
    total_binding_records = 0
    for resource_map in member_binding_index.values():
        if not isinstance(resource_map, dict):
            continue
        total_resources += len(resource_map)
        for payload in resource_map.values():
            if not isinstance(payload, dict):
                continue
            binding_records = payload.get("binding_records") or []
            if isinstance(binding_records, list):
                total_binding_records += len(binding_records)
    print(
        "[*] Stage 2 tally: "
        f"members={total_members}, resources={total_resources}, binding_records={total_binding_records}"
    )
    processed_members = 0
    processed_resources = 0
    processed_binding_records = 0

    for member_key, resource_map in member_binding_index.items():
        processed_members += 1
        _print_stage2_progress_inline(
            processed_members=processed_members,
            total_members=total_members,
            processed_resources=processed_resources,
            total_resources=total_resources,
            processed_binding_records=processed_binding_records,
            total_binding_records=total_binding_records,
        )
        if not isinstance(resource_map, dict):
            continue

        member_token = principal_node_id(member_key)

        # Step through each resoruce for a given member and its correspnding bindings
        for payload in resource_map.values():
            processed_resources += 1
            _print_stage2_progress_inline(
                processed_members=processed_members,
                total_members=total_members,
                processed_resources=processed_resources,
                total_resources=total_resources,
                processed_binding_records=processed_binding_records,
                total_binding_records=total_binding_records,
            )
            if not isinstance(payload, dict):
                continue
            binding_records = payload.get("binding_records") or []
            if not isinstance(binding_records, list):
                continue

            # Step through each binding for a given resource for a given member
            for raw_record in binding_records:
                processed_binding_records += 1
                _print_stage2_progress_inline(
                    processed_members=processed_members,
                    total_members=total_members,
                    processed_resources=processed_resources,
                    total_resources=total_resources,
                    processed_binding_records=processed_binding_records,
                    total_binding_records=total_binding_records,
                )
                
                # Inherited rows are generated from direct rows during simplification.
                # Skip them here and rely on this stage's fan-out logic.
                if raw_record.get("record_origin") == "inherited":
                    continue

                # Clone the source binding record and attach only the computed fields
                # needed by fan-out/emission. This keeps the flow close to upstream data.
                binding_ctx = dict(raw_record)
                condition = binding_ctx.get("condition") if isinstance(binding_ctx.get("condition"), dict) else None
                attached_scope_name = binding_ctx["attached_scope_name"]
                role_name = binding_ctx["role_name"]
                attached_type = canonical_scope_type_for_bindings(
                    binding_ctx["attached_scope_type"],
                    attached_scope_name,
                )
                project_id = binding_ctx.get("project_id", "")
                cond_hash = _condition_hash(condition)
                attached_scope_ref = binding_scope_token(attached_type, attached_scope_name, project_id=project_id)
                source_scope_display = str(scope_display_by_name.get(attached_scope_name) or attached_scope_ref)

                binding_ctx.update(
                    {
                        "role_token": role_name,
                        "attached_scope": attached_scope_name,
                        "attached_type": attached_type,
                        "project_id": project_id,
                        "cond_hash": cond_hash,
                        "attached_scope_ref": attached_scope_ref,
                        "source_scope_display": source_scope_display,
                        "condition_dict": condition,
                    }
                )

                common_entry_fields = {
                    # str; graph principal node key, ex: "user:alice@example.com"
                    "principal_id": member_token,
                    # str; convenience source if expanded, ex: "projectViewer:my-project"
                    "expanded_from_convenience_member": binding_ctx.get("derived_from", ""),
                    # str; IAM role bound on source scope, ex: "roles/storage.objectViewer"
                    "role_name": role_name,
                    # frozenset[str]; resolved role permissions, ex: {"storage.objects.get", ...}
                    "permissions": frozenset(role_to_permissions.get(role_name, ())),
                }

                # Fan out into effective-scope rows.
                # This is where one binding can become many entries:
                # - inheritance fan-out: org/folder -> descendant projects/folders
                # - condition fan-out: one condition -> multiple narrowed options
                #
                # Each emitted BindingPlusScopeEntry keeps:
                # - source scope metadata (where role is granted)
                # - effective scope metadata (where role applies after fan-out)
                # - condition option metadata (for conditional narrowing downstream)
                _append_scoped_binding_entries(
                    entries=entries,
                    common_entry_fields=common_entry_fields,
                    binding_ctx=binding_ctx,
                    expansion=expansion,
                )

    _print_stage2_progress_inline(
        processed_members=processed_members,
        total_members=total_members,
        processed_resources=processed_resources,
        total_resources=total_resources,
        processed_binding_records=processed_binding_records,
        total_binding_records=total_binding_records,
        force=True,
    )

    # Output: normalized list consumed by base and advanced IAM edge emitters.
    return entries


# Stage 29 public entrypoint:
# resolve all IAM bindings into normalized composite entries and publish them as
# context artifact `resolved_bindings_composite` for later graph-emission stages.
def build_resolved_binding_entries(
    context,
) -> list[BindingPlusScopeEntry]:
    """
    Build normalized IAM binding+scope entries used by all IAM graph passes.

    Input sources:
    - simplified hierarchy IAM bindings (`member_binding_index`)
    - custom role definitions (`iam_custom_roles`)
    - hierarchy/scope indexes from context

    What this does:
    - expands each IAM binding into typed objects (one object per principal+role+effective scope)
    - resolves role -> permission sets (predefined map + custom role permissions)
    - fans out inherited scope coverage (org/folder -> descendants) when enabled
    - applies conditional option expansion/narrowing metadata when enabled
    - emits single-permission and multi-permission IAM dangerous-edge graph relationships

    Output:
    - list[BindingPlusScopeEntry] where each row has principal, role, permissions,
      source/attached/effective scope metadata, inheritance flags, and condition metadata
    - writes entries to `resolved_bindings_composite` and merged emit stats to
      `iam_policy_bindings_stage_stats`
    """
    # ---------------------------------------------------------------------
    # SECTION 10: Load role/permission maps and record dangerous-rule coverage
    # ---------------------------------------------------------------------
    scope_resource_indexes = context.scope_resource_indexes()
    simplified_base = context.simplified_hierarchy_permissions(include_inferred_permissions=False)
    member_binding_index = simplified_base["member_binding_index"]
    expand_inheritance = bool(context.options.expand_inheritance)
    conditional_evaluation = bool(context.options.conditional_evaluation)
    iam_roles_rows = context.rows("iam_custom_roles")

    permission_to_roles = _load_permission_to_roles()
    role_to_permissions = _invert_permission_to_roles(permission_to_roles)
    for role_name, perms in _custom_role_permissions(iam_roles_rows).items():
        role_to_permissions.setdefault(role_name, set()).update(perms)
    normalized_single_rules, normalized_multi_rules = _dangerous_rules_by_family(context)
    binding_permission_coverage = _binding_rule_permission_map_coverage(
        permission_to_roles=permission_to_roles,
        single_rules=normalized_single_rules,
        multi_rules=normalized_multi_rules,
    )
    context.set_artifact("binding_permission_map_coverage", binding_permission_coverage)
    context.set_artifact("binding_unsupported_rule_names", list(binding_permission_coverage.get("unsupported_rule_names") or []))
    context.set_artifact("binding_unmapped_permissions", list(binding_permission_coverage.get("unmapped_permissions") or []))

    # ---------------------------------------------------------------------
    # SECTION 20: Expand raw binding rows into normalized composite entries
    # ---------------------------------------------------------------------
    # `member_binding_index` is keyed by principal member, then by resource.
    # We iterate each member -> resource -> binding-record set and emit normalized
    # BindingPlusScopeEntry rows for downstream edge generation.
    #
    # Mini example input shape:
    # {
    #   "user:alice@example.com": {
    #     "projects/my-project": {
    #       "binding_records": [
    #         {
    #           "role_name": "roles/storage.objectViewer",
    #           "attached_scope_name": "projects/123456789012",
    #           "attached_scope_type": "project",
    #           "project_id": "my-project",
    #           "record_origin": "direct"
    #         }
    #       ]
    #     }
    #   }
    # }
    #
    # Example output:
    # - one entry per effective scope/condition option, e.g.
    #   principal_id="user:alice@example.com", role_name="roles/storage.objectViewer",
    #   attached_scope_name="projects/123456789012", inherited=False
    entries = _section_build_binding_entries(
        context=context,
        scope_resource_indexes=scope_resource_indexes,
        member_binding_index=member_binding_index,
        role_to_permissions=role_to_permissions,
        expand_inheritance=expand_inheritance,
        conditional_evaluation=conditional_evaluation,
    )

    # ---------------------------------------------------------------------
    # SECTION 30: Publish artifact for downstream IAM binding emitters
    # ---------------------------------------------------------------------
    context.set_artifact("resolved_bindings_composite", entries)

    # ---------------------------------------------------------------------
    # SECTION 40: Emit single-permission IAM dangerous edges
    # ---------------------------------------------------------------------
    step_stats = build_iam_bindings_single_permissions(context) or {}

    # ---------------------------------------------------------------------
    # SECTION 50: Emit multi-permission/combo IAM dangerous edges
    # ---------------------------------------------------------------------
    advanced_step_stats = build_iam_bindings_multi_permission_graph(context) or {}
    step_stats.update({f"advanced_{key}": value for key, value in dict(advanced_step_stats).items()})
    context.set_artifact("iam_policy_bindings_stage_stats", step_stats)
    return entries
