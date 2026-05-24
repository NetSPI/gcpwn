from __future__ import annotations

"""
Stage 50: inferred-permission graphing.

Merged module containing:
- entry building (formerly stage 51)
- inferred edge emission (formerly stage 52)
- top-level orchestrator for the OpenGraph pipeline
"""

from collections import deque
import hashlib
from typing import Any, Iterable

from gcpwn.core.utils.iam_simplifier import split_member_credname_key
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_event_helpers import (
    collect_rule_events as _collect_rule_events_shared,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    gcp_resource_node_type,
    principal_member_properties,
    principal_type,
    principal_node_id,
    role_agent_metadata,
    resource_display_label,
    resource_location_token,
    resource_node_id,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
    ScopeResourceIndexes,
    canonical_scope_type_for_bindings,
    load_normalized_dangerous_rules_by_family,
    _scope_leaf,
    parse_scoped_resource_key,
    binding_scope_token,
    existing_binding_rule_targets,
    _effective_scope_target,
    _matches_for_group,
    _normalize_binding_permission_map,
    _scope_target_matches_selector,
    _target_candidates_for_entry,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.normalization import normalized_token_list


# Inferred-permissions graphing intentionally skips IAM-condition evaluation.
# We only review the credential permission summary and materialize:
#   principal -> HAS_IMPLIED_PERMISSIONS -> implied-IAM-binding -> INFERRED_<EDGE_NAME> -> resource


def build_inferred_entries(context) -> tuple[list[BindingPlusScopeEntry], dict[str, dict[str, Any]]]:
    # Section A: load hierarchy context and aggregate raw inferred permission rows.
    hierarchy = context.hierarchy_data()
    scope_display_by_name = hierarchy.get("scope_display_by_name") or {}
    project_scope_by_name = hierarchy.get("scope_project_by_name") or {}
    scope_type_by_name = hierarchy.get("scope_type_by_name") or {}
    children_by_parent = hierarchy.get("children_by_parent") or {}
    expand_inheritance = bool(getattr(context.options, "expand_inheritance", False))
    aggregated: dict[tuple[str, str], dict[str, Any]] = {}
    simplified_with_inferred = context.simplified_hierarchy_permissions(include_inferred_permissions=True)
    member_inferred_permissions_index = dict(simplified_with_inferred.get("member_inferred_permissions_index") or {})
    for member_credname_key_raw, resource_map in member_inferred_permissions_index.items():
        member_credname_key = str(member_credname_key_raw or "").strip()
        split_key = split_member_credname_key(member_credname_key)
        if not split_key:
            continue
        principal_member_raw, credname_raw = split_key
        principal_member = principal_node_id(principal_member_raw)
        credname = str(credname_raw or "").strip()
        if not principal_member or not credname or not isinstance(resource_map, dict):
            continue
        for resource_key, inferred_payload in resource_map.items():
            resource_key_token = str(resource_key or "").strip()
            parsed = parse_scoped_resource_key(resource_key_token)
            if not parsed:
                continue
            scope_type, scope_name, project_id = parsed
            scope_display = str(scope_display_by_name.get(scope_name) or "").strip() or scope_name
            resolved_project_id = str(project_id or "").strip() or str(project_scope_by_name.get(scope_name) or "").strip()
            raw_permissions = inferred_payload
            normalized_permissions = {
                str(permission or "").strip()
                for permission in (raw_permissions if isinstance(raw_permissions, (list, tuple, set)) else [raw_permissions])
                if str(permission or "").strip()
            }
            if not normalized_permissions:
                continue
            key = (principal_member, resource_key_token)
            bucket = aggregated.setdefault(
                key,
                {
                    "principal_member": principal_member,
                    "resource_key": resource_key_token,
                    "scope_type": scope_type,
                    "scope_name": scope_name,
                    "scope_display": scope_display,
                    "project_id": resolved_project_id,
                    "permissions": set(),
                    "crednames": set(),
                    "permission_crednames": {},
                },
            )
            bucket["permissions"].update(normalized_permissions)
            bucket["crednames"].add(credname)
            for permission in normalized_permissions:
                permission_token = str(permission or "").strip()
                if not permission_token:
                    continue
                bucket["permission_crednames"].setdefault(permission_token, set()).add(credname)

    descendant_project_cache: dict[str, list[str]] = {}

    def _descendant_project_scopes(root_scope: str) -> list[str]:
        root = str(root_scope or "").strip()
        if not root:
            return []
        cached = descendant_project_cache.get(root)
        if cached is not None:
            return list(cached)
        seen = {root}
        queue: deque[str] = deque(children_by_parent.get(root, []) or [])
        projects: list[str] = []
        while queue:
            current = str(queue.popleft() or "").strip()
            if not current or current in seen:
                continue
            seen.add(current)
            current_type = canonical_scope_type_for_bindings(
                str(scope_type_by_name.get(current) or "").strip(),
                current,
            )
            if current_type == "project":
                projects.append(current)
            queue.extend(children_by_parent.get(current, []) or [])
        descendant_project_cache[root] = sorted(set(projects))
        return list(descendant_project_cache[root])

    entry_groups: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    project_permission_sources: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _ensure_group(
        *,
        principal_member: str,
        effective_scope_name: str,
        effective_scope_type: str,
        effective_scope_display: str,
        source_scope_name: str,
        source_scope_type: str,
        source_scope_display: str,
        project_id: str,
    ) -> dict[str, Any]:
        group_key = (
            str(principal_member or "").strip(),
            str(effective_scope_name or "").strip(),
            str(effective_scope_type or "").strip(),
            str(source_scope_name or "").strip(),
            str(source_scope_type or "").strip(),
            str(project_id or "").strip(),
        )
        return entry_groups.setdefault(
            group_key,
            {
                "principal_member": str(principal_member or "").strip(),
                "effective_scope_name": str(effective_scope_name or "").strip(),
                "effective_scope_type": str(effective_scope_type or "").strip(),
                "effective_scope_display": str(effective_scope_display or "").strip() or str(effective_scope_name or "").strip(),
                "source_scope_name": str(source_scope_name or "").strip(),
                "source_scope_type": str(source_scope_type or "").strip(),
                "source_scope_display": str(source_scope_display or "").strip() or str(source_scope_name or "").strip(),
                "project_id": str(project_id or "").strip(),
                "permissions": set(),
                "crednames": set(),
                "resource_keys": set(),
                "permission_crednames": {},
            },
        )

    for principal_member, resource_key in sorted(aggregated.keys()):
        payload = aggregated[(principal_member, resource_key)]
        scope_name = str(payload.get("scope_name") or "").strip()
        raw_scope_type = str(payload.get("scope_type") or "").strip()
        scope_type = canonical_scope_type_for_bindings(raw_scope_type, scope_name)
        if not scope_name or not scope_type:
            continue
        normalized_row = {
            "principal_member": str(payload.get("principal_member") or principal_member).strip(),
            "resource_key": str(payload.get("resource_key") or resource_key).strip(),
            "scope_name": scope_name,
            "scope_type": scope_type,
            "scope_display": str(payload.get("scope_display") or "").strip() or scope_name,
            "project_id": str(payload.get("project_id") or "").strip() or str(project_scope_by_name.get(scope_name) or "").strip(),
            "permissions": set(payload.get("permissions") or set()),
            "crednames": set(payload.get("crednames") or set()),
            "permission_crednames": {
                str(permission or "").strip(): set(crednames or set())
                for permission, crednames in (payload.get("permission_crednames") or {}).items()
                if str(permission or "").strip()
            },
        }
        if scope_type != "project":
            bucket = _ensure_group(
                principal_member=normalized_row["principal_member"],
                effective_scope_name=scope_name,
                effective_scope_type=scope_type,
                effective_scope_display=normalized_row["scope_display"],
                source_scope_name=scope_name,
                source_scope_type=scope_type,
                source_scope_display=normalized_row["scope_display"],
                project_id=normalized_row["project_id"],
            )
            bucket["permissions"].update(normalized_row["permissions"])
            bucket["crednames"].update(normalized_row["crednames"])
            for permission, crednames in (normalized_row.get("permission_crednames") or {}).items():
                permission_token = str(permission or "").strip()
                if not permission_token:
                    continue
                bucket["permission_crednames"].setdefault(permission_token, set()).update(crednames or set())
            if normalized_row["resource_key"]:
                bucket["resource_keys"].add(normalized_row["resource_key"])

        # Project-scoped sources always contribute to project_permission_sources.
        if scope_type == "project":
            project_scope = scope_name
            project_display = normalized_row["scope_display"]
            project_id = normalized_row["project_id"] or str(project_scope_by_name.get(project_scope) or "").strip() or _scope_leaf(project_scope)
            for permission in sorted(normalized_row["permissions"]):
                permission_token = str(permission or "").strip()
                if not permission_token:
                    continue
                permission_crednames = set(
                    (normalized_row.get("permission_crednames") or {}).get(permission_token) or set()
                ) or set(normalized_row["crednames"])
                pkey = (normalized_row["principal_member"], project_scope, permission_token)
                existing = project_permission_sources.get(pkey)
                if existing is not None:
                    existing["crednames"].update(permission_crednames)
                    if normalized_row["resource_key"]:
                        existing["resource_keys"].add(normalized_row["resource_key"])
                    continue
                project_permission_sources[pkey] = {
                    "rank": 1,
                    "principal_member": normalized_row["principal_member"],
                    "effective_scope_name": project_scope,
                    "effective_scope_type": "project",
                    "effective_scope_display": project_display,
                    "source_scope_name": project_scope,
                    "source_scope_type": "project",
                    "source_scope_display": project_display,
                    "project_id": project_id,
                    "permission": permission_token,
                    "crednames": set(permission_crednames),
                    "resource_keys": {normalized_row["resource_key"]} if normalized_row["resource_key"] else set(),
                }
            continue

        # Org/folder rows can be inherited into descendant project scopes.
        if not expand_inheritance or scope_type not in {"org", "folder"}:
            continue

        scope_rank = 3 if scope_type == "org" else 2
        for project_scope in _descendant_project_scopes(scope_name):
            project_scope = str(project_scope or "").strip()
            if not project_scope:
                continue
            project_display = str(scope_display_by_name.get(project_scope) or "").strip() or project_scope
            project_id = (
                str(project_scope_by_name.get(project_scope) or "").strip()
                or str(normalized_row["project_id"] or "").strip()
                or _scope_leaf(project_scope)
            )
            for permission in sorted(normalized_row["permissions"]):
                permission_token = str(permission or "").strip()
                if not permission_token:
                    continue
                permission_crednames = set(
                    (normalized_row.get("permission_crednames") or {}).get(permission_token) or set()
                ) or set(normalized_row["crednames"])
                pkey = (normalized_row["principal_member"], project_scope, permission_token)
                existing = project_permission_sources.get(pkey)
                if not existing or scope_rank > int(existing.get("rank", 0)):
                    project_permission_sources[pkey] = {
                        "rank": scope_rank,
                        "principal_member": normalized_row["principal_member"],
                        "effective_scope_name": project_scope,
                        "effective_scope_type": "project",
                        "effective_scope_display": project_display,
                        "source_scope_name": scope_name,
                        "source_scope_type": scope_type,
                        "source_scope_display": normalized_row["scope_display"],
                        "project_id": project_id,
                        "permission": permission_token,
                        "crednames": set(permission_crednames),
                        "resource_keys": {normalized_row["resource_key"]} if normalized_row["resource_key"] else set(),
                    }
                    continue
                if scope_rank == int(existing.get("rank", 0)):
                    existing["crednames"].update(permission_crednames)
                    if normalized_row["resource_key"]:
                        existing["resource_keys"].add(normalized_row["resource_key"])

    for source_row in project_permission_sources.values():
        bucket = _ensure_group(
            principal_member=str(source_row.get("principal_member") or "").strip(),
            effective_scope_name=str(source_row.get("effective_scope_name") or "").strip(),
            effective_scope_type=str(source_row.get("effective_scope_type") or "").strip() or "project",
            effective_scope_display=str(source_row.get("effective_scope_display") or "").strip(),
            source_scope_name=str(source_row.get("source_scope_name") or "").strip(),
            source_scope_type=str(source_row.get("source_scope_type") or "").strip(),
            source_scope_display=str(source_row.get("source_scope_display") or "").strip(),
            project_id=str(source_row.get("project_id") or "").strip(),
        )
        permission_token = str(source_row.get("permission") or "").strip()
        if permission_token:
            bucket["permissions"].add(permission_token)
            bucket["permission_crednames"].setdefault(permission_token, set()).update(
                source_row.get("crednames") or set()
            )
        bucket["crednames"].update(source_row.get("crednames") or set())
        bucket["resource_keys"].update(source_row.get("resource_keys") or set())

    # Section D: build BindingPlusScopeEntry outputs + metadata used by stage 52.
    entries: list[BindingPlusScopeEntry] = []
    entry_metadata: dict[str, dict[str, Any]] = {}
    for group_key in sorted(entry_groups.keys()):
        payload = entry_groups[group_key]
        principal_member = str(payload.get("principal_member") or "").strip()
        principal_id = principal_node_id(principal_member)
        if not principal_id:
            continue

        effective_scope_name = str(payload.get("effective_scope_name") or "").strip()
        effective_scope_type = canonical_scope_type_for_bindings(
            str(payload.get("effective_scope_type") or "").strip(),
            effective_scope_name,
        )
        source_scope_name = str(payload.get("source_scope_name") or "").strip()
        source_scope_type = canonical_scope_type_for_bindings(
            str(payload.get("source_scope_type") or "").strip(),
            source_scope_name,
        )
        project_id = str(payload.get("project_id") or "").strip()
        inherited = bool(source_scope_name and effective_scope_name and source_scope_name != effective_scope_name)

        effective_scope_ref = binding_scope_token(
            effective_scope_type,
            effective_scope_name,
            project_id=project_id,
        )
        source_scope_ref = binding_scope_token(
            source_scope_type,
            source_scope_name,
            project_id=project_id,
        )
        binding_composite_id = f"inferred:{principal_id}:{effective_scope_ref}"
        if inherited and source_scope_ref:
            binding_composite_id = f"{binding_composite_id}#src:{source_scope_ref}"

        permissions = frozenset(sorted(str(token or "").strip() for token in (payload.get("permissions") or set()) if str(token or "").strip()))
        if not permissions:
            continue

        entry = BindingPlusScopeEntry(
            principal_id=principal_id,
            expanded_from_convenience_member="",
            binding_composite_id=binding_composite_id,
            role_name=f"inferred:{effective_scope_ref}",
            permissions=permissions,
            attached_scope_name=effective_scope_name,
            attached_scope_type=effective_scope_type,
            attached_scope_display=str(payload.get("effective_scope_display") or "").strip() or effective_scope_name,
            source_scope_name=source_scope_name,
            source_scope_type=source_scope_type,
            source_scope_display=str(payload.get("source_scope_display") or "").strip() or source_scope_name,
            effective_scope_name=effective_scope_name,
            effective_scope_type=effective_scope_type,
            effective_scope_display=str(payload.get("effective_scope_display") or "").strip() or effective_scope_name,
            project_id=project_id,
            inherited=inherited,
            source="credential_permission_summary",
            condition_expr_raw="",
            condition_hash="",
            condition_option_id="default",
            condition_option_summary="",
            condition_services=frozenset(),
            condition_resource_types=frozenset(),
            condition_name_prefixes=frozenset(),
            condition_name_equals=frozenset(),
        )
        entries.append(entry)

        resource_keys = sorted(str(token or "").strip() for token in (payload.get("resource_keys") or set()) if str(token or "").strip())
        entry_metadata[binding_composite_id] = {
            "crednames": sorted(str(token or "").strip() for token in (payload.get("crednames") or set()) if str(token or "").strip()),
            "resource_key": resource_keys[0] if resource_keys else "",
            "resource_keys": resource_keys,
            "permission_crednames": {
                str(permission or "").strip(): sorted(
                    str(credname or "").strip()
                    for credname in (crednames or set())
                    if str(credname or "").strip()
                )
                for permission, crednames in (payload.get("permission_crednames") or {}).items()
                if str(permission or "").strip()
            },
        }

    return entries, entry_metadata


def augment_scope_resource_indexes(
    base_indexes: ScopeResourceIndexes,
    entries: Iterable[BindingPlusScopeEntry],
) -> ScopeResourceIndexes:
    allow_resources = list(base_indexes.allow_resources or [])
    allow_resources_by_project = {
        str(project_id): list(rows or [])
        for project_id, rows in (base_indexes.allow_resources_by_project or {}).items()
    }
    allow_resources_by_project_type = {
        str(project_id): {str(resource_type): list(rows or []) for resource_type, rows in (resource_map or {}).items()}
        for project_id, resource_map in (base_indexes.allow_resources_by_project_type or {}).items()
    }
    seen = {
        (
            str(resource.get("resource_name") or "").strip(),
            str(resource.get("resource_type") or "").strip(),
            str(resource.get("project_id") or "").strip(),
        )
        for resource in allow_resources
    }

    for entry in entries:
        resource_name = str(entry.effective_scope_name or "").strip()
        resource_type = str(entry.effective_scope_type or "").strip()
        project_id = str(entry.project_id or "").strip()
        key = (resource_name, resource_type, project_id)
        if not resource_name or key in seen:
            continue
        seen.add(key)
        resource_row = {
            "resource_name": resource_name,
            "resource_type": resource_type,
            "display_name": str(entry.effective_scope_display or "").strip() or resource_name,
            "project_id": project_id,
        }
        allow_resources.append(resource_row)
        if project_id:
            allow_resources_by_project.setdefault(project_id, []).append(resource_row)
            allow_resources_by_project_type.setdefault(project_id, {}).setdefault(resource_type, []).append(resource_row)

    return ScopeResourceIndexes(
        project_scope_by_project_id=dict(base_indexes.project_scope_by_project_id or {}),
        project_id_by_scope_name=dict(base_indexes.project_id_by_scope_name or {}),
        known_project_ids=set(base_indexes.known_project_ids or set()),
        allow_resources=allow_resources,
        allow_resources_by_project=allow_resources_by_project,
        allow_resources_by_project_type=allow_resources_by_project_type,
    )

def implied_scope_for_event(
    *,
    contributors: list[BindingPlusScopeEntry],
    project_scope_by_project_id: dict[str, str],
    scope_display_by_name: dict[str, str],
    scope_type_by_name: dict[str, str],
) -> dict[str, str]:
    inherited_sources: list[tuple[int, str, str, str]] = []
    for entry in contributors:
        if not bool(entry.inherited):
            continue
        source_scope_name = str(entry.source_scope_name or "").strip()
        if not source_scope_name:
            continue
        source_scope_type = canonical_scope_type_for_bindings(
            str(entry.source_scope_type or "").strip(),
            source_scope_name,
        )
        if source_scope_type not in {"org", "folder"}:
            continue
        rank = 3 if source_scope_type == "org" else 2
        source_scope_display = (
            str(scope_display_by_name.get(source_scope_name) or "").strip()
            or str(entry.source_scope_display or "").strip()
            or source_scope_name
        )
        inherited_sources.append((rank, source_scope_name, source_scope_type, source_scope_display))

    if inherited_sources:
        inherited_sources.sort(key=lambda item: (-int(item[0]), str(item[1])))
        _rank, scope_name, scope_type, scope_display = inherited_sources[0]
        project_ids = normalized_token_list(str(entry.project_id or "").strip() for entry in contributors)
        return {
            "attached_scope_id": scope_name,
            "attached_scope_type": scope_type,
            "attached_scope_display": scope_display,
            "project_id": project_ids[0] if project_ids else "",
        }

    project_ids = normalized_token_list(str(entry.project_id or "").strip() for entry in contributors)
    project_scope_ids = normalized_token_list(
        str(project_scope_by_project_id.get(project_id) or "").strip()
        for project_id in project_ids
        if str(project_id or "").strip()
    )
    if project_scope_ids:
        scope_name = project_scope_ids[0]
        scope_type = str(scope_type_by_name.get(scope_name) or "project").strip() or "project"
        project_id = project_ids[0] if project_ids else ""
        return {
            "attached_scope_id": scope_name,
            "attached_scope_type": scope_type,
            "attached_scope_display": str(scope_display_by_name.get(scope_name) or "").strip() or scope_name,
            "project_id": project_id,
        }

    first = contributors[0]
    fallback_scope = str(first.effective_scope_name or "").strip()
    fallback_type = str(first.effective_scope_type or "").strip() or "resource"
    return {
        "attached_scope_id": fallback_scope,
        "attached_scope_type": fallback_type,
        "attached_scope_display": str(scope_display_by_name.get(fallback_scope) or "").strip()
        or str(first.effective_scope_display or "").strip()
        or fallback_scope,
        "project_id": str(first.project_id or "").strip(),
    }


def implied_binding_id(
    *,
    principal_id: str,
    rule_name: str,
    attached_scope_ref: str,
    inferred_permissions: list[str],
    crednames: list[str],
    contributing_resource_keys: list[str],
) -> str:
    payload = "|".join(
        [
            str(principal_id or "").strip(),
            str(rule_name or "").strip(),
            str(attached_scope_ref or "").strip(),
            ",".join(normalized_token_list(inferred_permissions)),
            ",".join(normalized_token_list(crednames)),
            ",".join(normalized_token_list(contributing_resource_keys)),
        ]
    )
    digest = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:14]
    scope_suffix = str(attached_scope_ref or "").strip()
    if scope_suffix:
        return f"implied-iambinding:{digest}@{scope_suffix}"
    return f"implied-iambinding:{digest}"


def emit_inferred_permission_edges(
    *,
    context,
    entries: list[BindingPlusScopeEntry],
    entry_metadata: dict[str, dict[str, Any]],
    events: list[dict[str, Any]],
    scope_resource_indexes: ScopeResourceIndexes,
) -> dict[str, Any]:
    # Section A: hydrate shared lookup context and dedupe trackers.
    hierarchy = context.hierarchy_data()
    scope_display_by_name = hierarchy.get("scope_display_by_name") or {}
    scope_type_by_name = hierarchy.get("scope_type_by_name") or {}
    parent_by_name = hierarchy.get("parent_by_name") or {}
    project_scope_by_project_id = scope_resource_indexes.project_scope_by_project_id
    project_id_by_scope_name = scope_resource_indexes.project_id_by_scope_name
    existing_binding_targets = existing_binding_rule_targets(context.builder)

    inferred_edges_emitted = 0
    implied_bindings_emitted = 0
    skipped_existing_binding_edges = 0
    emitted_targets: set[tuple[str, str, str]] = set()
    emitted_subject_bindings: set[tuple[str, str]] = set()

    # Section B: process each rule-match event and emit inferred graph paths.
    for event in events:
        contributors = [entry for entry in (event.get("contributors") or []) if isinstance(entry, BindingPlusScopeEntry)]
        if not contributors:
            continue
        contributor_metadata = {
            contributor.binding_composite_id: dict(entry_metadata.get(contributor.binding_composite_id) or {})
            for contributor in contributors
        }
        principal_entry = contributors[0]
        principal_props = principal_member_properties(principal_entry.principal_id)
        context.builder.add_node(
            principal_entry.principal_id,
            principal_type(principal_entry.principal_id),
            **principal_props,
        )

        target_pool: dict[tuple[str, str, str], dict[str, str]] = {}
        selector = event.get("target_selector") or {}
        for contributor in contributors:
            scope_target = _effective_scope_target(
                entry=contributor,
                scope_display_by_name=scope_display_by_name,
                scope_type_by_name=scope_type_by_name,
            )
            if _scope_target_matches_selector(scope_target=scope_target, selector=selector):
                scope_key = (
                    str(scope_target.get("resource_name") or "").strip(),
                    str(scope_target.get("resource_type") or "").strip(),
                    str(scope_target.get("project_id") or "").strip(),
                )
                if scope_key[0]:
                    target_pool[scope_key] = scope_target

            for target in _target_candidates_for_entry(
                entry=contributor,
                selector=selector,
                allow_resources=scope_resource_indexes.allow_resources,
                allow_resources_by_project=scope_resource_indexes.allow_resources_by_project,
                allow_resources_by_project_type=scope_resource_indexes.allow_resources_by_project_type,
                parent_by_name=parent_by_name,
                project_scope_by_project_id=project_scope_by_project_id,
                project_id_by_scope_name=project_id_by_scope_name,
                scope_ancestor_cache=None,
            ):
                target_key = (
                    str(target.get("resource_name") or "").strip(),
                    str(target.get("resource_type") or "").strip(),
                    str(target.get("project_id") or "").strip(),
                )
                if target_key[0]:
                    target_pool[target_key] = target

        contributing_resource_keys = sorted(
            {
                str(resource_key or "").strip()
                for contributor in contributors
                for resource_key in (
                    contributor_metadata.get(contributor.binding_composite_id, {}).get("resource_keys")
                    or [str(contributor_metadata.get(contributor.binding_composite_id, {}).get("resource_key") or "").strip()]
                )
                if str(resource_key or "").strip()
            }
        )
        contributing_scope_ids = normalized_token_list(contributor.effective_scope_name for contributor in contributors)
        contributing_scope_types = normalized_token_list(contributor.effective_scope_type for contributor in contributors)
        inferred_permissions = normalized_token_list(event.get("matched_permissions") or [])
        inferred_permission_set = set(inferred_permissions)
        contributing_permission_crednames_raw: dict[str, set[str]] = {}
        for contributor in contributors:
            metadata = contributor_metadata.get(contributor.binding_composite_id, {})
            permission_crednames_map = metadata.get("permission_crednames") or {}
            if not isinstance(permission_crednames_map, dict):
                continue
            for permission in inferred_permission_set:
                crednames = permission_crednames_map.get(permission) or []
                normalized_crednames = {
                    str(credname or "").strip()
                    for credname in (crednames if isinstance(crednames, (list, tuple, set)) else [crednames])
                    if str(credname or "").strip()
                }
                if normalized_crednames:
                    contributing_permission_crednames_raw.setdefault(permission, set()).update(
                        normalized_crednames
                    )

        if inferred_permission_set and not contributing_permission_crednames_raw:
            fallback_crednames = {
                str(credname or "").strip()
                for contributor in contributors
                for credname in (contributor_metadata.get(contributor.binding_composite_id, {}).get("crednames") or [])
                if str(credname or "").strip()
            }
            if fallback_crednames:
                for permission in inferred_permission_set:
                    contributing_permission_crednames_raw[permission] = set(fallback_crednames)

        contributing_permission_crednames = {
            permission: sorted(crednames)
            for permission, crednames in contributing_permission_crednames_raw.items()
            if permission and crednames
        }
        contributing_crednames = sorted(
            {
                credname
                for crednames in contributing_permission_crednames.values()
                for credname in crednames
                if str(credname or "").strip()
            }
        )
        if not contributing_crednames:
            contributing_crednames = sorted(
                {
                    credname
                    for contributor in contributors
                    for credname in (contributor_metadata.get(contributor.binding_composite_id, {}).get("crednames") or [])
                    if str(credname or "").strip()
                }
            )
        inferred_edge_type = f"INFERRED_{str(event.get('edge_type') or '').strip()}"
        original_edge_type = str(event.get("edge_type") or "").strip()
        if not original_edge_type:
            continue

        implied_scope = implied_scope_for_event(
            contributors=contributors,
            project_scope_by_project_id=project_scope_by_project_id,
            scope_display_by_name=scope_display_by_name,
            scope_type_by_name=scope_type_by_name,
        )
        attached_scope_id = str(implied_scope.get("attached_scope_id") or "").strip()
        attached_scope_type = str(implied_scope.get("attached_scope_type") or "").strip()
        attached_scope_display = str(implied_scope.get("attached_scope_display") or "").strip() or attached_scope_id
        implied_project_id = str(implied_scope.get("project_id") or "").strip() or principal_entry.project_id
        attached_scope_ref = binding_scope_token(
            attached_scope_type,
            attached_scope_id,
            project_id=implied_project_id,
        )
        implied_role_name = f"IMPLIED_PERMISSIONS@{attached_scope_ref}" if attached_scope_ref else "IMPLIED_PERMISSIONS"
        implied_binding_family_id = (
            f"iambinding:{implied_role_name}@{attached_scope_ref}"
            if attached_scope_ref
            else f"iambinding:{implied_role_name}"
        )
        binding_id = implied_binding_id(
            principal_id=principal_entry.principal_id,
            rule_name=str(event.get("rule_name") or ""),
            attached_scope_ref=attached_scope_ref,
            inferred_permissions=inferred_permissions,
            crednames=contributing_crednames,
            contributing_resource_keys=contributing_resource_keys,
        )
        subject_binding_key = (principal_entry.principal_id, "HAS_IMPLIED_PERMISSIONS", binding_id)
        if (
            (principal_entry.principal_id, binding_id) not in emitted_subject_bindings
            and subject_binding_key not in context.builder.edge_map
        ):
            context.builder.add_node(
                binding_id,
                "GCPIamSimpleBinding",
                role_name=implied_role_name,
                **role_agent_metadata(implied_role_name),
                implied_role_name=implied_role_name,
                binding_origin="inferred",
                binding_family_id=implied_binding_family_id,
                attached_scope_id=attached_scope_id,
                attached_scope_type=attached_scope_type,
                attached_scope_display=attached_scope_display or attached_scope_ref,
                source_scope_id=attached_scope_id,
                source_scope_type=attached_scope_type,
                source_scope_display=attached_scope_display,
                inherited=False,
                source="credential_permission_summary",
                binding_display=implied_role_name,
                member=principal_entry.principal_id,
                expanded_from_convenience_member="",
                conditional=False,
                condition_expr_raw="",
                condition_hash="",
                condition_summary="",
                inferred=True,
                privilege_escalation=True,
                inferred_permissions=inferred_permissions,
                permission_crednames=contributing_permission_crednames,
                contributing_resource_keys=contributing_resource_keys,
                contributing_scope_ids=contributing_scope_ids,
                contributing_scope_types=contributing_scope_types,
                crednames=contributing_crednames,
                implied_from_rule_name=str(event.get("rule_name") or ""),
                implied_from_edge_type=original_edge_type,
                implied_project_id=implied_project_id,
            )
            context.builder.add_edge(
                principal_entry.principal_id,
                binding_id,
                "HAS_IMPLIED_PERMISSIONS",
                source="credential_permission_summary",
                role_name=implied_role_name,
                binding_origin="inferred",
                binding_family_id=implied_binding_family_id,
                attached_scope_id=attached_scope_id,
                attached_scope_type=attached_scope_type,
                source_scope_id=attached_scope_id,
                source_scope_type=attached_scope_type,
                inferred=True,
                conditional=False,
                inherited=False,
                privilege_escalation=True,
                inferred_permissions=inferred_permissions,
                permission_crednames=contributing_permission_crednames,
                contributing_resource_keys=contributing_resource_keys,
                contributing_scope_ids=contributing_scope_ids,
                contributing_scope_types=contributing_scope_types,
                crednames=contributing_crednames,
                implied_from_rule_name=str(event.get("rule_name") or ""),
                implied_from_edge_type=original_edge_type,
                implied_project_id=implied_project_id,
            )
            emitted_subject_bindings.add((principal_entry.principal_id, binding_id))
            implied_bindings_emitted += 1

        # Section C: emit inferred binding -> target resource edges.
        for target in target_pool.values():
            target_name = str(target.get("resource_name") or "").strip()
            target_type = str(target.get("resource_type") or "").strip()
            if not target_name:
                continue
            target_project_id = str(target.get("project_id") or "").strip() or principal_entry.project_id
            target_label = resource_display_label(
                target_name,
                resource_type=target_type,
                project_id=target_project_id,
            )
            target_region = resource_location_token(target_name)
            target_id = resource_node_id(target_name)
            existing_key = (principal_entry.principal_id, original_edge_type, target_id)
            if existing_key in existing_binding_targets:
                if str(attached_scope_type or "").strip() not in {"org", "folder"}:
                    skipped_existing_binding_edges += 1
                    continue

            dedupe_key = (binding_id, inferred_edge_type, target_id)
            if dedupe_key in emitted_targets:
                continue
            if dedupe_key in context.builder.edge_map:
                continue

            context.builder.add_node(
                target_id,
                gcp_resource_node_type(target_type),
                name=target_label,
                display_name=target_label,
                resource_name=target_name,
                region=target_region,
                project_id=target_project_id,
                resource_type=target_type,
            )
            context.builder.add_edge(
                binding_id,
                target_id,
                inferred_edge_type,
                source="credential_permission_summary",
                inferred=True,
                rule_name=str(event.get("rule_name") or ""),
                inferred_permissions=inferred_permissions,
                permission_crednames=contributing_permission_crednames,
                contributing_resource_keys=contributing_resource_keys,
                contributing_scope_ids=contributing_scope_ids,
                contributing_scope_types=contributing_scope_types,
                crednames=contributing_crednames,
                implied_binding_id=binding_id,
                implied_role_name=implied_role_name,
                binding_origin="inferred",
                binding_family_id=implied_binding_family_id,
                attached_scope_id=attached_scope_id,
                attached_scope_type=attached_scope_type,
                target_resource_id=target_name,
                target_resource_type=target_type,
                privilege_escalation=True,
                match_mode="combo" if len(contributors) > 1 or str(event.get("emission_mode") or "") == "combo" else "single",
            )
            emitted_targets.add(dedupe_key)
            inferred_edges_emitted += 1

    # Section D: return compact emission stats for stage_50 orchestration.
    return {
        "events_total": len(events),
        "implied_bindings_emitted": implied_bindings_emitted,
        "edges_emitted": inferred_edges_emitted,
        "skipped_existing_binding_edges": skipped_existing_binding_edges,
    }


def _emit_inferred_permissions_for_rules(
    *,
    context,
    entries: list[BindingPlusScopeEntry],
    entry_metadata: dict[str, dict[str, Any]],
    scope_resource_indexes: ScopeResourceIndexes,
    rules: Iterable[dict[str, Any]],
) -> dict[str, int]:
    rules_list = list(rules or [])
    events = _collect_rule_events_shared(
        entries=entries,
        rules=rules_list,
        matches_for_group=_matches_for_group,
        normalize_binding_permission_map=_normalize_binding_permission_map,
        normalized_token_list=normalized_token_list,
    )
    emit_stats = emit_inferred_permission_edges(
        context=context,
        entries=entries,
        entry_metadata=entry_metadata,
        events=events,
        scope_resource_indexes=scope_resource_indexes,
    )
    return {
        "rules_total": len(rules_list),
        "matched_events": int(emit_stats.get("events_total", 0)),
        "implied_bindings_emitted": int(emit_stats.get("implied_bindings_emitted", 0)),
        "inferred_edges_emitted": int(emit_stats.get("edges_emitted", 0)),
        "skipped_existing_binding_edges": int(emit_stats.get("skipped_existing_binding_edges", 0)),
    }


def build_inferred_permissions_single_permission(
    *,
    context,
    entries: list[BindingPlusScopeEntry],
    entry_metadata: dict[str, dict[str, Any]],
    scope_resource_indexes: ScopeResourceIndexes,
    rules: Iterable[dict[str, Any]],
) -> dict[str, int]:
    return _emit_inferred_permissions_for_rules(
        context=context,
        entries=entries,
        entry_metadata=entry_metadata,
        scope_resource_indexes=scope_resource_indexes,
        rules=rules,
    )


def build_inferred_permissions_multiple_permissions(
    *,
    context,
    entries: list[BindingPlusScopeEntry],
    entry_metadata: dict[str, dict[str, Any]],
    scope_resource_indexes: ScopeResourceIndexes,
    rules: Iterable[dict[str, Any]],
) -> dict[str, int]:
    return _emit_inferred_permissions_for_rules(
        context=context,
        entries=entries,
        entry_metadata=entry_metadata,
        scope_resource_indexes=scope_resource_indexes,
        rules=rules,
    )


def build_iam_inferred_permissions_graph(context) -> dict[str, int | bool]:
    """
    Build inferred-permission grant paths from cached credential permission summaries:
      principal -> HAS_IMPLIED_PERMISSIONS -> implied grant -> INFERRED_<RULE_EDGE> -> resource
    """
    before_nodes, before_edges = context.counts()
    inferred_single_rules, inferred_multi_rules = load_normalized_dangerous_rules_by_family()
    entries, entry_metadata = build_inferred_entries(context)
    if not entries:
        after_nodes, after_edges = context.counts()
        return {
            "entries_total": 0,
            "rules_total": len(inferred_single_rules) + len(inferred_multi_rules),
            "matched_events": 0,
            "inferred_edges_emitted": 0,
            "skipped_existing_binding_edges": 0,
            "nodes_added": max(0, after_nodes - before_nodes),
            "edges_added": max(0, after_edges - before_edges),
            "total_nodes": after_nodes,
            "total_edges": after_edges,
        }

    scope_resource_indexes = augment_scope_resource_indexes(context.scope_resource_indexes(), entries)
    single_stats = build_inferred_permissions_single_permission(
        context=context,
        entries=entries,
        entry_metadata=entry_metadata,
        scope_resource_indexes=scope_resource_indexes,
        rules=inferred_single_rules,
    )
    multi_stats = build_inferred_permissions_multiple_permissions(
        context=context,
        entries=entries,
        entry_metadata=entry_metadata,
        scope_resource_indexes=scope_resource_indexes,
        rules=inferred_multi_rules,
    )
    emit_stats = {
        "events_total": int(single_stats.get("matched_events", 0)) + int(multi_stats.get("matched_events", 0)),
        "implied_bindings_emitted": int(single_stats.get("implied_bindings_emitted", 0))
        + int(multi_stats.get("implied_bindings_emitted", 0)),
        "edges_emitted": int(single_stats.get("inferred_edges_emitted", 0))
        + int(multi_stats.get("inferred_edges_emitted", 0)),
        "skipped_existing_binding_edges": int(single_stats.get("skipped_existing_binding_edges", 0))
        + int(multi_stats.get("skipped_existing_binding_edges", 0)),
    }
    context.set_artifact(
        "iam_inferred_permissions_state",
        {
            "entries": entries,
            "events_total": int(emit_stats.get("events_total", 0)),
            "implied_bindings_emitted": int(emit_stats.get("implied_bindings_emitted", 0)),
            "edges_emitted": int(emit_stats.get("edges_emitted", 0)),
            "skipped_existing_binding_edges": int(emit_stats.get("skipped_existing_binding_edges", 0)),
            "single_permission_stats": single_stats,
            "multi_permission_stats": multi_stats,
        },
    )

    after_nodes, after_edges = context.counts()
    return {
        "entries_total": len(entries),
        "rules_total": len(inferred_single_rules) + len(inferred_multi_rules),
        "matched_events": int(emit_stats.get("events_total", 0)),
        "implied_bindings_emitted": int(emit_stats.get("implied_bindings_emitted", 0)),
        "inferred_edges_emitted": int(emit_stats.get("edges_emitted", 0)),
        "skipped_existing_binding_edges": int(emit_stats.get("skipped_existing_binding_edges", 0)),
        "nodes_added": max(0, after_nodes - before_nodes),
        "edges_added": max(0, after_edges - before_edges),
        "total_nodes": after_nodes,
        "total_edges": after_edges,
    }
