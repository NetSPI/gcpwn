from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any, Callable, Iterable

from gcpwn.core.action_schema import (
    ACTION_COLUMN_TO_RESOURCE_TYPE,
    ACTION_SCOPE_COLUMNS,
    ACTION_SCOPE_KEY_TO_SCOPE_TYPE,
)
from gcpwn.core.utils.module_helpers import extract_path_tail, parse_json_value


_CONVENIENCE_MEMBER_PREFIXES = ("projectViewer:", "projectEditor:", "projectOwner:")


def _default_normalize_member(member: str) -> str:
    return str(member or "").strip()


def _default_is_convenience_member(member: str) -> bool:
    return str(member or "").strip().startswith(_CONVENIENCE_MEMBER_PREFIXES)


def _normalize_tokens(values: Iterable[Any] | Any) -> set[str]:
    if isinstance(values, (list, tuple, set, frozenset)):
        candidates = values
    else:
        candidates = [values]
    return {token for value in candidates if (token := str(value or "").strip())}


def _policy_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    parsed = parse_json_value(raw, default=None)
    return parsed if isinstance(parsed, dict) else {}


def _resource_binding_key(resource_type: str, resource_name: str, project_id: str) -> str:
    key = f"{resource_type}:{resource_name}" if resource_type else resource_name
    return f"{key}@{project_id}" if project_id else key


def _canonical_scope_type(scope_type: str, scope_name: str) -> str:
    token = str(scope_type or "").strip().lower()
    if token in {"org", "folder", "project"}:
        return token
    name = str(scope_name or "").strip()
    if name.startswith("organizations/"):
        return "org"
    if name.startswith("folders/"):
        return "folder"
    if name.startswith("projects/"):
        return "project"
    return token


def _descendants(children_by_parent: dict[str, list[str]], root: str) -> list[str]:
    root_name = str(root or "").strip()
    if not root_name:
        return []
    out: list[str] = []
    seen = {root_name}
    queue: deque[str] = deque(children_by_parent.get(root_name, []))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        out.append(current)
        for child in children_by_parent.get(current, []):
            if child not in seen:
                queue.append(child)
    return out


def _parse_scope_binding_key(
    resource_key: str,
    *,
    known_project_ids: set[str],
) -> tuple[str, str, str] | None:
    parsed = _parse_resource_key(resource_key, known_project_ids=known_project_ids)
    if not parsed:
        return None
    scope_type, scope_name, project_id = parsed
    if scope_type not in {"org", "folder", "project"}:
        return None
    if scope_type == "org" and not scope_name.startswith("organizations/"):
        return None
    if scope_type == "folder" and not scope_name.startswith("folders/"):
        return None
    if scope_type == "project" and not scope_name.startswith("projects/"):
        return None
    return scope_type, scope_name, project_id


def _parse_resource_key(
    resource_key: str,
    *,
    known_project_ids: set[str] | None = None,
) -> tuple[str, str, str] | None:
    token = str(resource_key or "").strip()
    if not token:
        return None

    base_key = token
    project_id = ""
    maybe_base, sep, suffix = token.rpartition("@")
    if sep and ":" in maybe_base and (
        known_project_ids is None or suffix in known_project_ids
    ):
        base_key = maybe_base
        project_id = suffix

    if ":" not in base_key:
        return None
    scope_type, scope_name = base_key.split(":", 1)
    scope_type = str(scope_type or "").strip().lower()
    scope_name = str(scope_name or "").strip()
    if not scope_type or not scope_name:
        return None
    return scope_type, scope_name, project_id


def _member_credname_key(member: str, credname: str) -> str:
    return f"{str(member or '').strip()}:{str(credname or '').strip()}"


def _split_member_credname_key(token: str) -> tuple[str, str] | None:
    value = str(token or "").strip()
    if not value:
        return None
    member, sep, credname = value.rpartition(":")
    member = str(member or "").strip()
    credname = str(credname or "").strip()
    if not sep or not member or not credname:
        return None
    if ":" not in member:
        return None
    return member, credname


def split_member_credname_key(token: str) -> tuple[str, str] | None:
    """Public helper used by OpenGraph inferred-permission stage."""
    return _split_member_credname_key(token)


def _iter_member_roles_from_policy(
    policy: dict[str, Any],
    *,
    normalize_member: Callable[[str], str],
) -> Iterable[tuple[str, list[str]]]:
    by_member = policy.get("by_member")
    if isinstance(by_member, dict):
        for member, details in by_member.items():
            member_token = normalize_member(str(member or "").strip())
            if not member_token:
                continue
            roles = details.get("roles") if isinstance(details, dict) else details
            normalized_roles = sorted(_normalize_tokens(roles))
            if normalized_roles:
                yield member_token, normalized_roles
        return

    collapsed: dict[str, set[str]] = {}
    for binding in policy.get("bindings") or []:
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role") or "").strip()
        if not role:
            continue
        members = binding.get("members") or []
        if not isinstance(members, list):
            members = [members]
        for member in members:
            member_token = normalize_member(str(member or "").strip())
            if member_token:
                collapsed.setdefault(member_token, set()).add(role)

    for member, roles in collapsed.items():
        normalized_roles = sorted(_normalize_tokens(roles))
        if normalized_roles:
            yield member, normalized_roles


def _build_project_role_members(
    member_binding_index: dict[str, dict[str, dict[str, Any]]] | None,
    *,
    normalize_member: Callable[[str], str],
    is_convenience_member: Callable[[str], bool],
) -> dict[str, dict[str, set[str]]]:
    owner_editor_viewer = {"roles/owner", "roles/editor", "roles/viewer"}
    index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for member, resource_map in (member_binding_index or {}).items():
        member_token = normalize_member(str(member or "").strip())
        if not member_token or is_convenience_member(member_token):
            continue

        for payload in (resource_map or {}).values():
            records = (payload.get("direct_binding_records") or []) + (payload.get("inherited_binding_records") or [])
            for record in records:
                if not isinstance(record, dict):
                    continue
                role_name = str(record.get("role_name") or "").strip()
                if role_name not in owner_editor_viewer:
                    continue

                attached_scope_name = str(record.get("attached_scope_name") or "").strip()
                attached_scope_type = _canonical_scope_type(
                    str(record.get("attached_scope_type") or "").strip(),
                    attached_scope_name,
                )
                if attached_scope_type != "project" or not attached_scope_name.startswith("projects/"):
                    continue

                project_number = extract_path_tail(attached_scope_name, default=attached_scope_name)
                project_id = str(record.get("project_id") or "").strip()
                for project_key in (project_id, project_number):
                    if project_key:
                        index[project_key][role_name].add(member_token)

    return {
        project_key: {role_name: set(members) for role_name, members in role_map.items()}
        for project_key, role_map in index.items()
    }


def _build_member_binding_index(
    raw_allow_bindings: list[dict[str, Any]] | None,
    *,
    include_inheritance: bool,
    hierarchy_data: dict[str, Any] | None,
    normalize_member: Callable[[str], str],
    is_convenience_member: Callable[[str], bool],
) -> dict[str, dict[str, dict[str, Any]]]:
    # Example `member_binding_index` shape returned from this helper:
    # Note: keys are always "<resource_type>:<resource_name>@<project_id>".
    # For project scopes this can look repetitive (e.g.
    # "project:projects/example-project@example-project") when the
    # project_id also appears in the resource_name path. We keep this format
    # for one consistent keying scheme across all resource types.
    # {
    #   "user:alice@example.com": {
    #     "project:projects/example-project@example-project": {
    #       "binding_records": [
    #         {
    #           "role_name": "roles/viewer",
    #           "condition": None,
    #           "attached_scope_type": "project",
    #           "attached_scope_name": "projects/example-project",
    #           "project_id": "example-project",
    #           "record_origin": "direct"
    #         }
    #       ]
    #     },
    #     "bucket:projects/_/buckets/example-artifacts@example-project": {
    #       "binding_records": [
    #         {
    #           "role_name": "roles/storage.objectViewer",
    #           "condition": None,
    #           "attached_scope_type": "project",
    #           "attached_scope_name": "projects/example-project",
    #           "project_id": "example-project",
    #           "inherited": True,
    #           "inherited_from": "projects/example-project",
    #           "record_origin": "inherited"
    #         }
    #       ]
    #     }
    #   }
    # }
    by_member: dict[str, dict[str, dict[str, Any]]] = {}

    def _binding_record_fingerprint(
        *,
        role_name: str,
        condition: dict[str, Any] | None,
        inherited: bool,
        inherited_from: str = "",
    ) -> tuple[str, str, bool, str]:
        condition_fingerprint = ""
        if isinstance(condition, dict):
            try:
                condition_fingerprint = json.dumps(condition, ensure_ascii=False, sort_keys=True)
            except Exception:
                condition_fingerprint = str(condition)
        return (
            str(role_name or "").strip(),
            condition_fingerprint,
            bool(inherited),
            str(inherited_from or "").strip(),
        )

    def _ensure_resource_bucket(member: str, resource_key: str) -> dict[str, Any]:
        member_bucket = by_member.setdefault(member, {})
        return member_bucket.setdefault(
            resource_key,
            {
                "direct_binding_records": [],
                "convenience_binding_records": [],
                "inherited_binding_records": [],
                "_binding_seen": set(),
                "_convenience_binding_seen": set(),
            },
        )

    def _append_binding_record(
        *,
        bucket: dict[str, Any],
        role_name: str,
        condition: dict[str, Any] | None,
        attached_scope_type: str,
        attached_scope_name: str,
        project_id: str,
        record_list_key: str,
        inherited: bool = False,
        inherited_from: str = "",
    ) -> None:
        role_token = str(role_name or "").strip()
        if not role_token:
            return
        fingerprint = _binding_record_fingerprint(
            role_name=role_token,
            condition=condition,
            inherited=inherited,
            inherited_from=inherited_from,
        )
        if fingerprint in bucket["_binding_seen"]:
            return
        bucket["_binding_seen"].add(fingerprint)
        record = {
            "role_name": role_token,
            "condition": condition,
            "attached_scope_type": str(attached_scope_type or "").strip(),
            "attached_scope_name": str(attached_scope_name or "").strip(),
            "project_id": str(project_id or "").strip(),
        }
        if inherited:
            record["inherited"] = True
            record["inherited_from"] = str(inherited_from or "").strip()
        bucket[record_list_key].append(record)

    for row in raw_allow_bindings or []:
        resource_name = str(row.get("resource_name") or "").strip()
        resource_type = str(row.get("resource_type") or "").strip()
        project_id = str(row.get("project_id") or "").strip()
        if not resource_name:
            continue

        key = _resource_binding_key(resource_type, resource_name, project_id)
        parsed_policy = _policy_dict(row.get("policy"))

        bindings = parsed_policy.get("bindings") or []
        if any(isinstance(binding, dict) for binding in bindings):
            for binding in bindings:
                if not isinstance(binding, dict):
                    continue
                role_token = str(binding.get("role") or "").strip()
                if not role_token:
                    continue
                members = binding.get("members") if isinstance(binding.get("members"), list) else [binding.get("members")]
                condition = binding.get("condition") if isinstance(binding.get("condition"), dict) else None
                for member in members:
                    member_token = normalize_member(str(member or "").strip())
                    if not member_token:
                        continue
                    bucket = _ensure_resource_bucket(member_token, key)
                    _append_binding_record(
                        bucket=bucket,
                        role_name=role_token,
                        condition=condition,
                        attached_scope_type=resource_type,
                        attached_scope_name=resource_name,
                        project_id=project_id,
                        record_list_key="direct_binding_records",
                        inherited=False,
                    )
            continue

        for member_token, roles in _iter_member_roles_from_policy(parsed_policy, normalize_member=normalize_member):
            bucket = _ensure_resource_bucket(member_token, key)
            for role_token in roles:
                _append_binding_record(
                    bucket=bucket,
                    role_name=role_token,
                    condition=None,
                    attached_scope_type=resource_type,
                    attached_scope_name=resource_name,
                    project_id=project_id,
                    record_list_key="direct_binding_records",
                    inherited=False,
                )

    if include_inheritance:
        hierarchy = dict(hierarchy_data or {})
        children_by_parent = dict(hierarchy.get("children_by_parent") or {})
        scope_type_by_name = dict(hierarchy.get("scope_type_by_name") or {})
        project_id_by_scope_name = dict(hierarchy.get("scope_project_by_name") or {})
        known_project_ids = set(hierarchy.get("known_project_ids") or set())
        descendants_cache: dict[str, list[str]] = {}
        for member, resource_map in list(by_member.items()):
            inherited_updates: list[tuple[str, list[dict[str, Any]], str, str, str, str]] = []
            for resource_key, data in list(resource_map.items()):
                parsed = _parse_scope_binding_key(resource_key, known_project_ids=known_project_ids)
                if not parsed:
                    continue
                _, scope_name, _ = parsed
                descendants = descendants_cache.get(scope_name)
                if descendants is None:
                    descendants = _descendants(children_by_parent, scope_name)
                    descendants_cache[scope_name] = descendants
                if not descendants:
                    continue

                direct_binding_records = [dict(record) for record in (data.get("direct_binding_records") or []) if isinstance(record, dict)]
                if not direct_binding_records:
                    continue

                for descendant_scope_name in descendants:
                    descendant_scope_type = scope_type_by_name.get(descendant_scope_name)
                    if descendant_scope_type not in {"org", "folder", "project"}:
                        continue
                    descendant_project_id = str(project_id_by_scope_name.get(descendant_scope_name) or "").strip()
                    descendant_key = _resource_binding_key(
                        descendant_scope_type,
                        descendant_scope_name,
                        descendant_project_id,
                    )
                    inherited_updates.append(
                        (
                            descendant_key,
                            direct_binding_records,
                            scope_name,
                            str(descendant_scope_type or "").strip(),
                            str(descendant_scope_name or "").strip(),
                            str(descendant_project_id or "").strip(),
                        )
                    )

            for (
                descendant_key,
                direct_binding_records,
                inherited_from,
                inherited_scope_type,
                inherited_scope_name,
                inherited_project_id,
            ) in inherited_updates:
                bucket = _ensure_resource_bucket(member, descendant_key)
                for direct_record in direct_binding_records:
                    role_name = str(direct_record.get("role_name") or "").strip()
                    condition = direct_record.get("condition") if isinstance(direct_record.get("condition"), dict) else None
                    _append_binding_record(
                        bucket=bucket,
                        role_name=role_name,
                        condition=condition,
                        attached_scope_type=inherited_scope_type,
                        attached_scope_name=inherited_scope_name,
                        project_id=inherited_project_id,
                        record_list_key="inherited_binding_records",
                        inherited=True,
                        inherited_from=inherited_from,
                    )

    project_role_members = _build_project_role_members(
        by_member,
        normalize_member=normalize_member,
        is_convenience_member=is_convenience_member,
    )
    role_by_prefix = {
        "projectOwner": "roles/owner",
        "projectEditor": "roles/editor",
        "projectViewer": "roles/viewer",
    }
    for member, resource_map in list(by_member.items()):
        convenience_member = normalize_member(str(member or "").strip())
        if not is_convenience_member(convenience_member):
            continue
        prefix, _, suffix = convenience_member.partition(":")
        required_role = role_by_prefix.get(prefix)
        if not required_role:
            continue

        for resource_key, payload in (resource_map or {}).items():
            record_lists = (
                list(payload.get("direct_binding_records") or [])
                + list(payload.get("inherited_binding_records") or [])
            )
            for record in record_lists:
                if not isinstance(record, dict):
                    continue
                attached_scope_name = str(record.get("attached_scope_name") or "").strip()
                project_id = str(record.get("project_id") or "").strip()

                candidate_keys = [
                    token
                    for token in dict.fromkeys(
                        (
                            str(suffix or "").strip(),
                            str(project_id or "").strip(),
                            str(extract_path_tail(attached_scope_name, default=attached_scope_name) or "").strip(),
                        )
                    )
                    if token
                ]

                concrete_members: set[str] = set()
                for project_key in candidate_keys:
                    concrete_members.update(project_role_members.get(project_key, {}).get(required_role, set()))

                if not concrete_members:
                    continue

                for concrete_member in sorted(concrete_members):
                    bucket = _ensure_resource_bucket(concrete_member, resource_key)
                    derived_record = dict(record)
                    derived_record["derived_from"] = convenience_member
                    fingerprint = _binding_record_fingerprint(
                        role_name=str(derived_record.get("role_name") or "").strip(),
                        condition=derived_record.get("condition") if isinstance(derived_record.get("condition"), dict) else None,
                        inherited=bool(derived_record.get("inherited")),
                        inherited_from=str(derived_record.get("inherited_from") or "").strip(),
                    ) + (convenience_member,)
                    if fingerprint in bucket["_convenience_binding_seen"]:
                        continue
                    bucket["_convenience_binding_seen"].add(fingerprint)
                    bucket["convenience_binding_records"].append(derived_record)

    finalized: dict[str, dict[str, dict[str, Any]]] = {}
    for member, resource_map in by_member.items():
        member_token = normalize_member(str(member or "").strip())
        if is_convenience_member(member_token):
            continue
        member_out: dict[str, dict[str, Any]] = {}
        for resource_key, role_entry in resource_map.items():
            binding_records: list[dict[str, Any]] = []
            for origin, key in (
                ("direct", "direct_binding_records"),
                ("convenience", "convenience_binding_records"),
                ("inherited", "inherited_binding_records"),
            ):
                for record in (role_entry.get(key) or []):
                    if not isinstance(record, dict):
                        continue
                    normalized_record = dict(record)
                    normalized_record["record_origin"] = origin
                    binding_records.append(normalized_record)
            if not binding_records:
                continue
            member_out[resource_key] = {"binding_records": binding_records}
        if member_out:
            finalized[member_token] = member_out
    return finalized


def _build_inferred_permission_inputs_from_session(
    session: Any,
) -> tuple[dict[str, dict[str, list[str]]], dict[str, list[str]]]:
    credname_member_map: dict[str, list[str]] = {}
    for row in (session.get_session_data("session", columns=["credname", "email", "credtype"]) or []):
        credname = str(row.get("credname") or "").strip()
        email = str(row.get("email") or "").strip()
        credtype = str(row.get("credtype") or "").strip().lower()
        if not credname or not email:
            continue
        if credtype == "service" or email.endswith(".gserviceaccount.com"):
            credname_member_map[credname] = [f"serviceAccount:{email}"]
        else:
            credname_member_map[credname] = [f"user:{email}"]

    scope_columns = {column_name for _, column_name in ACTION_SCOPE_COLUMNS}
    output: dict[str, dict[str, set[str]]] = {}
    for record in (session.get_actions() or []):
        credname = str(record.get("credname") or "").strip()
        if not credname:
            continue
        cred_bucket = output.setdefault(credname, {})

        for scope_key, action_column in ACTION_SCOPE_COLUMNS:
            scope_permissions = record.get(action_column) or {}
            if not isinstance(scope_permissions, dict):
                continue
            for scope_name, permissions in scope_permissions.items():
                scope_name_token = str(scope_name or "").strip()
                if not scope_name_token:
                    continue
                scope_type = ACTION_SCOPE_KEY_TO_SCOPE_TYPE.get(str(scope_key or "").strip(), "scope")
                resource_key = f"{scope_type}:{scope_name_token}"
                permission_bucket = cred_bucket.setdefault(resource_key, set())
                for permission in permissions or []:
                    permission_token = str(permission or "").strip()
                    if permission_token:
                        permission_bucket.add(permission_token)

        for action_column, canonical_resource_type in ACTION_COLUMN_TO_RESOURCE_TYPE.items():
            if action_column in scope_columns:
                continue
            resource_permissions = record.get(action_column) or {}
            if not isinstance(resource_permissions, dict):
                continue
            canonical_kind = str(canonical_resource_type or "").strip().lower()
            for project_id, permission_map in resource_permissions.items():
                project_token = str(project_id or "").strip()
                if not isinstance(permission_map, dict):
                    continue
                for permission, asset_map in permission_map.items():
                    permission_token = str(permission or "").strip()
                    if not permission_token:
                        continue
                    emitted = False
                    if isinstance(asset_map, dict):
                        for asset_kind, asset_names in asset_map.items():
                            kind_token = str(asset_kind or "").strip().lower()
                            kind = canonical_kind if kind_token == canonical_kind else kind_token
                            values = asset_names if isinstance(asset_names, list) else [asset_names]
                            for asset_name in values or []:
                                name_token = str(asset_name or "").strip()
                                if not name_token:
                                    continue
                                resource_key = f"{kind}:{name_token}" if kind else name_token
                                if project_token:
                                    resource_key = f"{resource_key}@{project_token}"
                                cred_bucket.setdefault(resource_key, set()).add(permission_token)
                                emitted = True
                    if not emitted and project_token:
                        fallback_key = f"project:{project_token}"
                        cred_bucket.setdefault(fallback_key, set()).add(permission_token)

    enumed_permissions_by_credname = {
        credname: {
            resource_key: sorted(permission_set)
            for resource_key, permission_set in resource_map.items()
            if permission_set
        }
        for credname, resource_map in output.items()
    }
    return enumed_permissions_by_credname, credname_member_map


def create_simplified_hierarchy_permissions(
    allow_bindings_rows: Iterable[dict[str, Any]] | None,
    *,
    include_inheritance: bool = False,
    include_inferred_permissions: bool = False,
    hierarchy_data: dict[str, Any] | None = None,
    normalize_member: Callable[[str], str] | None = None,
    is_convenience_member: Callable[[str], bool] | None = None,
    enumed_permissions_by_credname: dict[str, dict[str, Iterable[str]]] | None = None,
    credname_member_map: dict[str, list[str]] | None = None,
    session: Any | None = None,
) -> dict[str, Any]:
    # Concrete example return payload:
    # {
    #   "flattened_member_rows": [
    #     {
    #       "member": "user:alice@example.com",
    #       "project_id": "example-project",
    #       "name": "projects/example-project",
    #       "display_name": "Example Project A",
    #       "type": "project",
    #       "roles": "[\"roles/viewer\"]"
    #     },
    #     {
    #       "member": "user:alice@example.com",
    #       "project_id": "example-project",
    #       "name": "projects/example-project/zones/us-central1-a/instances/web-01",
    #       "display_name": "",
    #       "type": "computeinstance",
    #       "roles": "[\"roles/compute.instanceAdmin.v1\"]"
    #     },
    #     {
    #       "member": "serviceAccount:app@example-project.iam.gserviceaccount.com",
    #       "project_id": "example-project",
    #       "name": "projects/_/buckets/example-artifacts",
    #       "display_name": "",
    #       "type": "bucket",
    #       "roles": "[\"roles/storage.objectViewer\"]"
    #     }
    #   ],
    #   "member_binding_index": {
    #     "user:alice@example.com": {
    #       "project:projects/example-project@example-project": {
    #         "binding_records": [
    #           {"role_name": "...", "record_origin": "direct", ...},
    #           {"role_name": "...", "record_origin": "convenience", ...},
    #           {"role_name": "...", "record_origin": "inherited", ...}
    #         ]
    #       }
    #     }
    #   },
    #   "member_inferred_permissions_index": {
    #     "user:alice@example.com:example-cred": {
    #       "project:projects/example-project@example-project": [
    #         "compute.instances.get"
    #       ],
    #       "computeinstance:projects/example-project/zones/us-central1-a/instances/web-01@example-project": [
    #         "compute.instances.get",
    #         "compute.instances.setMetadata"
    #       ]
    #     }
    #   }
    # }
    """
    Canonical IAM simplifier used by both process and OpenGraph pipelines.

    Output structure (single source of truth):
    {
      "flattened_member_rows": [
        {
          "member": "<normalized-member>",
          "project_id": "<project-id>",
          "name": "<resource-name>",
          "display_name": "<resource-display-name-or-empty>",
          "type": "<resource-type>",
          "roles": "[\"roles/viewer\", \"roles/editor\", ...]"   # JSON string
        },
        ...
      ],
      "member_binding_index": {
        "<normalized-member>": {
          "<resource_type>:<resource_name>@<project_id?>": {
            "binding_records": [
              {"role_name", "condition", "attached_scope_type", "attached_scope_name", "project_id", "record_origin"},
              {"role_name", "condition", "attached_scope_type", "attached_scope_name", "project_id", "derived_from", "record_origin"},
              {"role_name", "condition", "attached_scope_type", "attached_scope_name", "project_id", "inherited", "inherited_from", "record_origin"}
            ]
          }
        }
      },
      "member_inferred_permissions_index": {
        "<normalized-member>:<credname>": {
          "<resource-key>": ["<permission>", "..."]
        }
      }
    }

    Notes:
    - Inferred permissions are intentionally centralized in
      `member_inferred_permissions_index` (not duplicated into
      `member_binding_index`), to keep bindings vs inferred capability data
      cleanly separated.
    - Inferred entries are credname-specific (`member:credname`) to keep
      provenance precise without extra credname mapping fields.
    - When `include_inheritance=True`, inferred org/folder/project scope entries
      are fanned out where possible to descendant project scopes and to known
      member-bound resources in those projects.
    - If `include_inferred_permissions=True` and `session` is provided while
      inferred inputs are omitted, inferred inputs are built automatically from
      `session.get_actions()` and `session.get_session_data("session", ...)`.
    """
    member_normalizer = normalize_member or _default_normalize_member
    convenience_checker = is_convenience_member or _default_is_convenience_member
    rows = list(allow_bindings_rows or [])

    flattened_member_rows: list[dict[str, str]] = []
    for row in rows:
        resource_name = str(row.get("resource_name") or "").strip()
        resource_type = str(row.get("resource_type") or "").strip()
        project_id = str(row.get("project_id") or "").strip()
        display_name = str(row.get("display_name") or "").strip()
        if not resource_name or not resource_type:
            continue
        parsed_policy = _policy_dict(row.get("policy"))
        for member, roles in _iter_member_roles_from_policy(parsed_policy, normalize_member=member_normalizer):
            flattened_member_rows.append(
                {
                    "member": member,
                    "project_id": project_id,
                    "name": resource_name,
                    "display_name": display_name,
                    "type": resource_type,
                    "roles": json.dumps(roles, ensure_ascii=False),
                }
            )

    member_binding_index = _build_member_binding_index(
        rows,
        include_inheritance=bool(include_inheritance),
        hierarchy_data=hierarchy_data,
        normalize_member=member_normalizer,
        is_convenience_member=convenience_checker,
    )

    if include_inferred_permissions and session is not None and (
        not isinstance(enumed_permissions_by_credname, dict) or not isinstance(credname_member_map, dict)
    ):
        enumed_permissions_by_credname, credname_member_map = _build_inferred_permission_inputs_from_session(session)

    member_inferred_permissions_index: dict[str, dict[str, list[str]]] = {}
    if include_inferred_permissions and isinstance(enumed_permissions_by_credname, dict) and isinstance(credname_member_map, dict):
        inferred_aggregate: dict[str, dict[str, set[str]]] = {}

        def _merge_inferred_entry(
            *,
            member_credname: str,
            resource_key: str,
            permissions: set[str],
        ) -> None:
            if not member_credname or not resource_key or not permissions:
                return
            member_bucket = inferred_aggregate.setdefault(member_credname, {})
            permission_bucket = member_bucket.setdefault(resource_key, set())
            for permission in permissions:
                permission_token = str(permission or "").strip()
                if not permission_token:
                    continue
                permission_bucket.add(permission_token)

        for raw_credname, resource_map in enumed_permissions_by_credname.items():
            credname = str(raw_credname or "").strip()
            if not credname or not isinstance(resource_map, dict):
                continue
            members: list[str] = []
            for raw_member in (credname_member_map.get(credname) or []):
                member = member_normalizer(str(raw_member or "").strip())
                if member and member not in members:
                    members.append(member)
            if not members:
                continue

            for raw_resource_key, raw_permissions in resource_map.items():
                resource_key = str(raw_resource_key or "").strip()
                if not resource_key:
                    continue
                permissions = _normalize_tokens(raw_permissions)
                if not permissions:
                    continue

                for member in members:
                    member_credname = _member_credname_key(member, credname)
                    _merge_inferred_entry(
                        member_credname=member_credname,
                        resource_key=resource_key,
                        permissions=permissions,
                    )

        if include_inheritance:
            hierarchy = dict(hierarchy_data or {})
            children_by_parent = dict(hierarchy.get("children_by_parent") or {})
            scope_type_by_name = dict(hierarchy.get("scope_type_by_name") or {})
            project_id_by_scope_name = dict(hierarchy.get("scope_project_by_name") or {})
            project_scope_by_project_id = {
                str(project_id or "").strip(): str(scope_name or "").strip()
                for scope_name, project_id in project_id_by_scope_name.items()
                if str(scope_name or "").strip() and str(project_id or "").strip()
            }

            def _resolve_scope_name(scope_type: str, scope_name: str) -> str:
                token = str(scope_name or "").strip()
                stype = _canonical_scope_type(scope_type, token)
                if stype == "org":
                    if token.startswith("organizations/"):
                        return token
                    if token.isdigit():
                        return f"organizations/{token}"
                    return ""
                if stype == "folder":
                    if token.startswith("folders/"):
                        return token
                    if token.isdigit():
                        return f"folders/{token}"
                    return ""
                if stype == "project":
                    if token.startswith("projects/"):
                        return token
                    scope_name_from_project = project_scope_by_project_id.get(token)
                    if scope_name_from_project:
                        return scope_name_from_project
                    if token.isdigit():
                        return f"projects/{token}"
                    return ""
                return ""

            def _descendant_project_scopes(root_scope_name: str) -> list[str]:
                root_token = str(root_scope_name or "").strip()
                if not root_token:
                    return []
                return [
                    scope_name
                    for scope_name in _descendants(children_by_parent, root_token)
                    if _canonical_scope_type(str(scope_type_by_name.get(scope_name) or ""), scope_name) == "project"
                ]

            seed_entries = [
                (member_credname, resource_key, set(permissions or set()))
                for member_credname, resource_map in inferred_aggregate.items()
                for resource_key, permissions in resource_map.items()
            ]

            for member_credname, resource_key, permissions in seed_entries:
                member_cred_split = _split_member_credname_key(member_credname)
                if not member_cred_split:
                    continue
                member, _credname = member_cred_split
                parsed = _parse_resource_key(resource_key)
                if not parsed:
                    continue
                resource_type, resource_name, explicit_project_id = parsed
                scope_type = _canonical_scope_type(resource_type, resource_name)
                if scope_type not in {"org", "folder", "project"}:
                    continue

                target_project_scopes: list[str] = []
                resolved_scope_name = _resolve_scope_name(scope_type, resource_name)
                if scope_type == "project":
                    if resolved_scope_name:
                        target_project_scopes = [resolved_scope_name]
                else:
                    if resolved_scope_name:
                        target_project_scopes = _descendant_project_scopes(resolved_scope_name)

                target_project_ids = {
                    str(project_id_by_scope_name.get(scope_name) or "").strip() or extract_path_tail(scope_name, default=scope_name)
                    for scope_name in target_project_scopes
                    if str(scope_name or "").strip()
                }
                if explicit_project_id:
                    target_project_ids.add(explicit_project_id)

                for project_scope in target_project_scopes:
                    project_id = str(project_id_by_scope_name.get(project_scope) or "").strip() or extract_path_tail(project_scope, default=project_scope)
                    project_key = f"project:{project_scope}@{project_id}" if project_id else f"project:{project_scope}"
                    _merge_inferred_entry(
                        member_credname=member_credname,
                        resource_key=project_key,
                        permissions=permissions,
                    )

                for bound_resource_key in (member_binding_index.get(member) or {}):
                    _, sep, bound_project_id = str(bound_resource_key or "").strip().rpartition("@")
                    if not sep:
                        continue
                    if str(bound_project_id or "").strip() not in target_project_ids:
                        continue
                    _merge_inferred_entry(
                        member_credname=member_credname,
                        resource_key=str(bound_resource_key or "").strip(),
                        permissions=permissions,
                    )

        member_inferred_permissions_index = {
            member_credname: {
                resource_key: sorted(permission_set)
                for resource_key, permission_set in resource_map.items()
                if permission_set
            }
            for member_credname, resource_map in inferred_aggregate.items()
            if resource_map
        }

    return {
        "flattened_member_rows": flattened_member_rows,
        "member_binding_index": member_binding_index,
        "member_inferred_permissions_index": member_inferred_permissions_index,
    }
