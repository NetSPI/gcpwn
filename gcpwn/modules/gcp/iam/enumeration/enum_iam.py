from __future__ import annotations

import argparse
import ast
import json
from types import SimpleNamespace

from google.cloud import iam_admin_v1

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, run_components
from gcpwn.core.utils.module_helpers import extract_path_tail, split_path_tokens
from gcpwn.core.utils.service_runtime import (
    parse_component_args,
    parse_csv_arg,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.gcp.iam.utilities.helpers import (
    HashableCustomRole,
    IAMCustomRolesResource,
    IAMServiceAccountsResource,
    IAMWorkloadIdentityPoolsResource,
    IAMWorkloadIdentityProvidersResource,
)


# --------------------------------------------------------------------------- #
# Service accounts (framework) -- keys are fetched per-SA in an enrich step and
# rendered as the SA -> keys map the same way buckets -> blobs is.
# --------------------------------------------------------------------------- #
class _SARef:
    __slots__ = ("email", "display_name", "unique_id")

    def __init__(self, email: str, display_name: str, unique_id: str) -> None:
        self.email = email
        self.display_name = display_name
        self.unique_id = unique_id

    def __hash__(self) -> int:
        return hash((self.email, self.display_name, self.unique_id))

    def __eq__(self, other) -> bool:
        return isinstance(other, _SARef) and (self.email, self.unique_id) == (other.email, other.unique_id)


def _enrich_sa_keys(rows, *, resource, args, api_actions):
    for service_account in rows:
        name = str(service_account.get("name") or "").strip()
        descriptions: list[str] = []
        if name:
            listed_keys = resource.list_keys(resource_id=name, action_dict=api_actions)
            if listed_keys and listed_keys not in ("Not Enabled", None):
                resource.save_keys(listed_keys)
                for key in listed_keys:
                    descriptions.append(f"{extract_path_tail(key.name)} (DISABLED: {key.disabled})")
                    if getattr(args, "get", False):
                        key_get = resource.get_key(resource_id=key.name, action_dict=api_actions)
                        if key_get:
                            resource.save_keys([key_get])
        service_account["_keys"] = sorted(descriptions)
    return rows


SA_COMPONENT = Component(
    "service_accounts", IAMServiceAccountsResource, "Service Account Principals/Keys", "Service Accounts",
    help_text="Enumerate service accounts and keys", scope=PROJECT, summarize=False,
    columns=["email", "display_name", "unique_id"], primary_sort_key="email",
    enrich_fn=_enrich_sa_keys,
    manual_id_arg="sa_account_names",
    manual_help="Service accounts as projects/<pid>/serviceAccounts/<email>.",
)

WIF_COMPONENTS = [
    Component(
        "pools", IAMWorkloadIdentityPoolsResource, "Workload Identity Pools", "Pools",
        help_text="Enumerate Workload Identity Pools (WIF)", scope=PROJECT, primary_sort_key="name",
    ),
    Component(
        "providers", IAMWorkloadIdentityProvidersResource, "Workload Identity Providers", "Providers",
        help_text="Enumerate Workload Identity Providers (WIF)", scope=NESTED, parent_key="pools",
        dependency_label="Workload Identity pools", primary_sort_key="name",
    ),
]

ALL_KEYS = ["service_accounts", "custom_roles", "pools", "providers"]


def _summarize_service_accounts(project_id, sa_rows) -> None:
    keyed = {
        _SARef(
            str(row.get("email") or "").strip(),
            str(row.get("display_name") or "").strip(),
            str(row.get("unique_id") or "").strip(),
        ): row.get("_keys") or []
        for row in sa_rows
    }
    UtilityTools.summary_wrapup(
        project_id, "Service Account Principals/Keys", keyed,
        ["email", "display_name", "unique_id"], primary_resource="Service Accounts",
        secondary_title_name="SA Keys",
    )


# --------------------------------------------------------------------------- #
# Custom roles -- dual (project AND org) scope with a run-scoped org cache so
# enum_all (per-project) lists org roles once. Genuinely bespoke; kept as a tail.
# --------------------------------------------------------------------------- #
def _normalize_role_scope_value(raw_scope: str, scope_type: str) -> str:
    text = str(raw_scope or "").strip()
    if not text:
        return ""
    if scope_type == "project":
        return text if text.startswith("projects/") else f"projects/{text}"
    if scope_type == "org":
        return text if text.startswith("organizations/") else f"organizations/{text}"
    return text


def _normalize_role_scope_list(raw, scope_type: str) -> list[str]:
    values = parse_csv_arg(raw if isinstance(raw, str) else ",".join(raw or []))
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized_value = _normalize_role_scope_value(value, scope_type)
        if normalized_value and normalized_value not in seen:
            seen.add(normalized_value)
            normalized.append(normalized_value)
    return normalized


def _resolve_org_for_project(session, project_id: str) -> str | None:
    rows = session.get_data("abstract_tree_hierarchy", columns=["parent"], where={"type": "project", "project_id": project_id})
    cursor = rows[0].get("parent") if rows else None
    seen: set[str] = set()
    while cursor and cursor not in seen:
        if str(cursor).startswith("organizations/"):
            return str(cursor)
        seen.add(cursor)
        parent_rows = session.get_data("abstract_tree_hierarchy", columns=["parent"], where={"name": cursor})
        cursor = parent_rows[0].get("parent") if parent_rows else None
    return None


def _parse_role_resource_name(role_name: str) -> tuple[str, str]:
    parts = split_path_tokens(role_name, separator="/", drop_empty=True)
    if len(parts) < 4 or parts[1] != "roles" or parts[0] not in ("projects", "organizations"):
        return "", ""
    return parts[0], parts[2]


def _coerce_included_permissions(raw_permissions):
    if raw_permissions is None:
        return []
    if isinstance(raw_permissions, list):
        return raw_permissions
    if isinstance(raw_permissions, str):
        text = raw_permissions.strip()
        if not text:
            return []
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
                if isinstance(parsed, list):
                    return parsed
            except (ValueError, SyntaxError, json.JSONDecodeError):
                pass
        return [item for item in text.split(",") if item.strip()]
    if isinstance(raw_permissions, dict):
        included = raw_permissions.get("includedPermissions")
        return included if isinstance(included, list) else []
    # Proto RepeatedScalarContainer (role.included_permissions) and other iterables.
    try:
        return list(raw_permissions)
    except TypeError:
        return []


_STAGE_LABELS = {0: "ALPHA", 1: "BETA", 2: "GA", 3: "DEPRECATED", 4: "DISABLED", 5: "EAP"}


def _coerce_custom_role_stage(raw_stage):
    if raw_stage is None:
        return ""
    if isinstance(raw_stage, int):
        return _STAGE_LABELS.get(raw_stage, str(raw_stage))
    stage = str(raw_stage).strip()
    if stage.isdigit():
        return _STAGE_LABELS.get(int(stage), stage)
    return stage.upper() if stage.upper() in set(_STAGE_LABELS.values()) else stage


def _hydrate_cached_custom_role(row):
    return SimpleNamespace(
        name=row.get("name", ""), title=row.get("title", ""),
        stage=_coerce_custom_role_stage(row.get("stage")),
        included_permissions=_coerce_included_permissions(row.get("included_permissions")),
    )


def _run_custom_roles(session, args, project_id) -> None:
    custom_roles_resource = IAMCustomRolesResource(session)
    action_dict: dict = {}
    all_custom_roles: dict = {}
    explicit_project_scopes = _normalize_role_scope_list(getattr(args, "project", None), "project")
    explicit_org_scopes = _normalize_role_scope_list(getattr(args, "org", None), "org")
    # Run-scoped cache: enum_all invokes enum_iam per project, but org roles are the
    # same across a tree -> list a given org's roles only once per run.
    run_ctx = getattr(session, "_module_run_context", None) or {}
    if int(run_ctx.get("index", 0) or 0) == 0 or not isinstance(getattr(session, "_enum_iam_org_cache", None), set):
        session._enum_iam_org_cache = set()
    org_cache: set = session._enum_iam_org_cache

    role_names = parse_csv_file_args(getattr(args, "role_names", None), getattr(args, "role_names_file", None))
    if role_names:
        for role_name in role_names:
            scope_prefix, role_scope_id = _parse_role_resource_name(role_name)
            if not scope_prefix:
                print(f"[X] Skipping custom role argument with invalid format: {role_name}")
                continue
            scope_key = role_scope_id if scope_prefix == "projects" else _normalize_role_scope_value(role_scope_id, "org")
            all_custom_roles.setdefault(scope_key, set()).add(HashableCustomRole(iam_admin_v1.Role(name=role_name), validated=False))
    else:
        requested_scopes = explicit_project_scopes or [_normalize_role_scope_value(project_id, "project")]
        if explicit_org_scopes:
            requested_scopes.extend(explicit_org_scopes)
        else:
            resolved_org = _resolve_org_for_project(session, project_id)
            if resolved_org:
                requested_scopes.append(resolved_org)
        for scope in list(dict.fromkeys(requested_scopes)):
            scope = scope if scope.startswith(("projects/", "organizations/")) else _normalize_role_scope_value(scope, "project")
            if scope.startswith("organizations/"):
                if scope in org_cache:
                    cached = session.get_data(
                        custom_roles_resource.TABLE_NAME,
                        columns=["name", "title", "stage", "included_permissions", "scope_of_custom_role"],
                        conditions="name LIKE ?", params=[f"{scope}/roles/%"],
                    ) or []
                    all_custom_roles[scope] = {HashableCustomRole(_hydrate_cached_custom_role(r), validated=False) for r in cached if r.get("name")}
                    continue
                org_cache.add(scope)
                listed = custom_roles_resource.list(org_id=scope, action_dict=action_dict)
                if listed and listed not in ("Not Enabled", None):
                    org_roles = [r for r in listed if r.name and "organizations/" in r.name]
                    custom_roles_resource.save(org_roles)
                    all_custom_roles[scope] = {HashableCustomRole(r) for r in org_roles}
                else:
                    all_custom_roles.setdefault(scope, set())
            else:
                scope_id = extract_path_tail(scope, default=scope)
                listed = custom_roles_resource.list(project_id=scope_id, action_dict=action_dict)
                if listed and listed not in ("Not Enabled", None):
                    project_roles = [r for r in listed if r.name and "projects/" in r.name]
                    custom_roles_resource.save(project_roles)
                    all_custom_roles[scope_id] = {HashableCustomRole(r) for r in project_roles}
                else:
                    all_custom_roles.setdefault(scope_id, set())

    for scope_label, roles in all_custom_roles.items():
        for role in list(roles):
            if not getattr(args, "get", False):
                continue
            role_get = custom_roles_resource.get(resource_id=role.name, action_dict=action_dict)
            if role_get:
                custom_roles_resource.save([role_get])
                role._custom_role.included_permissions = _coerce_included_permissions(getattr(role_get, "included_permissions", None))
                role._custom_role.stage = _coerce_custom_role_stage(getattr(role_get, "stage", None))
        session.insert_actions(action_dict, scope_label)

    for scope_label, roles in all_custom_roles.items():
        final_roles = list(roles)
        for role in final_roles:
            role._custom_role.included_permissions = _coerce_included_permissions(role._custom_role.included_permissions)
            role._custom_role.stage = _coerce_custom_role_stage(role._custom_role.stage)
            role._custom_role.name = extract_path_tail(role._custom_role.name)
        if final_roles:
            UtilityTools.summary_wrapup(
                scope_label, "IAM Custom Roles", final_roles,
                ["name", "title", "stage", "included_permissions"], primary_resource="Custom Roles", primary_sort_key="name",
            )
        else:
            print(f"{UtilityTools.YELLOW}[*] No custom IAM roles found in scope {scope_label}.{UtilityTools.RESET}")


# --------------------------------------------------------------------------- #
def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        roles_group = parser.add_mutually_exclusive_group(required=False)
        roles_group.add_argument("--role-names", type=str, help="Roles as projects/<pid>/roles/<role> or organizations/<id>/roles/<role>")
        roles_group.add_argument("--role-names-file", type=str, help="File containing role resource names")
        parser.add_argument("--project", type=str, help="Limit custom role enumeration to these project IDs (comma-separated)")
        parser.add_argument("--org", type=str, help="Limit custom role enumeration to these organization IDs (comma-separated)")

    return parse_component_args(
        user_args,
        description="Enumerate IAM resources",
        components=[
            ("service_accounts", "Enumerate service accounts and keys"),
            ("custom_roles", "Enumerate custom IAM roles"),
            ("pools", "Enumerate Workload Identity Pools (WIF)"),
            ("providers", "Enumerate Workload Identity Providers (WIF)"),
        ],
        add_extra_args=build_extra_args([SA_COMPONENT], extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on service accounts"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id

    if args.sa_account_names or args.sa_account_names_file:
        args.service_accounts = True
    if args.role_names or args.role_names_file:
        args.custom_roles = True
    selected = resolve_selected_components(args, ALL_KEYS)
    for key in ALL_KEYS:
        setattr(args, key, selected[key])

    if selected["service_accounts"]:
        discovered = run_components(
            session, args, components=[SA_COMPONENT], column_name="service_account_actions_allowed",
            module_name="enum_iam",
        )
        _summarize_service_accounts(project_id, discovered.get("service_accounts", []))

    if selected["custom_roles"]:
        _run_custom_roles(session, args, project_id)

    if selected["pools"] or selected["providers"]:
        try:
            run_components(session, args, components=WIF_COMPONENTS, column_name=None, module_name="enum_iam")
        except RuntimeError as exc:
            print(f"{UtilityTools.YELLOW}[!] Skipping Workload Identity pools/providers: {exc}{UtilityTools.RESET}")

    return 1
