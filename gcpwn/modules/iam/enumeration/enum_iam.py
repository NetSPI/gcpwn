from __future__ import annotations

import argparse
import ast
import json
from collections import defaultdict
from types import SimpleNamespace

from google.cloud import iam_admin_v1

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_tail, extract_project_id_from_resource, split_path_tokens
from gcpwn.core.utils.service_runtime import (
    get_cached_rows,
    parse_component_args,
    parse_csv_file_args,
    parse_csv_arg,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.iam.utilities.helpers import (
    HashableCustomRole,
    HashableServiceAccount,
    IAMCustomRolesResource,
    IAMServiceAccountsResource,
    IAMWorkloadIdentityPoolsResource,
    IAMWorkloadIdentityProvidersResource,
)


COMPONENTS = [
    ("service_accounts", "Enumerate service accounts and keys"),
    ("custom_roles", "Enumerate custom IAM roles"),
    ("pools", "Enumerate Workload Identity Pools (WIF)"),
    ("providers", "Enumerate Workload Identity Providers (WIF)"),
]


def _make_service_account_resource(resource_name: str, email: str | None = None, display_name: str | None = None):
    payload = {"name": str(resource_name or "").strip()}
    if email:
        payload["email"] = str(email).strip()
    if display_name:
        payload["display_name"] = str(display_name).strip()
    if not payload.get("email") and "serviceAccounts/" in payload["name"]:
        possible_email = payload["name"].split("serviceAccounts/")[-1]
        if possible_email and "@" in possible_email:
            payload["email"] = possible_email
    return iam_admin_v1.ServiceAccount(**payload)


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        sa_group = parser.add_mutually_exclusive_group(required=False)
        sa_group.add_argument("--sa-account-names", type=str, help="Service accounts in format projects/<pid>/serviceAccounts/<email>")
        sa_group.add_argument("--sa-account-names-file", type=str, help="File containing service account resource names")

        roles_group = parser.add_mutually_exclusive_group(required=False)
        roles_group.add_argument("--role-names", type=str, help="Roles in format projects/<project_id>/roles/<role_name>")
        roles_group.add_argument("--role-names-file", type=str, help="File containing role resource names")
        parser.add_argument(
            "--project",
            type=str,
            help="Limit custom role enumeration to these project IDs (comma-separated)",
        )
        parser.add_argument(
            "--org",
            type=str,
            help="Limit custom role enumeration to these organization IDs (comma-separated, with or without organizations/ prefix)",
        )

    return parse_component_args(
        user_args,
        description="Enumerate IAM resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on service accounts"},
        },
    )


def _normalize_role_scope_value(raw_scope: str, scope_type: str) -> str:
    text = str(raw_scope or "").strip()
    if not text:
        return ""
    if scope_type == "project":
        if text.startswith("projects/"):
            return text
        return f"projects/{text}"
    if scope_type == "org":
        if text.startswith("organizations/"):
            return text
        return f"organizations/{text}"
    return text


def _normalize_role_scope_list(raw: str | list[str] | None, scope_type: str) -> list[str]:
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
    rows = session.get_data(
        "abstract_tree_hierarchy",
        columns=["parent"],
        conditions=f'type="project" AND project_id="{project_id}"',
    )
    if not rows:
        return None

    cursor = rows[0].get("parent") if rows else None
    seen: set[str] = set()
    while cursor and cursor not in seen:
        if str(cursor).startswith("organizations/"):
            return str(cursor)
        seen.add(cursor)
        parent_rows = session.get_data(
            "abstract_tree_hierarchy",
            columns=["parent"],
            conditions=f'name="{cursor}"',
        )
        cursor = parent_rows[0].get("parent") if parent_rows else None
    return None


def _parse_role_resource_name(role_name: str) -> tuple[str, str]:
    parts = split_path_tokens(role_name, separator="/", drop_empty=True)
    if len(parts) < 4 or parts[1] != "roles":
        return "", ""
    if parts[0] in ("projects", "organizations"):
        return parts[0], parts[2]
    return "", ""


def _coerce_included_permissions(raw_permissions):
    if raw_permissions is None:
        return []
    if isinstance(raw_permissions, tuple):
        raw_permissions = list(raw_permissions)
    if isinstance(raw_permissions, list):
        return raw_permissions
    if isinstance(raw_permissions, str):
        text = raw_permissions.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list):
                return parsed
        except (ValueError, SyntaxError):
            pass
        return [item for item in text.split(",") if item.strip()]
    if isinstance(raw_permissions, dict):
        included = raw_permissions.get("includedPermissions")
        if isinstance(included, list):
            return included
    return []


def _coerce_custom_role_stage(raw_stage):
    stage_labels = {
        0: "ALPHA",
        1: "BETA",
        2: "GA",
        3: "DEPRECATED",
        4: "DISABLED",
        5: "EAP",
    }
    if raw_stage is None:
        return ""
    if isinstance(raw_stage, int):
        return stage_labels.get(raw_stage, str(raw_stage))
    stage = str(raw_stage).strip()
    if not stage:
        return ""
    if stage.isdigit():
        return stage_labels.get(int(stage), stage)
    stage_upper = stage.upper()
    if stage_upper in {"ALPHA", "BETA", "GA", "DEPRECATED", "DISABLED", "EAP"}:
        return stage_upper
    return stage


def _hydrate_cached_custom_role(row):
    permissions = _coerce_included_permissions(row.get("included_permissions"))
    normalized_stage = _coerce_custom_role_stage(row.get("stage"))
    return SimpleNamespace(
        name=row.get("name", ""),
        title=row.get("title", ""),
        stage=normalized_stage,
        included_permissions=permissions,
    )


def _get_run_scoped_custom_role_org_cache(session) -> set[str]:
    run_ctx = getattr(session, "_module_run_context", None) or {}
    run_index = int(run_ctx.get("index", 0) or 0)

    if run_index == 0:
        run_state = {"custom_role_org_scope_cache": set()}
        setattr(session, "_enum_iam_custom_role_run_state", run_state)
        return run_state["custom_role_org_scope_cache"]

    run_state = getattr(session, "_enum_iam_custom_role_run_state", None)
    if not isinstance(run_state, dict) or "custom_role_org_scope_cache" not in run_state:
        run_state = {"custom_role_org_scope_cache": set()}
        setattr(session, "_enum_iam_custom_role_run_state", run_state)
        return run_state["custom_role_org_scope_cache"]

    cached_org_scopes = run_state.get("custom_role_org_scope_cache")
    if not isinstance(cached_org_scopes, set):
        run_state["custom_role_org_scope_cache"] = set()
        return run_state["custom_role_org_scope_cache"]
    return cached_org_scopes


def _load_service_account_resource_names(args, session, project_id: str) -> list[str]:
    resource_names: list[str] = parse_csv_file_args(
        getattr(args, "sa_account_names", None),
        getattr(args, "sa_account_names_file", None),
    )

    if resource_names:
        return list(dict.fromkeys(resource_names))

    scoped_project_id = str(project_id or "").strip()
    cached_sas = get_cached_rows(
        session,
        "iam_service_accounts",
        project_id=scoped_project_id or None,
        columns=["name", "email", "project_id"],
    ) or []
    for row in cached_sas:
        row_project_id = str(row.get("project_id") or scoped_project_id).strip()
        name = row.get("name") or ""
        if name:
            resource_names.append(name)
            continue
        email = row.get("email") or ""
        if email:
            resource_names.append(f"projects/{row_project_id}/serviceAccounts/{email}")

    return list(dict.fromkeys([name for name in resource_names if name]))


def run_module(user_args, session):
    args = _parse_args(user_args)
    if args.sa_account_names or args.sa_account_names_file:
        args.service_accounts = True
    if args.role_names or args.role_names_file:
        args.custom_roles = True
    component_keys = [component_key for component_key, _help_text in COMPONENTS]
    selected = resolve_selected_components(args, component_keys)

    project_id = session.project_id
    service_accounts_resource = IAMServiceAccountsResource(session)
    custom_roles_resource = IAMCustomRolesResource(session)
    wif_pools_resource = None
    wif_providers_resource = None
    wants_wif = bool(selected.get("pools", False) or selected.get("providers", False))
    if wants_wif:
        try:
            wif_pools_resource = IAMWorkloadIdentityPoolsResource(session)
            if selected.get("providers", False):
                wif_providers_resource = IAMWorkloadIdentityProvidersResource(session)
        except RuntimeError as exc:
            print(f"{UtilityTools.YELLOW}[!] Skipping Workload Identity pools/providers: {exc}{UtilityTools.RESET}")
            selected["pools"] = False
            selected["providers"] = False
    # Service account IAM policy enumeration is handled by enum_policy_bindings through
    # everything.utilities.iam_policy_bindings (table: iam_allow_policies).

    if selected.get("service_accounts", False):
        resource_actions = {
            "project_permissions": defaultdict(set),
            "folder_permissions": {},
            "organization_permissions": {},
        }
        service_account_api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        service_account_iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        all_service_accounts = defaultdict(dict)

        if args.sa_account_names or args.sa_account_names_file:
            service_account_names = parse_csv_file_args(
                getattr(args, "sa_account_names", None),
                getattr(args, "sa_account_names_file", None),
            )
            for name in service_account_names:
                pid = extract_project_id_from_resource(name, fallback_project=project_id)
                all_service_accounts[pid][
                    HashableServiceAccount(
                        _make_service_account_resource(
                            resource_name=name,
                            email=extract_path_tail(name) if "/" in name else None,
                        ),
                        validated=False,
                    )
                ] = set()
        else:
            scoped_project_id = str(project_id or "").strip()
            cached = get_cached_rows(
                session,
                service_accounts_resource.TABLE_NAME,
                project_id=scoped_project_id or None,
                columns=["name", "email", "display_name", "project_id"],
                conditions='email != ""',
            )
            if cached:
                for row in cached:
                    row_project_id = str(row.get("project_id") or scoped_project_id).strip()
                    name = row.get("name") or f"projects/{row_project_id}/serviceAccounts/{row.get('email', '')}"
                    if name and "serviceAccounts/" in name:
                        pid = extract_project_id_from_resource(name, fallback_project=row_project_id or scoped_project_id)
                        all_service_accounts[pid][
                            HashableServiceAccount(
                                _make_service_account_resource(
                                    resource_name=name,
                                    email=row.get("email"),
                                    display_name=row.get("display_name"),
                                ),
                                validated=False,
                            )
                        ] = set()
            else:
                listed = service_accounts_resource.list(project_id=project_id, action_dict=resource_actions)
                if listed and listed not in ("Not Enabled", None):
                    service_accounts_resource.save(listed)
                    for service_account in listed:
                        all_service_accounts[project_id][HashableServiceAccount(service_account)] = set()

        for target_project_id, service_account_map in all_service_accounts.items():
            for service_account in list(service_account_map):
                name = service_account.name
                current_service_account = service_account

                if args.get:
                    service_account_get = service_accounts_resource.get(resource_id=name, action_dict=service_account_api_actions)
                    if service_account_get:
                        service_accounts_resource.save([service_account_get])
                        if not service_account.validated and (args.sa_account_names or args.sa_account_names_file):
                            del service_account_map[current_service_account]
                            current_service_account = HashableServiceAccount(service_account_get, validated=True)
                            service_account_map[current_service_account] = set()

                if args.iam:
                    perms = service_accounts_resource.get_iam_permissions(
                        resource_id=name,
                        action_dict=service_account_iam_actions,
                    )
                    if perms:
                        if not service_account.validated and (args.sa_account_names or args.sa_account_names_file):
                            service_account.validated = True

                listed_keys = service_accounts_resource.list_keys(resource_id=name, action_dict=service_account_api_actions)
                if listed_keys and listed_keys not in ("Not Enabled", None):
                    service_accounts_resource.save_keys(listed_keys)
                    for key in listed_keys:
                        key_id = extract_path_tail(key.name)
                        service_account_map[current_service_account].add(f"{key_id} (DISABLED: {key.disabled})")
                        if args.get:
                            key_get = service_accounts_resource.get_key(
                                resource_id=key.name,
                                action_dict=service_account_api_actions,
                            )
                            if key_get:
                                service_accounts_resource.save_keys([key_get])

            session.insert_actions(resource_actions, target_project_id, column_name="service_account_actions_allowed")
            session.insert_actions(service_account_api_actions, target_project_id, column_name="service_account_actions_allowed")
            session.insert_actions(
                service_account_iam_actions,
                target_project_id,
                column_name="service_account_actions_allowed",
                evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
            )

        for target_project_id, service_account_map in all_service_accounts.items():
            final_map = service_account_map
            if args.sa_account_names or args.sa_account_names_file:
                final_map = {key: value for key, value in final_map.items() if key.validated}
            for service_account in final_map:
                service_account._sa_account.name = extract_path_tail(service_account._sa_account.name)
            UtilityTools.summary_wrapup(
                target_project_id,
                "Service Account Principals/Keys",
                {key: sorted(list(value)) for key, value in final_map.items()},
                ["email", "display_name", "unique_id"],
                primary_resource="Service Accounts",
                secondary_title_name="SA Keys",
                )

    if selected.get("custom_roles", False):
        action_dict = {}
        all_custom_roles = {}
        explicit_project_scopes = _normalize_role_scope_list(getattr(args, "project", None), "project")
        explicit_org_scopes = _normalize_role_scope_list(getattr(args, "org", None), "org")
        custom_role_org_scope_cache = _get_run_scoped_custom_role_org_cache(session)

        if args.role_names or args.role_names_file:
            role_names = parse_csv_file_args(
                getattr(args, "role_names", None),
                getattr(args, "role_names_file", None),
            )
            for role_name in role_names:
                scope_prefix, role_scope_id = _parse_role_resource_name(role_name)
                if not scope_prefix or not role_scope_id:
                    print(f"[X] Skipping custom role argument with invalid format: {role_name}")
                    continue
                if scope_prefix == "projects":
                    all_custom_roles.setdefault(role_scope_id, set()).add(HashableCustomRole(iam_admin_v1.Role(name=role_name), validated=False))
                elif scope_prefix == "organizations":
                    all_custom_roles.setdefault(_normalize_role_scope_value(role_scope_id, "org"), set()).add(
                        HashableCustomRole(iam_admin_v1.Role(name=role_name), validated=False)
                    )
        else:
            requested_scopes = explicit_project_scopes or [_normalize_role_scope_value(project_id, "project")]
            if not explicit_org_scopes:
                resolved_org = _resolve_org_for_project(session, project_id)
                if resolved_org:
                    requested_scopes.append(resolved_org)
            else:
                requested_scopes.extend(explicit_org_scopes)

            requested_scopes = list(dict.fromkeys(requested_scopes))

            for requested_scope in requested_scopes:
                requested_scope_normalized = (
                    requested_scope
                    if requested_scope.startswith(("projects/", "organizations/"))
                    else _normalize_role_scope_value(requested_scope, "project")
                )
                if requested_scope_normalized.startswith("projects/"):
                    requested_scope_id = extract_path_tail(requested_scope_normalized, default=requested_scope_normalized)
                    cached_roles = session.get_data(
                        custom_roles_resource.TABLE_NAME,
                        columns=["name", "title", "stage", "included_permissions", "scope_of_custom_role"],
                        conditions=f'name LIKE "{requested_scope_normalized}/roles/%"',
                    )
                    if cached_roles:
                        all_custom_roles[requested_scope_id] = {
                            HashableCustomRole(
                                _hydrate_cached_custom_role(row),
                                validated=False,
                            )
                            for row in cached_roles
                            if row.get("name")
                        }
                        continue

                    listed = custom_roles_resource.list(project_id=requested_scope_id, action_dict=action_dict)
                    if listed and listed not in ("Not Enabled", None):
                        project_roles = [role for role in listed if role.name and "projects/" in role.name]
                        custom_roles_resource.save(project_roles)
                        all_custom_roles[requested_scope_id] = {HashableCustomRole(role) for role in project_roles}
                    else:
                        if listed == "Not Enabled":
                            print(f"{UtilityTools.YELLOW}[!] Custom IAM roles listing is not enabled for project {requested_scope_id}.{UtilityTools.RESET}")
                        all_custom_roles.setdefault(requested_scope_id, set())

                elif requested_scope_normalized.startswith("organizations/"):
                    if requested_scope_normalized in custom_role_org_scope_cache:
                        cached_roles = session.get_data(
                            custom_roles_resource.TABLE_NAME,
                            columns=["name", "title", "stage", "included_permissions", "scope_of_custom_role"],
                            conditions=f'name LIKE "{requested_scope_normalized}/roles/%"',
                        ) or []
                        if cached_roles:
                            all_custom_roles[requested_scope_normalized] = {
                                HashableCustomRole(
                                    _hydrate_cached_custom_role(row),
                                    validated=False,
                                )
                            for row in cached_roles
                            if row.get("name")
                        }
                        custom_role_org_scope_cache.add(requested_scope_normalized)
                        continue

                    listed = custom_roles_resource.list(org_id=requested_scope_normalized, action_dict=action_dict)
                    custom_role_org_scope_cache.add(requested_scope_normalized)
                    if listed and listed not in ("Not Enabled", None):
                        org_roles = [role for role in listed if role.name and "organizations/" in role.name]
                        custom_roles_resource.save(org_roles)
                        all_custom_roles[requested_scope_normalized] = {HashableCustomRole(role) for role in org_roles}
                    else:
                        if listed == "Not Enabled":
                            print(f"{UtilityTools.YELLOW}[!] Custom IAM roles listing is not enabled for organization {requested_scope_normalized}.{UtilityTools.RESET}")
                        all_custom_roles.setdefault(requested_scope_normalized, set())

        for target_project_id, roles in all_custom_roles.items():
            for role in list(roles):
                role_name = role.name
                if not args.get:
                    continue
                role_get = custom_roles_resource.get(resource_id=role_name, action_dict=action_dict)
                if role_get:
                    role_get_wrapped = HashableCustomRole(role_get, validated=True)
                    role_get_wrapped._custom_role.included_permissions = _coerce_included_permissions(
                        getattr(role_get_wrapped._custom_role, "included_permissions", None)
                    )
                    role_get_wrapped._custom_role.stage = _coerce_custom_role_stage(
                        getattr(role_get_wrapped._custom_role, "stage", None)
                    )
                    custom_roles_resource.save([role_get])
                    if (args.role_names or args.role_names_file) and not role.validated:
                        roles.discard(role)
                        roles.add(role_get_wrapped)
                        continue
                    role._custom_role.included_permissions = _coerce_included_permissions(
                        getattr(role_get, "included_permissions", None)
                    )
                    role._custom_role.stage = _coerce_custom_role_stage(getattr(role_get, "stage", None))
               

            session.insert_actions(action_dict, target_project_id)

        for target_project_id, roles in all_custom_roles.items():
            final_roles = list(roles)
            if args.role_names or args.role_names_file:
                final_roles = [role for role in final_roles if role.validated]
            for role in final_roles:
                role._custom_role.included_permissions = _coerce_included_permissions(role._custom_role.included_permissions)
                role._custom_role.stage = _coerce_custom_role_stage(role._custom_role.stage)
                role._custom_role.name = extract_path_tail(role._custom_role.name)
            if final_roles:
                UtilityTools.summary_wrapup(
                    target_project_id,
                    "IAM Custom Roles",
                    final_roles,
                    ["name", "title", "stage", "included_permissions"],
                    primary_resource="Custom Roles",
                    primary_sort_key="name",
                )
            else:
                print(
                    f"{UtilityTools.YELLOW}[*] No custom IAM roles found in scope {target_project_id}.{UtilityTools.RESET}"
                )

    if selected.get("pools", False) or selected.get("providers", False):
        pools_rows = []
        providers_rows = []
        wif_actions = {}
        project_number = ""

        if selected.get("pools", False):
            listed_pools = wif_pools_resource.list(project_id=project_id, action_dict=wif_actions) if wif_pools_resource else []
            if listed_pools and listed_pools not in ("Not Enabled", None):
                pools_rows = listed_pools
                if args.get:
                    enriched_pools = []
                    for row in pools_rows:
                        resource_name = row.get("name", "")
                        if resource_name:
                            enriched_pools.append(wif_pools_resource.get(resource_id=resource_name, action_dict=wif_actions) or row)
                    pools_rows = enriched_pools
                if pools_rows:
                    wif_pools_resource.save(pools_rows, project_id=project_id, project_number=project_number)
        elif selected.get("providers", False):
            pools_rows = session.get_data(
                wif_pools_resource.TABLE_NAME,
                columns=wif_pools_resource.COLUMNS,
                conditions=f'project_id="{project_id}"',
            ) or []

        if selected.get("providers", False) and wif_providers_resource:
            if not pools_rows:
                print_missing_dependency(
                    component_name="Workload Identity providers",
                    dependency_name="Workload Identity pools",
                    module_name="enum_iam",
                    manual_flags=["--pools"],
                )
            else:
                for pool in pools_rows:
                    pool_name = pool.get("name", "")
                    if not pool_name:
                        continue
                    listed_providers = wif_providers_resource.list(pool_name=pool_name, action_dict=wif_actions)
                    if not listed_providers or listed_providers in ("Not Enabled", None):
                        continue
                    if args.get:
                        enriched_providers = []
                        for row in listed_providers:
                            resource_name = row.get("name", "")
                            if resource_name:
                                enriched_providers.append(wif_providers_resource.get(resource_id=resource_name, action_dict=wif_actions) or row)
                        listed_providers = enriched_providers
                    if listed_providers:
                        wif_providers_resource.save(listed_providers, project_id=project_id, project_number=project_number)
                        providers_rows.extend(listed_providers)

        if wif_actions:
            session.insert_actions(wif_actions, project_id)

        if selected.get("pools", False):
            UtilityTools.summary_wrapup(
                project_id,
                "Workload Identity Pools",
                pools_rows,
                wif_pools_resource.COLUMNS if wif_pools_resource else ["name"],
                primary_resource="Pools",
                primary_sort_key="name",
                )
        if selected.get("providers", False):
            UtilityTools.summary_wrapup(
                project_id,
                "Workload Identity Providers",
                providers_rows,
                wif_providers_resource.COLUMNS if wif_providers_resource else ["name"],
                primary_resource="Providers",
                primary_sort_key="name",
                )

    return 1
