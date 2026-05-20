from __future__ import annotations

import argparse
import importlib
import re
import shutil
from time import perf_counter

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import add_standard_arguments, parse_id_input_values

_ENUM_PROGRESS: dict[str, int | bool] = {"enabled": False, "index": 0, "total": 0}

_SERVICE_NAME_OVERRIDES = {
    "enum_resources": "Resource Manager",
    "enum_cloudcompute_resources": "Compute Resources",
    "enum_cloudcompute_network": "Compute Network",
    "enum_cloudcompute_lb": "Compute Load Balancing",
    "enum_cloudfunctions": "Cloud Functions",
    "enum_cloudstorage": "Cloud Storage",
    "enum_bigquery": "BigQuery",
    "enum_bigtable": "Bigtable",
    "enum_pubsub": "Pub/Sub",
    "enum_firestore": "Firestore",
    "enum_clouddns": "Cloud DNS",
    "enum_servicedirectory": "Service Directory",
    "enum_appengine": "App Engine",
    "enum_cloud_identity": "Google Workspace Cloud Identity",
    "enum_secretsmanager": "Secret Manager",
    "enum_storagetransfer": "Storage Transfer",
    "enum_memorystore": "Memorystore",
    "enum_iam": "IAM",
    "enum_cloudrun": "Cloud Run",
    "enum_cloudsql": "Cloud SQL",
    "enum_kms": "Cloud KMS",
    "enum_artifactregistry": "Artifact Registry",
    "enum_gke": "GKE",
    "enum_cloudbuild": "Cloud Build",
    "enum_cloudcomposer": "Cloud Composer",
    "enum_cloudtasks": "Cloud Tasks",
    "enum_apikeys": "API Keys",
    "enum_batch": "Batch",
    "enum_policy_bindings": "IAM Policy Bindings",
}

DOWNLOAD_CATEGORY_TOKENS: dict[str, set[str]] = {
    "metadata": {
        "function_env",
        "cloudbuild_builds",
        "composer_configs",
        "cloudtasks_requests",
        "cloudrun_revision_env",
        "clouddns_record_sets",
    },
    "content": {
        "buckets",
        "function_source",
        "secrets",
        "firestore_data",
        "bigquery_tables",
        "compute_serial",
        "compute_screenshot",
        "artifactregistry_files",
        "batch_scripts",
        "apikeys_content",
    },
}

DOWNLOAD_TOKEN_ALIASES = {
    "all": "all",
    "metadata": "metadata",
    "content": "content",
    "bucket": "buckets",
    "buckets": "buckets",
    "bucket_content": "buckets",
    "bucket_contents": "buckets",
    "bucket_objects": "buckets",
    "cloudstorage": "buckets",
    "cloudstorage_blobs": "buckets",
    "function_source": "function_source",
    "function_sources": "function_source",
    "functions_source": "function_source",
    "cloudfunctions_source": "function_source",
    "function_env": "function_env",
    "function_envs": "function_env",
    "function_environment": "function_env",
    "function_environments": "function_env",
    "functions_env": "function_env",
    "secrets": "secrets",
    "secret": "secrets",
    "secret_values": "secrets",
    "secretsmanager_values": "secrets",
    "firestore": "firestore_data",
    "firestore_data": "firestore_data",
    "firestore_content": "firestore_data",
    "bigquery": "bigquery_tables",
    "bigquery_tables": "bigquery_tables",
    "bigquery_table": "bigquery_tables",
    "bigquery_data": "bigquery_tables",
    "compute_serial": "compute_serial",
    "serial": "compute_serial",
    "compute_screenshot": "compute_screenshot",
    "compute_screenshots": "compute_screenshot",
    "screenshot": "compute_screenshot",
    "screenshots": "compute_screenshot",
    "compute_artifacts": "compute_artifacts",
    "compute_metadata": "compute_artifacts",
    "compute_download": "compute_artifacts",
    "cloudbuild": "cloudbuild_builds",
    "cloudbuild_build": "cloudbuild_builds",
    "cloudbuild_builds": "cloudbuild_builds",
    "composer": "composer_configs",
    "cloudcomposer": "composer_configs",
    "composer_configs": "composer_configs",
    "cloudtasks": "cloudtasks_requests",
    "cloudtasks_requests": "cloudtasks_requests",
    "cloudtasks_http_requests": "cloudtasks_requests",
    "cloudrun_revision_env": "cloudrun_revision_env",
    "dns": "clouddns_record_sets",
    "clouddns": "clouddns_record_sets",
    "dns_records": "clouddns_record_sets",
    "record_sets": "clouddns_record_sets",
    "clouddns_record_sets": "clouddns_record_sets",
    "artifactregistry": "artifactregistry_files",
    "artifact_registry": "artifactregistry_files",
    "artifactregistry_files": "artifactregistry_files",
    "batch": "batch_scripts",
    "batch_scripts": "batch_scripts",
    "apikeys": "apikeys_content",
    "api_keys": "apikeys_content",
    "apikeys_content": "apikeys_content",
}

ALL_DOWNLOAD_TOKENS = set(DOWNLOAD_CATEGORY_TOKENS["metadata"]) | set(DOWNLOAD_CATEGORY_TOKENS["content"])


def _parse_csv_tokens(raw: str | None) -> list[str]:
    value = str(raw or "").strip()
    if not value:
        return []
    return [token.strip().lower() for token in value.split(",") if token and token.strip()]


def _expand_download_tokens(raw: str | None) -> set[str]:
    selected: set[str] = set()
    for token in _parse_csv_tokens(raw):
        mapped = DOWNLOAD_TOKEN_ALIASES.get(token)
        if mapped is None:
            supported = ", ".join(sorted(DOWNLOAD_TOKEN_ALIASES.keys()))
            raise ValueError(f"Invalid --download token: {token}. Supported values: {supported}")
        if mapped == "all":
            selected |= set(ALL_DOWNLOAD_TOKENS)
            continue
        if mapped in DOWNLOAD_CATEGORY_TOKENS:
            selected |= set(DOWNLOAD_CATEGORY_TOKENS[mapped])
            continue
        selected.add(mapped)
    return selected


def _pretty_service_name(module_name: str) -> str:
    token = str(module_name or "").split(".")[-1]
    if token in _SERVICE_NAME_OVERRIDES:
        return _SERVICE_NAME_OVERRIDES[token]
    token = re.sub(r"^enum_", "", token)
    token = token.replace("_", " ").strip()
    return token.title() if token else "Unknown Service"


def _service_divider() -> str:
    term_width = shutil.get_terminal_size((120, 24)).columns
    return "-" * max(30, min(140, term_width - 10))


def _run_other_module(session, user_args, module_name):
    progress_enabled = bool(_ENUM_PROGRESS.get("enabled"))
    start = 0.0
    service_name = _pretty_service_name(module_name)
    if progress_enabled:
        _ENUM_PROGRESS["index"] = int(_ENUM_PROGRESS.get("index", 0)) + 1
        idx = int(_ENUM_PROGRESS.get("index", 0))
        total = int(_ENUM_PROGRESS.get("total", 0))
        print(f"{UtilityTools.BOLD}[*] {_service_divider()} [*]{UtilityTools.RESET}")
        if total > 0:
            print(f"{UtilityTools.BOLD}[*] Service {idx}/{total}: {service_name}{UtilityTools.RESET}")
        else:
            print(f"{UtilityTools.BOLD}[*] Service {idx}: {service_name}{UtilityTools.RESET}")
        start = perf_counter()

    module = importlib.import_module(module_name)
    result = module.run_module(user_args, session)
    if progress_enabled:
        elapsed = perf_counter() - start
        print(f"[*] Completed {service_name} in {elapsed:.1f}s")
    return result


def _flatten_arg_groups(values: list[list[str]] | None) -> list[str]:
    return [token for group in (values or []) for token in (group or [])]


def _normalize_scope_values(values) -> set[str]:
    return {str(value).strip() for value in (values or []) if str(value).strip()}


def _resource_name_tail(resource_name: str) -> str:
    return str(resource_name or "").strip().rsplit("/", 1)[-1].strip()


def _load_hierarchy_rows(session) -> list[dict]:
    hierarchy_rows = session.get_data(
        "abstract_tree_hierarchy",
        columns=["name", "parent", "type", "project_id"],
    ) or []
    return [row for row in hierarchy_rows if isinstance(row, dict)]


def _resolve_parent_descendants(
    hierarchy_rows: list[dict],
    *,
    parent_folder_ids: set[str],
    parent_org_ids: set[str],
) -> dict[str, set[str]]:
    roots = {f"folders/{folder_id}" for folder_id in parent_folder_ids} | {
        f"organizations/{org_id}" for org_id in parent_org_ids
    }
    if not roots:
        return {"projects": set(), "folders": set(), "organizations": set()}

    by_name = {}
    children_by_parent: dict[str, list[dict]] = {}
    for row in hierarchy_rows:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        by_name[name] = row
        parent = str(row.get("parent") or "").strip()
        children_by_parent.setdefault(parent, []).append(row)

    projects: set[str] = set()
    folders: set[str] = set()
    organizations: set[str] = set()

    queue = [root for root in roots if root in by_name]
    seen: set[str] = set()
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        row = by_name.get(current) or {}
        row_type = str(row.get("type") or "").strip().lower()
        if row_type == "project":
            project_id = str(row.get("project_id") or "").strip()
            if project_id:
                projects.add(project_id)
        elif row_type == "folder":
            folder_id = _resource_name_tail(current)
            if folder_id.isdigit():
                folders.add(folder_id)
        elif row_type == "org":
            org_id = _resource_name_tail(current)
            if org_id.isdigit():
                organizations.add(org_id)

        for child in children_by_parent.get(current, []):
            child_name = str(child.get("name") or "").strip()
            if child_name and child_name not in seen:
                queue.append(child_name)

    return {"projects": projects, "folders": folders, "organizations": organizations}


def _resolve_effective_allowlist_scope(
    session,
    *,
    project_ids: list[str],
    folder_ids: list[str],
    organization_ids: list[str],
    parent_folder_ids: list[str],
    parent_org_ids: list[str],
) -> dict[str, set[str] | bool]:
    direct_projects = _normalize_scope_values(project_ids)
    direct_folders = _normalize_scope_values(folder_ids)
    direct_orgs = _normalize_scope_values(organization_ids)
    parent_folders = _normalize_scope_values(parent_folder_ids)
    parent_orgs = _normalize_scope_values(parent_org_ids)
    direct_active = bool(direct_projects or direct_folders or direct_orgs)
    parent_active = bool(parent_folders or parent_orgs)
    allowlist_active = bool(direct_active or parent_active)

    if not allowlist_active:
        return {
            "allowlist_active": False,
            "projects": set(),
            "folders": set(),
            "organizations": set(),
        }

    parent_scope = {"projects": set(), "folders": set(), "organizations": set()}
    if parent_active:
        parent_scope = _resolve_parent_descendants(
            _load_hierarchy_rows(session),
            parent_folder_ids=parent_folders,
            parent_org_ids=parent_orgs,
        )

    if direct_active:
        effective_projects = set(direct_projects)
        effective_folders = set(direct_folders)
        effective_orgs = set(direct_orgs)
        if parent_active:
            if effective_projects:
                effective_projects &= set(parent_scope["projects"])
            if effective_folders:
                effective_folders &= set(parent_scope["folders"])
            if effective_orgs:
                effective_orgs &= set(parent_scope["organizations"])
    else:
        effective_projects = set(parent_scope["projects"])
        effective_folders = set(parent_scope["folders"])
        effective_orgs = set(parent_scope["organizations"])

    return {
        "allowlist_active": True,
        "projects": effective_projects,
        "folders": effective_folders,
        "organizations": effective_orgs,
    }


def _count_non_rm_service_plan(args, *, every_flag_missing: bool, first_run: bool, last_run: bool, more: bool) -> int:
    count = 0
    count += int(args.cloud_compute or args.cloud_compute_resources or every_flag_missing)
    count += int(args.cloud_compute or args.cloud_compute_network or every_flag_missing)
    count += int(args.cloud_compute or args.cloud_compute_lb or every_flag_missing)
    count += int(args.cloud_functions or every_flag_missing)
    count += int(args.cloud_storage or every_flag_missing)
    count += int(args.cloud_bigquery or every_flag_missing)
    count += int(args.cloud_bigtable or every_flag_missing)
    count += int(args.cloud_pubsub or every_flag_missing)
    count += int(args.cloud_firestore or every_flag_missing)
    count += int(args.cloud_dns or every_flag_missing)
    count += int(args.service_directory or every_flag_missing)
    count += int(args.app_engine or every_flag_missing)
    count += int(first_run and args.workspace_cloud_identity)
    count += int(args.cloud_secretsmanager or every_flag_missing)
    count += int(args.storage_transfer or every_flag_missing)
    count += int(args.cloud_redis or every_flag_missing)
    count += int(args.cloud_iam or every_flag_missing)
    count += int(args.cloud_run or every_flag_missing)
    count += int(args.cloud_sql or every_flag_missing)
    count += int(args.cloud_kms or every_flag_missing)
    count += int(args.artifact_registry or every_flag_missing)
    count += int(args.gke or every_flag_missing)
    count += int(args.cloud_build or every_flag_missing)
    count += int(args.cloud_composer or every_flag_missing)
    count += int(args.cloud_tasks or every_flag_missing)
    count += int(args.api_keys or every_flag_missing)
    count += int(args.cloud_batch or every_flag_missing)
    count += int(last_run and not more)
    return count


def run_module(user_args, session):
    parser = argparse.ArgumentParser(description="Enumerate all services", allow_abbrev=False)
    parser.add_argument("--download-output", required=False, help="Output directory for downloaded artifacts")
    parser.add_argument("--threads", type=int, default=3, help="Worker threads for region/zone fan-out (default: 3)")
    parser.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
    parser.add_argument("--zones-list", required=False, help="Zones in comma-separated format")
    allowlist_group = parser.add_argument_group(
        "Scoped Allowlist Options",
        "Optional scope controls. If no allowlist flags are provided, all discovered resources are in scope.",
    )
    allowlist_group.add_argument(
        "--project-allowlist",
        action="append",
        nargs="+",
        help=(
            "Project IDs for Resource Manager filtering. Supports space/comma-separated inline values."
        ),
    )
    allowlist_group.add_argument(
        "--project-allowlist-file",
        action="append",
        nargs="+",
        help="File path(s) containing project IDs (one ID per line).",
    )
    allowlist_group.add_argument(
        "--folder-allowlist",
        action="append",
        nargs="+",
        help=(
            "Folder numeric IDs for Resource Manager filtering. Supports space/comma-separated inline values."
        ),
    )
    allowlist_group.add_argument(
        "--folder-allowlist-file",
        action="append",
        nargs="+",
        help="File path(s) containing folder numeric IDs (one ID per line).",
    )
    allowlist_group.add_argument(
        "--org-allowlist",
        action="append",
        nargs="+",
        help=(
            "Organization numeric IDs for Resource Manager filtering. Supports space/comma-separated inline values."
        ),
    )
    allowlist_group.add_argument(
        "--org-allowlist-file",
        action="append",
        nargs="+",
        help="File path(s) containing organization numeric IDs (one ID per line).",
    )
    allowlist_group.add_argument(
        "--parent-allowlist-folder",
        action="append",
        nargs="+",
        help="Folder numeric IDs used as parent scope filters (inline values).",
    )
    allowlist_group.add_argument(
        "--parent-allowlist-folder-file",
        action="append",
        nargs="+",
        help="File path(s) containing folder numeric IDs used as parent scope filters (one ID per line).",
    )
    allowlist_group.add_argument(
        "--parent-allowlist-org",
        action="append",
        nargs="+",
        help="Organization numeric IDs used as parent scope filters (inline values).",
    )
    allowlist_group.add_argument(
        "--parent-allowlist-org-file",
        action="append",
        nargs="+",
        help="File path(s) containing organization numeric IDs used as parent scope filters (one ID per line).",
    )
    parser.add_argument(
        "--all-resource-permissions",
        "--all-permissions",
        dest="all_resource_permissions",
        action="store_true",
        help="For Resource Manager, pass --all-permissions to test the large permission sets",
    )
    parser.add_argument("--cloud-run", action="store_true", help="Execute Cloud Run enumeration")
    parser.add_argument("--cloud-sql", action="store_true", help="Execute Cloud SQL enumeration")
    parser.add_argument("--cloud-kms", action="store_true", help="Execute Cloud KMS enumeration")
    parser.add_argument("--artifact-registry", action="store_true", help="Execute Artifact Registry enumeration")
    parser.add_argument("--gke", action="store_true", help="Execute GKE enumeration")
    parser.add_argument("--cloud-build", action="store_true", help="Execute Cloud Build enumeration")
    parser.add_argument("--cloud-composer", action="store_true", help="Execute Cloud Composer enumeration")
    parser.add_argument("--cloud-tasks", action="store_true", help="Execute Cloud Tasks enumeration")
    parser.add_argument("--api-keys", action="store_true", help="Execute API Keys enumeration")
    parser.add_argument("--cloud-compute-network", action="store_true", help="Execute Compute network enumeration")
    parser.add_argument("--cloud-compute-lb", action="store_true", help="Execute Compute load balancing enumeration")
    parser.add_argument("--cloud-batch", action="store_true", help="Execute Batch enumeration")
    parser.add_argument("--resource-manager", action="store_true", help="Execute Resource Manager enumeration")
    parser.add_argument("--cloud-compute", action="store_true", help="Execute all Compute Engine enumeration modules")
    parser.add_argument("--cloud-compute-resources", action="store_true", help="Execute Compute resource enumeration")
    parser.add_argument("--cloud-functions", action="store_true", help="Execute Cloud Functions enumeration")
    parser.add_argument("--cloud-storage", action="store_true", help="Execute Cloud Storage enumeration")
    parser.add_argument("--cloud-bigquery", action="store_true", help="Execute BigQuery enumeration")
    parser.add_argument("--cloud-bigtable", action="store_true", help="Execute Bigtable enumeration")
    parser.add_argument("--cloud-pubsub", action="store_true", help="Execute Pub/Sub enumeration")
    parser.add_argument("--cloud-firestore", action="store_true", help="Execute Firestore enumeration")
    parser.add_argument("--cloud-iam", action="store_true", help="Execute IAM enumeration")
    parser.add_argument("--cloud-secretsmanager", action="store_true", help="Execute Secret Manager enumeration")
    parser.add_argument("--cloud-redis", action="store_true", help="Execute Memorystore enumeration")
    parser.add_argument("--storage-transfer", action="store_true", help="Execute Storage Transfer enumeration")
    parser.add_argument("--cloud-dns", action="store_true", help="Execute Cloud DNS enumeration")
    parser.add_argument("--service-directory", action="store_true", help="Execute Service Directory enumeration")
    parser.add_argument("--app-engine", action="store_true", help="Execute App Engine enumeration")
    parser.add_argument("--workspace-cloud-identity", action="store_true", help="Execute Google Workspace Cloud Identity enumeration")
    parser.add_argument(
        "--download",
        nargs="?",
        const="all",
        default=None,
        help=(
            "Download token scopes. Examples: --download, --download metadata, --download content, "
            "--download buckets,function_env,secrets,bigquery_tables,cloudrun_revision_env,artifactregistry_files,compute_artifacts"
        ),
    )
    parser.add_argument(
        "--dont-download",
        required=False,
        help=(
            "Exclude download tokens from --download. Supports categories/tokens, "
            "for example: --dont-download buckets,secrets or --dont-download metadata"
        ),
    )
    add_standard_arguments(
        parser,
        ("iam", "get", "debug"),
        overrides={
            "iam": {"help": "Execute TestIamPermissions wherever applicable"},
            "get": {"help": "After listing, also fetch per-resource metadata where supported"},
            "debug": {"flags": ("--debug",)},
        },
    )
    args = parser.parse_args(user_args)

    try:
        project_allowlist_inline = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "project_allowlist", None)),
            value_label="project id",
            numeric_only=False,
        )
        project_allowlist_files = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "project_allowlist_file", None)),
            value_label="project id",
            numeric_only=False,
            files_only=True,
        )
        scoped_project_ids = list(dict.fromkeys([*project_allowlist_inline, *project_allowlist_files]))

        folder_allowlist_inline = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "folder_allowlist", None)),
            value_label="folder id",
            numeric_only=True,
        )
        folder_allowlist_files = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "folder_allowlist_file", None)),
            value_label="folder id",
            numeric_only=True,
            files_only=True,
        )
        scoped_folder_ids = list(dict.fromkeys([*folder_allowlist_inline, *folder_allowlist_files]))

        org_allowlist_inline = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "org_allowlist", None)),
            value_label="organization id",
            numeric_only=True,
        )
        org_allowlist_files = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "org_allowlist_file", None)),
            value_label="organization id",
            numeric_only=True,
            files_only=True,
        )
        scoped_organization_ids = list(dict.fromkeys([*org_allowlist_inline, *org_allowlist_files]))

        parent_folder_inline = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "parent_allowlist_folder", None)),
            value_label="parent folder id",
            numeric_only=True,
        )
        parent_folder_files = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "parent_allowlist_folder_file", None)),
            value_label="parent folder id",
            numeric_only=True,
            files_only=True,
        )
        parent_allowlist_folder_ids = list(dict.fromkeys([*parent_folder_inline, *parent_folder_files]))

        parent_org_inline = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "parent_allowlist_org", None)),
            value_label="parent organization id",
            numeric_only=True,
        )
        parent_org_files = parse_id_input_values(
            _flatten_arg_groups(getattr(args, "parent_allowlist_org_file", None)),
            value_label="parent organization id",
            numeric_only=True,
            files_only=True,
        )
        parent_allowlist_org_ids = list(dict.fromkeys([*parent_org_inline, *parent_org_files]))
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    direct_allowlist_active = bool(scoped_project_ids or scoped_folder_ids or scoped_organization_ids)
    parent_allowlist_active = bool(parent_allowlist_folder_ids or parent_allowlist_org_ids)
    allowlist_requested = bool(direct_allowlist_active or parent_allowlist_active)

    download_enabled = args.download is not None
    download_tokens: set[str] = set()
    if download_enabled:
        try:
            download_tokens = _expand_download_tokens(args.download)
            if args.dont_download:
                download_tokens -= _expand_download_tokens(args.dont_download)
        except ValueError as exc:
            UtilityTools.print_error(str(exc))
            return -1
        if not download_tokens:
            print("[*] Download was requested, but all selected download tokens were excluded.")

    def _download_requested(*tokens: str) -> bool:
        if not download_enabled:
            return False
        return any(str(token).strip() in download_tokens for token in tokens)

    every_flag_missing = not any(
        [
            args.cloud_run,
            args.cloud_sql,
            args.cloud_kms,
            args.artifact_registry,
            args.gke,
            args.cloud_build,
            args.cloud_composer,
            args.cloud_tasks,
            args.api_keys,
            args.cloud_compute_network,
            args.cloud_compute_lb,
            args.cloud_batch,
            args.resource_manager,
            args.cloud_compute,
            args.cloud_compute_resources,
            args.cloud_functions,
            args.cloud_storage,
            args.cloud_bigquery,
            args.cloud_bigtable,
            args.cloud_pubsub,
            args.cloud_firestore,
            args.cloud_iam,
            args.cloud_secretsmanager,
            args.cloud_redis,
            args.storage_transfer,
            args.cloud_dns,
            args.service_directory,
            args.app_engine,
            args.workspace_cloud_identity,
        ]
    )

    run_ctx = getattr(session, "_module_run_context", None) or {}
    run_index = int(run_ctx.get("index", 0) or 0)
    run_total = max(1, int(run_ctx.get("total", 1) or 1))
    first_run = run_index == 0
    last_run = run_index == (run_total - 1)

    planned_services = 0
    planned_services += int(
        first_run
        and (
            args.resource_manager
            or every_flag_missing
            or allowlist_requested
        )
    )
    planned_services += int(args.cloud_compute or args.cloud_compute_resources or every_flag_missing)
    planned_services += int(args.cloud_compute or args.cloud_compute_network or every_flag_missing)
    planned_services += int(args.cloud_compute or args.cloud_compute_lb or every_flag_missing)
    planned_services += int(args.cloud_functions or every_flag_missing)
    planned_services += int(args.cloud_storage or every_flag_missing)
    planned_services += int(args.cloud_bigquery or every_flag_missing)
    planned_services += int(args.cloud_bigtable or every_flag_missing)
    planned_services += int(args.cloud_pubsub or every_flag_missing)
    planned_services += int(args.cloud_firestore or every_flag_missing)
    planned_services += int(args.cloud_dns or every_flag_missing)
    planned_services += int(args.service_directory or every_flag_missing)
    planned_services += int(args.app_engine or every_flag_missing)
    planned_services += int(first_run and args.workspace_cloud_identity)
    planned_services += int(args.cloud_secretsmanager or every_flag_missing)
    planned_services += int(args.storage_transfer or every_flag_missing)
    planned_services += int(args.cloud_redis or every_flag_missing)
    planned_services += int(args.cloud_iam or every_flag_missing)
    planned_services += int(args.cloud_run or every_flag_missing)
    planned_services += int(args.cloud_sql or every_flag_missing)
    planned_services += int(args.cloud_kms or every_flag_missing)
    planned_services += int(args.artifact_registry or every_flag_missing)
    planned_services += int(args.gke or every_flag_missing)
    planned_services += int(args.cloud_build or every_flag_missing)
    planned_services += int(args.cloud_composer or every_flag_missing)
    planned_services += int(args.cloud_tasks or every_flag_missing)
    planned_services += int(args.api_keys or every_flag_missing)
    planned_services += int(args.cloud_batch or every_flag_missing)
    planned_services += int(last_run)

    _ENUM_PROGRESS.update({"enabled": True, "index": 0, "total": planned_services})

    more = False
    print(f"{UtilityTools.BOLD}[*] Starting enum_all for project {session.project_id}{UtilityTools.RESET}")
    if planned_services > 0:
        print(f"[*] Planned service modules: {planned_services}")
    if scoped_project_ids:
        print(f"[*] Resource Manager project ID filter: {', '.join(scoped_project_ids)}")
    if scoped_folder_ids:
        print(f"[*] Resource Manager folder ID filter: {', '.join(scoped_folder_ids)}")
    if scoped_organization_ids:
        print(f"[*] Resource Manager organization ID filter: {', '.join(scoped_organization_ids)}")
    if parent_allowlist_folder_ids:
        print(f"[*] Parent folder scope filter: {', '.join(parent_allowlist_folder_ids)}")
    if parent_allowlist_org_ids:
        print(f"[*] Parent organization scope filter: {', '.join(parent_allowlist_org_ids)}")
    if download_enabled:
        token_string = ", ".join(sorted(download_tokens)) if download_tokens else "(none)"
        print(f"[*] Download tokens enabled: {token_string}")

    allowlist_active = allowlist_requested

    if first_run and (args.resource_manager or every_flag_missing or allowlist_active):
        original_project_count = len(session.global_project_list)
        module_args = ["-v"] if args.debug else []
        if args.iam:
            module_args.append("--iam")
        if args.all_resource_permissions:
            module_args.append("--all-permissions")
        previous_rm_scope = getattr(session, "_enum_all_rm_scope", None)
        # Parent-only allowlists need baseline tree discovery first; only pass direct allowlists
        # into the initial enum_resources scope.
        session._enum_all_rm_scope = {
            "projects": list(scoped_project_ids),
            "folders": list(scoped_folder_ids),
            "organizations": list(scoped_organization_ids),
            "allowlist_active": bool(direct_allowlist_active),
        }
        try:
            _run_other_module(session, module_args, "gcpwn.modules.resourcemanager.enumeration.enum_resources")
        finally:
            if previous_rm_scope is None:
                if hasattr(session, "_enum_all_rm_scope"):
                    delattr(session, "_enum_all_rm_scope")
            else:
                session._enum_all_rm_scope = previous_rm_scope
        if len(session.global_project_list) != original_project_count:
            more = True

    run_non_rm_for_project = True
    if allowlist_active:
        cached_scope = getattr(session, "_enum_all_effective_allowlist_scope", None)
        if first_run or not isinstance(cached_scope, dict):
            resolved_scope = _resolve_effective_allowlist_scope(
                session,
                project_ids=scoped_project_ids,
                folder_ids=scoped_folder_ids,
                organization_ids=scoped_organization_ids,
                parent_folder_ids=parent_allowlist_folder_ids,
                parent_org_ids=parent_allowlist_org_ids,
            )
            cached_scope = {
                "allowlist_active": bool(resolved_scope.get("allowlist_active", False)),
                "projects": sorted(_normalize_scope_values(resolved_scope.get("projects", []))),
                "folders": sorted(_normalize_scope_values(resolved_scope.get("folders", []))),
                "organizations": sorted(_normalize_scope_values(resolved_scope.get("organizations", []))),
            }
            session._enum_all_effective_allowlist_scope = dict(cached_scope)
        effective_projects = _normalize_scope_values(cached_scope.get("projects", []))
        current_project_id = str(session.project_id or "").strip()
        run_non_rm_for_project = current_project_id in effective_projects
        if first_run:
            if effective_projects:
                print(
                    "[*] Effective non-Resource-Manager project allowlist: "
                    + ", ".join(sorted(effective_projects))
                )
            else:
                print("[*] Allowlist filters did not resolve to any scoped projects.")
            if cached_scope.get("folders"):
                print("[*] Effective folder scope: " + ", ".join(cached_scope.get("folders", [])))
            if cached_scope.get("organizations"):
                print("[*] Effective organization scope: " + ", ".join(cached_scope.get("organizations", [])))
        if not run_non_rm_for_project:
            print(f"[*] Skipping non-Resource-Manager modules for {current_project_id or 'N/A'} (not in allowlist scope).")

    completed_services = int(_ENUM_PROGRESS.get("index", 0) or 0)
    if run_non_rm_for_project:
        remaining_services = _count_non_rm_service_plan(
            args,
            every_flag_missing=every_flag_missing,
            first_run=first_run,
            last_run=last_run,
            more=more,
        )
    else:
        remaining_services = int(last_run and not more)
    _ENUM_PROGRESS["total"] = max(completed_services, completed_services + remaining_services)

    if run_non_rm_for_project and (args.cloud_compute or args.cloud_compute_resources or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.zones_list:
            module_args.extend(["--zones-list", args.zones_list])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        if _download_requested("compute_screenshot"):
            module_args.append("--take-screenshot")
        if _download_requested("compute_serial"):
            module_args.append("--download-serial")
        if _download_requested("compute_artifacts"):
            module_args.append("--download")
        if _download_requested("compute_screenshot", "compute_serial", "compute_artifacts"):
            if args.download_output:
                module_args.extend(["--output", args.download_output])
        _run_other_module(session, module_args, "gcpwn.modules.cloudcompute.enumeration.enum_cloudcompute_resources")

    if run_non_rm_for_project and (args.cloud_compute or args.cloud_compute_network or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        _run_other_module(session, module_args, "gcpwn.modules.cloudcompute.enumeration.enum_cloudcompute_network")

    if run_non_rm_for_project and (args.cloud_compute or args.cloud_compute_lb or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        _run_other_module(session, module_args, "gcpwn.modules.cloudcompute.enumeration.enum_cloudcompute_lb")

    if run_non_rm_for_project and (args.cloud_functions or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get or _download_requested("function_env"):
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        if _download_requested("function_source"):
            module_args.append("--download")
            if args.download_output:
                module_args.extend(["--output", args.download_output])
        _run_other_module(session, module_args, "gcpwn.modules.cloudfunctions.enumeration.enum_cloudfunctions")

    if run_non_rm_for_project and (args.cloud_storage or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        if _download_requested("buckets"):
            module_args.append("--download")
            if args.download_output:
                module_args.extend(["--output", args.download_output])
        _run_other_module(session, module_args, "gcpwn.modules.cloudstorage.enumeration.enum_cloudstorage")

    if run_non_rm_for_project and (args.cloud_bigquery or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("bigquery_tables"):
            module_args.extend(["--download", "table"])
        _run_other_module(session, module_args, "gcpwn.modules.bigquery.enumeration.enum_bigquery")

    if run_non_rm_for_project and (args.cloud_bigtable or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.bigtable.enumeration.enum_bigtable")

    if run_non_rm_for_project and (args.cloud_pubsub or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.pubsub.enumeration.enum_pubsub")

    if run_non_rm_for_project and (args.cloud_firestore or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("firestore_data"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.firestore.enumeration.enum_firestore")

    if run_non_rm_for_project and (args.cloud_dns or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("clouddns_record_sets"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.clouddns.enumeration.enum_clouddns")

    if run_non_rm_for_project and (args.service_directory or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.servicedirectory.enumeration.enum_servicedirectory")

    if run_non_rm_for_project and (args.app_engine or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.appengine.enumeration.enum_appengine")

    if run_non_rm_for_project and first_run and args.workspace_cloud_identity:
        module_args = ["-v"] if args.debug else []
        _run_other_module(session, module_args, "gcpwn.modules.workspace_cloud_identity.enumeration.enum_cloud_identity")

    if run_non_rm_for_project and (args.cloud_secretsmanager or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        if _download_requested("secrets"):
            module_args.extend(["--download", "--values"])
        _run_other_module(session, module_args, "gcpwn.modules.secretsmanager.enumeration.enum_secretsmanager")

    if run_non_rm_for_project and (args.storage_transfer or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.storagetransfer.enumeration.enum_storagetransfer")

    if run_non_rm_for_project and (args.cloud_redis or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.memorystore.enumeration.enum_memorystore")

    if run_non_rm_for_project and (args.cloud_iam or every_flag_missing):
        module_args = ["--service-accounts", "--custom-roles", "--pools", "--providers"]
        if args.iam:
            module_args.append("--iam")
        if args.get:
            module_args.append("--get")
        if args.debug:
            module_args.append("-v")
        _run_other_module(session, module_args, "gcpwn.modules.iam.enumeration.enum_iam")

    if run_non_rm_for_project and (args.cloud_run or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("cloudrun_revision_env"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.cloudrun.enumeration.enum_cloudrun")

    if run_non_rm_for_project and (args.cloud_sql or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.cloudsql.enumeration.enum_cloudsql")

    if run_non_rm_for_project and (args.cloud_kms or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.kms.enumeration.enum_kms")

    if run_non_rm_for_project and (args.artifact_registry or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("artifactregistry_files"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.artifactregistry.enumeration.enum_artifactregistry")

    if run_non_rm_for_project and (args.gke or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.gke.enumeration.enum_gke")

    if run_non_rm_for_project and (args.cloud_build or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("cloudbuild_builds"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.cloudbuild.enumeration.enum_cloudbuild")

    if run_non_rm_for_project and (args.cloud_composer or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("composer_configs"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.cloudcomposer.enumeration.enum_cloudcomposer")

    if run_non_rm_for_project and (args.cloud_tasks or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        if _download_requested("cloudtasks_requests"):
            module_args.append("--download")
            if args.download_output:
                module_args.extend(["--output", args.download_output])
        _run_other_module(session, module_args, "gcpwn.modules.cloudtasks.enumeration.enum_cloudtasks")

    if run_non_rm_for_project and (args.api_keys or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("apikeys_content"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.apikeys.enumeration.enum_apikeys")

    if run_non_rm_for_project and (args.cloud_batch or every_flag_missing):
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("batch_scripts"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.batch.enumeration.enum_batch")

    # Must be called last: builds IAM allow-policy cache across all cached resources.
    if last_run and not more:
        module_args = ["-v"] if args.debug else []
        _run_other_module(session, module_args, "gcpwn.modules.everything.enumeration.enum_policy_bindings")

    _ENUM_PROGRESS.update({"enabled": False, "index": 0, "total": 0})
    if more:
        return 2
    return 1
