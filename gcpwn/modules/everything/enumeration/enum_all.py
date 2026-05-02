from __future__ import annotations

import argparse
import importlib
import re
import shutil
from time import perf_counter

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import add_standard_arguments

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


def run_module(user_args, session):
    parser = argparse.ArgumentParser(description="Enumerate all services", allow_abbrev=False)
    parser.add_argument("--download-output", required=False, help="Output directory for downloaded artifacts")
    parser.add_argument("--threads", type=int, default=3, help="Worker threads for region/zone fan-out (default: 3)")
    parser.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
    parser.add_argument("--zones-list", required=False, help="Zones in comma-separated format")
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
    planned_services += int(first_run and (args.resource_manager or every_flag_missing))
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
    if download_enabled:
        token_string = ", ".join(sorted(download_tokens)) if download_tokens else "(none)"
        print(f"[*] Download tokens enabled: {token_string}")

    if first_run and (args.resource_manager or every_flag_missing):
        original_project_count = len(session.global_project_list)
        module_args = ["-v"] if args.debug else []
        if args.iam:
            module_args.append("--iam")
        if args.all_resource_permissions:
            module_args.append("--all-permissions")
        _run_other_module(session, module_args, "gcpwn.modules.resourcemanager.enumeration.enum_resources")
        if len(session.global_project_list) != original_project_count:
            more = True

    if args.cloud_compute or args.cloud_compute_resources or every_flag_missing:
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

    if args.cloud_compute or args.cloud_compute_network or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        _run_other_module(session, module_args, "gcpwn.modules.cloudcompute.enumeration.enum_cloudcompute_network")

    if args.cloud_compute or args.cloud_compute_lb or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        _run_other_module(session, module_args, "gcpwn.modules.cloudcompute.enumeration.enum_cloudcompute_lb")

    if args.cloud_functions or every_flag_missing:
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

    if args.cloud_storage or every_flag_missing:
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

    if args.cloud_bigquery or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("bigquery_tables"):
            module_args.extend(["--download", "table"])
        _run_other_module(session, module_args, "gcpwn.modules.bigquery.enumeration.enum_bigquery")

    if args.cloud_bigtable or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.bigtable.enumeration.enum_bigtable")

    if args.cloud_pubsub or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.pubsub.enumeration.enum_pubsub")

    if args.cloud_firestore or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("firestore_data"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.firestore.enumeration.enum_firestore")

    if args.cloud_dns or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("clouddns_record_sets"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.clouddns.enumeration.enum_clouddns")

    if args.service_directory or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.servicedirectory.enumeration.enum_servicedirectory")

    if args.app_engine or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.appengine.enumeration.enum_appengine")

    if first_run and args.workspace_cloud_identity:
        module_args = ["-v"] if args.debug else []
        _run_other_module(session, module_args, "gcpwn.modules.workspace_cloud_identity.enumeration.enum_cloud_identity")

    if args.cloud_secretsmanager or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if args.iam:
            module_args.append("--iam")
        if _download_requested("secrets"):
            module_args.extend(["--download", "--values"])
        _run_other_module(session, module_args, "gcpwn.modules.secretsmanager.enumeration.enum_secretsmanager")

    if args.storage_transfer or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.storagetransfer.enumeration.enum_storagetransfer")

    if args.cloud_redis or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.memorystore.enumeration.enum_memorystore")

    if args.cloud_iam or every_flag_missing:
        module_args = ["--service-accounts", "--custom-roles"]
        if args.iam:
            module_args.append("--iam")
        if args.get:
            module_args.append("--get")
        if args.debug:
            module_args.append("-v")
        _run_other_module(session, module_args, "gcpwn.modules.iam.enumeration.enum_iam")

    if args.cloud_run or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("cloudrun_revision_env"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.cloudrun.enumeration.enum_cloudrun")

    if args.cloud_sql or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.cloudsql.enumeration.enum_cloudsql")

    if args.cloud_kms or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.kms.enumeration.enum_kms")

    if args.artifact_registry or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("artifactregistry_files"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.artifactregistry.enumeration.enum_artifactregistry")

    if args.gke or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        _run_other_module(session, module_args, "gcpwn.modules.gke.enumeration.enum_gke")

    if args.cloud_build or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("cloudbuild_builds"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.cloudbuild.enumeration.enum_cloudbuild")

    if args.cloud_composer or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        module_args.extend(["--threads", str(args.threads)])
        if args.regions_list:
            module_args.extend(["--regions-list", args.regions_list])
        if args.get:
            module_args.append("--get")
        if _download_requested("composer_configs"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.cloudcomposer.enumeration.enum_cloudcomposer")

    if args.cloud_tasks or every_flag_missing:
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

    if args.api_keys or every_flag_missing:
        module_args = ["-v"] if args.debug else []
        if args.get:
            module_args.append("--get")
        if _download_requested("apikeys_content"):
            module_args.append("--download")
        _run_other_module(session, module_args, "gcpwn.modules.apikeys.enumeration.enum_apikeys")

    if args.cloud_batch or every_flag_missing:
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
