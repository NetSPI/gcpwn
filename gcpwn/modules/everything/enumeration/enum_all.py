"""enum_all: orchestrate every per-service enumerator + IAM policy bindings.

Two execution paths share the declarative _SERVICES ServiceSpec table:
  * run_module (sequential): Resource Manager once, then each selected service
    enumerator, then enum_gcp_policy_bindings last. Drives a shared progress counter
    and supports a hidden --phase used by the parallel orchestrator.
  * run_parallel (--parallel-services N): cross-project pool that pipelines IAM
    policy-binding collection per hierarchy node. Each run prints a resume TOKEN;
    a plain re-run starts fresh, while ``--resume <token>`` continues an interrupted
    run by skipping the units that token already finished (token-scoped ledger).

Adding a service is normally just one ServiceSpec row plus its --parallel-services
entry; _build_service_args turns the spec + user flags into that module's argv.
"""

from __future__ import annotations

import argparse
import importlib
import re
import shutil
import threading
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.hierarchy import descendants
from gcpwn.core.utils.module_helpers import extract_path_tail, normalize_str_set
from gcpwn.core.utils.parallel_output import ParallelOutputManager
from gcpwn.core.utils.resume import resolve_run_token
from gcpwn.core.utils.scoped_session import ProjectScopedSession
from gcpwn.core.utils.service_runtime import (
    add_standard_arguments,
    cancel_requested,
    clear_cancel,
    flatten_arg_groups,
    parse_csv_arg,
    parse_id_input_values,
    request_cancel,
)

# (service dest -> CLI flag) for the per-project enumerators the orchestrator
# fans out. Mirrors the 26 run_services blocks in run_module (RM + bindings +
# workspace-identity are once-per-run and handled outside the pool).
_PARALLEL_SERVICES: tuple[tuple[str, str], ...] = (
    ("cloud_compute_resources", "--cloud-compute-resources"),
    ("cloud_compute_network", "--cloud-compute-network"),
    ("cloud_compute_lb", "--cloud-compute-lb"),
    ("cloud_functions", "--cloud-functions"),
    ("cloud_storage", "--cloud-storage"),
    ("cloud_bigquery", "--cloud-bigquery"),
    ("cloud_bigtable", "--cloud-bigtable"),
    ("cloud_pubsub", "--cloud-pubsub"),
    ("cloud_firestore", "--cloud-firestore"),
    ("cloud_dns", "--cloud-dns"),
    ("service_directory", "--service-directory"),
    ("app_engine", "--app-engine"),
    ("cloud_secretsmanager", "--cloud-secretsmanager"),
    ("storage_transfer", "--storage-transfer"),
    ("cloud_redis", "--cloud-redis"),
    ("cloud_iam", "--cloud-iam"),
    ("cloud_run", "--cloud-run"),
    ("cloud_sql", "--cloud-sql"),
    ("cloud_kms", "--cloud-kms"),
    ("artifact_registry", "--artifact-registry"),
    ("gke", "--gke"),
    ("cloud_build", "--cloud-build"),
    ("cloud_composer", "--cloud-composer"),
    ("cloud_tasks", "--cloud-tasks"),
    ("api_keys", "--api-keys"),
    ("cloud_batch", "--cloud-batch"),
    ("cloud_scheduler", "--cloud-scheduler"),
    ("cloud_workflows", "--cloud-workflows"),
    ("spanner", "--spanner"),
    ("alloydb", "--alloydb"),
    ("orgpolicy", "--orgpolicy"),
    ("asset_inventory", "--asset-inventory"),
    ("eventarc", "--eventarc"),
    ("workstations", "--workstations"),
    ("cloud_billing", "--cloud-billing"),
    ("cloud_shell", "--cloud-shell"),
    ("cloud_logging", "--cloud-logging"),
    ("dataproc", "--dataproc"),
    ("dataflow", "--dataflow"),
    ("notebooks", "--notebooks"),
    ("cloud_deploy", "--cloud-deploy"),
    ("bigquery_datatransfer", "--bigquery-datatransfer"),
    ("service_usage", "--service-usage"),
)
@dataclass(frozen=True)
class ServiceSpec:
    """One per-project resource enumerator. Replaces ~10 lines of hand-written
    arg-building per service with a single declaration + the shared builder below."""
    gate_flags: tuple[str, ...]          # runs if any of these args attrs is set (or every_flag_missing)
    module: str                          # dotted module path
    threads: bool = False                # pass --threads
    regions: bool = False                # pass --regions-list when set
    zones: bool = False                  # pass --zones-list when set
    iam: bool = False                    # pass --iam when args.iam
    get: bool = True                     # pass --get when args.get
    get_tokens: tuple[str, ...] = ()     # download tokens that ALSO imply --get
    downloads: tuple = ()                # ((tokens...), (flags...)) rules -> flags appended when requested
    download_output: bool = False        # append --output <dir> once when any download fired
    extra_args: tuple[str, ...] = ()     # always-prepended args (e.g. iam's component flags)
    opt_in: bool = False                 # NEVER runs under every_flag_missing; only when its gate flag is set


# Order mirrors the original sequential run. Resource Manager, Workspace Cloud
# Identity and policy-bindings are once-per-run and stay as explicit blocks.
_SERVICES: tuple[ServiceSpec, ...] = (
    ServiceSpec(("cloud_compute", "cloud_compute_resources"), "gcpwn.modules.gcp.cloudcompute.enumeration.enum_cloudcompute_resources",
                threads=True, regions=True, zones=True, iam=True, download_output=True,
                downloads=((("compute_screenshot",), ("--take-screenshot",)),
                           (("compute_serial",), ("--download-serial",)),
                           (("compute_artifacts",), ("--download",)))),
    ServiceSpec(("cloud_compute", "cloud_compute_network"), "gcpwn.modules.gcp.cloudcompute.enumeration.enum_cloudcompute_network",
                threads=True, regions=True, iam=True),
    ServiceSpec(("cloud_compute", "cloud_compute_lb"), "gcpwn.modules.gcp.cloudcompute.enumeration.enum_cloudcompute_lb",
                threads=True, regions=True, iam=True),
    ServiceSpec(("cloud_functions",), "gcpwn.modules.gcp.cloudfunctions.enumeration.enum_cloudfunctions",
                threads=True, regions=True, iam=True, get_tokens=("function_env",), download_output=True,
                downloads=((("function_source",), ("--download",)),)),
    ServiceSpec(("cloud_storage",), "gcpwn.modules.gcp.cloudstorage.enumeration.enum_cloudstorage",
                iam=True, download_output=True, downloads=((("buckets",), ("--download",)),)),
    ServiceSpec(("cloud_bigquery",), "gcpwn.modules.gcp.bigquery.enumeration.enum_bigquery",
                downloads=((("bigquery_tables",), ("--download", "table")),)),
    ServiceSpec(("cloud_bigtable",), "gcpwn.modules.gcp.bigtable.enumeration.enum_bigtable"),
    ServiceSpec(("cloud_pubsub",), "gcpwn.modules.gcp.pubsub.enumeration.enum_pubsub"),
    ServiceSpec(("cloud_firestore",), "gcpwn.modules.gcp.firestore.enumeration.enum_firestore",
                downloads=((("firestore_data",), ("--download",)),)),
    ServiceSpec(("cloud_dns",), "gcpwn.modules.gcp.clouddns.enumeration.enum_clouddns",
                downloads=((("clouddns_record_sets",), ("--download",)),)),
    ServiceSpec(("service_directory",), "gcpwn.modules.gcp.servicedirectory.enumeration.enum_servicedirectory",
                threads=True, regions=True),
    ServiceSpec(("app_engine",), "gcpwn.modules.gcp.appengine.enumeration.enum_appengine"),
    ServiceSpec(("cloud_secretsmanager",), "gcpwn.modules.gcp.secretsmanager.enumeration.enum_secretsmanager",
                iam=True, downloads=((("secrets",), ("--download", "--values")),)),
    ServiceSpec(("storage_transfer",), "gcpwn.modules.gcp.storagetransfer.enumeration.enum_storagetransfer"),
    ServiceSpec(("cloud_redis",), "gcpwn.modules.gcp.memorystore.enumeration.enum_memorystore"),
    ServiceSpec(("cloud_iam",), "gcpwn.modules.gcp.iam.enumeration.enum_iam", iam=True,
                extra_args=("--service-accounts", "--custom-roles", "--pools", "--providers")),
    ServiceSpec(("cloud_run",), "gcpwn.modules.gcp.cloudrun.enumeration.enum_cloudrun",
                threads=True, regions=True, downloads=((("cloudrun_revision_env",), ("--download",)),)),
    ServiceSpec(("cloud_sql",), "gcpwn.modules.gcp.cloudsql.enumeration.enum_cloudsql"),
    ServiceSpec(("cloud_kms",), "gcpwn.modules.gcp.kms.enumeration.enum_kms", threads=True, regions=True),
    ServiceSpec(("artifact_registry",), "gcpwn.modules.gcp.artifactregistry.enumeration.enum_artifactregistry",
                threads=True, regions=True, downloads=((("artifactregistry_files",), ("--download",)),)),
    ServiceSpec(("gke",), "gcpwn.modules.gcp.gke.enumeration.enum_gke", threads=True, regions=True),
    ServiceSpec(("cloud_build",), "gcpwn.modules.gcp.cloudbuild.enumeration.enum_cloudbuild",
                threads=True, regions=True, downloads=((("cloudbuild_builds",), ("--download",)),)),
    ServiceSpec(("cloud_composer",), "gcpwn.modules.gcp.cloudcomposer.enumeration.enum_cloudcomposer",
                threads=True, regions=True, downloads=((("composer_configs",), ("--download",)),)),
    ServiceSpec(("cloud_tasks",), "gcpwn.modules.gcp.cloudtasks.enumeration.enum_cloudtasks",
                threads=True, regions=True, iam=True, download_output=True,
                downloads=((("cloudtasks_requests",), ("--download",)),)),
    ServiceSpec(("api_keys",), "gcpwn.modules.gcp.apikeys.enumeration.enum_apikeys",
                downloads=((("apikeys_content",), ("--download",)),)),
    ServiceSpec(("cloud_batch",), "gcpwn.modules.gcp.batch.enumeration.enum_batch",
                threads=True, regions=True, downloads=((("batch_scripts",), ("--download",)),)),
    ServiceSpec(("cloud_scheduler",), "gcpwn.modules.gcp.cloudscheduler.enumeration.enum_cloudscheduler",
                threads=True, regions=True),
    ServiceSpec(("cloud_workflows",), "gcpwn.modules.gcp.cloudworkflows.enumeration.enum_cloudworkflows",
                threads=True, regions=True),
    ServiceSpec(("spanner",), "gcpwn.modules.gcp.spanner.enumeration.enum_spanner"),
    ServiceSpec(("alloydb",), "gcpwn.modules.gcp.alloydb.enumeration.enum_alloydb",
                threads=True, regions=True),
    ServiceSpec(("orgpolicy",), "gcpwn.modules.gcp.orgpolicy.enumeration.enum_orgpolicy"),
    # Opt-in: slow org-wide scan, skipped by default; runs only with --asset-inventory.
    ServiceSpec(("asset_inventory",), "gcpwn.modules.gcp.assetinventory.enumeration.enum_asset_inventory",
                opt_in=True),
    ServiceSpec(("eventarc",), "gcpwn.modules.gcp.eventarc.enumeration.enum_eventarc",
                threads=True, regions=True),
    ServiceSpec(("workstations",), "gcpwn.modules.gcp.workstations.enumeration.enum_workstations",
                threads=True, regions=True),
    ServiceSpec(("cloud_billing",), "gcpwn.modules.gcp.billing.enumeration.enum_billing", get=False),
    ServiceSpec(("cloud_shell",), "gcpwn.modules.gcp.cloudshell.enumeration.enum_cloudshell", get=False),
    ServiceSpec(("cloud_logging",), "gcpwn.modules.gcp.logging.enumeration.enum_logging", get=False),
    ServiceSpec(("dataproc",), "gcpwn.modules.gcp.dataproc.enumeration.enum_dataproc",
                threads=True, regions=True),
    ServiceSpec(("dataflow",), "gcpwn.modules.gcp.dataflow.enumeration.enum_dataflow",
                threads=True, regions=True),
    ServiceSpec(("notebooks",), "gcpwn.modules.gcp.notebooks.enumeration.enum_notebooks",
                threads=True, regions=True, iam=True),
    ServiceSpec(("cloud_deploy",), "gcpwn.modules.gcp.clouddeploy.enumeration.enum_clouddeploy",
                threads=True, regions=True, iam=True),
    ServiceSpec(("bigquery_datatransfer",), "gcpwn.modules.gcp.bigquerydatatransfer.enumeration.enum_bigquerydatatransfer",
                threads=True, regions=True),
    ServiceSpec(("service_usage",), "gcpwn.modules.gcp.serviceusage.enumeration.enum_serviceusage",
                threads=True, get=False),
)


def _service_selected(spec: "ServiceSpec", args, every_flag_missing: bool) -> bool:
    """True if this service should run: no service flags given (run all) or one of its gates is set.

    Opt-in services (e.g. Cloud Asset Inventory) are EXCLUDED from the every_flag_missing
    'run all' default and only run when their gate flag is explicitly passed; since their
    flags are also excluded from the every_flag_missing computation, passing one is additive
    (it does not suppress the other services)."""
    gate_set = any(getattr(args, flag, False) for flag in spec.gate_flags)
    if spec.opt_in:
        return gate_set
    return every_flag_missing or gate_set


def _build_service_args(spec: "ServiceSpec", args, download_requested) -> list[str]:
    """Translate a ServiceSpec + the user's enum_all args into that service module's argv.

    Applies the spec's knobs against the parsed args: -v/extra_args, --threads,
    --zones-list/--regions-list, --get (directly or implied by a requested
    get_token download), --iam, each download rule whose tokens were requested,
    and a single --output when any download fired. download_requested(*tokens) is
    the closure from run_module that resolves whether a download token is in scope.
    """
    module_args = ["-v"] if args.debug else []
    module_args.extend(spec.extra_args)
    if spec.threads:
        module_args.extend(["--threads", str(args.threads)])
    if spec.zones and args.zones_list:
        module_args.extend(["--zones-list", args.zones_list])
    if spec.regions and args.regions_list:
        module_args.extend(["--regions-list", args.regions_list])
    if (spec.get and args.get) or any(download_requested(token) for token in spec.get_tokens):
        module_args.append("--get")
    if spec.iam and args.iam:
        module_args.append("--iam")
    any_download = False
    for tokens, flags in spec.downloads:
        if download_requested(*tokens):
            module_args.extend(flags)
            any_download = True
    if spec.download_output and any_download and args.download_output:
        module_args.extend(["--output", args.download_output])
    return module_args


_TASK_LEDGER_TABLE = "enum_all_task_ledger"
# Pipelined IAM-policy-binding ledger units (collected per hierarchy node rather
# than in one end-of-run barrier). Stored as pseudo (project, service) pairs so
# they resume alongside the per-(project, service) enumeration units.
_BINDINGS_SERVICE = "__bindings__"
_HIERARCHY_LEDGER_KEY = "__hierarchy__"

_ENUM_PROGRESS: dict[str, int | bool] = {"enabled": False, "index": 0, "total": 0}
# Guards the _ENUM_PROGRESS counter when services fan out via --parallel-services.
_ENUM_PROGRESS_LOCK = threading.Lock()

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
    "enum_cloudscheduler": "Cloud Scheduler",
    "enum_cloudworkflows": "Cloud Workflows",
    "enum_spanner": "Cloud Spanner",
    "enum_alloydb": "AlloyDB",
    "enum_orgpolicy": "Organization Policy",
    "enum_asset_inventory": "Cloud Asset Inventory",
    "enum_eventarc": "Eventarc",
    "enum_workstations": "Cloud Workstations",
    "enum_billing": "Cloud Billing",
    "enum_cloudshell": "Cloud Shell",
    "enum_logging": "Cloud Logging",
    "enum_dataproc": "Dataproc",
    "enum_dataflow": "Dataflow",
    "enum_notebooks": "Vertex AI Workbench",
    "enum_clouddeploy": "Cloud Deploy",
    "enum_bigquerydatatransfer": "BigQuery Data Transfer",
    "enum_serviceusage": "Service Usage",
    "enum_gcp_policy_bindings": "IAM Policy Bindings",
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

# Canonical download tokens -- one per download, NO aliases. Users pass EITHER a
# category keyword OR one/more individual tokens (comma-separated) to --download /
# --dont-download:
#   all       -> every token in both groups (see the compute_artifacts note below)
#   metadata  -> the whole "metadata" group
#   content   -> the whole "content" group
#   <token>   -> just that one download (e.g. buckets, secrets, function_source)
ALL_DOWNLOAD_TOKENS = DOWNLOAD_CATEGORY_TOKENS["metadata"] | DOWNLOAD_CATEGORY_TOKENS["content"]
DOWNLOAD_CATEGORY_KEYWORDS = ("all", "metadata", "content")
# compute_artifacts is a heavy, full compute-instance artifact dump: requestable by
# name, but deliberately kept OUT of `all`/`content` so a broad --download won't pull
# it. Run it with an explicit `--download compute_artifacts`.
EXPLICIT_ONLY_DOWNLOAD_TOKENS = {"compute_artifacts"}
INDIVIDUAL_DOWNLOAD_TOKENS = ALL_DOWNLOAD_TOKENS | EXPLICIT_ONLY_DOWNLOAD_TOKENS


def _parse_csv_tokens(raw: str | None) -> list[str]:
    # Canonical CSV split (strip + drop-empty) via parse_csv_arg; download tokens
    # are matched case-insensitively, so lower-case here.
    return [token.lower() for token in parse_csv_arg(raw)]


def _expand_download_tokens(raw: str | None) -> set[str]:
    """Resolve comma-separated --download / --dont-download values into download tokens.

    Each value is EITHER a category keyword (``all`` / ``metadata`` / ``content`` ->
    that whole group) OR a single canonical token (e.g. ``buckets``, ``secrets``,
    ``function_source``). There are no aliases; an unknown value raises ValueError
    listing every accepted keyword and token.
    """
    selected: set[str] = set()
    for token in _parse_csv_tokens(raw):
        if token == "all":
            selected |= ALL_DOWNLOAD_TOKENS
        elif token in DOWNLOAD_CATEGORY_TOKENS:
            selected |= DOWNLOAD_CATEGORY_TOKENS[token]
        elif token in INDIVIDUAL_DOWNLOAD_TOKENS:
            selected.add(token)
        else:
            valid = ", ".join([*DOWNLOAD_CATEGORY_KEYWORDS, *sorted(INDIVIDUAL_DOWNLOAD_TOKENS)])
            raise ValueError(f"Invalid --download token: {token}. Supported values: {valid}")
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
    """Import and run another enum module, printing the shared progress banner.

    Imports module_name, calls its run_module(user_args, session), and returns the
    result. When the global _ENUM_PROGRESS counter is enabled, advances the
    Service i/N banner (under _ENUM_PROGRESS_LOCK so the parallel pool stays
    consistent) and prints elapsed time.
    """
    progress_enabled = bool(_ENUM_PROGRESS.get("enabled"))
    start = 0.0
    service_name = _pretty_service_name(module_name)
    if progress_enabled:
        with _ENUM_PROGRESS_LOCK:
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
    """BFS the cached hierarchy from the given parent folders/orgs to all descendants.

    Returns {"projects", "folders", "organizations"} sets of the IDs reachable
    under any parent root, used to expand a --parent-allowlist into the concrete
    scope. Empty roots short-circuit to empty sets.
    """
    roots = {f"folders/{folder_id}" for folder_id in parent_folder_ids} | {
        f"organizations/{org_id}" for org_id in parent_org_ids
    }
    if not roots:
        return {"projects": set(), "folders": set(), "organizations": set()}

    by_name: dict[str, dict] = {}
    children_by_parent: dict[str, list[str]] = {}
    for row in hierarchy_rows:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        by_name[name] = row
        parent = str(row.get("parent") or "").strip()
        children_by_parent.setdefault(parent, []).append(name)

    # Every scope name reachable from a root that exists in the cached hierarchy,
    # INCLUDING the roots themselves. The shared descendants() BFS excludes its
    # root, so add each root back explicitly.
    scope_names: set[str] = set()
    for root in roots:
        if root in by_name:
            scope_names.add(root)
            scope_names.update(descendants(children_by_parent, root))

    projects: set[str] = set()
    folders: set[str] = set()
    organizations: set[str] = set()
    for name in scope_names:
        row = by_name.get(name) or {}
        row_type = str(row.get("type") or "").strip().lower()
        if row_type == "project":
            project_id = str(row.get("project_id") or "").strip()
            if project_id:
                projects.add(project_id)
        elif row_type == "folder":
            folder_id = extract_path_tail(name)
            if folder_id.isdigit():
                folders.add(folder_id)
        elif row_type == "org":
            org_id = extract_path_tail(name)
            if org_id.isdigit():
                organizations.add(org_id)

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
    """Resolve direct + parent allowlists into the effective scope to enumerate.

    Direct allowlists (project/folder/org IDs) and parent allowlists (folder/org
    whose descendants are included) combine by INTERSECTION when both are present
    (direct narrows the parent-expanded set); otherwise whichever is active wins.
    Returns {"allowlist_active": bool, "projects"/"folders"/"organizations": set}.
    allowlist_active is False (empty scope) when no allowlist flags were given.
    """
    direct_projects = normalize_str_set(project_ids)
    direct_folders = normalize_str_set(folder_ids)
    direct_orgs = normalize_str_set(organization_ids)
    parent_folders = normalize_str_set(parent_folder_ids)
    parent_orgs = normalize_str_set(parent_org_ids)
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
    count = sum(1 for spec in _SERVICES if _service_selected(spec, args, every_flag_missing))
    count += int(first_run and args.workspace_identity)
    count += int(last_run and not more)
    return count


def _extract_global_tokens(user_args) -> tuple[list[str], int]:
    """Pull the project-independent flags (and --parallel-services) out of the
    user's enum_all args so they can be re-passed to each per-service sub-call."""
    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    p.add_argument("--debug", "-v", action="store_true")
    p.add_argument("--iam", action="store_true")
    p.add_argument("--get", action="store_true")
    p.add_argument("--all-resource-permissions", "--all-permissions", dest="all_perms", action="store_true")
    p.add_argument("--download", nargs="?", const="all", default=None)
    p.add_argument("--dont-download", dest="dont_download", default=None)
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--regions-list", dest="regions_list", default=None)
    p.add_argument("--zones-list", dest="zones_list", default=None)
    p.add_argument("--download-output", dest="download_output", default=None)
    p.add_argument("--parallel-services", dest="parallel_services", type=int, default=1)
    g, _ = p.parse_known_args(list(user_args or []))

    tokens: list[str] = []
    if g.debug:
        tokens.append("-v")
    if g.iam:
        tokens.append("--iam")
    if g.get:
        tokens.append("--get")
    if g.all_perms:
        tokens.append("--all-permissions")
    if g.download is not None:
        tokens += ["--download", g.download]
    if g.dont_download:
        tokens += ["--dont-download", g.dont_download]
    if g.threads:
        tokens += ["--threads", str(g.threads)]
    if g.regions_list:
        tokens += ["--regions-list", g.regions_list]
    if g.zones_list:
        tokens += ["--zones-list", g.zones_list]
    if g.download_output:
        tokens += ["--download-output", g.download_output]
    return tokens, max(1, int(g.parallel_services or 1))


def _enabled_parallel_services(user_args) -> list[tuple[str, str]]:
    """Which per-project services to run, matching run_module's every_flag_missing
    semantics: no service flags -> all; otherwise only the ones requested."""
    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    for key, flag in _PARALLEL_SERVICES:
        p.add_argument(flag, dest=key, action="store_true")
    p.add_argument("--cloud-compute", dest="cloud_compute", action="store_true")
    p.add_argument("--resource-manager", dest="resource_manager", action="store_true")
    p.add_argument("--workspace-cloud-identity", dest="workspace_identity", action="store_true")
    g, _ = p.parse_known_args(list(user_args or []))

    selected = {key for key, _ in _PARALLEL_SERVICES if getattr(g, key, False)}
    if g.cloud_compute:
        selected |= {"cloud_compute_resources", "cloud_compute_network", "cloud_compute_lb"}

    # Opt-in services (e.g. asset_inventory) are ADDITIVE: they never count toward
    # "a service was selected" and run ONLY when their own flag is passed -- so a bare
    # run (or a run with only opt-in flags) still runs every non-opt-in service. This
    # matches run_module's every_flag_missing semantics (which excludes opt-in gates).
    opt_in_gates = {spec.gate_flags[0] for spec in _SERVICES if spec.opt_in}
    non_opt_in_selected = selected - opt_in_gates
    any_service_flag = bool(non_opt_in_selected) or g.resource_manager or g.workspace_identity
    if not any_service_flag:
        non_opt_in_selected = {key for key, _ in _PARALLEL_SERVICES if key not in opt_in_gates}
    final = non_opt_in_selected | (selected & opt_in_gates)
    return [(key, flag) for key, flag in _PARALLEL_SERVICES if key in final]


def _resolve_target_projects(session, explicit_project_ids) -> list[str]:
    explicit = [str(p).strip() for p in (explicit_project_ids or []) if str(p).strip()]
    if explicit:
        return list(dict.fromkeys(explicit))
    rows = session.get_data("abstract_tree_hierarchy", columns=["project_id", "type"]) or []
    discovered = [
        str(row.get("project_id") or "").strip()
        for row in rows
        if str(row.get("type") or "").strip().lower() == "project" and str(row.get("project_id") or "").strip()
    ]
    return list(dict.fromkeys(discovered))


def _ledger_done_units(session, run_id: str) -> set[tuple[str, str]]:
    """Return the (project_id, service) units marked done UNDER ``run_id``.

    Scoped to one run token so runs are independent: a fresh token sees nothing
    done (full re-run), while ``--resume <token>`` re-reads that token's completed
    units and skips them. Binding units appear here too, keyed by the pseudo
    (__hierarchy__/project, __bindings__) pair.
    """
    rows = session.get_data(
        _TASK_LEDGER_TABLE,
        columns=["project_id", "service", "status"],
        where={"run_id": run_id},
    ) or []
    return {
        (str(r.get("project_id")), str(r.get("service")))
        for r in rows
        if str(r.get("status") or "") == "done"
    }


def _ledger_mark(session, project_id, service, status, run_id, *, error=""):
    """Upsert a (project_id, service) unit's status into the resume ledger.

    status is pending/running/done/failed; started_at/finished_at timestamps are
    stamped on the relevant transitions and error text is truncated to 2000 chars.
    DB write -- called on the main thread only.
    """
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "project_id": project_id,
        "service": service,
        "status": status,
        "run_id": run_id,
        "error": str(error or "")[:2000],
    }
    if status == "running":
        payload["started_at"] = now
    if status in ("done", "failed"):
        payload["finished_at"] = now
    session.insert_data(_TASK_LEDGER_TABLE, payload)


def _ledger_incomplete(session, run_id: str) -> bool:
    """True if any unit recorded under ``run_id`` is not yet 'done' (so the run has
    resumable work left). Used to decide whether to drop the ledger on completion."""
    rows = session.get_data(_TASK_LEDGER_TABLE, columns=["status"], where={"run_id": run_id}) or []
    return any(str(row.get("status") or "") != "done" for row in rows)


def _ledger_clear(session, run_id: str) -> None:
    """Drop this run's ledger rows -- a fully-completed run has nothing to resume."""
    session.delete_data(_TASK_LEDGER_TABLE, {"run_id": run_id})


def _resume_hint(mod_name: str, run_id: str, workers: int) -> str:
    """The 'resume THIS run with: ...' command line, shown at run start AND when a run
    is interrupted, so the token is never buried in scrollback."""
    return (
        f"modules run {mod_name} ... --parallel-services {workers} --resume {run_id}"
    )


def _token_generated_at(run_id: str) -> str:
    """Run tokens are minted as a UTC ``%Y%m%d%H%M%S`` timestamp -> render it back to a
    readable date. Non-timestamp tokens (unlikely) fall back to the raw value."""
    try:
        return datetime.strptime(run_id, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return "unknown"


def _list_run_tokens(session) -> int:
    """Print every resumable run token in this workspace with when it was generated,
    its last activity, and how far it got. Interrupted/failed runs persist their
    ledger; cleanly-finished runs clear theirs, so this lists what you can --resume."""
    rows = session.get_data(
        _TASK_LEDGER_TABLE,
        columns=["run_id", "status", "started_at", "finished_at"],
    ) or []
    if not rows:
        print(f"{UtilityTools.YELLOW}[!] No saved run tokens -- nothing to resume "
              f"(finished runs clear their ledger).{UtilityTools.RESET}")
        return 0

    runs: dict[str, dict] = {}
    for r in rows:
        rid = str(r.get("run_id") or "")
        if not rid:
            continue
        agg = runs.setdefault(rid, {"total": 0, "done": 0, "failed": 0, "last": ""})
        agg["total"] += 1
        status = str(r.get("status") or "")
        if status == "done":
            agg["done"] += 1
        elif status == "failed":
            agg["failed"] += 1
        for stamp in (r.get("finished_at"), r.get("started_at")):
            stamp = str(stamp or "")
            if stamp and stamp > agg["last"]:
                agg["last"] = stamp

    print(f"{UtilityTools.BOLD}[*] Saved run tokens ({len(runs)}) -- resume with "
          f"--parallel-services N --resume <TOKEN>:{UtilityTools.RESET}")
    for rid in sorted(runs, reverse=True):
        agg = runs[rid]
        remaining = agg["total"] - agg["done"]
        state = "complete" if remaining == 0 else f"{remaining} unit(s) left"
        if agg["failed"]:
            state += f", {agg['failed']} failed"
        last = str(agg["last"] or "").replace("T", " ")[:19] or "n/a"
        print(
            f"    {rid}  | generated {_token_generated_at(rid)} | last activity {last} "
            f"| {agg['done']}/{agg['total']} done ({state})"
        )
    return 0


def run_parallel(session, user_args, explicit_project_ids=None, *, include_workspace: bool = True) -> int:
    """Cross-project parallel enum_all with pipelined IAM policy bindings.

    Phase 1 runs Resource Manager once to discover the hierarchy. Phase 2 then
    fans the per-(project, service) enumerators out across a worker pool AND
    pipelines IAM policy-binding collection per hierarchy node instead of waiting
    in one end-of-run barrier:

      * org + folder node bindings depend only on the hierarchy, so they start
        immediately alongside the service pool;
      * each project's node + resource bindings fire the moment that project's
        services finish, overlapping the still-running projects.

    Phase 3 reconciles any cached resource missing a project_id and rebuilds the
    principal table once. Resumable: completed (project, service) units -- and the
    pipelined binding units (``__bindings__`` per project plus ``__hierarchy__``)
    -- are recorded in enum_all_task_ledger and skipped on re-run.
    """
    from gcpwn.modules.everything.utilities.iam_policy_bindings import (
        IAMPolicyBindingsResource,
        materialize_member_permissions,
    )

    # --list-tokens is a standalone report: list resumable tokens and exit without
    # touching the pool (works whether or not --parallel-services was passed).
    if "--list-tokens" in list(user_args or []):
        return _list_run_tokens(session)

    # enum_gcp re-exports run_parallel with include_workspace=False; surface the
    # invoked name so token/resume hints say the command the user actually typed.
    mod_name = "enum_all" if include_workspace else "enum_gcp"
    clear_cancel()  # fresh run: reset any cancel flag left set by a prior Ctrl+C

    global_tokens, workers = _extract_global_tokens(user_args)
    services = _enabled_parallel_services(user_args)
    run_id, is_resume = resolve_run_token(user_args)

    # Per-download-type wall-clock cap, read off the shared session by the sub-modules'
    # download loops (scoped sessions delegate the attribute to this base). 0 = unlimited.
    _dt_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    _dt_parser.add_argument("--download-timeout", dest="download_timeout", type=int, default=0)
    _dt_args, _ = _dt_parser.parse_known_args(list(user_args or []))
    session.download_time_budget = int(_dt_args.download_timeout or 0)

    # Fresh per-run cache of orgs whose custom roles enum_iam has already listed. Seeded
    # on the BASE session here (once) so the parallel cloud_iam workers -- each a
    # ProjectScopedSession whose writes stay local to its own view -- SHARE this one set
    # and list a tree's org custom roles once per run instead of once per project.
    session._enum_iam_org_cache = set()

    # Phase 1: Resource Manager once (discovers the hierarchy + all projects).
    print(f"{UtilityTools.BOLD}[*] Parallel enum_all | phase 1/3: Resource Manager (discovery){UtilityTools.RESET}")
    run_module([*global_tokens, "--phase", "rm", "--resource-manager"], session)

    targets = _resolve_target_projects(session, explicit_project_ids)
    if not targets:
        print(f"{UtilityTools.RED}[X] No target projects resolved; nothing to enumerate.{UtilityTools.RESET}")
        return -1

    done_units = _ledger_done_units(session, run_id)
    tasks: list[tuple[str, str, str]] = []
    skipped = 0
    for project_id in targets:
        for service_key, service_flag in services:
            if (project_id, service_key) in done_units:
                skipped += 1
                continue
            _ledger_mark(session, project_id, service_key, "pending", run_id)
            tasks.append((project_id, service_key, service_flag))

    # Pipelined binding units: org+folder once, plus one per project.
    hierarchy_pending = (_HIERARCHY_LEDGER_KEY, _BINDINGS_SERVICE) not in done_units
    bindings_pending = {p for p in targets if (p, _BINDINGS_SERVICE) not in done_units}
    binding_total = (1 if hierarchy_pending else 0) + len(bindings_pending)
    total_units = len(tasks) + binding_total

    if is_resume and not done_units:
        print(
            f"{UtilityTools.YELLOW}[!] --resume {run_id}: no completed units recorded for this token; "
            f"running all units under it.{UtilityTools.RESET}"
        )
    print(
        f"{UtilityTools.BOLD}[*] Run token: {run_id}{UtilityTools.RESET}"
        f"  (interrupt-safe -- resume THIS run with:  {_resume_hint(mod_name, run_id, workers)})"
    )
    resume_note = f" (resuming: {skipped} services already done)" if skipped else ""
    print(
        f"{UtilityTools.BOLD}[*] Phase 2/3: {len(tasks)} (project,service) units + "
        f"{binding_total} pipelined binding unit(s) across {len(targets)} project(s), "
        f"{workers} workers{resume_note}{UtilityTools.RESET}"
    )

    if total_units:
        # Service units still to run this invocation, counted per project so each
        # project's binding task can fire the moment its last service completes.
        remaining: dict[str, int] = defaultdict(int)
        for pid, _svc, _flag in tasks:
            remaining[pid] += 1

        def _run_service(project_id: str, service_key: str, service_flag: str) -> bool:
            if cancel_requested():
                # Aborting: don't touch the ledger so the unit stays 'pending' and a
                # --resume re-runs it. (begin/end_task both skipped -> counts stay balanced.)
                return True
            scoped = ProjectScopedSession(session, project_id)
            scoped._enum_all_suppress_progress = True
            output.begin_task(f"{service_key}@{project_id}")
            _ledger_mark(session, project_id, service_key, "running", run_id)
            failed = False
            try:
                run_module([*global_tokens, "--phase", "services", service_flag], scoped)
                if cancel_requested():
                    # A Ctrl+C cut this service's region/zone fan-out short, so its data
                    # may be partial -- mark it NOT done so --resume re-enumerates it fully.
                    failed = True
                    _ledger_mark(session, project_id, service_key, "failed", run_id,
                                 error="interrupted: partial enumeration; will re-run on resume")
                else:
                    _ledger_mark(session, project_id, service_key, "done", run_id)
            except Exception:
                failed = True
                _ledger_mark(session, project_id, service_key, "failed", run_id, error=traceback.format_exc())
            finally:
                output.end_task(failed=failed)
            return failed

        def _run_bindings(scope: dict, label: str, ledger_pid: str, bind_project: str, *, mark_done: bool = True) -> None:
            # A project's binding pass reads that project's *enumerated resources* for
            # per-resource getIamPolicy (scope={"project_id":..} sets include_resources=True).
            # So if any of the project's services FAILED this run, its resource set is
            # incomplete -- run the binding anyway (captures what's present) but do NOT mark
            # the unit "done" (mark_done=False), so a resume re-runs it once the failed
            # service's resources exist. Otherwise the failed service's resources would keep
            # their direct IAM policies forever unenumerated (Phase 3 orphan reconcile skips
            # in-targets projects).
            if cancel_requested():
                return  # aborting: leave the binding unit unmarked so --resume re-runs it
            scoped = ProjectScopedSession(session, bind_project)
            scoped._enum_all_suppress_progress = True
            output.begin_task(label)
            _ledger_mark(session, ledger_pid, _BINDINGS_SERVICE, "running", run_id)
            failed = False
            try:
                IAMPolicyBindingsResource(scoped).run(save_raw_policies=True, scope=scope, sync_users=False)
                if mark_done and not cancel_requested():
                    _ledger_mark(session, ledger_pid, _BINDINGS_SERVICE, "done", run_id)
                else:
                    _ledger_mark(session, ledger_pid, _BINDINGS_SERVICE, "failed", run_id,
                                 error="deferred: a service in this project failed; bindings will re-run on resume")
            except Exception:
                failed = True
                _ledger_mark(session, ledger_pid, _BINDINGS_SERVICE, "failed", run_id, error=traceback.format_exc())
            finally:
                output.end_task(failed=failed)

        base_project = str(session.project_id or "")
        with ParallelOutputManager(total=total_units) as output:
            # Manual (not `with`) so a Ctrl+C can shut the pool down with
            # cancel_futures=True -- dropping the queued units immediately -- instead of
            # the context manager's shutdown(wait=True) draining the whole backlog first.
            executor = ThreadPoolExecutor(max_workers=workers)
            try:
                binding_futures = []
                # org + folder bindings depend only on Phase 1 -> launch immediately.
                if hierarchy_pending:
                    binding_futures.append(
                        executor.submit(_run_bindings, {"hierarchy": True}, "bindings@org+folder", _HIERARCHY_LEDGER_KEY, base_project)
                    )
                # Projects whose services are all already done (resume) bind now.
                for project_id in targets:
                    if project_id in bindings_pending and remaining[project_id] == 0:
                        bindings_pending.discard(project_id)
                        binding_futures.append(
                            executor.submit(_run_bindings, {"project_id": project_id}, f"bindings@{project_id}", project_id, project_id)
                        )

                service_futures = {
                    executor.submit(_run_service, pid, svc, flag): pid
                    for pid, svc, flag in tasks
                }
                # Projects with >=1 failed service this run -> their binding runs but isn't
                # marked done, so a resume re-binds after the failed service's resources land.
                failed_projects: set[str] = set()
                # As each project's last service finishes, pipeline its bindings.
                for future in as_completed(service_futures):
                    pid = service_futures[future]
                    try:
                        service_failed = bool(future.result())
                    except Exception:
                        service_failed = True
                    if service_failed:
                        failed_projects.add(pid)
                    remaining[pid] -= 1
                    if remaining[pid] <= 0 and pid in bindings_pending:
                        bindings_pending.discard(pid)
                        binding_futures.append(
                            executor.submit(
                                _run_bindings, {"project_id": pid}, f"bindings@{pid}", pid, pid,
                                mark_done=(pid not in failed_projects),
                            )
                        )

                for future in binding_futures:
                    future.result()
            except KeyboardInterrupt:
                # One Ctrl+C: flip the cancel flag so in-flight workers (and their inner
                # region fan-outs) stop, and echo the resume token so it isn't buried in
                # scrollback. Re-raise for the REPL's handler; the finally drains the pool.
                request_cancel()
                print(
                    f"\n{UtilityTools.YELLOW}[!] Interrupted -- resume THIS run with:  "
                    f"{_resume_hint(mod_name, run_id, workers)}{UtilityTools.RESET}"
                )
                raise
            finally:
                # cancel_futures drops the queued units at once. On the interrupt path
                # cancel is set -> wait=True so the <=N in-flight workers finish (their
                # inner fan-outs bail immediately) BEFORE the prompt returns -- no
                # background chatter, and no thread survives into the next command to
                # race clear_cancel(). Normal path: all futures already done -> no wait.
                executor.shutdown(wait=cancel_requested(), cancel_futures=True)

    # Phase 3: reconcile cached resources missing a project_id, then rebuild the
    # principal/user table once now that every node's bindings have landed.
    print(f"{UtilityTools.BOLD}[*] Phase 3/3: reconcile orphan resources + rebuild principals{UtilityTools.RESET}")
    try:
        IAMPolicyBindingsResource(session).run(
            save_raw_policies=True,
            scope={"orphans": True, "known_projects": targets},
            sync_users=False,
        )
    except Exception:
        traceback.print_exc()
    session.sync_users()
    materialize_member_permissions(session)  # keep the member view in sync (no manual process step)
    # Phase 4: Google Workspace (tenant-scoped -> run ONCE, after GCP). enum_gcp
    # passes include_workspace=False; the top enum_all runs it. Degrades gracefully
    # when the caller has no Workspace access (most GCP creds don't).
    if include_workspace:
        print(f"{UtilityTools.BOLD}[*] Parallel enum_all | phase 4: Google Workspace (tenant-scoped, once){UtilityTools.RESET}")
        try:
            from gcpwn.modules.everything.enumeration.enum_google_workspace import (
                run_module as run_workspace_all,
            )
            ws_args = ["-v"] if ("-v" in user_args or "--debug" in user_args) else []
            if "--download-google-drive" in user_args:
                ws_args.append("--download-google-drive")
            run_workspace_all(ws_args, session)
        except Exception:
            traceback.print_exc()
    if not _ledger_incomplete(session, run_id):
        _ledger_clear(session, run_id)  # every unit done -> nothing to resume; drop this run's token
    print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Parallel enum_all complete.{UtilityTools.RESET}")
    return 1


def run_module(user_args, session):
    """Module entrypoint: run the selected per-service enumerators for one project.

    Standard module contract: returns 1 on success, 2 when Resource Manager
    discovered MORE projects than were previously cached (signals the caller to
    re-run across the expanded project set), -1 on an arg/allowlist error.

    With no service flags every service runs; otherwise only the requested ones.
    --phase (hidden) lets the parallel orchestrator drive rm/services/bindings
    independently; the default "all" preserves the original monolithic order:
    Resource Manager once, then each service, then enum_gcp_policy_bindings last
    (bindings must run last so the allow-policy cache covers all discovered
    resources). Allowlist flags scope which projects/folders/orgs are enumerated.
    """
    parser = argparse.ArgumentParser(description="Enumerate all services", allow_abbrev=False)
    parser.add_argument("--download-output", required=False, help="Output directory for downloaded artifacts")
    parser.add_argument(
        "--download-timeout",
        dest="download_timeout",
        type=int,
        default=0,
        help=(
            "Per-download-TYPE wall-clock cap in seconds. If a download type (bucket blobs, "
            "function sources, secrets, serial output, ...) runs longer than this, its remaining "
            "items are skipped and enumeration moves to the next type. Default: 0 = no limit."
        ),
    )
    parser.add_argument(
        "--download-google-drive",
        dest="download_google_drive",
        action="store_true",
        help=(
            "Opt in to Google Drive in the Workspace phase: runs enum_drive --all-users "
            "--download (lists AND downloads Drive file content for every cached user). "
            "OFF by default so Drive files are never pulled unless explicitly requested."
        ),
    )
    parser.add_argument("--threads", type=int, default=4, help="Worker threads for region/zone fan-out (default: 4)")
    parser.add_argument(
        "--phase",
        choices=["all", "rm", "services"],
        default="all",
        help=argparse.SUPPRESS,  # internal: used by the parallel orchestrator to run one pipeline phase
    )
    parser.add_argument(
        "--parallel-services",
        type=int,
        default=1,
        help=(
            "Enumerate services concurrently across projects with N workers "
            "(default: 1 = sequential). Each run records progress under a run token "
            "(printed at start); a plain re-run starts fresh."
        ),
    )
    parser.add_argument(
        "--resume",
        default=None,
        help=(
            "Resume a prior --parallel-services run by its token (printed at that run's "
            "start): re-runs ONLY the units that run left incomplete, instead of starting "
            "over. Requires --parallel-services > 1."
        ),
    )
    parser.add_argument(
        "--list-tokens",
        dest="list_tokens",
        action="store_true",
        help=(
            "List every saved run token (interrupted/failed --parallel-services runs) with "
            "when it was generated and its progress, then exit. Pick one to pass to --resume."
        ),
    )
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
    parser.add_argument("--workspace-cloud-identity", dest="workspace_identity", action="store_true", help="Execute Google Workspace Cloud Identity enumeration")
    parser.add_argument("--cloud-scheduler", action="store_true", help="Execute Cloud Scheduler enumeration")
    parser.add_argument("--cloud-workflows", action="store_true", help="Execute Cloud Workflows enumeration")
    parser.add_argument("--spanner", action="store_true", help="Execute Cloud Spanner enumeration")
    parser.add_argument("--alloydb", action="store_true", help="Execute AlloyDB enumeration")
    parser.add_argument("--orgpolicy", action="store_true", help="Execute Organization Policy enumeration")
    parser.add_argument("--eventarc", action="store_true", help="Execute Eventarc enumeration")
    parser.add_argument("--workstations", action="store_true", help="Execute Cloud Workstations enumeration")
    parser.add_argument("--cloud-billing", action="store_true", help="Execute Cloud Billing enumeration")
    parser.add_argument("--cloud-shell", action="store_true", help="Execute Cloud Shell enumeration")
    parser.add_argument("--cloud-logging", action="store_true", help="Execute Cloud Logging enumeration")
    parser.add_argument("--dataproc", action="store_true", help="Execute Dataproc enumeration")
    parser.add_argument("--dataflow", action="store_true", help="Execute Dataflow enumeration")
    parser.add_argument("--notebooks", action="store_true", help="Execute Vertex AI Workbench enumeration")
    parser.add_argument("--cloud-deploy", action="store_true", help="Execute Cloud Deploy enumeration")
    parser.add_argument("--bigquery-datatransfer", action="store_true", help="Execute BigQuery Data Transfer enumeration")
    parser.add_argument("--service-usage", action="store_true", help="Execute Service Usage (enabled-API) enumeration")
    parser.add_argument("--asset-inventory", action="store_true", help="Execute Cloud Asset Inventory enumeration (opt-in; skipped by default)")
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

    # Standalone report: list resumable run tokens and exit (also handled in the
    # parallel dispatcher, but keep it here so the flag works on any code path).
    if getattr(args, "list_tokens", False):
        return _list_run_tokens(session)

    # Per-download-type wall-clock cap; download loops in the sub-modules read it off
    # the shared session (DownloadBudget). 0 = unlimited.
    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)

    if getattr(args, "resume", None) and int(getattr(args, "parallel_services", 1) or 1) <= 1:
        print(
            f"{UtilityTools.YELLOW}[!] --resume only applies to --parallel-services runs "
            f"(the resumable ledger is built there); ignoring it for this sequential run.{UtilityTools.RESET}"
        )

    try:
        project_allowlist_inline = parse_id_input_values(
            flatten_arg_groups(getattr(args, "project_allowlist", None)),
            value_label="project id",
            numeric_only=False,
        )
        project_allowlist_files = parse_id_input_values(
            flatten_arg_groups(getattr(args, "project_allowlist_file", None)),
            value_label="project id",
            numeric_only=False,
            files_only=True,
        )
        scoped_project_ids = list(dict.fromkeys([*project_allowlist_inline, *project_allowlist_files]))

        folder_allowlist_inline = parse_id_input_values(
            flatten_arg_groups(getattr(args, "folder_allowlist", None)),
            value_label="folder id",
            numeric_only=True,
        )
        folder_allowlist_files = parse_id_input_values(
            flatten_arg_groups(getattr(args, "folder_allowlist_file", None)),
            value_label="folder id",
            numeric_only=True,
            files_only=True,
        )
        scoped_folder_ids = list(dict.fromkeys([*folder_allowlist_inline, *folder_allowlist_files]))

        org_allowlist_inline = parse_id_input_values(
            flatten_arg_groups(getattr(args, "org_allowlist", None)),
            value_label="organization id",
            numeric_only=True,
        )
        org_allowlist_files = parse_id_input_values(
            flatten_arg_groups(getattr(args, "org_allowlist_file", None)),
            value_label="organization id",
            numeric_only=True,
            files_only=True,
        )
        scoped_organization_ids = list(dict.fromkeys([*org_allowlist_inline, *org_allowlist_files]))

        parent_folder_inline = parse_id_input_values(
            flatten_arg_groups(getattr(args, "parent_allowlist_folder", None)),
            value_label="parent folder id",
            numeric_only=True,
        )
        parent_folder_files = parse_id_input_values(
            flatten_arg_groups(getattr(args, "parent_allowlist_folder_file", None)),
            value_label="parent folder id",
            numeric_only=True,
            files_only=True,
        )
        parent_allowlist_folder_ids = list(dict.fromkeys([*parent_folder_inline, *parent_folder_files]))

        parent_org_inline = parse_id_input_values(
            flatten_arg_groups(getattr(args, "parent_allowlist_org", None)),
            value_label="parent organization id",
            numeric_only=True,
        )
        parent_org_files = parse_id_input_values(
            flatten_arg_groups(getattr(args, "parent_allowlist_org_file", None)),
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
            args.workspace_identity,
            args.cloud_scheduler,
            args.cloud_workflows,
            args.spanner,
            args.alloydb,
            args.orgpolicy,
            args.eventarc,
            args.workstations,
            args.cloud_billing,
            args.cloud_shell,
            args.cloud_logging,
            args.dataproc,
            args.dataflow,
            args.notebooks,
            args.cloud_deploy,
            args.bigquery_datatransfer,
            args.service_usage,
        ]
    )

    run_ctx = getattr(session, "_module_run_context", None) or {}
    run_index = int(run_ctx.get("index", 0) or 0)
    run_total = max(1, int(run_ctx.get("total", 1) or 1))
    first_run = run_index == 0
    last_run = run_index == (run_total - 1)

    # Pipeline phase gating. "all" (default) keeps the original monolithic
    # behavior. The parallel orchestrator drives the phases independently:
    #   rm       -> Resource Manager (once; discovers the hierarchy/projects)
    #   services -> the per-project resource enumerators (parallelizable)
    #   bindings -> enum_gcp_policy_bindings (once; aggregates across all projects)
    phase = getattr(args, "phase", "all")
    do_rm = phase in ("all", "rm")
    do_services = phase in ("all", "services")
    do_bindings = phase == "all"
    # Parallel orchestrator drives per-(project,service) sub-calls; suppress the
    # shared _ENUM_PROGRESS counter/banner there (the orchestrator owns progress).
    suppress_progress = bool(getattr(session, "_enum_all_suppress_progress", False))

    planned_services = 0
    planned_services += int(
        first_run
        and (
            args.resource_manager
            or every_flag_missing
            or allowlist_requested
        )
    )
    planned_services += sum(1 for spec in _SERVICES if _service_selected(spec, args, every_flag_missing))
    planned_services += int(first_run and args.workspace_identity)
    planned_services += int(last_run)

    if not suppress_progress:
        _ENUM_PROGRESS.update({"enabled": True, "index": 0, "total": planned_services})

    more = False
    if not suppress_progress:
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

    if do_rm and first_run and (args.resource_manager or every_flag_missing or allowlist_active):
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
            _run_other_module(session, module_args, "gcpwn.modules.gcp.resourcemanager.enumeration.enum_resources")
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
                "projects": sorted(normalize_str_set(resolved_scope.get("projects", []))),
                "folders": sorted(normalize_str_set(resolved_scope.get("folders", []))),
                "organizations": sorted(normalize_str_set(resolved_scope.get("organizations", []))),
            }
            session._enum_all_effective_allowlist_scope = dict(cached_scope)
        effective_projects = normalize_str_set(cached_scope.get("projects", []))
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

    # Per-project resource enumerators run only in the 'services' phase
    # (and in 'all'). RM/bindings phases skip them.
    run_services = run_non_rm_for_project and do_services
    # Workspace Cloud Identity is a once-per-run (first_run) discovery, like RM.
    if do_rm and run_non_rm_for_project and first_run and args.workspace_identity:
        module_args = ["-v"] if args.debug else []
        _run_other_module(session, module_args, "gcpwn.modules.workspace.cloud_identity.enumeration.enum_cloud_identity")

    # Per-project resource enumerators -> one declarative table (see _SERVICES).
    for spec in _SERVICES:
        if run_services and _service_selected(spec, args, every_flag_missing):
            _run_other_module(session, _build_service_args(spec, args, _download_requested), spec.module)

    # Must be called last: builds IAM allow-policy cache across all cached resources.
    if do_bindings and last_run and not more:
        module_args = ["-v"] if args.debug else []
        _run_other_module(session, module_args, "gcpwn.modules.everything.enumeration.enum_gcp_policy_bindings")

    _ENUM_PROGRESS.update({"enabled": False, "index": 0, "total": 0})
    if more:
        return 2
    return 1
