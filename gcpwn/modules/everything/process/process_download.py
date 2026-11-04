"""
process_download – re-download content for already-enumerated resources.

Reads resource IDs from the workspace DB (populated by prior enum runs) and
downloads their content without re-enumerating. Uses the same download token
vocabulary as enum_all --download.

Usage:
    modules run process_download --download all
    modules run process_download --download secrets,function_env,cloudrun_revision_env
    modules run process_download --download content --project-id my-project

Token categories:
    all       -> every token
    metadata  -> function_env, cloudbuild_builds, composer_configs,
                 cloudtasks_requests, cloudrun_revision_env, clouddns_record_sets,
                 clouddomains_contacts
    content   -> buckets, function_source, secrets, firestore_data,
                 bigquery_tables, compute_serial, compute_screenshot,
                 compute_user_data, artifactregistry_files, batch_scripts,
                 apikeys_content, datastream_connection_profiles
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from typing import Any

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_csv_arg

# ---------------------------------------------------------------------------
# Token vocabulary (mirrors enum_all DOWNLOAD_CATEGORY_TOKENS)
# ---------------------------------------------------------------------------

_CATEGORY_TOKENS: dict[str, set[str]] = {
    "metadata": {
        "function_env",
        "cloudbuild_builds",
        "composer_configs",
        "cloudtasks_requests",
        "cloudrun_revision_env",
        "clouddns_record_sets",
        "clouddomains_contacts",
    },
    "content": {
        "buckets",
        "function_source",
        "secrets",
        "firestore_data",
        "bigquery_tables",
        "compute_serial",
        "compute_screenshot",
        "compute_user_data",
        "artifactregistry_files",
        "batch_scripts",
        "apikeys_content",
        "datastream_connection_profiles",
    },
}
_ALL_TOKENS: set[str] = _CATEGORY_TOKENS["metadata"] | _CATEGORY_TOKENS["content"]


def _expand_tokens(raw: str) -> set[str]:
    selected: set[str] = set()
    for token in [t.lower() for t in parse_csv_arg(raw) if t.strip()]:
        if token == "all":
            selected |= _ALL_TOKENS
        elif token in _CATEGORY_TOKENS:
            selected |= _CATEGORY_TOKENS[token]
        elif token in _ALL_TOKENS:
            selected.add(token)
        else:
            valid = "all, metadata, content, " + ", ".join(sorted(_ALL_TOKENS))
            raise ValueError(f"Unknown download token '{token}'. Valid: {valid}")
    return selected


def _load_raw(row: dict[str, Any]) -> dict[str, Any]:
    """Return the full proto dict: raw_json string → dict, or the row itself."""
    raw = row.get("raw_json") or row
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    return raw if isinstance(raw, dict) else {}


# ---------------------------------------------------------------------------
# Per-token handlers
# Each takes (session, project_id, budget) and returns count of downloaded items.
# ---------------------------------------------------------------------------

def _handle_clouddomains_contacts(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.clouddomains.utilities.helpers import DomainsRegistrationsResource
    rows = session.get_data("clouddomains_registrations", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = DomainsRegistrationsResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        path = resource.download_contacts(row=row, project_id=project_id)
        if path:
            n += 1
            print(f"[*] Wrote domain contacts: {path}")
    return n


def _handle_datastream_connection_profiles(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.datastream.utilities.helpers import DatastreamConnectionProfilesResource
    rows = session.get_data("datastream_connection_profiles", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = DatastreamConnectionProfilesResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        path = resource.download_credentials(row=row, project_id=project_id)
        if path:
            n += 1
            print(f"[*] Wrote Datastream connection profile credentials: {path}")
    return n


def _handle_apikeys(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.apikeys.utilities.helpers import ApiKeysKeysResource as APIKeysResource
    rows = session.get_data("apikeys_keys", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = APIKeysResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        path = resource.download_key_string(row=row, project_id=project_id)
        if path:
            n += 1
            print(f"[*] Wrote API key: {path}")
    return n


def _handle_batch_scripts(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.batch.enumeration.enum_batch import _download_scripts
    rows = session.get_data("batch_jobs", where={"project_id": project_id}) or []
    if not rows:
        return 0
    _download_scripts(session, project_id=project_id, job_rows=rows)
    return 1  # _download_scripts prints its own output


def _handle_cloudbuild_builds(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudbuild.utilities.helpers import CloudBuildBuildsResource
    rows = session.get_data("cloudbuild_builds", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = CloudBuildBuildsResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        for dl_fn in (resource.download_build_env_summary, resource.download_build_step_arguments):
            path = dl_fn(row=row, project_id=project_id)
            if path:
                n += 1
                print(f"[*] Wrote Cloud Build artifact: {path}")
    return n


def _handle_cloudrun_revision_env(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudrun.utilities.helpers import (
        CloudRunRevisionsResource,
        CloudRunWorkerPoolRevisionsResource,
    )
    service_rows = session.get_data("cloudrun_services", where={"project_id": project_id}) or []
    worker_pool_rows = session.get_data("cloudrun_worker_pools", where={"project_id": project_id}) or []
    if not service_rows and not worker_pool_rows:
        return 0
    n = 0
    rev_resource = CloudRunRevisionsResource(session)
    for svc in service_rows:
        if budget.exceeded():
            break
        svc_name = str(svc.get("name") or "").strip()
        if not svc_name:
            continue
        try:
            revisions = rev_resource.list(parent=svc_name) or []
            if revisions in ("Not Enabled", None):
                continue
            for rev in list(revisions):
                if budget.exceeded():
                    break
                rev_name = str((rev if isinstance(rev, dict) else {}).get("name") or "").strip()
                if not rev_name:
                    continue
                full_rev = rev_resource.get(resource_id=rev_name) or rev
                path = rev_resource.download_env_yaml(revision_row=full_rev, project_id=project_id)
                if path:
                    n += 1
                    print(f"[*] Wrote Cloud Run revision env: {path}")
        except Exception:
            pass

    wp_rev_resource = CloudRunWorkerPoolRevisionsResource(session)
    for pool in worker_pool_rows:
        if budget.exceeded():
            break
        pool_name = str(pool.get("name") or "").strip()
        if not pool_name:
            continue
        try:
            revisions = wp_rev_resource.list_for_worker_pool(pool_name=pool_name) or []
            if not revisions:
                continue
            for rev in list(revisions):
                if budget.exceeded():
                    break
                path = wp_rev_resource.download_env_yaml(revision_row=rev, project_id=project_id)
                if path:
                    n += 1
                    print(f"[*] Wrote Cloud Run worker pool revision env: {path}")
        except Exception:
            pass
    return n


def _handle_function_env(session, project_id: str, budget: DownloadBudget) -> int:
    rows = session.get_data("cloudfunctions_functions", where={"project_id": project_id}) or []
    if not rows:
        return 0
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        raw = _load_raw(row)
        env_vars: dict[str, str] = {}
        # Gen1: environment_variables at top level
        top_env = raw.get("environment_variables")
        if isinstance(top_env, dict):
            env_vars.update(top_env)
        # Gen2: service_config.environment_variables
        svc_cfg = raw.get("service_config") or {}
        if isinstance(svc_cfg, dict):
            svc_env = svc_cfg.get("environment_variables")
            if isinstance(svc_env, dict):
                env_vars.update(svc_env)
        if not env_vars:
            continue
        fn_name = str(row.get("name") or raw.get("name") or "").rsplit("/", 1)[-1] or "function"
        path = resolve_download_path(
            session, service_name="cloudfunctions", project_id=project_id,
            subdirs=["env"], filename=f"{fn_name}_env.json",
        )
        path.write_text(json.dumps(env_vars, indent=2, sort_keys=True), encoding="utf-8")
        n += 1
        print(f"[*] Wrote Cloud Function env vars: {path}")
    return n


def _handle_cloudtasks_requests(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudtasks.utilities.helpers import CloudTasksQueuesResource
    rows = session.get_data("cloudtasks_queues", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = CloudTasksQueuesResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        paths = resource.download_http_request_samples(row=row, project_id=project_id)
        for path in (paths or []):
            n += 1
            print(f"[*] Wrote Cloud Tasks HTTP request sample: {path}")
    return n


def _handle_composer_configs(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudcomposer.utilities.helpers import ComposerEnvironmentsResource as CloudComposerEnvironmentsResource
    rows = session.get_data("cloudcomposer_environments", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = CloudComposerEnvironmentsResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        path = resource.download_environment_configs(row=row, project_id=project_id)
        if path:
            n += 1
            print(f"[*] Wrote Composer environment config: {path}")
    return n


def _handle_compute_user_data(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudcompute.utilities.helpers import (
        ComputeInstancesResource,
        ComputeInstanceTemplatesResource,
        ComputeProjectsResource,
    )
    n = 0
    for table, ResourceClass, kw in (
        ("cloudcompute_instances", ComputeInstancesResource, {}),
        ("cloudcompute_instance_templates", ComputeInstanceTemplatesResource, {}),
        ("cloudcompute_projects", ComputeProjectsResource, {}),
    ):
        rows = session.get_data(table, where={"project_id": project_id}) or []
        if not rows:
            continue
        resource = ResourceClass(session)
        for row in rows:
            if budget.exceeded():
                break
            try:
                paths = resource.download_user_data(row=row, project_id=project_id, **kw)
                for path in (paths or []):
                    n += 1
                    print(f"[*] Wrote compute user-data / startup script: {path}")
            except Exception:
                pass
    return n


def _handle_clouddns_record_sets(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.clouddns.utilities.helpers import CloudDnsManagedZonesResource as CloudDNSManagedZonesResource
    record_rows = session.get_data("clouddns_record_sets", where={"project_id": project_id}) or []
    if not record_rows:
        return 0
    resource = CloudDNSManagedZonesResource(session)
    by_zone: dict[str, list[dict]] = defaultdict(list)
    for rec in record_rows:
        zone = str(rec.get("zone_name") or "").strip()
        if zone:
            by_zone[zone].append(rec)
    n = 0
    for zone_name, records in by_zone.items():
        if budget.exceeded():
            break
        path = resource.download_record_sets(project_id=project_id, zone_name=zone_name, records=records)
        if path:
            n += 1
            print(f"[*] Wrote Cloud DNS record sets: {path}")
    return n


def _handle_secrets(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.secretsmanager.utilities.helpers import SecretVersionsResource
    version_rows = session.get_data("secretsmanager_secretversions", where={"project_id": project_id}) or []
    enabled = [r for r in version_rows if str(r.get("state") or "").upper() not in ("DESTROYED", "DISABLED")]
    if not enabled:
        return 0
    resource = SecretVersionsResource(session)
    n = 0
    for ver in enabled:
        if budget.exceeded():
            break
        name = str(ver.get("name") or "").strip()
        if not name:
            continue
        try:
            value = resource.access_value(resource_id=name, action_dict=None)
            if not value:
                continue
            payload_bytes = value.payload.data
            secret_name = name.split("/secrets/", 1)[1].split("/", 1)[0] if "/secrets/" in name else ""
            from gcpwn.core.utils.module_helpers import extract_path_tail
            version_id = extract_path_tail(name, default=name)
            resource.download(project_id=project_id, secret_name=secret_name,
                              version=version_id, payload=payload_bytes)
            n += 1
        except Exception:
            pass
    return n


def _handle_function_source(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudfunctions.utilities.helpers import CloudFunctionsResource
    rows = session.get_data("cloudfunctions_functions", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = CloudFunctionsResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        try:
            paths = resource.download(row=row)
            for path in (paths or []):
                n += 1
                print(f"[*] Wrote Cloud Function source: {path}")
        except Exception:
            pass
    return n


def _handle_bigquery_tables(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.bigquery.utilities.helpers import BigQueryTablesResource
    rows = session.get_data("bigquery_tables", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = BigQueryTablesResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        try:
            path = resource.download_table_data(row=row, project_id=project_id)
            if path:
                n += 1
                print(f"[*] Wrote BigQuery table data: {path}")
        except Exception:
            pass
    return n


def _handle_buckets(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudstorage.utilities.helpers import CloudStorageBlobsResource
    bucket_rows = session.get_data("cloudstorage_buckets", where={"project_id": project_id}) or []
    blob_rows = session.get_data("cloudstorage_bucketblobs", where={"project_id": project_id}) or []
    if not bucket_rows and not blob_rows:
        return 0
    bucket_names = list(dict.fromkeys(
        str(r.get("name") or "") for r in bucket_rows if r.get("name")
    ))
    blob_names = [str(r.get("name") or "") for r in blob_rows if r.get("name")]
    if not bucket_names:
        return 0
    resource = CloudStorageBlobsResource(session)
    resource.download_blobs(
        project_id=project_id,
        bucket_names=bucket_names,
        blob_name_inputs=blob_names,
    )
    return 1  # download_blobs prints its own output


def _handle_artifactregistry_files(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.artifactregistry.enumeration.enum_artifactregistry import _run_downloads
    from gcpwn.modules.gcp.artifactregistry.utilities.helpers import ArtifactRegistryRepositoriesResource as ArtifactRegistryReposResource
    repo_rows = session.get_data("artifactregistry_repositories", where={"project_id": project_id}) or []
    if not repo_rows:
        return 0
    resource = ArtifactRegistryReposResource(session)
    # Build the same index dict that _run_downloads expects (name -> row)
    index = {str(r.get("name") or ""): r for r in repo_rows if r.get("name")}
    try:
        _run_downloads(
            session, args=None, project_id=project_id,
            download_scopes=["packages", "maven", "npm", "pypi", "generic"],
            index=index, repositories_resource=resource,
        )
    except Exception:
        pass
    return 1


def _handle_compute_serial(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudcompute.utilities.helpers import CloudComputeInstancesResource as ComputeInstancesResource
    rows = session.get_data("cloudcompute_instances", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = ComputeInstancesResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        name = str(row.get("name") or "").strip()
        zone = str(row.get("zone") or "").strip()
        if not name or not zone:
            continue
        try:
            path = resource.download_serial(project_id=project_id, zone=zone, resource_id=name)
            if path:
                n += 1
                print(f"[*] Wrote compute serial output: {path}")
        except Exception:
            pass
    return n


def _handle_compute_screenshot(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.cloudcompute.utilities.helpers import CloudComputeInstancesResource as ComputeInstancesResource
    rows = session.get_data("cloudcompute_instances", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = ComputeInstancesResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        name = str(row.get("name") or "").strip()
        zone = str(row.get("zone") or "").strip()
        if not name or not zone:
            continue
        try:
            path = resource.download_screenshot(project_id=project_id, zone=zone, resource_id=name)
            if path:
                n += 1
                print(f"[*] Wrote compute screenshot: {path}")
        except Exception:
            pass
    return n


def _handle_firestore_data(session, project_id: str, budget: DownloadBudget) -> int:
    from gcpwn.modules.gcp.firestore.utilities.helpers import FirestoreDatabasesResource
    rows = session.get_data("firestore_databases", where={"project_id": project_id}) or []
    if not rows:
        return 0
    resource = FirestoreDatabasesResource(session)
    n = 0
    for row in rows:
        if budget.exceeded():
            break
        try:
            path = resource.download_database_documents(row=row, project_id=project_id)
            if path:
                n += 1
                print(f"[*] Wrote Firestore database documents: {path}")
        except Exception:
            pass
    return n


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_HANDLERS = {
    "clouddomains_contacts": _handle_clouddomains_contacts,
    "datastream_connection_profiles": _handle_datastream_connection_profiles,
    "apikeys_content": _handle_apikeys,
    "batch_scripts": _handle_batch_scripts,
    "cloudbuild_builds": _handle_cloudbuild_builds,
    "cloudrun_revision_env": _handle_cloudrun_revision_env,
    "function_env": _handle_function_env,
    "cloudtasks_requests": _handle_cloudtasks_requests,
    "composer_configs": _handle_composer_configs,
    "compute_user_data": _handle_compute_user_data,
    "clouddns_record_sets": _handle_clouddns_record_sets,
    "secrets": _handle_secrets,
    "function_source": _handle_function_source,
    "bigquery_tables": _handle_bigquery_tables,
    "buckets": _handle_buckets,
    "artifactregistry_files": _handle_artifactregistry_files,
    "compute_serial": _handle_compute_serial,
    "compute_screenshot": _handle_compute_screenshot,
    "firestore_data": _handle_firestore_data,
}

# Tables each token reads from (used to auto-discover projects)
_TOKEN_TABLES = {
    "clouddomains_contacts": ("clouddomains_registrations",),
    "datastream_connection_profiles": ("datastream_connection_profiles",),
    "apikeys_content": ("apikeys_keys",),
    "batch_scripts": ("batch_jobs",),
    "cloudbuild_builds": ("cloudbuild_builds",),
    "cloudrun_revision_env": ("cloudrun_services", "cloudrun_worker_pools"),
    "function_env": ("cloudfunctions_functions",),
    "cloudtasks_requests": ("cloudtasks_queues",),
    "composer_configs": ("cloudcomposer_environments",),
    "compute_user_data": ("cloudcompute_instances", "cloudcompute_instance_templates"),
    "clouddns_record_sets": ("clouddns_record_sets",),
    "secrets": ("secretsmanager_secretversions",),
    "function_source": ("cloudfunctions_functions",),
    "bigquery_tables": ("bigquery_tables",),
    "buckets": ("cloudstorage_buckets",),
    "artifactregistry_files": ("artifactregistry_repositories",),
    "compute_serial": ("cloudcompute_instances",),
    "compute_screenshot": ("cloudcompute_instances",),
    "firestore_data": ("firestore_databases",),
}


def _collect_projects(session, tokens: set[str]) -> list[str]:
    """Return distinct project_ids that have data for at least one requested token."""
    seen: dict[str, None] = {}
    for token in tokens:
        for table in _TOKEN_TABLES.get(token, ()):
            try:
                rows = session.get_data(table, columns="project_id") or []
                for row in rows:
                    pid = str(row.get("project_id") or "").strip()
                    if pid:
                        seen[pid] = None
            except Exception:
                pass
    return list(seen)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_module(user_args, session):
    parser = argparse.ArgumentParser(
        description="Download content for already-enumerated GCP resources (reads from DB).",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--download", "-d",
        default=None,
        help=(
            "Comma-separated download tokens (or category: all/metadata/content). "
            "Tokens: " + ", ".join(sorted(_ALL_TOKENS))
        ),
    )
    parser.add_argument(
        "--projects",
        default=None,
        help="Comma-separated project IDs to process (default: all projects with matching data)",
    )
    parser.add_argument("-v", "--debug", action="store_true")
    args = parser.parse_args(user_args)

    if not args.download:
        parser.print_help()
        return 0

    try:
        tokens = _expand_tokens(args.download)
    except ValueError as exc:
        print(f"[X] {exc}")
        return -1

    if not tokens:
        print("[!] No download tokens selected.")
        return 0

    # Project scope
    if args.projects:
        project_ids = [p.strip() for p in parse_csv_arg(args.projects) if p.strip()]
    else:
        project_ids = _collect_projects(session, tokens)

    if not project_ids:
        print("[!] No projects with matching enumerated data found in this workspace.")
        return 0

    print(f"[*] process_download: {len(tokens)} token(s), {len(project_ids)} project(s)")

    budget = DownloadBudget(session, label="process_download")
    total = 0

    for project_id in project_ids:
        for token in sorted(tokens):
            if budget.exceeded():
                print("[!] Download budget exceeded; stopping.")
                break
            handler = _HANDLERS.get(token)
            if not handler:
                continue
            try:
                count = handler(session, project_id, budget)
                total += count
                if args.debug and count:
                    print(f"[DEBUG] {token} @ {project_id}: {count} item(s)")
            except Exception as exc:
                if args.debug:
                    import traceback
                    traceback.print_exc()
                else:
                    print(f"[!] {token} @ {project_id}: {exc}")
        if budget.exceeded():
            break

    print(f"[*] process_download complete: {total} item(s) across {len(project_ids)} project(s).")
    return 1
