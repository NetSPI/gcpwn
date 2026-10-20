from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parallel_map, parse_component_args
from gcpwn.modules.gcp.cloudrun.utilities.helpers import (
    CloudRunJobExecutionsResource,
    CloudRunJobsResource,
    CloudRunRevisionsResource,
    CloudRunServicesResource,
    CloudRunWorkerPoolRevisionsResource,
    CloudRunWorkerPoolsResource,
    resolve_regions,
)


COMPONENTS = [
    Component("services", CloudRunServicesResource, "Cloud Run Services", "Services",
              help_text="Enumerate Cloud Run services", scope=REGION,
              manual_id_arg="service_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "services", 1),
              manual_error="Invalid service ID format. Use LOCATION/SERVICE_ID or projects/PROJECT_ID/locations/LOCATION/services/SERVICE_ID.",
              manual_help="Service IDs as LOCATION/SERVICE_ID or full resource names."),
    Component("jobs", CloudRunJobsResource, "Cloud Run Jobs", "Jobs",
              help_text="Enumerate Cloud Run jobs", scope=REGION,
              manual_id_arg="job_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "jobs", 1),
              manual_error="Invalid job ID format. Use LOCATION/JOB_ID or projects/PROJECT_ID/locations/LOCATION/jobs/JOB_ID.",
              manual_help="Job IDs as LOCATION/JOB_ID or full resource names."),
    Component("worker_pools", CloudRunWorkerPoolsResource, "Cloud Run Worker Pools", "Worker Pools",
              help_text="Enumerate Cloud Run Worker Pools (surfaces serviceAccount per pool)", scope=REGION,
              supports_iam=False,
              manual_id_arg="worker_pool_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "workerPools", 1),
              manual_error="Invalid worker pool ID format. Use LOCATION/POOL_ID or full resource name.",
              manual_help="Worker pool IDs as LOCATION/POOL_ID or full resource names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Scan all known Cloud Run regions from module data")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Run resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "iam", "get"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Cloud Run services and jobs"},
            "download": {"help": "Download Cloud Run service revision ENV YAML (run.revisions.list + run.revisions.get) and worker pool revision ENV YAML (run.workerPoolRevisions.list + run.workerPoolRevisions.get)."},
        },
    )


def _enum_job_executions(session, args, job_rows: list) -> None:
    """List recent executions for each enumerated Cloud Run Job.

    Stores results in cloudrun_job_executions; running_count > 0 means the job
    has at least one actively running task instance — used by the graph to gate
    SSH_CLOUDRUN_JOB_AS_SA edges on has_active_execution.
    """
    if not job_rows:
        return
    exec_resource = CloudRunJobExecutionsResource(session)
    all_rows: list[dict] = []

    def _fetch(job_row):
        job_name = str(job_row.get("name") or "").strip()
        if not job_name:
            return []
        return exec_resource.list_for_job(job_name=job_name)

    results = parallel_map(
        job_rows,
        _fetch,
        threads=getattr(args, "threads", 3),
        progress_label="Cloud Run Job Executions",
    )
    for item in results or []:
        if item:
            all_rows.extend(item)

    if all_rows:
        session.insert_data(
            CloudRunJobExecutionsResource.TABLE_NAME,
            all_rows,
            CloudRunJobExecutionsResource.COLUMNS + ["raw_json"],
        )
        print(f"[*] Stored {len(all_rows)} Cloud Run job execution(s).")


def _download_revision_env(session, args, service_rows):
    project_id = session.project_id
    revisions_resource = CloudRunRevisionsResource(session)
    service_names = [str(row.get("name") or "").strip() for row in service_rows if isinstance(row, dict) and row.get("name")]
    paths = []
    def _safe_revisions(service_name):
        try:
            return (service_name, revisions_resource.list(parent=service_name))
        except Exception:
            return (service_name, None)

    listed_by_service = parallel_map(
        service_names,
        _safe_revisions,
        threads=getattr(args, "threads", 3),
        progress_label="Cloud Run Revisions",
    ) if service_names else []
    for item in listed_by_service:
        if item is None:
            continue
        _service_name, revisions = item
        if revisions in ("Not Enabled", None) or not revisions:
            continue
        for revision in revisions:
            if not isinstance(revision, dict):
                continue
            revision_name = str(revision.get("name") or "").strip()
            if not revision_name:
                continue
            revision_full = revisions_resource.get(resource_id=revision_name) or revision
            path = revisions_resource.download_env_yaml(revision_row=revision_full, project_id=project_id)
            if path is not None:
                paths.append(path)

    if paths:
        for path in paths:
            print(f"[*] Wrote Cloud Run revision ENV YAML to {path}")
        print(f"[*] Downloaded {len(paths)} Cloud Run revision ENV YAML file(s) for project {project_id}.")
    elif service_names:
        print(f"[*] No Cloud Run revisions with ENV data were available to download for project {project_id}.")
    else:
        print("[*] No Cloud Run services were available for revision download. Use --service-ids or run service enumeration first.")


def _download_worker_pool_revision_env(session, args, worker_pool_rows):
    project_id = session.project_id
    revisions_resource = CloudRunWorkerPoolRevisionsResource(session)
    pool_names = [
        str(row.get("name") or "").strip()
        for row in worker_pool_rows
        if isinstance(row, dict) and row.get("name")
    ]
    paths = []

    def _safe_revisions(pool_name):
        try:
            return (pool_name, revisions_resource.list_for_worker_pool(pool_name=pool_name))
        except Exception:
            return (pool_name, None)

    listed = parallel_map(
        pool_names,
        _safe_revisions,
        threads=getattr(args, "threads", 3),
        progress_label="Cloud Run Worker Pool Revisions",
    ) if pool_names else []

    for item in listed:
        if item is None:
            continue
        _pool_name, revisions = item
        if not revisions:
            continue
        for revision in revisions:
            if not isinstance(revision, dict):
                continue
            revision_name = str(revision.get("name") or "").strip()
            if not revision_name:
                continue
            revision_full = revisions_resource.get_revision(revision_name=revision_name) or revision
            path = revisions_resource.download_env_yaml(revision_row=revision_full, project_id=project_id)
            if path is not None:
                paths.append(path)

    if paths:
        for path in paths:
            print(f"[*] Wrote Cloud Run worker pool revision ENV YAML to {path}")
        print(f"[*] Downloaded {len(paths)} Cloud Run worker pool revision ENV YAML file(s) for project {project_id}.")
    elif pool_names:
        print(f"[*] No Cloud Run worker pool revisions with ENV data were available to download for project {project_id}.")


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.services = True  # revision ENV download is driven off enumerated services

    discovered = run_components(session, args, components=COMPONENTS, column_name="cloudrun_actions_allowed",
                                region_resolver=resolve_regions, module_name="enum_cloudrun")

    if getattr(args, "download", False):
        _download_revision_env(session, args, discovered.get("services", []))
        worker_pool_rows = discovered.get("worker_pools", [])
        if worker_pool_rows:
            _download_worker_pool_revision_env(session, args, worker_pool_rows)

    job_rows = discovered.get("jobs", [])
    if job_rows:
        _enum_job_executions(session, args, job_rows)

    return 1
