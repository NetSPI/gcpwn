from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import name_from_input
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_component_args,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.cloudrun.utilities.helpers import (
    CloudRunJobsResource,
    CloudRunRevisionsResource,
    CloudRunServicesResource,
    resolve_regions,
)


COMPONENTS = [
    ("services", "Enumerate Cloud Run services"),
    ("jobs", "Enumerate Cloud Run jobs"),
]


def _scan_regions(*, regions: list[str], threads: int, label: str, worker):
    if not regions:
        print("[*] No Cloud Run regions available. Supply --regions-list/--regions-file, or use --all-regions.")
        return []
    return map_regions_with_disabled_short_circuit(
        regions,
        worker,
        threads=threads,
        progress_label=f"Cloud Run {label}",
    )


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Scan all known Cloud Run regions from module data")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument(
            "--service-ids",
            required=False,
            help=(
                "Service IDs in comma-separated format. Accepts LOCATION/SERVICE_ID pairs "
                "or full names like `projects/PROJECT_ID/locations/LOCATION/services/SERVICE_ID`."
            ),
        )
        parser.add_argument(
            "--service-ids-file",
            required=False,
            help="File containing service IDs, one per line or comma-separated, using the same formats as --service-ids.",
        )
        parser.add_argument(
            "--job-ids",
            required=False,
            help=(
                "Job IDs in comma-separated format. Accepts LOCATION/JOB_ID pairs "
                "or full names like `projects/PROJECT_ID/locations/LOCATION/jobs/JOB_ID`."
            ),
        )
        parser.add_argument(
            "--job-ids-file",
            required=False,
            help="File containing job IDs, one per line or comma-separated, using the same formats as --job-ids.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Run resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Cloud Run services and jobs"},
            "download": {
                "help": (
                    "Download Cloud Run service revision ENV YAML (env category only) by listing revisions per service "
                    "and fetching revision metadata (run.revisions.list + run.revisions.get)."
                ),
            },
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id
    service_ids = parse_csv_file_args(getattr(args, "service_ids", None), getattr(args, "service_ids_file", None))
    job_ids = parse_csv_file_args(getattr(args, "job_ids", None), getattr(args, "job_ids_file", None))
    if service_ids:
        args.services = True
    if job_ids:
        args.jobs = True
    if args.download:
        args.services = True
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    services_resource = CloudRunServicesResource(session)
    revisions_resource = CloudRunRevisionsResource(session)
    jobs_resource = CloudRunJobsResource(session)
    regions = resolve_regions(session, args)
    all_services: list[dict] = []

    try:
        service_names = [
            name_from_input(
                token,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "services", 1),
                error_message=(
                    "Invalid service ID format. Use LOCATION/SERVICE_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/services/SERVICE_ID."
                ),
            )
            for token in service_ids
        ]
        job_names = [
            name_from_input(
                token,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "jobs", 1),
                error_message=(
                    "Invalid job ID format. Use LOCATION/JOB_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/jobs/JOB_ID."
                ),
            )
            for token in job_ids
        ]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    if selected.get("services", False):
        manual_services_requested = bool(service_names)

        if manual_services_requested and args.get:
            all_services = [
                row
                for row in (services_resource.get(resource_id=name, action_dict=api_actions) for name in service_names)
                if row
            ]
        elif not manual_services_requested:
            listed_by_region = _scan_regions(
                regions=regions,
                threads=getattr(args, "threads", 3),
                label="services",
                worker=lambda region: services_resource.list(
                    project_id=project_id,
                    location=region,
                    action_dict=scope_actions,
                ),
            )
            for region, listed in listed_by_region:
                if listed in ("Not Enabled", None):
                    continue
                if listed:
                    if args.get:
                        listed = [
                            services_resource.get(resource_id=row.get("name", ""), action_dict=api_actions) or row
                            for row in listed
                        ]
                    services_resource.save(listed, project_id=project_id, location=region)
                    all_services.extend(listed)

        if all_services and manual_services_requested:
            for row in all_services:
                services_resource.save(
                    [row],
                    project_id=project_id,
                    location=str(row.get("location") or "").strip(),
                )

        if args.iam:
            service_targets = service_names if manual_services_requested else [
                str(row.get("name") or "").strip()
                for row in all_services
                if isinstance(row, dict) and row.get("name")
            ]
            for name in service_targets:
                services_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

        show_service_summary = bool(all_services) or not manual_services_requested
        if show_service_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud Run Services",
                all_services,
                services_resource.COLUMNS,
                primary_resource="Services",
                primary_sort_key="location",
                )
        elif args.get:
            print("[*] No Cloud Run services found for the supplied --service-ids.")
        else:
            print("[*] Manual --service-ids supplied without --get; skipping service summary.")

    if args.download:
        revision_service_targets = (
            service_names
            if service_names
            else [
                str(row.get("name") or "").strip()
                for row in all_services
                if isinstance(row, dict) and row.get("name")
            ]
        )
        downloaded_revision_paths = []
        listed_by_service = parallel_map(
            revision_service_targets,
            lambda service_name: (
                service_name,
                revisions_resource.list(service_name=service_name, action_dict=api_actions),
            ),
            threads=getattr(args, "threads", 3),
            progress_label="Cloud Run Revisions",
        ) if revision_service_targets else []

        for service_name, revisions in listed_by_service:
            if revisions in ("Not Enabled", None) or not revisions:
                continue
            for revision in revisions:
                if not isinstance(revision, dict):
                    continue
                revision_name = str(revision.get("name") or "").strip()
                if not revision_name:
                    continue
                revision_full = revisions_resource.get(resource_id=revision_name, action_dict=api_actions) or revision
                path = revisions_resource.download_env_yaml(revision_row=revision_full, project_id=project_id)
                if path is not None:
                    downloaded_revision_paths.append(path)

        if downloaded_revision_paths:
            for path in downloaded_revision_paths:
                print(f"[*] Wrote Cloud Run revision ENV YAML to {path}")
            print(f"[*] Downloaded {len(downloaded_revision_paths)} Cloud Run revision ENV YAML file(s) for project {project_id}.")
        elif revision_service_targets:
            print(f"[*] No Cloud Run revisions with ENV data were available to download for project {project_id}.")
        else:
            print(
                "[*] No Cloud Run services were available for revision download. "
                "Use --service-ids or run service enumeration first."
            )

    if selected.get("jobs", False):
        manual_jobs_requested = bool(job_names)
        all_jobs = []

        if manual_jobs_requested and args.get:
            all_jobs = [
                row
                for row in (jobs_resource.get(resource_id=name, action_dict=api_actions) for name in job_names)
                if row
            ]
        elif not manual_jobs_requested:
            listed_by_region = _scan_regions(
                regions=regions,
                threads=getattr(args, "threads", 3),
                label="jobs",
                worker=lambda region: jobs_resource.list(
                    project_id=project_id,
                    location=region,
                    action_dict=scope_actions,
                ),
            )
            for region, listed in listed_by_region:
                if listed in ("Not Enabled", None):
                    continue
                if listed:
                    if args.get:
                        listed = [
                            jobs_resource.get(resource_id=row.get("name", ""), action_dict=api_actions) or row
                            for row in listed
                        ]
                    jobs_resource.save(listed, project_id=project_id, location=region)
                    all_jobs.extend(listed)

        if all_jobs and manual_jobs_requested:
            for row in all_jobs:
                jobs_resource.save(
                    [row],
                    project_id=project_id,
                    location=str(row.get("location") or "").strip(),
                )

        if args.iam:
            job_targets = job_names if manual_jobs_requested else [
                str(row.get("name") or "").strip()
                for row in all_jobs
                if isinstance(row, dict) and row.get("name")
            ]
            for name in job_targets:
                jobs_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

        show_job_summary = bool(all_jobs) or not manual_jobs_requested
        if show_job_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud Run Jobs",
                all_jobs,
                jobs_resource.COLUMNS,
                primary_resource="Jobs",
                primary_sort_key="location",
                )
        elif args.get:
            print("[*] No Cloud Run jobs found for the supplied --job-ids.")
        else:
            print("[*] Manual --job-ids supplied without --get; skipping job summary.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="cloudrun_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="cloudrun_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="cloudrun_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
