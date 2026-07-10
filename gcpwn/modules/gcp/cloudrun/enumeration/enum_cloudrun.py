from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parallel_map, parse_component_args
from gcpwn.modules.gcp.cloudrun.utilities.helpers import (
    CloudRunJobsResource,
    CloudRunRevisionsResource,
    CloudRunServicesResource,
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
        standard_args=("download", "iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Cloud Run services and jobs"},
            "download": {"help": "Download Cloud Run service revision ENV YAML (run.revisions.list + run.revisions.get)."},
        },
    )


def _download_revision_env(session, args, service_rows):
    project_id = session.project_id
    revisions_resource = CloudRunRevisionsResource(session)
    service_names = [str(row.get("name") or "").strip() for row in service_rows if isinstance(row, dict) and row.get("name")]
    paths = []
    listed_by_service = parallel_map(
        service_names,
        lambda service_name: (service_name, revisions_resource.list(parent=service_name)),
        threads=getattr(args, "threads", 3),
        progress_label="Cloud Run Revisions",
    ) if service_names else []
    for _service_name, revisions in listed_by_service:
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


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.services = True  # revision ENV download is driven off enumerated services

    discovered = run_components(session, args, components=COMPONENTS, column_name="cloudrun_actions_allowed",
                                region_resolver=resolve_regions, module_name="enum_cloudrun")

    if getattr(args, "download", False):
        _download_revision_env(session, args, discovered.get("services", []))
    return 1
