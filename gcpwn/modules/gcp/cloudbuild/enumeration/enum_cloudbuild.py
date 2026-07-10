from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.cloudbuild.utilities.helpers import (
    CloudBuildBuildsResource,
    CloudBuildConnectionsResource,
    CloudBuildTriggersResource,
    resolve_regions,
)


COMPONENTS = [
    Component("triggers", CloudBuildTriggersResource, "Cloud Build Triggers", "Triggers",
              help_text="Enumerate Cloud Build triggers", scope=REGION, primary_sort_key="name", supports_iam=False,
              manual_id_arg="trigger_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "triggers", 1),
              manual_help="Trigger IDs as LOCATION/TRIGGER_ID or full resource names."),
    Component("builds", CloudBuildBuildsResource, "Cloud Build Builds", "Builds",
              help_text="Enumerate recent Cloud Build builds", scope=REGION, primary_sort_key="create_time",
              supports_iam=False, manual_id_arg="build_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "builds", 1),
              manual_help="Build IDs as LOCATION/BUILD_ID or full resource names.",
              list_kwargs=lambda args: {"page_size": int(getattr(args, "page_size", 50) or 50)}),
    Component("connections", CloudBuildConnectionsResource, "Cloud Build Connections", "Connections",
              help_text="Enumerate Cloud Build repository connections", scope=REGION, primary_sort_key="location",
              manual_id_arg="connection_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "connections", 1),
              manual_error="Invalid connection ID format. Use LOCATION/CONNECTION_ID or projects/PROJECT_ID/locations/LOCATION/connections/CONNECTION_ID."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--page-size", type=int, default=50, help="Max builds to fetch per request (best-effort)")
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all available Cloud Build locations")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument("--download", nargs="?", const="build", default=None, help="Download Cloud Build build summaries.")
        parser.add_argument("--download-limit", type=int, default=0, help="Limit downloaded builds (0 = unlimited).")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Build resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on Cloud Build connections"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    download_requested = getattr(args, "download", None) is not None
    if download_requested:
        args.builds = True
        args.get = True

    discovered = run_components(session, args, components=COMPONENTS, column_name="cloudbuild_actions_allowed",
                                region_resolver=resolve_regions, module_name="enum_cloudbuild")

    if download_requested:
        project_id = session.project_id
        builds_resource = CloudBuildBuildsResource(session)
        limit = int(getattr(args, "download_limit", 0) or 0)
        rows = discovered.get("builds", [])
        if limit > 0:
            rows = rows[:limit]
        downloaded = []
        for row in rows:
            for path in (builds_resource.download_build_env_summary(row=row, project_id=project_id),
                         builds_resource.download_build_step_arguments(row=row, project_id=project_id)):
                if path is not None:
                    downloaded.append(str(path))
        for path in downloaded:
            print(f"[*] Wrote Cloud Build summary to {path}")
        if downloaded:
            print(f"[*] Downloaded {len(downloaded)} Cloud Build build summary file(s) for project {project_id}.")
        elif discovered.get("builds"):
            print(f"[*] No Cloud Build build summaries were downloaded for project {project_id}.")
    return 1
