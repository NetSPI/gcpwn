from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.cloudtasks.utilities.helpers import (
    CloudTasksQueuesResource,
    CloudTasksTasksResource,
    resolve_locations,
)


def _tasks_full_view(args):
    # FULL view fetches the HTTP request body needed for --get and --download.
    return {"full_view": bool(getattr(args, "get", False) or getattr(args, "download", None))}


COMPONENTS = [
    Component("queues", CloudTasksQueuesResource, "Cloud Tasks Queues", "Queues",
              help_text="Enumerate Cloud Tasks queues", scope=REGION,
              manual_id_arg="queue_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "queues", 1),
              manual_error="Invalid queue ID format. Use LOCATION/QUEUE_ID or projects/PROJECT_ID/locations/LOCATION/queues/QUEUE_ID.",
              manual_help="Queue IDs as LOCATION/QUEUE_ID or full projects/.../queues/... names."),
    Component("tasks", CloudTasksTasksResource, "Cloud Tasks Tasks", "Tasks",
              help_text="Enumerate Cloud Tasks tasks (per queue)", scope=NESTED,
              parent_key="queues", dependency_label="Queues", supports_iam=False,
              list_kwargs=_tasks_full_view),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Cloud Tasks locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")
        parser.add_argument("--output", required=False, help="Output directory for downloaded HTTP task request samples")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Tasks resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on Cloud Tasks queues"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.tasks = True  # downloading HTTP samples requires enumerating tasks

    project_id = session.project_id
    discovered = run_components(
        session, args, components=COMPONENTS, column_name="cloudtasks_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_cloudtasks",
    )

    if getattr(args, "download", False):
        tasks_resource = CloudTasksTasksResource(session)
        downloaded_paths = tasks_resource.download_http_request_samples(
            task_rows=discovered.get("tasks", []), project_id=project_id, output=getattr(args, "output", None),
        )
        if downloaded_paths:
            for path in downloaded_paths:
                print(f"[*] Wrote Cloud Tasks HTTP request sample to {path}")
            print(f"[*] Downloaded {len(downloaded_paths)} Cloud Tasks HTTP request sample file(s) for project {project_id}.")
        elif discovered.get("tasks"):
            print(f"[*] No HTTP tasks were present on the retrieved Cloud Tasks tasks for project {project_id}.")
        else:
            print(f"[*] No Cloud Tasks tasks were available to download HTTP task request samples from in project {project_id}.")
    return 1
