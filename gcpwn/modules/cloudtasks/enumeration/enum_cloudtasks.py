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
from gcpwn.modules.cloudtasks.utilities.helpers import (
    CloudTasksQueuesResource,
    CloudTasksTasksResource,
    resolve_locations,
)


COMPONENTS = [
    ("queues", "Enumerate Cloud Tasks queues"),
    ("tasks", "Enumerate Cloud Tasks tasks"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Cloud Tasks locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")
        parser.add_argument(
            "--queue-ids",
            required=False,
            help=(
                "Queue IDs in comma-separated format. Accepts LOCATION/QUEUE_ID pairs "
                "or full names like `projects/PROJECT_ID/locations/LOCATION/queues/QUEUE_ID`."
            ),
        )
        parser.add_argument(
            "--queue-ids-file",
            required=False,
            help="File containing queue IDs, one per line or comma-separated, using the same formats as --queue-ids.",
        )
        parser.add_argument("--output", required=False, help="Output directory for downloaded HTTP task request samples")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Tasks resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Cloud Tasks queues"},
        },
    )


def _resolve_queue_names(project_id: str, queue_ids: list[str]) -> list[str]:
    return [
        name_from_input(
            token,
            project_id=project_id,
            template=("projects", "{project_id}", "locations", 0, "queues", 1),
            error_message=(
                "Invalid queue ID format. Use LOCATION/QUEUE_ID or "
                "projects/PROJECT_ID/locations/LOCATION/queues/QUEUE_ID."
            ),
        )
        for token in queue_ids
    ]


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id

    queue_ids = parse_csv_file_args(getattr(args, "queue_ids", None), getattr(args, "queue_ids_file", None))
    if queue_ids:
        args.queues = True
    if args.download:
        args.tasks = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not selected.get("queues", False) and not selected.get("tasks", False):
        return 1

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    queues_resource = CloudTasksQueuesResource(session)
    tasks_resource = CloudTasksTasksResource(session)
    locations = resolve_locations(session, args)

    try:
        manual_queue_names = _resolve_queue_names(project_id, queue_ids)
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    manual_queues_requested = bool(manual_queue_names)
    queue_rows: list[dict] = []
    discovered_queue_names: list[str] = list(manual_queue_names)

    need_queue_discovery = selected.get("queues", False) or (selected.get("tasks", False) and not manual_queues_requested)

    if selected.get("queues", False):
        if manual_queues_requested and args.get:
            queue_rows = [
                row
                for row in (queues_resource.get(resource_id=name, action_dict=api_actions) for name in manual_queue_names)
                if isinstance(row, dict) and row
            ]
            if queue_rows:
                for row in queue_rows:
                    queues_resource.save([row], project_id=project_id, location=str(row.get("location") or "").strip())
        elif not manual_queues_requested:
            listed_by_location = map_regions_with_disabled_short_circuit(
                locations,
                lambda location: queues_resource.list(
                    project_id=project_id,
                    location=location,
                    action_dict=scope_actions,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Cloud Tasks Queues",
            )
            for location, listed in listed_by_location:
                if listed in ("Not Enabled", None):
                    continue
                rows = list(listed or [])
                if rows and args.get:
                    rows = [
                        queues_resource.get(resource_id=str(row.get("name") or "").strip(), action_dict=api_actions) or row
                        for row in rows
                    ]
                if rows:
                    queues_resource.save(rows, project_id=project_id, location=location)
                    queue_rows.extend(rows)
        if queue_rows:
            discovered_queue_names.extend(
                [
                    str(row.get("name") or "").strip()
                    for row in queue_rows
                    if isinstance(row, dict) and row.get("name")
                ]
            )

    if selected.get("tasks", False) and not discovered_queue_names and need_queue_discovery:
        listed_by_location = map_regions_with_disabled_short_circuit(
            locations,
            lambda location: queues_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
            progress_label="Cloud Tasks Queue Discovery",
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            rows = list(listed or [])
            if rows:
                queues_resource.save(rows, project_id=project_id, location=location)
                if selected.get("queues", False):
                    queue_rows.extend(rows)
                discovered_queue_names.extend(
                    [
                        str(row.get("name") or "").strip()
                        for row in rows
                        if isinstance(row, dict) and row.get("name")
                    ]
                )

    discovered_queue_names = sorted({name for name in discovered_queue_names if name})

    if args.iam:
        queue_targets = discovered_queue_names if discovered_queue_names else manual_queue_names
        for name in queue_targets:
            queues_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

    if selected.get("queues", False):
        show_queue_summary = bool(queue_rows) or not manual_queues_requested
        if show_queue_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud Tasks Queues",
                queue_rows,
                queues_resource.COLUMNS,
                primary_resource="Queues",
                primary_sort_key="location",
            )
        elif args.get:
            print("[*] No Cloud Tasks queues found for the supplied --queue-ids.")
        else:
            print("[*] Manual --queue-ids supplied without --get; skipping queue summary.")

    task_rows: list[dict] = []
    if selected.get("tasks", False):
        listed_by_queue = parallel_map(
            discovered_queue_names,
            lambda queue_name: (
                queue_name,
                tasks_resource.list(
                    queue_name=queue_name,
                    full_view=bool(args.get or args.download),
                    action_dict=scope_actions,
                ),
            ),
            threads=getattr(args, "threads", 3),
            progress_label="Cloud Tasks Tasks",
        )
        for queue_name, listed in listed_by_queue:
            rows = []
            if listed in ("Not Enabled", None):
                if args.get or args.download:
                    fallback_list = tasks_resource.list(queue_name=queue_name, full_view=False, action_dict=scope_actions)
                    rows = list(fallback_list or []) if fallback_list not in ("Not Enabled", None) else []
                else:
                    continue
            else:
                rows = list(listed or [])
            if rows and (args.get or args.download):
                rows = [
                    tasks_resource.get(
                        resource_id=str(row.get("name") or "").strip(),
                        full_view=True,
                        action_dict=api_actions,
                    ) or row
                    for row in rows
                ]
            if rows:
                tasks_resource.save(rows, project_id=project_id)
                task_rows.extend(rows)

        UtilityTools.summary_wrapup(
            project_id,
            "Cloud Tasks Tasks",
            task_rows,
            tasks_resource.COLUMNS,
            primary_resource="Tasks",
            primary_sort_key="location",
        )
        if not task_rows:
            print("[*] No Cloud Tasks tasks found in project {}.".format(project_id))

    if args.download:
        downloaded_paths = tasks_resource.download_http_request_samples(
            task_rows=task_rows,
            project_id=project_id,
            output=getattr(args, "output", None),
        )
        if downloaded_paths:
            for path in downloaded_paths:
                print(f"[*] Wrote Cloud Tasks HTTP request sample to {path}")
            print(f"[*] Downloaded {len(downloaded_paths)} Cloud Tasks HTTP request sample file(s) for project {project_id}.")
        elif task_rows:
            print(f"[*] No HTTP tasks were present on the retrieved Cloud Tasks tasks for project {project_id}.")
        else:
            print(f"[*] No Cloud Tasks tasks were available to download HTTP task request samples from in project {project_id}.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="cloudtasks_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="cloudtasks_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="cloudtasks_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )
    return 1
