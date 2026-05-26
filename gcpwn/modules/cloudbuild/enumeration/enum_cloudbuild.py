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
    parse_csv_arg,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.cloudbuild.utilities.helpers import (
    CloudBuildBuildsResource,
    CloudBuildConnectionsResource,
    CloudBuildTriggersResource,
    resolve_regions,
)


COMPONENTS = [
    ("triggers", "Enumerate Cloud Build triggers"),
    ("builds", "Enumerate recent Cloud Build builds"),
    ("connections", "Enumerate Cloud Build repository connections"),
]

DOWNLOAD_SCOPE_ALIASES = {
    "build": "build",
    "builds": "build",
}
ALL_DOWNLOAD_SCOPES = ["build"]


def _scan_regions(
    *,
    regions: list[str],
    label: str,
    threads: int,
    worker,
) -> list[tuple[str, object]]:
    if not regions:
        print("[*] No Cloud Build regions available. Supply --regions-list/--regions-file, or use --all-regions if supported.")
        return []

    return map_regions_with_disabled_short_circuit(
        regions,
        worker,
        threads=threads,
        progress_label=f"Cloud Build {label}",
    )


def _parse_download_scopes(raw_value: str | None) -> list[str]:
    if raw_value is None:
        return []
    tokens = [str(token).strip().lower() for token in parse_csv_arg(raw_value) if str(token).strip()]
    if not tokens:
        return list(ALL_DOWNLOAD_SCOPES)

    normalized: list[str] = []
    for token in tokens:
        mapped = DOWNLOAD_SCOPE_ALIASES.get(token)
        if mapped is None:
            raise ValueError(
                "Invalid Cloud Build download scope. Supported values: "
                + ", ".join(sorted(set(DOWNLOAD_SCOPE_ALIASES)))
            )
        if mapped not in normalized:
            normalized.append(mapped)
    return normalized


def _limit_items(items: list, limit: int) -> list:
    if limit <= 0:
        return list(items)
    return list(items[:limit])


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--trigger-ids",
            required=False,
            help="Trigger IDs in comma-separated format. Accepts TRIGGER_ID, LOCATION/TRIGGER_ID, or full trigger resource names.",
        )
        parser.add_argument(
            "--trigger-ids-file",
            required=False,
            help="File containing trigger IDs, one per line or comma-separated, using the same formats as --trigger-ids.",
        )
        parser.add_argument(
            "--build-ids",
            required=False,
            help="Build IDs in comma-separated format. Accepts BUILD_ID, LOCATION/BUILD_ID, or full build resource names.",
        )
        parser.add_argument(
            "--build-ids-file",
            required=False,
            help="File containing build IDs, one per line or comma-separated, using the same formats as --build-ids.",
        )
        parser.add_argument("--page-size", type=int, default=50, help="Max builds to fetch per request (best-effort)")
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all available Cloud Build connection locations")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument(
            "--connection-ids",
            required=False,
            help=(
                "Connection IDs in comma-separated format. Accepts LOCATION/CONNECTION_ID "
                "pairs or full names like "
                "`projects/PROJECT_ID/locations/LOCATION/connections/CONNECTION_ID`."
            ),
        )
        parser.add_argument(
            "--connection-ids-file",
            required=False,
            help="File containing connection IDs, one per line or comma-separated, using the same formats as --connection-ids.",
        )
        parser.add_argument(
            "--download",
            nargs="?",
            const="build",
            default=None,
            help="Download Cloud Build build summaries. Optional CSV scopes: build.",
        )
        parser.add_argument(
            "--download-limit",
            type=int,
            default=0,
            help="Limit downloaded builds per region. For explicit --build-ids, this caps the total selected builds. 0 means unlimited.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Build resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Cloud Build connections"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    try:
        download_scopes = _parse_download_scopes(getattr(args, "download", None))
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    if getattr(args, "download_limit", 0) < 0:
        UtilityTools.print_error("--download-limit must be 0 or greater.")
        return -1

    project_id = session.project_id

    if getattr(args, "trigger_ids", None):
        args.triggers = True
    if getattr(args, "build_ids", None):
        args.builds = True
    connection_ids = parse_csv_file_args(getattr(args, "connection_ids", None), getattr(args, "connection_ids_file", None))
    if connection_ids:
        args.connections = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    try:
        connection_names = [
            name_from_input(
                token,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "connections", 1),
                error_message=(
                    "Invalid connection ID format. Use LOCATION/CONNECTION_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/connections/CONNECTION_ID."
                ),
            )
            for token in connection_ids
        ]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    triggers_resource = CloudBuildTriggersResource(session) if selected.get("triggers", False) else None
    builds_resource = CloudBuildBuildsResource(session) if (selected.get("builds", False) or download_scopes) else None
    connections_resource = CloudBuildConnectionsResource(session) if selected.get("connections", False) else None
    regions = resolve_regions(session, args)
    build_rows: list[dict] = []
    build_rows_by_region: dict[str, list[dict]] = defaultdict(list)
    build_ids = parse_csv_file_args(args.build_ids, getattr(args, "build_ids_file", None))

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    if selected.get("triggers", False):
        if triggers_resource is None:
            UtilityTools.print_error("Cloud Build trigger support is unavailable in the installed SDK.")
            return -1
        trigger_ids = parse_csv_file_args(args.trigger_ids, getattr(args, "trigger_ids_file", None))
        manual_triggers_requested = bool(trigger_ids)
        rows = []

        if manual_triggers_requested and args.get:
            rows = [
                triggers_resource.get(
                    project_id=project_id,
                    trigger_id=triggers_resource._resource_id_from_row(trigger_id),
                    action_dict=api_actions,
                )
                for trigger_id in trigger_ids
            ]
            rows = [row for row in rows if isinstance(row, dict) and row]
        elif not manual_triggers_requested:
            listed_by_region = _scan_regions(
                regions=regions,
                label="triggers",
                threads=getattr(args, "threads", 3),
                worker=lambda region: triggers_resource.list(
                    project_id=project_id,
                    location=region,
                    action_dict=scope_actions,
                ),
            )
            for region, listed in listed_by_region:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                triggers_resource.save(listed, project_id=project_id)
                rows.extend(listed)
            if rows and args.get:
                print("[*] --get is only supported with explicit --trigger-ids; listing only (no per-trigger hydration).")

        if rows and manual_triggers_requested:
            triggers_resource.save(rows, project_id=project_id)

        show_trigger_summary = bool(rows) or not manual_triggers_requested
        if show_trigger_summary:
            if rows:
                UtilityTools.summary_wrapup(
                    project_id,
                    "Cloud Build Triggers",
                    rows,
                    triggers_resource.COLUMNS,
                    primary_resource="Triggers",
                    primary_sort_key="name",
                )
            else:
                print(f"[*] GCPwn found 0 Triggers in project {project_id}")
        elif args.get:
            print("[*] No Cloud Build triggers found for the supplied --trigger-ids.")
        else:
            print("[*] Manual --trigger-ids supplied without --get; skipping trigger summary.")

    if selected.get("builds", False) or download_scopes:
        if builds_resource is None:
            UtilityTools.print_error("Cloud Build build support is unavailable in the installed SDK.")
            return -1
        manual_builds_requested = bool(build_ids)
        rows = []
        show_build_summary = selected.get("builds", False)

        if manual_builds_requested and (args.get or download_scopes):
            rows = [
                builds_resource.get(
                    project_id=project_id,
                    build_id=builds_resource._resource_id_from_row(build_id),
                    action_dict=api_actions,
                )
                for build_id in build_ids
            ]
            rows = [row for row in rows if isinstance(row, dict) and row]
        elif not manual_builds_requested:
            listed_by_region = _scan_regions(
                regions=regions,
                label="builds",
                threads=getattr(args, "threads", 3),
                worker=lambda region: builds_resource.list(
                    project_id=project_id,
                    location=region,
                    page_size=args.page_size,
                    action_dict=scope_actions,
                ),
            )
            for region, listed in listed_by_region:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                builds_resource.save(listed, project_id=project_id)
                region_rows = [row for row in listed if isinstance(row, dict)]
                build_rows_by_region[region].extend(region_rows)
                rows.extend(region_rows)
            if rows and args.get and show_build_summary:
                print("[*] --get is only supported with explicit --build-ids; listing only (no per-build hydration).")

        if rows and manual_builds_requested:
            builds_resource.save(rows, project_id=project_id)
            for row in rows:
                region = str(row.get("location") or "").strip() or "global"
                build_rows_by_region[region].append(row)

        build_rows = rows

        summary_available = bool(rows) or not manual_builds_requested
        if show_build_summary and summary_available:
            if rows:
                UtilityTools.summary_wrapup(
                    project_id,
                    "Cloud Build Builds",
                    rows,
                    builds_resource.COLUMNS,
                    primary_resource="Builds",
                    primary_sort_key="create_time",
                )
            else:
                print(f"[*] GCPwn found 0 Builds in project {project_id}")
        elif show_build_summary and args.get:
            print("[*] No Cloud Build builds found for the supplied --build-ids.")
        elif show_build_summary:
            print("[*] Manual --build-ids supplied without --get; skipping build summary.")

    if selected.get("connections", False):
        if connections_resource is None:
            UtilityTools.print_error("Cloud Build connection support is unavailable in the installed SDK.")
            return -1
        manual_connections_requested = bool(connection_names)
        rows = []

        if manual_connections_requested and args.get:
            for name in connection_names:
                row = connections_resource.get(name=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    rows.append(row)
        elif not manual_connections_requested:
            listed_by_region = _scan_regions(
                regions=regions,
                label="connections",
                threads=getattr(args, "threads", 3),
                worker=lambda region: connections_resource.list(
                    project_id=project_id,
                    location=region,
                    action_dict=scope_actions,
                ),
            )
            for region, listed in listed_by_region:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                connections_resource.save(listed, project_id=project_id, location=region)
                rows.extend(listed)
            if rows and args.get:
                print("[*] --get is only supported with explicit --connection-ids; listing only (no per-connection hydration).")

        if rows and manual_connections_requested:
            for row in rows:
                connections_resource.save(
                    [row],
                    project_id=project_id,
                    location=str(row.get("location") or "").strip(),
                )

        if args.iam:
            connection_targets = connection_names if manual_connections_requested else [
                str(row.get("name") or "").strip()
                for row in rows
                if isinstance(row, dict) and row.get("name")
            ]
            for name in connection_targets:
                connections_resource.test_iam_permissions(name=name, action_dict=iam_actions)

        show_connection_summary = bool(rows) or not manual_connections_requested
        if show_connection_summary:
            if rows:
                UtilityTools.summary_wrapup(
                    project_id,
                    "Cloud Build Connections",
                    rows,
                    connections_resource.COLUMNS,
                    primary_resource="Connections",
                    primary_sort_key="location",
                )
            else:
                print(f"[*] GCPwn found 0 Connections in project {project_id}")
        elif args.get:
            print("[*] No Cloud Build connections found for the supplied --connection-ids.")
        else:
            print("[*] Manual --connection-ids supplied without --get; skipping connection summary.")

    if download_scopes:
        downloaded_paths: list[str] = []
        download_count = 0
        if "build" in download_scopes:
            if build_ids:
                build_rows_by_id = {
                    builds_resource._resource_id_from_row(row): row
                    for row in build_rows
                    if isinstance(row, dict) and builds_resource._resource_id_from_row(row)
                }
                for build_id in _limit_items(build_ids, int(getattr(args, "download_limit", 0) or 0)):
                    resource_id = builds_resource._resource_id_from_row(build_id)
                    row = build_rows_by_id.get(resource_id)
                    if row is None:
                        row = builds_resource.get(
                            project_id=project_id,
                            build_id=resource_id,
                            action_dict=api_actions,
                        )
                    if not isinstance(row, dict) or not row:
                        continue
                    env_path = builds_resource.download_build_env_summary(row=row, project_id=project_id)
                    args_path = builds_resource.download_build_step_arguments(row=row, project_id=project_id)
                    if env_path is not None:
                        downloaded_paths.append(str(env_path))
                        download_count += 1
                    if args_path is not None:
                        downloaded_paths.append(str(args_path))
                        download_count += 1
            else:
                for region in regions:
                    candidate_rows = list(build_rows_by_region.get(region, []))
                    if not candidate_rows:
                        continue
                    for listed_row in _limit_items(candidate_rows, int(getattr(args, "download_limit", 0) or 0)):
                        if not isinstance(listed_row, dict) or not listed_row:
                            continue
                        env_path = builds_resource.download_build_env_summary(row=listed_row, project_id=project_id)
                        args_path = builds_resource.download_build_step_arguments(row=listed_row, project_id=project_id)
                        if env_path is not None:
                            downloaded_paths.append(str(env_path))
                            download_count += 1
                        if args_path is not None:
                            downloaded_paths.append(str(args_path))
                            download_count += 1

        for download_path in downloaded_paths:
            print(f"[*] Wrote Cloud Build summary to {download_path}")
        if download_count:
            print(f"[*] Downloaded {download_count} Cloud Build build summary file(s) for project {project_id}.")
        elif build_ids or build_rows_by_region:
            print(f"[*] No Cloud Build build summaries were downloaded for project {project_id}.")
        else:
            print(f"[*] No Cloud Build build targets matched the requested download scopes for project {project_id}.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="cloudbuild_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="cloudbuild_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="cloudbuild_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
