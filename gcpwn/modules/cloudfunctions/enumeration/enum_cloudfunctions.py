from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import name_from_input
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.cloudfunctions.utilities.helpers import (
    CloudFunctionsResource,
    check_function_format,
)


COMPONENTS = [
    ("functions", "Enumerate Cloud Functions resources"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--function-names",
            type=str,
            help=(
                "Function names in comma-separated format using full resource names like "
                "`projects/PROJECT_ID/locations/REGION/functions/FUNCTION_ID`. "
                "`LOCATION/FUNCTION_ID` is also supported."
            ),
        )
        parser.add_argument(
            "--function-names-file",
            type=str,
            help="File containing function names, one per line or comma-separated, using the same formats as --function-names.",
        )
        parser.add_argument(
            "--version",
            required=False,
            choices=["1", "2"],
            help="Function generation when manually targeting LOCATION/FUNCTION_ID entries",
        )

        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument(
            "--v1-regions",
            action="store_true",
            required=False,
            help="Target known Cloud Functions v1 region list",
        )
        regions_group.add_argument(
            "--v2-regions",
            action="store_true",
            required=False,
            help="Target known Cloud Functions v2 region list",
        )
        regions_group.add_argument(
            "--v1v2-regions",
            action="store_true",
            required=False,
            help="Target combined known Cloud Functions v1+v2 region list",
        )
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one line per entry")

        parser.add_argument(
            "--external-curl",
            required=False,
            action="store_true",
            help="Attempt to curl function URLs anonymously",
        )
        parser.add_argument(
            "--output",
            required=False,
            help="Output directory for downloaded function source bundles",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Functions resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on functions"},
            "download": {"help": "Attempt to download function source bundles"},
        },
    )


def _normalize_input_function_name(function_name: str, project_id: str) -> str:
    text = str(function_name or "").strip()
    if not text:
        return ""

    if text.startswith("projects/"):
        if not check_function_format(text):
            raise ValueError(
                "Invalid function resource format. Expected projects/PROJECT_ID/locations/REGION/functions/FUNCTION_ID"
            )
        return text

    return name_from_input(
        text,
        project_id=project_id,
        template=("projects", "{project_id}", "locations", 0, "functions", 1),
        error_message=(
            "Invalid function ID format. Use LOCATION/FUNCTION_ID for manual entries or "
            "projects/PROJECT_ID/locations/REGION/functions/FUNCTION_ID."
        ),
    )


def _row_name(row) -> str:
    if isinstance(row, dict):
        return str(row.get("name") or "").strip()
    return str(row or "").strip()


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not selected.get("functions", False):
        return 1

    function_inputs = parse_csv_file_args(
        getattr(args, "function_names", None),
        getattr(args, "function_names_file", None),
    )
    if function_inputs:
        args.functions = True

    try:
        function_names = [_normalize_input_function_name(value, project_id) for value in function_inputs]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    resource = CloudFunctionsResource(session)
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    detailed_needed = bool(args.get or args.download)
    rows: list[dict] = []

    if function_names:
        if detailed_needed:
            rows = [
                row
                for row in (
                    resource.get(resource_id=name, action_dict=api_actions)
                    for name in function_names
                )
                if isinstance(row, dict) and row
            ]
        else:
            rows = [{"name": name} for name in function_names]
    else:
        regions = resource.resolve_regions(
            v1_regions=getattr(args, "v1_regions", False),
            v2_regions=getattr(args, "v2_regions", False),
            v1v2_regions=getattr(args, "v1v2_regions", False),
            regions_list=getattr(args, "regions_list", None),
            regions_file=getattr(args, "regions_file", None),
        )
        if not regions:
            regions = ["-"]
            print("[*] No explicit Cloud Functions regions provided; attempting wildcard listing (locations/-).")

        listed_by_region = map_regions_with_disabled_short_circuit(
            regions,
            lambda region: resource.list(
                project_id=project_id,
                parent=f"projects/{project_id}/locations/{region}",
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for _region, listed in listed_by_region:
            if listed in ("Not Enabled", None) or not listed:
                continue
            listed_rows = listed
            if detailed_needed:
                listed_rows = [
                    resource.get(resource_id=_row_name(row), action_dict=api_actions) or row
                    for row in listed
                    if _row_name(row)
                ]
            rows.extend(
                resource.normalize_summary_row(row)
                for row in listed_rows
                if isinstance(row, dict) and row
            )

    normalized_rows: list[dict] = []
    seen_names: set[str] = set()
    for row in rows:
        payload = resource.normalize_summary_row(row)
        function_name = _row_name(payload)
        if not function_name or function_name in seen_names:
            continue
        seen_names.add(function_name)
        normalized_rows.append(payload)

    if normalized_rows:
        resource.save(normalized_rows)

    if args.iam:
        iam_targets = function_names if function_names else [_row_name(row) for row in normalized_rows]
        for name in iam_targets:
            if not name:
                continue
            resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)

    if args.external_curl:
        for row in normalized_rows:
            function_url = str(row.get("url") or "").strip()
            function_name = _row_name(row)
            if not function_url or not function_name:
                continue
            if not resource.check_external_curl(function_url=function_url):
                continue
            session.insert_data(
                resource.TABLE_NAME,
                {
                    "primary_keys_to_match": {
                        "project_id": row.get("project_id") or project_id,
                        "name": function_name,
                    },
                    "data_to_insert": {"external_curl": "True"},
                    "update_only": True,
                },
            )

    UtilityTools.summary_wrapup(
        project_id,
        "Cloud Functions",
        normalized_rows,
        CloudFunctionsResource.COLUMNS,
        primary_resource="Functions",
        primary_sort_key="region_val",
    )

    if args.download:
        downloaded_paths = []
        for row in normalized_rows:
            downloaded_paths.extend(
                resource.download(
                    row=row,
                    output=getattr(args, "output", None),
                )
            )
        for path in downloaded_paths:
            print(f"[*] Downloaded Cloud Function source to {path}")
        if not downloaded_paths and normalized_rows:
            print(f"[*] No Cloud Function source archives were downloaded for project {project_id}.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="function_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="function_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="function_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
