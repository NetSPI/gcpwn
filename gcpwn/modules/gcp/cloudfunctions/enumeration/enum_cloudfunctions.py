from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.cloudfunctions.utilities.helpers import CloudFunctionsResource


COMPONENTS = [
    Component("functions", CloudFunctionsResource, "Cloud Functions", "Functions",
              help_text="Enumerate Cloud Functions resources", scope=REGION,
              columns=["name", "region_val", "env", "state_output", "url"], primary_sort_key="region_val",
              manual_id_arg="function_names",
              manual_template=("projects", "{project_id}", "locations", 0, "functions", 1),
              manual_error="Invalid function ID format. Use LOCATION/FUNCTION_ID or projects/PROJECT_ID/locations/REGION/functions/FUNCTION_ID.",
              manual_help="Function names as LOCATION/FUNCTION_ID or full resource names."),
]


def _resolve_regions(session, args):
    resource = CloudFunctionsResource(session)
    regions = resource.resolve_regions(
        v1_regions=getattr(args, "v1_regions", False),
        v2_regions=getattr(args, "v2_regions", False),
        v1v2_regions=getattr(args, "v1v2_regions", False),
        regions_list=getattr(args, "regions_list", None),
        regions_file=getattr(args, "regions_file", None),
    )
    if not regions:
        print("[*] No explicit Cloud Functions regions provided; attempting wildcard listing (locations/-).")
        return ["-"]
    return regions


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--version", required=False, choices=["1", "2"],
                            help="Function generation when manually targeting LOCATION/FUNCTION_ID entries")
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--v1-regions", action="store_true", required=False, help="Target known Cloud Functions v1 region list")
        regions_group.add_argument("--v2-regions", action="store_true", required=False, help="Target known Cloud Functions v2 region list")
        regions_group.add_argument("--v1v2-regions", action="store_true", required=False, help="Target combined known Cloud Functions v1+v2 region list")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one line per entry")
        parser.add_argument("--external-curl", required=False, action="store_true", help="Attempt to curl function URLs anonymously")
        parser.add_argument("--output", required=False, help="Output directory for downloaded function source bundles")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Functions resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on functions"},
            "download": {"help": "Attempt to download function source bundles"},
        },
    )


def _external_curl(session, rows):
    project_id = session.project_id
    resource = CloudFunctionsResource(session)
    for row in rows:
        function_url = str(row.get("url") or "").strip()
        function_name = str(row.get("name") or "").strip()
        if not function_url or not function_name:
            continue
        if not resource.check_external_curl(function_url=function_url):
            continue
        session.insert_data(resource.TABLE_NAME, {
            "primary_keys_to_match": {"project_id": row.get("project_id") or project_id, "name": function_name},
            "data_to_insert": {"external_curl": "True"},
            "update_only": True,
        })


def _download_sources(session, args, rows):
    project_id = session.project_id
    resource = CloudFunctionsResource(session)
    downloaded_paths = []
    budget = DownloadBudget(session, label="function sources")
    for row in rows:
        if budget.exceeded():
            break
        downloaded_paths.extend(resource.download(row=row, output=getattr(args, "output", None)))
    for path in downloaded_paths:
        print(f"[*] Downloaded Cloud Function source to {path}")
    if not downloaded_paths and rows:
        print(f"[*] No Cloud Function source archives were downloaded for project {project_id}.")


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.get = True  # source download needs the hydrated per-function payload

    discovered = run_components(session, args, components=COMPONENTS, column_name="function_actions_allowed",
                                region_resolver=_resolve_regions, module_name="enum_cloudfunctions")
    functions = discovered.get("functions", [])

    if getattr(args, "external_curl", False):
        _external_curl(session, functions)
    if getattr(args, "download", False):
        _download_sources(session, args, functions)
    return 1
