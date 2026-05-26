from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    resolve_selected_components,
)
from gcpwn.modules.cloudcomposer.utilities.helpers import ComposerEnvironmentsResource, resolve_regions


COMPONENTS = [
    ("environments", "Enumerate Cloud Composer environments"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try wildcard location (-) when supported")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Composer resources (read-only)",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not selected.get("environments", False):
        return 1

    project_id = session.project_id
    resource = ComposerEnvironmentsResource(session)
    regions = resolve_regions(session, args)
    rows = []
    downloaded_paths: list[str] = []
    listed_by_location = map_regions_with_disabled_short_circuit(
        regions,
        lambda location: resource.list(project_id=project_id, location=location),
        threads=getattr(args, "threads", 3),
        progress_label="Cloud Composer environments",
    )
    for location, listed in listed_by_location:
        if listed in ("Not Enabled", None):
            continue
        if listed:
            if args.get:
                listed = [resource.get(resource_id=row.get("name", "")) or row for row in listed]
            resource.save(listed, project_id=project_id, location=location)
            rows.extend(listed)

    UtilityTools.summary_wrapup(
        project_id,
        "Cloud Composer Environments",
        rows,
        resource.COLUMNS,
        primary_resource="Environments",
        primary_sort_key="location",
        )

    if args.download:
        for row in rows:
            if not isinstance(row, dict):
                continue
            download_path = resource.download_environment_configs(row=row, project_id=project_id)
            if download_path is None:
                continue
            downloaded_paths.append(str(download_path))

        for download_path in downloaded_paths:
            print(f"[*] Wrote Cloud Composer configs to {download_path}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} Cloud Composer config file(s) for project {project_id}.")
        elif rows:
            print(f"[*] No Cloud Composer config files were downloaded for project {project_id}.")
        else:
            print(f"[*] No Cloud Composer environments were available to download configs from in project {project_id}.")

    return 1
