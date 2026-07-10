from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.cloudcomposer.utilities.helpers import ComposerEnvironmentsResource, resolve_regions


COMPONENTS = [
    Component("environments", ComposerEnvironmentsResource, "Cloud Composer Environments", "Environments",
              help_text="Enumerate Cloud Composer environments", scope=REGION, supports_iam=False),
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
        components=component_args(COMPONENTS),
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(session, args, components=COMPONENTS, column_name="cloudcomposer_actions_allowed",
                               region_resolver=resolve_regions, module_name="enum_cloudcomposer")

    if getattr(args, "download", False):
        project_id = session.project_id
        resource = ComposerEnvironmentsResource(session)
        downloaded_paths = []
        for row in discovered.get("environments", []):
            if not isinstance(row, dict):
                continue
            download_path = resource.download_environment_configs(row=row, project_id=project_id)
            if download_path is not None:
                downloaded_paths.append(str(download_path))
        for download_path in downloaded_paths:
            print(f"[*] Wrote Cloud Composer configs to {download_path}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} Cloud Composer config file(s) for project {project_id}.")
        elif discovered.get("environments"):
            print(f"[*] No Cloud Composer config files were downloaded for project {project_id}.")
        else:
            print(f"[*] No Cloud Composer environments were available to download configs from in project {project_id}.")
    return 1
