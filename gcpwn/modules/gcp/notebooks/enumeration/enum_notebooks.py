from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.notebooks.utilities.helpers import (
    NotebooksInstancesResource,
    resolve_locations,
)


COMPONENTS = [
    Component("instances", NotebooksInstancesResource, "Vertex AI Workbench Instances", "Instances",
              help_text="Enumerate Vertex AI Workbench instances", scope=REGION,
              manual_id_arg="instance_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "instances", 1),
              manual_error="Invalid instance ID format. Use LOCATION/INSTANCE_ID or projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID.",
              manual_help="Instance IDs as LOCATION/INSTANCE_ID or full projects/.../instances/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Vertex AI Workbench locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Vertex AI Workbench resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="notebooks_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_notebooks",
    )
    return 1
