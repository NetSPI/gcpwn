from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.cloudworkflows.utilities.helpers import (
    CloudWorkflowsWorkflowsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("workflows", CloudWorkflowsWorkflowsResource, "Cloud Workflows Workflows", "Workflows",
              help_text="Enumerate Cloud Workflows workflows", scope=REGION,
              supports_iam=False,
              manual_id_arg="workflow_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "workflows", 1),
              manual_error="Invalid workflow ID format. Use LOCATION/WORKFLOW_ID or projects/PROJECT_ID/locations/LOCATION/workflows/WORKFLOW_ID.",
              manual_help="Workflow IDs as LOCATION/WORKFLOW_ID or full projects/.../workflows/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Cloud Workflows locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Workflows resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="cloudworkflows_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_cloudworkflows",
    )
    return 1
