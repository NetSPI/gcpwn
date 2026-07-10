from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.clouddeploy.utilities.helpers import (
    CloudDeployDeliveryPipelinesResource,
    CloudDeployTargetsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("delivery_pipelines", CloudDeployDeliveryPipelinesResource, "Cloud Deploy Delivery Pipelines", "Delivery Pipelines",
              help_text="Enumerate Cloud Deploy delivery pipelines", scope=REGION,
              manual_id_arg="pipeline_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "deliveryPipelines", 1),
              manual_error="Invalid delivery pipeline ID format. Use LOCATION/PIPELINE_ID or projects/PROJECT_ID/locations/LOCATION/deliveryPipelines/PIPELINE_ID.",
              manual_help="Delivery pipeline IDs as LOCATION/PIPELINE_ID or full projects/.../deliveryPipelines/... names."),
    Component("targets", CloudDeployTargetsResource, "Cloud Deploy Targets", "Targets",
              help_text="Enumerate Cloud Deploy targets", scope=REGION,
              manual_id_arg="target_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "targets", 1),
              manual_error="Invalid target ID format. Use LOCATION/TARGET_ID or projects/PROJECT_ID/locations/LOCATION/targets/TARGET_ID.",
              manual_help="Target IDs as LOCATION/TARGET_ID or full projects/.../targets/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Cloud Deploy locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Deploy resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="clouddeploy_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_clouddeploy",
    )
    return 1
