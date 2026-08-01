from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.clouddatafusion.utilities.helpers import (
    DataFusionInstancesResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "instances",
        DataFusionInstancesResource,
        "Data Fusion Instances",
        "Instances",
        help_text="Enumerate Cloud Data Fusion instances",
        scope=REGION,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known Data Fusion regions")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Data Fusion resources",
        components=component_args(COMPONENTS),
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="datafusion_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_datafusion_resources",
    )
    return 1
