from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.dataflow.utilities.helpers import (
    DataflowJobsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("jobs", DataflowJobsResource, "Dataflow Jobs", "Jobs",
              help_text="Enumerate Dataflow jobs (and the worker SA each runs as)", scope=REGION,
              supports_get=False, supports_iam=False),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Dataflow regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions per line")

    return parse_component_args(
        user_args,
        description="Enumerate Dataflow resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="dataflow_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_dataflow",
    )
    return 1
