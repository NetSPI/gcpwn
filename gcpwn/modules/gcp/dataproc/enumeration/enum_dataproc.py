from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.dataproc.utilities.helpers import (
    DataprocBatchesResource,
    DataprocClustersResource,
    resolve_locations,
)


COMPONENTS = [
    Component("clusters", DataprocClustersResource, "Dataproc Clusters", "Clusters",
              help_text="Enumerate Dataproc clusters (and the SA each runs as)", scope=REGION,
              supports_get=False, supports_iam=False),
    Component("batches", DataprocBatchesResource, "Dataproc Serverless Batches", "Batches",
              help_text="Enumerate Dataproc Serverless batches (and the SA each runs as)", scope=REGION,
              supports_get=False, supports_iam=False),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Dataproc regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions per line")

    return parse_component_args(
        user_args,
        description="Enumerate Dataproc resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="dataproc_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_dataproc",
    )
    return 1
