from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.workstations.utilities.helpers import (
    WorkstationsClustersResource,
    WorkstationsConfigsResource,
    WorkstationsWorkstationsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("clusters", WorkstationsClustersResource, "Cloud Workstations Clusters", "Clusters",
              help_text="Enumerate Cloud Workstations clusters", scope=REGION,
              supports_iam=False,
              manual_id_arg="cluster_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "workstationClusters", 1),
              manual_error="Invalid cluster ID format. Use LOCATION/CLUSTER_ID or projects/PROJECT_ID/locations/LOCATION/workstationClusters/CLUSTER_ID.",
              manual_help="Cluster IDs as LOCATION/CLUSTER_ID or full projects/.../workstationClusters/... names."),
    Component("configs", WorkstationsConfigsResource, "Cloud Workstations Configs", "Configs",
              help_text="Enumerate Cloud Workstations configs (per cluster)", scope=NESTED,
              parent_key="clusters", dependency_label="Clusters"),
    Component("workstations", WorkstationsWorkstationsResource, "Cloud Workstations Workstations", "Workstations",
              help_text="Enumerate Cloud Workstations workstations (per config)", scope=NESTED,
              parent_key="configs", dependency_label="Configs"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Cloud Workstations locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Workstations resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on Cloud Workstations configs/workstations"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="workstations_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_workstations",
    )
    return 1
