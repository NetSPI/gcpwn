from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.alloydb.utilities.helpers import (
    AlloyDBClustersResource,
    AlloyDBInstancesResource,
    resolve_locations,
)


COMPONENTS = [
    Component("clusters", AlloyDBClustersResource, "AlloyDB Clusters", "Clusters",
              help_text="Enumerate AlloyDB clusters", scope=REGION,
              supports_iam=False,
              manual_id_arg="cluster_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "clusters", 1),
              manual_error="Invalid cluster ID format. Use LOCATION/CLUSTER_ID or projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER_ID.",
              manual_help="Cluster IDs as LOCATION/CLUSTER_ID or full projects/.../clusters/... names."),
    Component("instances", AlloyDBInstancesResource, "AlloyDB Instances", "Instances",
              help_text="Enumerate AlloyDB instances (per cluster)", scope=NESTED,
              parent_key="clusters", dependency_label="Clusters", supports_iam=False,
              manual_id_arg="instance_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "clusters", 1, "instances", 2),
              manual_error="Invalid instance ID format. Use LOCATION/CLUSTER_ID/INSTANCE_ID or projects/.../clusters/.../instances/INSTANCE_ID.",
              manual_help="Instance IDs as LOCATION/CLUSTER_ID/INSTANCE_ID or full projects/.../instances/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known AlloyDB locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate AlloyDB resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="alloydb_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_alloydb",
    )
    return 1
