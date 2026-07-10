from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.gke.utilities.helpers import GkeClustersResource, GkeNodePoolsResource, resolve_regions


COMPONENTS = [
    Component("clusters", GkeClustersResource, "GKE Clusters", "Clusters",
              help_text="Enumerate GKE clusters", scope=REGION, primary_sort_key="location", supports_iam=False,
              manual_id_arg="cluster_names",
              manual_template=("projects", "{project_id}", "locations", 0, "clusters", 1),
              manual_error="Invalid cluster name format. Use LOCATION/CLUSTER_ID or projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER_ID.",
              manual_help="Cluster names as LOCATION/CLUSTER_ID or full resource names."),
    Component("node_pools", GkeNodePoolsResource, "GKE Node Pools", "Node Pools",
              help_text="Enumerate GKE node pools (per cluster)", scope=NESTED, parent_key="clusters",
              dependency_label="Clusters", save_parent_kwarg="cluster_name", primary_sort_key="location",
              supports_iam=False,
              manual_id_arg="node_pool_names",
              manual_template=("projects", "{project_id}", "locations", 0, "clusters", 1, "nodePools", 2),
              manual_error="Invalid node pool name format. Use LOCATION/CLUSTER_ID/NODE_POOL_ID or full resource names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try wildcard location (-) when supported")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate GKE (Container API) resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="gke_actions_allowed",
                   region_resolver=resolve_regions, module_name="enum_gke")
    return 1
