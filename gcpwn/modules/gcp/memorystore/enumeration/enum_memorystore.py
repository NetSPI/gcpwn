from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_csv_file_args, parse_component_args
from gcpwn.modules.gcp.memorystore.utilities.cluster_helpers import MemorystoreRedisClusterResource
from gcpwn.modules.gcp.memorystore.utilities.helpers import MemorystoreRedisResource


COMPONENTS = [
    Component("instances", MemorystoreRedisResource, "Cloud Redis Instances", "instances",
              help_text="Enumerate Memorystore Redis instances", scope=REGION,
              columns=["name", "display_name", "state_output", "location_id", "host", "port", "auth_enabled", "auth_string"],
              primary_sort_key="location_id", supports_iam=False,
              manual_id_arg="redis_instance_names",
              manual_help="Instances as projects/<pid>/locations/<location>/instances/<name>."),
    Component("clusters", MemorystoreRedisClusterResource, "Memorystore Redis Clusters", "clusters",
              help_text="Enumerate Memorystore for Redis Cluster instances (distinct redis_cluster_v1 API)", scope=REGION,
              supports_iam=False,
              manual_id_arg="redis_cluster_names",
              manual_template=("projects", "{project_id}", "locations", 0, "clusters", 1),
              manual_help="Clusters as LOCATION/CLUSTER_ID or projects/<pid>/locations/<location>/clusters/<id>."),
]


def _resolve_regions(session, args):
    if getattr(args, "all_regions", False):
        return ["-"]
    regions = parse_csv_file_args(getattr(args, "regions_list", None), getattr(args, "regions_file", None))
    if regions:
        return regions
    preferred = getattr(session.workspace_config, "preferred_regions", None)
    return preferred or ["-"]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Memorystore resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="memorystore_actions_allowed",
                   region_resolver=_resolve_regions, module_name="enum_memorystore")
    return 1
