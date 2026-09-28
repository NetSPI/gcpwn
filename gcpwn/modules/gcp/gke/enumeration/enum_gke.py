from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, NESTED, REGION, parse_enum_args, run_components
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
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate GKE (Container API) resources",
        region_label="regions",
        region_unit="locations",
        region_all_help="Try wildcard location (-) when supported",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="gke_actions_allowed",
                   region_resolver=resolve_regions, module_name="enum_gke")
    return 1
