from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, NESTED, REGION, parse_enum_args, run_components
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
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate AlloyDB resources",
        region_label="AlloyDB locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="alloydb_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_alloydb",
    )
    return 1
