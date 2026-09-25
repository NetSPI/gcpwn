from __future__ import annotations


from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.inframanager.utilities.helpers import (
    InfraManagerDeploymentsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "deployments",
        InfraManagerDeploymentsResource,
        "Infrastructure Manager Deployments",
        "Deployments",
        help_text="Enumerate Infra Manager deployments",
        scope=REGION,
        manual_id_arg="deployment_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "deployments", 1),
        manual_error="Invalid deployment ID format. Use LOCATION/DEPLOYMENT_ID or full projects/.../deployments/... names.",
        manual_help="Deployment IDs as LOCATION/DEPLOYMENT_ID or full projects/.../deployments/... names.",
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser):
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known Infra Manager locations")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Infrastructure Manager resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="inframanager_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_inframanager",
    )
    return 1
