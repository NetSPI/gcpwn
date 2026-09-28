from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
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
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Infrastructure Manager resources",
        region_label="Infra Manager locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="inframanager_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_inframanager",
    )
    return 1
