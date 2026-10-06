from __future__ import annotations

from gcpwn.core.utils.enum_framework import Component, NESTED, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.securesourcemanager.utilities.helpers import (
    SSMInstancesResource,
    SSMRepositoriesResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "instances",
        SSMInstancesResource,
        "Secure Source Manager Instances",
        "Instances",
        help_text="Enumerate Secure Source Manager instances (managed Git hosting environments)",
        scope=REGION,
        manual_id_arg="instance_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "instances", 1),
        manual_error="Invalid instance ID. Use LOCATION/INSTANCE_ID or the full resource name.",
        manual_help="Instance IDs as LOCATION/INSTANCE_ID or full resource names.",
    ),
    Component(
        "repositories",
        SSMRepositoriesResource,
        "Secure Source Manager Repositories",
        "Repositories",
        help_text="Enumerate repositories under each Secure Source Manager instance",
        scope=NESTED,
        parent_key="instances",
        dependency_label="instances",
        supports_iam=True,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Secure Source Manager instances and repositories",
        region_label="Secure Source Manager locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="securesourcemanager_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_securesourcemanager",
    )
    return 1
