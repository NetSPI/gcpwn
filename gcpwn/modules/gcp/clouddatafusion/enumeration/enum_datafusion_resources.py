from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.clouddatafusion.utilities.helpers import (
    DataFusionInstancesResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "instances",
        DataFusionInstancesResource,
        "Data Fusion Instances",
        "Instances",
        help_text="Enumerate Cloud Data Fusion instances",
        scope=REGION,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Cloud Data Fusion resources",
        region_label="Data Fusion regions",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="datafusion_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_datafusion_resources",
    )
    return 1
