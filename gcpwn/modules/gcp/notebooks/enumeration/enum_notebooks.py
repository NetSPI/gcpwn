from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.notebooks.utilities.helpers import (
    NotebooksInstancesResource,
    resolve_locations,
)


COMPONENTS = [
    Component("instances", NotebooksInstancesResource, "Vertex AI Workbench Instances", "Instances",
              help_text="Enumerate Vertex AI Workbench instances", scope=REGION,
              manual_id_arg="instance_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "instances", 1),
              manual_error="Invalid instance ID format. Use LOCATION/INSTANCE_ID or projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID.",
              manual_help="Instance IDs as LOCATION/INSTANCE_ID or full projects/.../instances/... names."),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Vertex AI Workbench resources",
        region_label="Vertex AI Workbench locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="notebooks_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_notebooks",
    )
    return 1
