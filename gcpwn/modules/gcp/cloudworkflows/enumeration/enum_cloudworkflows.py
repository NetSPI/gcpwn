from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.cloudworkflows.utilities.helpers import (
    CloudWorkflowsWorkflowsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("workflows", CloudWorkflowsWorkflowsResource, "Cloud Workflows Workflows", "Workflows",
              help_text="Enumerate Cloud Workflows workflows", scope=REGION,
              supports_iam=False,
              manual_id_arg="workflow_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "workflows", 1),
              manual_error="Invalid workflow ID format. Use LOCATION/WORKFLOW_ID or projects/PROJECT_ID/locations/LOCATION/workflows/WORKFLOW_ID.",
              manual_help="Workflow IDs as LOCATION/WORKFLOW_ID or full projects/.../workflows/... names."),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Cloud Workflows resources",
        region_label="Cloud Workflows locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="cloudworkflows_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_cloudworkflows",
    )
    return 1
