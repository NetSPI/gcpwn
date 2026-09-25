from __future__ import annotations

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.dataform.utilities.helpers import (
    DataformRepositoriesResource,
    DataformWorkflowConfigsResource,
    DataformWorkspacesResource,
    resolve_locations,
)

COMPONENTS = [
    Component(
        "repositories",
        DataformRepositoriesResource,
        "Dataform Repositories",
        "Repositories",
        help_text="Enumerate Dataform repositories",
        scope=REGION,
        supports_iam=True,
    ),
    Component(
        "workspaces",
        DataformWorkspacesResource,
        "Dataform Workspaces",
        "Workspaces",
        help_text="Enumerate workspaces across all discovered repositories",
        scope=REGION,
        supports_iam=True,
    ),
    Component(
        "workflow_configs",
        DataformWorkflowConfigsResource,
        "Dataform Workflow Configs",
        "Workflow Configs",
        help_text="Enumerate workflow configs per repository",
        scope=REGION,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser):
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known Dataform regions")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Comma-separated list of regions to query")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Dataform repositories, workspaces, and workflow configs.",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "iam"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args,
        components=COMPONENTS,
        column_name="dataform_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_dataform",
    )
    return 1
