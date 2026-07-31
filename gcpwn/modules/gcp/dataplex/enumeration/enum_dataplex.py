from __future__ import annotations

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.dataplex.utilities.helpers import (
    DataplexLakesResource,
    DataplexTasksResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "lakes",
        DataplexLakesResource,
        "Knowledge Catalog Lakes",
        "Lakes",
        help_text="Enumerate Dataplex (Knowledge Catalog) lakes",
        scope=REGION,
        manual_id_arg="lake_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "lakes", 1),
        manual_error="Invalid lake ID. Use LOCATION/LAKE_ID or full projects/.../lakes/... names.",
        manual_help="Lake IDs as LOCATION/LAKE_ID or full projects/.../lakes/... names.",
    ),
    Component(
        "tasks",
        DataplexTasksResource,
        "Knowledge Catalog Tasks",
        "Tasks",
        help_text="Enumerate Dataplex tasks across all lakes (reveals execution service account)",
        scope=REGION,
        manual_id_arg="task_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "lakes", 1, "tasks", 2),
        manual_error="Invalid task ID. Use LOCATION/LAKE_ID/TASK_ID or full resource name.",
        manual_help="Task IDs as LOCATION/LAKE_ID/TASK_ID or full resource names.",
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser):
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known Dataplex locations")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Knowledge Catalog (formerly Dataplex) resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="dataplex_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_dataplex",
    )
    return 1
