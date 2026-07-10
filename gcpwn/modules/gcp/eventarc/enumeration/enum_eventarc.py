from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.eventarc.utilities.helpers import (
    EventarcTriggersResource,
    resolve_locations,
)


COMPONENTS = [
    Component("triggers", EventarcTriggersResource, "Eventarc Triggers", "Triggers",
              help_text="Enumerate Eventarc triggers", scope=REGION,
              supports_iam=False,
              manual_id_arg="trigger_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "triggers", 1),
              manual_error="Invalid trigger ID format. Use LOCATION/TRIGGER_ID or projects/PROJECT_ID/locations/LOCATION/triggers/TRIGGER_ID.",
              manual_help="Trigger IDs as LOCATION/TRIGGER_ID or full projects/.../triggers/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Eventarc locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Eventarc resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="eventarc_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_eventarc",
    )
    return 1
