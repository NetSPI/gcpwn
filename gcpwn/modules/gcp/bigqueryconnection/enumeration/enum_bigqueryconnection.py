from __future__ import annotations

from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.bigqueryconnection.utilities.helpers import (
    BigQueryConnectionsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "connections",
        BigQueryConnectionsResource,
        "BigQuery Connections",
        "Connections",
        help_text="Enumerate BigQuery external data connections (Cloud SQL, Cloud Resource, AWS, Azure, Spark, …)",
        scope=REGION,
        manual_id_arg="connection_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "connections", 1),
        manual_error="Invalid connection ID. Use LOCATION/CONNECTION_ID or the full resource name.",
        manual_help="Connection IDs as LOCATION/CONNECTION_ID or full resource names.",
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate BigQuery external data connections",
        region_label="BigQuery Connection locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="bigqueryconnection_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_bigqueryconnection",
    )
    return 1
