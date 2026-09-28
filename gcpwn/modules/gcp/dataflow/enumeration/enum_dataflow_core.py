from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.dataflow.utilities.helpers import (
    DataflowJobsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("jobs", DataflowJobsResource, "Dataflow Jobs", "Jobs",
              help_text="Enumerate Dataflow jobs (and the worker SA each runs as)", scope=REGION,
              supports_get=False, supports_iam=False),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Dataflow jobs across regions",
        region_label="Dataflow regions",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="dataflow_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_dataflow_core",
    )
    return 1
