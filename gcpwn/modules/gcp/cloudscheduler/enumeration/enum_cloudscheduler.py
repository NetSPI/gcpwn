from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.cloudscheduler.utilities.helpers import (
    CloudSchedulerJobsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("jobs", CloudSchedulerJobsResource, "Cloud Scheduler Jobs", "Jobs",
              help_text="Enumerate Cloud Scheduler jobs", scope=REGION,
              supports_iam=False,
              manual_id_arg="job_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "jobs", 1),
              manual_error="Invalid job ID format. Use LOCATION/JOB_ID or projects/PROJECT_ID/locations/LOCATION/jobs/JOB_ID.",
              manual_help="Job IDs as LOCATION/JOB_ID or full projects/.../jobs/... names."),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Cloud Scheduler resources",
        region_label="Cloud Scheduler locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="cloudscheduler_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_cloudscheduler",
    )
    return 1
