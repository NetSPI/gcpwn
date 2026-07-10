from __future__ import annotations

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.spanner.utilities.helpers import (
    SpannerDatabasesResource,
    SpannerInstancesResource,
)


COMPONENTS = [
    Component("instances", SpannerInstancesResource, "Cloud Spanner Instances", "Instances",
              help_text="Enumerate Cloud Spanner instances", scope=PROJECT, primary_sort_key="instance_id",
              manual_id_arg="instance_ids",
              manual_template=("projects", "{project_id}", "instances", 0),
              manual_error="Invalid instance ID format. Use INSTANCE_ID or projects/PROJECT_ID/instances/INSTANCE_ID.",
              manual_help="Instance IDs as INSTANCE_ID or full projects/.../instances/... names."),
    Component("databases", SpannerDatabasesResource, "Cloud Spanner Databases", "Databases",
              help_text="Enumerate Cloud Spanner databases (per instance)", scope=NESTED,
              parent_key="instances", dependency_label="Instances",
              primary_sort_key="database_id",
              manual_id_arg="database_ids",
              manual_template=("projects", "{project_id}", "instances", 0, "databases", 1),
              manual_error="Invalid database ID format. Use INSTANCE_ID/DATABASE_ID or projects/PROJECT_ID/instances/INSTANCE_ID/databases/DATABASE_ID.",
              manual_help="Database IDs as INSTANCE_ID/DATABASE_ID or full projects/.../databases/... names."),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate Cloud Spanner resources (read-only)",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on Cloud Spanner instances and databases"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="spanner_actions_allowed",
        module_name="enum_spanner",
    )
    return 1
