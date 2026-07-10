from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args, print_missing_dependency, resolve_selected_components
from gcpwn.modules.gcp.cloudsql.utilities.helpers import (
    CloudSqlConfigsResource,
    CloudSqlConnectionsResource,
    CloudSqlDatabasesResource,
    CloudSqlInstancesResource,
    CloudSqlUsersResource,
)


# Framework-driven components (real list/get/save). connections/configs are
# post-process views over cached instances -> handled as tails below.
COMPONENTS = [
    Component("instances", CloudSqlInstancesResource, "Cloud SQL Instances", "Instances",
              help_text="Enumerate Cloud SQL instances", scope=PROJECT, primary_sort_key="name", supports_iam=False,
              manual_id_arg="instance_names", manual_help="Cloud SQL instance IDs (comma-separated)."),
    Component("databases", CloudSqlDatabasesResource, "Cloud SQL Databases", "Databases",
              help_text="Enumerate Cloud SQL databases (per instance)", scope=NESTED, parent_key="instances",
              dependency_label="Instances", save_parent_kwarg="instance", primary_sort_key="instance",
              supports_get=False, supports_iam=False),
    Component("users", CloudSqlUsersResource, "Cloud SQL Users", "Users",
              help_text="Enumerate Cloud SQL users (per instance)", scope=NESTED, parent_key="instances",
              dependency_label="Instances", save_parent_kwarg="instance", primary_sort_key="instance",
              supports_get=False, supports_iam=False),
]

ALL_KEYS = ["instances", "connections", "configs", "databases", "users"]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--connections", action="store_true", help="Summarize Cloud SQL connection details")
        parser.add_argument("--configs", action="store_true", help="Summarize cached Cloud SQL instance configuration fields")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud SQL resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id
    if getattr(args, "instance_names", None) or getattr(args, "instance_names_file", None):
        args.instances = True

    sel = resolve_selected_components(args, ALL_KEYS)
    for key in ALL_KEYS:
        setattr(args, key, sel[key])  # make selection explicit so run_components doesn't auto-select-all

    discovered = {}
    if any(sel[k] for k in ("instances", "databases", "users")):
        discovered = run_components(session, args, components=COMPONENTS,
                                    column_name="cloudsql_actions_allowed", module_name="enum_cloudsql")

    if not (sel["connections"] or sel["configs"]):
        return 1

    instances_resource = CloudSqlInstancesResource(session)
    targets = [str(r.get("name") or "").strip() for r in discovered.get("instances", []) if isinstance(r, dict) and r.get("name")]
    if not targets and not sel["instances"]:
        targets = instances_resource.resolve_cached_targets(project_id=project_id)

    if sel["connections"]:
        if not targets:
            print_missing_dependency(component_name="Cloud SQL connections", dependency_name="Instances",
                                     module_name="enum_cloudsql", manual_flags=["--instance-names", "--instance-names-file"])
        else:
            rows = CloudSqlConnectionsResource(session).list(project_id=project_id, instance_names=targets)
            UtilityTools.summary_wrapup(project_id, "Cloud SQL Connections", rows,
                                        CloudSqlConnectionsResource(session).COLUMNS, primary_resource="Connections", primary_sort_key="region")
    if sel["configs"]:
        if not targets:
            print_missing_dependency(component_name="Cloud SQL configs", dependency_name="Instances",
                                     module_name="enum_cloudsql", manual_flags=["--instance-names", "--instance-names-file"])
        else:
            rows = CloudSqlConfigsResource(session).list(project_id=project_id, instance_names=targets)
            UtilityTools.summary_wrapup(project_id, "Cloud SQL Instance Configs", rows,
                                        CloudSqlConfigsResource(session).COLUMNS, primary_resource="Instances", primary_sort_key="region")
    return 1
