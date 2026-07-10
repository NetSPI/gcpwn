from __future__ import annotations

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.appengine.utilities.helpers import (
    AppEngineAppsResource,
    AppEngineInstancesResource,
    AppEngineServicesResource,
    AppEngineVersionsResource,
)


COMPONENTS = [
    Component("app", AppEngineAppsResource, "App Engine Application", "App",
              help_text="Enumerate App Engine application", scope=PROJECT, primary_sort_key="location_id",
              supports_iam=False, manual_id_arg="app_name", manual_template=("apps", 0),
              manual_help="Application name as apps/PROJECT_ID or plain PROJECT_ID."),
    Component("services", AppEngineServicesResource, "App Engine Services", "Services",
              help_text="Enumerate App Engine services", scope=PROJECT, primary_sort_key="service_id",
              supports_iam=False, manual_id_arg="service_ids",
              manual_template=("apps", "{project_id}", "services", 0),
              manual_help="Service IDs as SERVICE_ID or apps/PROJECT_ID/services/SERVICE_ID."),
    Component("versions", AppEngineVersionsResource, "App Engine Versions", "Versions",
              help_text="Enumerate App Engine versions (per service)", scope=NESTED, parent_key="services",
              dependency_label="Services", save_parent_kwarg="service_name", primary_sort_key="version_id",
              supports_iam=False, manual_id_arg="version_ids",
              manual_template=("apps", "{project_id}", "services", 0, "versions", 1),
              manual_help="Version IDs as SERVICE_ID/VERSION_ID or full names."),
    Component("instances", AppEngineInstancesResource, "App Engine Instances", "Instances",
              help_text="Enumerate App Engine instances (per version)", scope=NESTED, parent_key="versions",
              dependency_label="Versions", save_parent_kwarg="version_name", primary_sort_key="instance_id",
              supports_iam=False, manual_id_arg="instance_ids",
              manual_template=("apps", "{project_id}", "services", 0, "versions", 1, "instances", 2),
              manual_help="Instance IDs as SERVICE_ID/VERSION_ID/INSTANCE_ID or full names."),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate App Engine resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="appengine_actions_allowed",
                   module_name="enum_appengine")
    return 1
