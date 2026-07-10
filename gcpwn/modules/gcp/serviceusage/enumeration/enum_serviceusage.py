from __future__ import annotations

from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.serviceusage.utilities.helpers import ServiceUsageServicesResource


COMPONENTS = [
    Component("services", ServiceUsageServicesResource, "Enabled Services", "Services",
              help_text="Enumerate the APIs (services) enabled on the project",
              scope=PROJECT, primary_sort_key="service_name",
              supports_get=False, supports_iam=False),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate enabled APIs (Service Usage)",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="serviceusage_actions_allowed",
        region_resolver=None, module_name="enum_serviceusage",
    )
    return 1
