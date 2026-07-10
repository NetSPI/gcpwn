from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.servicedirectory.utilities.helpers import (
    ServiceDirectoryEndpointsResource,
    ServiceDirectoryNamespacesResource,
    ServiceDirectoryServicesResource,
    resolve_regions,
)


COMPONENTS = [
    Component("namespaces", ServiceDirectoryNamespacesResource, "Service Directory Namespaces", "Namespaces",
              help_text="Enumerate Service Directory namespaces", scope=REGION,
              columns=["location_id", "namespace_id", "name", "labels"], primary_sort_key="location_id"),
    Component("services", ServiceDirectoryServicesResource, "Service Directory Services", "Services",
              help_text="Enumerate Service Directory services (per namespace)", scope=NESTED,
              parent_key="namespaces", dependency_label="Namespaces", save_parent_kwarg="namespace_name",
              columns=["location_id", "service_id", "name", "namespace_name", "labels"], primary_sort_key="location_id"),
    Component("endpoints", ServiceDirectoryEndpointsResource, "Service Directory Endpoints", "Endpoints",
              help_text="Enumerate Service Directory endpoints (per service)", scope=NESTED,
              parent_key="services", dependency_label="Services", save_parent_kwarg="service_name",
              columns=["location_id", "endpoint_id", "name", "service_name", "address", "port", "network"],
              primary_sort_key="location_id", supports_get=False, supports_iam=False),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Service Directory resources",
        components=component_args(COMPONENTS),
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on namespaces and services"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="servicedirectory_actions_allowed",
        region_resolver=resolve_regions, module_name="enum_servicedirectory",
    )
    return 1
