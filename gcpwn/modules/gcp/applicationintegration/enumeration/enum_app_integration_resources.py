"""Enumerate Application Integration integrations and versions.

Highlights any integration carrying a non-default runAsServiceAccount — these
are candidates for the PE path documented in exploit_app_integration_as_sa.

Discovered integrations are persisted to the appintegration_integrations table.
"""

from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.applicationintegration.utilities.helpers import (
    IntegrationsResource,
    _DEFAULT_REGIONS,
    enumerate_integration_versions,
)


COMPONENTS = [
    Component(
        "integrations", IntegrationsResource,
        "Application Integration Integrations", "Integrations",
        help_text="Enumerate Application Integration integrations across regions",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true",
                                   help="Try all known Application Integration regions")
        regions_group.add_argument("--regions-list",
                                   help="Comma-separated regions to enumerate")
        regions_group.add_argument("--regions-file",
                                   help="File containing regions, one per line")
        parser.add_argument("--versions", action="store_true",
                            help="Also fetch and display versions for each integration")
        parser.add_argument("--download", action="store_true",
                            help="Download full integration version JSON to disk (implies --versions)")

    return parse_component_args(
        user_args,
        description="Enumerate Application Integration integrations and flag runAsServiceAccount PE candidates",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("debug",),
    )


def _region_resolver(session, args):
    if getattr(args, "all_regions", False):
        return _DEFAULT_REGIONS
    if getattr(args, "regions_list", None):
        return [r.strip() for r in args.regions_list.split(",") if r.strip()]
    if getattr(args, "regions_file", None):
        with open(args.regions_file) as f:
            return [line.strip() for line in f if line.strip()]
    return _DEFAULT_REGIONS


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(
        session, args, components=COMPONENTS,
        column_name="appintegration_actions_allowed",
        region_resolver=_region_resolver,
        module_name="enum_app_integration_resources",
    )

    integrations = discovered.get("integrations", [])

    if (getattr(args, "versions", False) or getattr(args, "download", False)) and integrations:
        enumerate_integration_versions(
            session, session.project_id, integrations,
            download=getattr(args, "download", False),
        )

    return 1 if integrations else 0
