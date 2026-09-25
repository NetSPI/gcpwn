from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import (
    REGION,
    Component,
    build_extra_args,
    component_args,
    run_components,
)
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.firebase.utilities.helpers import (
    FirebaseAppHostingBackendResource,
    resolve_fah_locations,
)


COMPONENTS = [
    Component(
        "backends", FirebaseAppHostingBackendResource,
        "Firebase App Hosting Backends", "Backends",
        help_text="Enumerate Firebase App Hosting backends",
        scope=REGION,
        supports_get=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        locations_group = parser.add_mutually_exclusive_group()
        locations_group.add_argument(
            "--location", default=None,
            help="Single region to query (default: common regions)",
        )
        locations_group.add_argument(
            "--all-locations", action="store_true",
            help="Try all known Firebase App Hosting regions",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Firebase App Hosting backends",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS,
        column_name="firebaseapphosting_actions_allowed",
        region_resolver=resolve_fah_locations,
        module_name="enum_firebase",
    )
    return 1
