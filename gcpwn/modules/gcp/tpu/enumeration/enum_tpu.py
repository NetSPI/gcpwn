from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.tpu.utilities.helpers import (
    TpuNodesResource,
    download_startup_scripts,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "nodes", TpuNodesResource,
        "Cloud TPU Nodes", "Nodes",
        help_text="Enumerate Cloud TPU nodes and the service account each runs as",
        scope=REGION,
        supports_get=True,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument(
            "--all-regions", action="store_true",
            help="Try all known TPU zones",
        )
        regions_group.add_argument(
            "--regions-list",
            help="Comma-separated TPU zones to enumerate",
        )
        regions_group.add_argument(
            "--regions-file",
            help="File containing TPU zones, one per line",
        )
        parser.add_argument(
            "--download", action="store_true",
            help="Download startup-script metadata from each TPU node to disk",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Cloud TPU nodes and the service account each runs as",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(
        session, args,
        components=COMPONENTS,
        column_name="tpu_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_tpu",
    )

    nodes = discovered.get("nodes", [])
    if getattr(args, "download", False) and nodes:
        download_startup_scripts(session, nodes)

    return 1
