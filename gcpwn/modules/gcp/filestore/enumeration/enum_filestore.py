from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.filestore.utilities.helpers import (
    FilestoreBackupsResource,
    FilestoreInstancesResource,
    FilestoreSnapshotsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "instances", FilestoreInstancesResource, "Cloud Filestore Instances", "Instances",
        help_text="Enumerate Filestore instances", scope=REGION,
    ),
    Component(
        "snapshots", FilestoreSnapshotsResource, "Cloud Filestore Snapshots", "Snapshots",
        help_text="Enumerate Filestore snapshots (per instance)", scope=NESTED,
        parent_key="instances", dependency_label="Instances",
        save_parent_kwarg="instance_name", supports_iam=False,
    ),
    Component(
        "backups", FilestoreBackupsResource, "Cloud Filestore Backups", "Backups",
        help_text="Enumerate Filestore backups", scope=REGION, supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        loc_group = parser.add_mutually_exclusive_group()
        loc_group.add_argument("--all-regions", action="store_true", required=False,
                               help="Enumerate all available Filestore locations")
        loc_group.add_argument("--regions-list", required=False,
                               help="Locations in comma-separated format")
        loc_group.add_argument("--regions-file", required=False,
                               help="File containing locations, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Filestore instances, snapshots, and backups",
        components=component_args(COMPONENTS),
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="filestore_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_filestore",
    )
    return 1
