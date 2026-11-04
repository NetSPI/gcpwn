from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.datastream.utilities.helpers import (
    DatastreamConnectionProfilesResource,
    DatastreamPrivateConnectionsResource,
    DatastreamRoutesResource,
    DatastreamStreamsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "connection_profiles",
        DatastreamConnectionProfilesResource,
        "Datastream Connection Profiles",
        "Connection Profiles",
        help_text="Enumerate Datastream connection profiles (source/dest DB credentials)",
        scope=REGION,
        supports_iam=False,
    ),
    Component(
        "streams",
        DatastreamStreamsResource,
        "Datastream Streams",
        "Streams",
        help_text="Enumerate Datastream streams",
        scope=REGION,
        supports_iam=False,
    ),
    Component(
        "private_connections",
        DatastreamPrivateConnectionsResource,
        "Datastream Private Connections",
        "Private Connections",
        help_text="Enumerate Datastream private connections (VPC peering)",
        scope=REGION,
        supports_iam=False,
    ),
    Component(
        "routes",
        DatastreamRoutesResource,
        "Datastream Routes",
        "Routes",
        help_text="Enumerate routes within each private connection",
        scope=NESTED,
        parent_key="private_connections",
        dependency_label="Private Connections",
        save_parent_kwarg="private_connection_name",
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        loc_group = parser.add_mutually_exclusive_group()
        loc_group.add_argument("--all-regions", action="store_true", required=False,
                               help="Try all known Datastream regions")
        loc_group.add_argument("--regions-list", required=False,
                               help="Comma-separated list of regions to query")
        loc_group.add_argument("--regions-file", required=False,
                               help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Datastream connection profiles, streams, private connections, and routes.",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "download", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)

    if getattr(args, "download", False):
        # Need the full resource payload to dump credential details
        args.get = True
        args.connection_profiles = True

    discovered = run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="datastream_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_datastream",
    )

    if getattr(args, "download", False):
        project_id = session.project_id
        resource = DatastreamConnectionProfilesResource(session)
        downloaded_paths = []
        budget = DownloadBudget(session, label="datastream connection profile credentials")
        for row in discovered.get("connection_profiles", []):
            if budget.exceeded():
                break
            path = resource.download_credentials(row=row, project_id=project_id)
            if path is not None:
                downloaded_paths.append(str(path))
        for p in downloaded_paths:
            print(f"[*] Wrote connection profile credentials to {p}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} connection profile file(s) for project {project_id}.")
        elif discovered.get("connection_profiles"):
            print(f"[*] No connection profile data was available to download for project {project_id}.")

    return 1
