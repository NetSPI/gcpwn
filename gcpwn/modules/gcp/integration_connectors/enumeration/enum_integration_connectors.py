"""Enumerate Integration Connector connections.

Records connector type, state, and the serviceAccount each connection runs as.
Records connector type, state, and the serviceAccount each connection runs as.
The connector runtime can only make predefined API calls for its connector type
(Pub/Sub, BQ, GCS, etc.) — not arbitrary Google APIs.

Required permission  : connectors.connections.list
"""

from __future__ import annotations

import argparse
import json

from gcpwn.core.console import UtilityTools
from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.module_helpers import get_bearer_token
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.integration_connectors.utilities.helpers import (
    ConnectionsResource,
    _DEFAULT_REGIONS,
    get_connection,
)


COMPONENTS = [
    Component(
        "connections", ConnectionsResource,
        "Integration Connector Connections", "Connections",
        help_text="Enumerate Integration Connector connections across regions",
        scope=REGION,
        supports_get=False,
        supports_iam=True,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known Integration Connectors regions")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File containing regions per line")
        parser.add_argument("--download", action="store_true",
                            help="Download full connection JSON (including authConfig) per connection")

    return parse_component_args(
        user_args,
        description="Enumerate Integration Connector connections across regions",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "debug"),
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
        column_name="connectors_actions_allowed",
        region_resolver=_region_resolver,
        module_name="enum_integration_connectors",
    )
    if getattr(args, "download", False):
        connections = discovered.get("connections", [])
        if connections:
            _download_connections(session, session.project_id, connections)
    return 1


def _download_connections(session, project_id: str, rows: list[dict]) -> None:
    """Download full connection JSON (including authConfig) per connection.

    Calls get_connection per name so the full authConfig is included
    (list responses may omit sensitive credential sub-fields).
    """
    budget = DownloadBudget(session, label="connector connection configs")
    tok = get_bearer_token(session)
    downloaded = 0

    for row in rows:
        if budget.exceeded():
            break
        name = row.get("name", "")
        if not name:
            continue
        location = row.get("location", "")
        connection_id = row.get("connection_id", "") or name.rsplit("/", 1)[-1]
        full = get_connection(tok, name)
        if full is None:
            print(f"{UtilityTools.YELLOW}[*] Could not fetch full JSON for {connection_id} — skipping.{UtilityTools.RESET}")
            continue
        path = resolve_download_path(
            session, service_name="integration_connectors", project_id=project_id,
            subdirs=[location], filename=f"{connection_id}.json",
        )
        path.write_text(json.dumps(full, indent=2), encoding="utf-8")
        print(f"{UtilityTools.GREEN}[+] Saved → {path}{UtilityTools.RESET}")
        downloaded += 1

    if downloaded:
        print(f"{UtilityTools.CYAN}[*] Downloaded {downloaded} connection JSON file(s).{UtilityTools.RESET}")
    else:
        print(f"{UtilityTools.YELLOW}[*] No connection JSON files downloaded.{UtilityTools.RESET}")
