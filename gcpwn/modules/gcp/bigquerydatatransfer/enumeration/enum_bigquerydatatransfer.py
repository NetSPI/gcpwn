from __future__ import annotations

import argparse
import json

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.bigquerydatatransfer.utilities.helpers import (
    BigQueryDataTransferConfigsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("transfer_configs", BigQueryDataTransferConfigsResource, "BigQuery Data Transfer Configs", "Configs",
              help_text="Enumerate BigQuery Data Transfer configs", scope=REGION,
              supports_iam=False,
              manual_id_arg="config_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "transferConfigs", 1),
              manual_error="Invalid config ID format. Use LOCATION/CONFIG_ID or projects/PROJECT_ID/locations/LOCATION/transferConfigs/CONFIG_ID.",
              manual_help="Config IDs as LOCATION/CONFIG_ID or full projects/.../transferConfigs/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known BigQuery Data Transfer locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate BigQuery Data Transfer resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(
        session, args, components=COMPONENTS, column_name="bigquerydatatransfer_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_bigquerydatatransfer",
    )

    if getattr(args, "download", False):
        project_id = session.project_id or ""
        written = 0
        for row in discovered.get("transfer_configs", []):
            if not isinstance(row, dict):
                continue
            params = row.get("params") or {}
            if not params:
                continue
            config_id = (row.get("config_id") or row.get("name", "").split("/")[-1] or "unknown")
            dest = resolve_download_path(
                session,
                service_name="bigquerydatatransfer",
                project_id=project_id,
                subdirs=["transfer_configs"],
                filename=f"{config_id}_params.json",
            )
            try:
                dest.write_text(json.dumps(params, indent=2, default=str), encoding="utf-8")
                print(f"[*] Wrote transfer config params to {dest}")
                written += 1
            except Exception as exc:
                print(f"[!] Failed to write params for {config_id}: {exc}")
        if written:
            print(f"[*] Downloaded params for {written} transfer config(s).")
        elif discovered.get("transfer_configs"):
            print("[*] No params to download — configs had empty params fields.")
        else:
            print("[*] No transfer configs found to download.")

    return 1
