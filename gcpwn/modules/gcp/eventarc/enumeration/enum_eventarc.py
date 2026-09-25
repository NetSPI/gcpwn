from __future__ import annotations

import argparse
import json

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.eventarc.utilities.helpers import (
    EventarcTriggersResource,
    resolve_locations,
)


COMPONENTS = [
    Component("triggers", EventarcTriggersResource, "Eventarc Triggers", "Triggers",
              help_text="Enumerate Eventarc triggers", scope=REGION,
              supports_iam=False,
              manual_id_arg="trigger_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "triggers", 1),
              manual_error="Invalid trigger ID format. Use LOCATION/TRIGGER_ID or projects/PROJECT_ID/locations/LOCATION/triggers/TRIGGER_ID.",
              manual_help="Trigger IDs as LOCATION/TRIGGER_ID or full projects/.../triggers/... names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Eventarc locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Eventarc resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "download", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(
        session, args, components=COMPONENTS, column_name="eventarc_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_eventarc",
    )

    if getattr(args, "download", False):
        project_id = session.project_id or ""
        written = 0
        for row in discovered.get("triggers", []):
            if not isinstance(row, dict):
                continue
            trigger_id = (row.get("trigger_id") or
                          (row.get("name") or "").split("/")[-1] or "unknown")
            dest = resolve_download_path(
                session,
                service_name="eventarc",
                project_id=project_id,
                subdirs=["triggers"],
                filename=f"{trigger_id}.json",
            )
            try:
                dest.write_text(json.dumps(row, indent=2, default=str), encoding="utf-8")
                print(f"[*] Wrote trigger definition to {dest}")
                written += 1
            except Exception as exc:
                print(f"[!] Failed to write trigger {trigger_id}: {exc}")
        if written:
            print(f"[*] Downloaded {written} trigger definition(s).")
        elif discovered.get("triggers"):
            print("[*] No trigger definitions written.")
        else:
            print("[*] No Eventarc triggers found to download.")

    return 1
