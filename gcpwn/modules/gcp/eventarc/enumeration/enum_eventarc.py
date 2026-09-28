from __future__ import annotations

import json

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
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
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Eventarc resources",
        region_label="Eventarc locations",
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
