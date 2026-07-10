from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.clouddns.utilities.helpers import CloudDnsManagedZonesResource, CloudDnsRecordSetsResource


COMPONENTS = [
    Component("zones", CloudDnsManagedZonesResource, "Cloud DNS Managed Zones", "Zones",
              help_text="Enumerate Cloud DNS managed zones", scope=PROJECT, primary_sort_key="dns_name",
              columns=["name", "dns_name", "type", "description"],
              manual_id_arg="zone_names", manual_help="Managed zone names (comma-separated)."),
    Component("record_sets", CloudDnsRecordSetsResource, "Cloud DNS Record Sets", "Record Sets",
              help_text="Enumerate Cloud DNS record sets (per managed zone)", scope=NESTED, parent_key="zones",
              dependency_label="Cloud DNS zones", save_parent_kwarg="parent", primary_sort_key="zone_name",
              columns=["zone_name", "name", "type", "ttl", "rrdatas"], supports_get=False, supports_iam=False,
              list_kwargs=lambda args: {"record_type": getattr(args, "record_type", None)}),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--record-type", type=str, required=False, help="Filter record sets by type (e.g. A, CNAME, TXT)")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud DNS resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on managed zones"},
            "download": {"help": "Write record sets to per-zone CSV-style text files"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.record_sets = True

    discovered = run_components(session, args, components=COMPONENTS, column_name="clouddns_actions_allowed",
                                module_name="enum_clouddns")

    if getattr(args, "download", False):
        project_id = session.project_id
        records_resource = CloudDnsRecordSetsResource(session)
        by_zone: dict[str, list] = defaultdict(list)
        for record in discovered.get("record_sets", []):
            by_zone[str(record.get("zone_name") or "").strip()].append(record)
        downloaded_paths = []
        for zone_name, records in by_zone.items():
            path = records_resource.download_record_sets(project_id=project_id, zone_name=zone_name, records=records)
            if path is not None:
                downloaded_paths.append(str(path))
        for path in downloaded_paths:
            print(f"[*] Wrote Cloud DNS record sets to {path}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} Cloud DNS record-set file(s) for project {project_id}.")
        else:
            print(f"[*] No Cloud DNS record sets were available to download for project {project_id}.")
    return 1
