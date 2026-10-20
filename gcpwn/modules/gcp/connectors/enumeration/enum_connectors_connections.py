"""Enumerate Integration Connector connections and flag non-default serviceAccount fields.

Any connection with a non-default serviceAccount is a PE indicator: the connector
runtime plane uses that SA for internal GCP API calls (Pub/Sub, BQ, GCS, Secret Manager,
etc.) without enforcing actAs on the connection creator.

See also: exploit_connectors_connection_as_sa
"""

from __future__ import annotations

import argparse
import json

import requests as _rlib

from gcpwn.core.console import UtilityTools
from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.service_runtime import DownloadBudget
from gcpwn.modules.gcp.connectors.utilities.helpers import (
    _CONN_BASE,
    _DEFAULT_REGIONS,
    caller_token,
    get_connection,
    list_connections,
)

_CONN_PERMISSIONS = permissions_with_prefixes("connectors.connections.")


def _test_iam_rest(tok: str, resource_name: str, permissions: tuple) -> list[str]:
    try:
        resp = _rlib.post(
            f"{_CONN_BASE}/{resource_name}:testIamPermissions",
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json={"permissions": list(permissions)},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("permissions", [])
    except Exception:
        pass
    return []


def run_module(user_args, session):
    parser = argparse.ArgumentParser(
        description="Enumerate Integration Connector connections; flag non-default serviceAccount",
        allow_abbrev=False,
    )
    parser.add_argument("--region", default=None,
                        help="Single region to enumerate (default: all common regions)")
    parser.add_argument("--regions-list", default=None,
                        help="Comma-separated regions to enumerate")
    parser.add_argument("--download", action="store_true",
                        help="Download full connection JSON (including authConfig) to disk per connection")
    parser.add_argument("--iam", action="store_true",
                        help="Run testIamPermissions on each discovered connection")
    args = parser.parse_args(user_args)

    project_id = session.project_id
    if not project_id:
        print(f"{UtilityTools.RED}[!] No project context.{UtilityTools.RESET}")
        return -1

    if args.region:
        regions = [args.region]
    elif args.regions_list:
        regions = [r.strip() for r in args.regions_list.split(",") if r.strip()]
    else:
        regions = _DEFAULT_REGIONS

    token = caller_token(session)
    found_any = False
    pe_candidates: list[tuple[str, str, str]] = []
    found_names: list[tuple[str, str]] = []
    action_dict: dict = {}

    for region in regions:
        conns = list_connections(token, project_id, region)
        if not conns:
            continue

        print(f"\n{UtilityTools.CYAN}[*] {region} — {len(conns)} connection(s){UtilityTools.RESET}")
        found_any = True

        for c in conns:
            name = c.get("name", "")
            conn_id = name.split("/")[-1] if "/" in name else name
            state = c.get("connectorVersion", "").split("/connectors/")[-1].split("/")[0] if c.get("connectorVersion") else "unknown"
            sa = c.get("serviceAccount", "")
            status = c.get("status", {}).get("state", "")

            sa_label = f"  SA={sa}" if sa else ""
            flag = f" {UtilityTools.YELLOW}[PE candidate — actAs NOT enforced]{UtilityTools.RESET}" if sa else ""
            print(f"  {conn_id:<40s} connector={state:<16s} state={status:<12s}{sa_label}{flag}")

            if sa:
                pe_candidates.append((region, conn_id, sa))
            if name:
                found_names.append((region, name))
                if args.iam and _CONN_PERMISSIONS:
                    token = caller_token(session)
                    granted = _test_iam_rest(token, name, _CONN_PERMISSIONS)
                    if granted:
                        print(f"    {UtilityTools.GREEN}[IAM] {conn_id}: {granted}{UtilityTools.RESET}")
                        record_permissions(
                            action_dict, permissions=granted,
                            project_id=project_id,
                            resource_type="connections",
                            resource_label=name,
                        )

    if not found_any:
        print(f"{UtilityTools.YELLOW}[*] No connections found in scanned regions.{UtilityTools.RESET}")

    if pe_candidates:
        print(f"\n{UtilityTools.YELLOW}[!] {len(pe_candidates)} PE candidate(s) — connections with non-default serviceAccount:{UtilityTools.RESET}")
        for region, conn_id, sa in pe_candidates:
            print(f"  {region}/{conn_id} → SA={sa}")
        print("\n    Run exploit_connectors_connection_as_sa to exploit these paths.")

    if args.download and found_names:
        _download_connections(session, project_id, token, found_names)

    if action_dict:
        session.insert_actions(action_dict, project_id)

    return 1 if found_any else 0


def _download_connections(
    session,
    project_id: str,
    token: str,
    found_names: list[tuple[str, str]],
) -> None:
    """Download full connection JSON (including authConfig) to the session download dir.

    Uses the already-collected resource names from the enumeration pass to avoid
    re-listing. Calls get_connection per name so the full authConfig is included
    (list responses may omit sensitive credential sub-fields).
    """
    budget = DownloadBudget(session, label="connector connection configs")
    downloaded = 0

    for region, name in found_names:
        if budget.exceeded():
            break
        conn_id = name.split("/")[-1] if "/" in name else name
        # GET the individual connection — list responses can omit authConfig details.
        full = get_connection(token, name)
        if full is None:
            print(f"{UtilityTools.YELLOW}[*] Could not fetch full JSON for {conn_id} — skipping.{UtilityTools.RESET}")
            continue
        filename = f"{conn_id}.json"
        path = resolve_download_path(
            session, service_name="connectors", project_id=project_id,
            subdirs=[region], filename=filename,
        )
        path.write_text(json.dumps(full, indent=2), encoding="utf-8")
        print(f"{UtilityTools.GREEN}[+] Saved connector JSON → {path}{UtilityTools.RESET}")
        downloaded += 1

    if downloaded:
        print(f"{UtilityTools.CYAN}[*] Downloaded {downloaded} connection JSON file(s).{UtilityTools.RESET}")
    else:
        print(f"{UtilityTools.YELLOW}[*] No connection JSON files downloaded.{UtilityTools.RESET}")
