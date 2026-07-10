from __future__ import annotations

import argparse

from gcpwn.core.utils.service_runtime import parse_csv_arg
from gcpwn.modules.gcp.assetinventory.utilities.helpers import enumerate_asset_inventory


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate resources + IAM policies via Cloud Asset Inventory",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--scope",
        required=False,
        help="CAI scope: projects/<id>, folders/<id>, or organizations/<id> (default: current project).",
    )
    parser.add_argument(
        "--asset-types",
        dest="asset_types",
        required=False,
        help="Optional comma-separated asset_type filter (e.g. compute.googleapis.com/Instance,iam.googleapis.com/ServiceAccount).",
    )
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")
    return parser.parse_args(user_args)


def run_module(user_args, session):
    """Pull Cloud Asset Inventory once and populate the shared workspace tables.

    A single CAI scan (list_assets RESOURCE + IAM_POLICY) populates iam_allow_policies,
    abstract_tree_hierarchy, iam_service_accounts/keys/roles, compute instances and WIF
    pools/providers across the whole scope -- a force-multiplier that feeds OpenGraph
    (and a fallback when per-service enumeration is denied but cloudasset.* is granted).
    Opt-in in enum_all (only runs with --asset-inventory) because org-wide scans are slow.
    """
    args = _parse_args(user_args)
    scope = str(args.scope or "").strip() or f"projects/{session.project_id}"
    asset_types = parse_csv_arg(args.asset_types) or None

    print(f"[*] Cloud Asset Inventory: scanning {scope} (this can take a while on large orgs)...")
    saved = enumerate_asset_inventory(session, scope=scope, asset_types=asset_types)
    if not saved:
        print(f"[*] No assets returned from Cloud Asset Inventory for {scope} (API disabled, denied, or empty).")
        return 1
    summary = ", ".join(f"{table}={count}" for table, count in sorted(saved.items()))
    print(f"[*] Populated workspace tables from CAI {scope}: {summary}")
    print("[*] These rows feed OpenGraph (process_og) and permission analysis like any enumerated data.")
    return 1
