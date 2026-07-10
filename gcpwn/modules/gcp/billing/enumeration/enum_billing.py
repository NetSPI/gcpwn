from __future__ import annotations

import argparse

from gcpwn.modules.gcp.billing.utilities.helpers import get_project_billing_info, list_billing_accounts


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate Cloud Billing accounts (+ their IAM admins) and the current project's billing info",
        allow_abbrev=False,
    )
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")
    return parser.parse_args(user_args)


def run_module(user_args, session):
    """List accessible billing accounts (+ best-effort admin IAM) and the project's billing link.

    Billing accounts are GLOBAL (not project-scoped); billing IAM admins can attach/move
    project billing, a quiet privilege path, so the admin member list is captured per account.
    """
    _parse_args(user_args)
    project_id = session.project_id

    accounts = list_billing_accounts(session)
    for row in accounts:
        session.insert_data("billing_accounts", {"project_id": project_id, **row})

    info = get_project_billing_info(session, project_id)
    if info:
        session.insert_data("project_billing_info", {"project_id": project_id, **info})

    billing_enabled = info["billing_enabled"] if info else "unknown"
    print(f"[*] Cloud Billing: {len(accounts)} accessible billing account(s); "
          f"project {project_id} billing_enabled={billing_enabled}.")
    return 1
