"""
Google Workspace mobile-device enumeration module.

Talks to the *Admin SDK Directory API* via the Google API Discovery client
(`googleapiclient.discovery.build("admin", "directory_v1")`).

Primary API call:
- Directory: `mobiledevices.list` (scoped by `customerId=<directoryCustomerId>`)

Tenant scoping:
- Best case: caller supplies `--customer-id C...` (Directory Customer ID / `directoryCustomerId`)
- Otherwise: try to derive `directoryCustomerId` from the current GCP Organization via
  Resource Manager `organizations.get` (see `resolve_directory_customer_id()`).

Workspace access model: a Workspace admin USER works directly; a service account
needs domain-wide delegation + an admin subject to impersonate (`--impersonate`).
"""

from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.workspace.common import (
    track_workspace_permission as _track_workspace_permission,
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)
from gcpwn.modules.workspace.directory.utilities.mobile_devices_helpers import (
    WorkspaceMobileDevicesResource,
)


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID (numeric) used to resolve directoryCustomerId")
        parser.add_argument("--directory-customer", required=False, default=None, help="Directory API customer selector (default: resolved customer ID or my_customer)")
        parser.add_argument("--page-size", required=False, type=int, default=100, help="Page size (best-effort)")
        parser.add_argument("--projection", required=False, default="FULL", help="Device projection (FULL or BASIC)")
        parser.add_argument("--order-by", required=False, help="Directory mobiledevices.list orderBy (passed as-is)")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (service-account domain-wide delegation); or set `configs set workspace_admin_subject admin@domain`")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace mobile devices (Admin SDK Directory API)",
        components=[],
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False))

    # Tenant scope resolution:
    # - Prefer explicit `--customer-id`
    # - Else try `configs set workspace_customer_id C...`
    # - Else try Resource Manager `organizations.get` to retrieve `directoryCustomerId`
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    # Workspace access model: an admin USER works directly; a service account needs
    # domain-wide delegation + an admin subject to impersonate (see --impersonate).
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))
    UtilityTools.dlog(
        debug,
        "mobile-device scope resolved",
        project_id=session.project_id,
        credname=getattr(session, "credname", None),
        customer_id=customer_id,
    )

    if not customer_id:
        print(
            f"{UtilityTools.YELLOW}[*] Cannot enumerate mobile devices without a customer ID (directoryCustomerId).{UtilityTools.RESET}\n"
            "    Supply `--customer-id C...` (or set `configs set workspace_customer_id C...`),\n"
            "    or `--org-id <numeric>` to derive it from the GCP organization."
        )
        return -1

    devices_resource = WorkspaceMobileDevicesResource(session, subject=subject)
    workspace_actions: dict[str, dict[str, set[str]]] = {"workspace_permissions": {}}

    devices = devices_resource.list(
        customer=str(args.directory_customer or customer_id or "my_customer"),
        max_results=int(args.page_size),
        order_by=getattr(args, "order_by", None),
        projection=str(args.projection),
    )
    UtilityTools.dlog(
        debug,
        "directory mobiledevices.list complete",
        ok=devices_resource.last_call_ok,
        count=len(devices),
    )

    if devices:
        devices_resource.save(devices, customer_id=customer_id)

    if devices_resource.last_call_ok:
        _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="mobiledevices.read")
        if workspace_actions["workspace_permissions"]:
            session.insert_actions(workspace_actions)

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace Mobile Devices",
        [
            {
                "resource_id": str(d.get("resourceId") or ""),
                "email": str((d.get("email") or [""])[0]) if isinstance(d.get("email"), list) else str(d.get("email") or ""),
                "model": str(d.get("model") or ""),
                "os": str(d.get("os") or ""),
                "status": str(d.get("status") or ""),
            }
            for d in devices
        ],
        ["resource_id", "email", "model", "os", "status"],
        primary_resource="Mobile Devices",
        primary_sort_key="resource_id",
    )

    return 1
