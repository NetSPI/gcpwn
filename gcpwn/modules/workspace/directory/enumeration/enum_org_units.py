"""
Google Workspace ORG UNITS enumeration module.

Talks to the Admin SDK Directory API via the Google API Discovery client
(`googleapiclient.discovery.build("admin", "directory_v1")`).

Primary API call:
- Admin SDK Directory: `orgunits.list(customerId=<customerId>, type="all")`
  - Returns `{"organizationUnits": [{orgUnitId, orgUnitPath, name,
    parentOrgUnitPath, ...}]}`

Tenant scoping:
- Best case: caller supplies `--customer-id C...` (Directory Customer ID /
  `directoryCustomerId`).
- Otherwise: derive `directoryCustomerId` from the current GCP Organization via
  Resource Manager `organizations.get` (see `resolve_directory_customer_id`).

Read-only: lists org units only; performs no writes/mutations to Workspace.
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
from gcpwn.modules.workspace.directory.utilities.org_units_helpers import (
    WorkspaceOrgUnitsResource,
)


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID (numeric) used to resolve directoryCustomerId")
        parser.add_argument("--directory-customer", required=False, default=None, help="Directory API customer selector (default: resolved customer ID or my_customer)")
        parser.add_argument("--type", required=False, default="all", dest="org_unit_type", help="Org unit type filter: all or children (default: all)")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (service-account domain-wide delegation); or set `configs set workspace_admin_subject admin@domain`")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace organizational units (Admin SDK Directory API)",
        components=[],
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False))

    # Tenant scope resolution mirrors enum_cloud_identity:
    # explicit --customer-id, else configs, else Resource Manager organizations.get.
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))
    UtilityTools.dlog(
        debug,
        "workspace org units scope resolved",
        project_id=session.project_id,
        credname=getattr(session, "credname", None),
        customer_id=customer_id,
        directory_customer=getattr(args, "directory_customer", None),
        org_unit_type=getattr(args, "org_unit_type", None),
    )

    if not customer_id:
        print(
            f"{UtilityTools.YELLOW}[*] Cannot enumerate org units without a customer ID (directoryCustomerId).{UtilityTools.RESET}\n"
            "    Supply `--customer-id C...` (or set `configs set workspace_customer_id C...`),\n"
            "    or `--org-id <numeric org id>` to resolve it via Resource Manager."
        )
        return -1

    org_units_resource = WorkspaceOrgUnitsResource(session, subject=subject)
    workspace_actions: dict[str, dict[str, set[str]]] = {"workspace_permissions": {}}

    # The Directory selector (`--directory-customer`, default `my_customer`) is used
    # for the API call; the resolved directoryCustomerId is used to scope storage.
    org_units = org_units_resource.list(
        customer=str(args.directory_customer or customer_id or "my_customer"),
        org_unit_type=str(getattr(args, "org_unit_type", "all") or "all"),
    )
    UtilityTools.dlog(
        debug,
        "directory orgunits.list complete",
        ok=org_units_resource.last_call_ok,
        count=len(org_units),
    )

    if org_units:
        org_units_resource.save(org_units, customer_id=customer_id)

    if org_units_resource.last_call_ok:
        _track_workspace_permission(workspace_actions, customer_id=customer_id, permission="orgunits.read")
        if workspace_actions["workspace_permissions"]:
            session.insert_actions(workspace_actions)

    if org_units_resource.last_call_ok and not org_units:
        print(
            f"{UtilityTools.YELLOW}[*] Admin SDK call succeeded but returned 0 org units for this scope.{UtilityTools.RESET}"
        )

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace Org Units",
        [
            {
                "org_unit_path": str(unit.get("orgUnitPath") or ""),
                "name": str(unit.get("name") or ""),
                "parent_org_unit_path": str(unit.get("parentOrgUnitPath") or ""),
            }
            for unit in org_units
        ],
        ["org_unit_path", "name", "parent_org_unit_path"],
        primary_resource="Org Units",
        primary_sort_key="org_unit_path",
    )

    return 1
