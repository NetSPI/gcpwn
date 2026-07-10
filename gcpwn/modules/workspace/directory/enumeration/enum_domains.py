"""
Google Workspace domains enumeration module (read-only).

Talks to the *Admin SDK Directory API* via the Google API Discovery client
(``googleapiclient.discovery.build("admin", "directory_v1")``).

Primary API call:
- Admin SDK Directory API: ``domains.list(customer=<customerId>)`` -- returns the
  domains registered for the Workspace tenant (``domainName``, ``isPrimary``,
  ``verified``, ...).

Tenant scoping:
- Best case: caller supplies ``--customer-id C...`` (Directory Customer ID /
  ``directoryCustomerId``).
- Otherwise: try to derive ``directoryCustomerId`` from the current GCP
  Organization via Resource Manager ``organizations.get`` (see
  ``resolve_directory_customer_id()``).

Workspace access model: an admin USER works directly; a service account needs
domain-wide delegation + an admin subject to impersonate (``--impersonate`` /
``configs set workspace_admin_subject admin@domain``).
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
from gcpwn.modules.workspace.directory.utilities.domains_helpers import WorkspaceDomainsResource


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID (numeric) used to resolve directoryCustomerId")
        parser.add_argument("--directory-customer", required=False, default="my_customer", help="Directory API customer selector when no customer ID is known (default: my_customer)")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (service-account domain-wide delegation); or set `configs set workspace_admin_subject admin@domain`")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace domains (Admin SDK Directory API)",
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

    # The Directory API `domains.list` accepts either a Directory Customer ID or the
    # `my_customer` alias. Use the resolved customer ID for the API call when we have
    # it, else fall back to the `my_customer` selector.
    customer_selector = customer_id or str(args.directory_customer or "my_customer")
    # `customer_id` is also the table scope; if we never resolved one, scope/save
    # under whatever selector we used so rows stay tenant-scoped.
    scope_customer_id = customer_id or customer_selector

    UtilityTools.dlog(
        debug,
        "workspace domains scope resolved",
        project_id=session.project_id,
        credname=getattr(session, "credname", None),
        customer_id=customer_id,
        customer_selector=customer_selector,
        subject=subject,
    )

    domains_resource = WorkspaceDomainsResource(session, subject=subject)
    workspace_actions: dict[str, dict[str, set[str]]] = {"workspace_permissions": {}}

    UtilityTools.dlog(debug, "calling directory domains.list", customer=customer_selector)
    raw_domains = domains_resource.list(customer=customer_selector)
    UtilityTools.dlog(
        debug,
        "directory domains.list complete",
        ok=domains_resource.last_call_ok,
        count=len(raw_domains),
        request=domains_resource.last_request,
        error_status=domains_resource.last_error_status,
        error=domains_resource.last_error_message,
    )

    if raw_domains:
        domains_resource.save(raw_domains, customer_id=scope_customer_id)

    if domains_resource.last_call_ok:
        _track_workspace_permission(workspace_actions, customer_id=scope_customer_id, permission="domains.read")
        if workspace_actions["workspace_permissions"]:
            session.insert_actions(workspace_actions)

    if domains_resource.last_call_ok and not raw_domains:
        print(
            f"{UtilityTools.YELLOW}[*] Admin SDK Directory API call succeeded but returned 0 domains for this scope.{UtilityTools.RESET}"
        )

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace Domains",
        [
            {
                "domain_name": str(d.get("domainName") or ""),
                "is_primary": "true" if d.get("isPrimary") else "false",
                "verified": "true" if d.get("verified") else "false",
            }
            for d in raw_domains
        ],
        ["domain_name", "is_primary", "verified"],
        primary_resource="Domains",
        primary_sort_key="domain_name",
    )

    return 1
