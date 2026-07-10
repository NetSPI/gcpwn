"""enum_group_settings: read each Workspace group's access + posting settings.

Reads the cached ``workspace_groups`` table (or a single ``--group-email``) and, for
each, calls the Groups Settings API ``groups.get`` -> flags externally-open /
anyone-can-post / anyone-can-join groups (abuse surfaces). Tenant-scoped; needs
Workspace admin creds or service-account domain-wide delegation (--impersonate /
`configs set workspace_admin_subject`). Run `enum_cloud_identity --groups` first to
populate the group set.
"""

from __future__ import annotations

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import normalize_str_set
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.workspace.common import (
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)
from gcpwn.modules.workspace.groups_settings.utilities.group_settings_helpers import (
    WorkspaceGroupSettingsResource,
)


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID used to resolve directoryCustomerId")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (SA domain-wide delegation)")
        parser.add_argument("--group-email", required=False, help="Single group email to read (default: all cached workspace_groups)")

    return parse_component_args(
        user_args,
        description="Read Google Workspace group access/posting settings",
        components=[],
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))

    if args.group_email:
        group_emails = [str(args.group_email).strip()]
    else:
        rows = session.get_data("workspace_groups", columns=["email"]) or []
        group_emails = sorted(normalize_str_set([r.get('email') for r in rows]))

    if not group_emails:
        print(
            f"{UtilityTools.YELLOW}[*] No groups to read. Run `modules run enum_cloud_identity --groups` "
            f"first, or pass --group-email group@domain.{UtilityTools.RESET}"
        )
        return 1

    resource = WorkspaceGroupSettingsResource(session, subject=subject)
    summary = []
    for group_email in group_emails:
        settings = resource.get(group_email=group_email)
        # A denial here (missing apps.groups.settings scope OR the Groups Settings API
        # not enabled) is global -> stop instead of repeating it per group. The specific
        # cause was already printed by handle_directory_error.
        if resource.last_error_status == 403:
            remaining = len(group_emails) - group_emails.index(group_email) - 1
            if remaining:
                print(f"{UtilityTools.YELLOW}[*] Skipping {remaining} remaining group(s).{UtilityTools.RESET}")
            break
        if settings:
            resource.save(settings, customer_id=customer_id or "my_customer", group_email=group_email)
            summary.append(
                {
                    "group": group_email,
                    "external_members": str(settings.get("allowExternalMembers") or ""),
                    "who_can_join": str(settings.get("whoCanJoin") or ""),
                    "who_can_post": str(settings.get("whoCanPostMessage") or ""),
                }
            )

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace Group Settings",
        summary,
        ["group", "external_members", "who_can_join", "who_can_post"],
        primary_resource="Group Settings",
        primary_sort_key="group",
    )
    return 1
