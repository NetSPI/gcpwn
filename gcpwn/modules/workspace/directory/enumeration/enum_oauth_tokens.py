"""enum_oauth_tokens: enumerate Workspace 3rd-party OAuth app grants, per user.

Reads the user set (the cached workspace_users table, or a single --user-key) and,
for each, lists the OAuth applications they have authorized via the Admin SDK
Directory API. Surfaces over-privileged / anomalous 3rd-party app grants. Tenant-
scoped; needs Workspace admin creds or service-account domain-wide delegation
(--impersonate / `configs set workspace_admin_subject`).
"""

from __future__ import annotations

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import normalize_str_set
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.workspace.common import (
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)
from gcpwn.modules.workspace.directory.utilities.oauth_tokens_helpers import (
    WorkspaceOAuthTokensResource,
)


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID used to resolve directoryCustomerId")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (SA domain-wide delegation)")
        parser.add_argument("--user-key", required=False, help="Single user email to scan (default: all cached workspace_users)")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace 3rd-party OAuth app grants per user",
        components=[],
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))

    # User set: explicit --user-key, else draw on the already-enumerated workspace_users.
    if args.user_key:
        user_emails = [str(args.user_key).strip()]
    else:
        rows = session.get_data("workspace_users", columns=["email"]) or []
        user_emails = sorted(normalize_str_set([r.get('email') for r in rows]))

    if not user_emails:
        print(
            f"{UtilityTools.YELLOW}[*] No users to scan for OAuth grants. Run "
            f"`modules run enum_cloud_identity --users` first, or pass --user-key user@domain.{UtilityTools.RESET}"
        )
        return 1

    resource = WorkspaceOAuthTokensResource(session, subject=subject)
    workspace_actions: dict[str, dict[str, set]] = {"workspace_permissions": {}}
    summary: list[dict[str, str]] = []
    any_ok = False

    for email in user_emails:
        tokens = resource.list(user_key=email)
        any_ok = any_ok or bool(resource.last_call_ok)
        # admin.directory.user.security denial is scope-level (global), so a 403 on
        # one user means every user 403s -- stop instead of spamming one line each.
        if resource.last_error_status == 403:
            remaining = len(user_emails) - user_emails.index(email) - 1
            print(
                f"{UtilityTools.YELLOW}[*] OAuth-token access denied (admin.directory.user.security is separately "
                f"elevated). Authorize that scope for the SA domain-wide-delegation client (or use a Workspace admin "
                f"credential). Skipping {remaining} remaining user(s).{UtilityTools.RESET}"
            )
            break
        if tokens:
            resource.save(tokens, customer_id=customer_id or "my_customer", user_email=email)
            for token in tokens:
                summary.append(
                    {
                        "user": email,
                        "app": str(token.get("displayText") or token.get("clientId") or ""),
                        "scopes": str(len(token.get("scopes") or [])),
                    }
                )

    if any_ok and customer_id:
        workspace_actions["workspace_permissions"].setdefault(customer_id, set()).add("users.security.tokens.read")
        session.insert_actions(workspace_actions)

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace OAuth App Grants",
        summary,
        ["user", "app", "scopes"],
        primary_resource="OAuth Grants",
        primary_sort_key="user",
    )
    return 1
