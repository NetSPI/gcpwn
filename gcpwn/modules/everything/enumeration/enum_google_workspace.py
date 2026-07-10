"""enum_google_workspace: orchestrate Google Workspace / Cloud Identity enumeration.

The Workspace counterpart of enum_all (GCP). Workspace is TENANT-scoped, so this is
a run-ONCE orchestrator (not per-project): it runs each registered Workspace
enumerator in turn. Today that is the Cloud Identity groups/memberships/users
module; new Workspace enumerators (admin roles + role assignments, OAuth tokens,
org units, domains, devices) plug into ``_WORKSPACE_MODULES`` as they land.

Degrades gracefully when the caller has no Workspace access -- most GCP credentials
don't. A user that is a Workspace admin works directly; a service account needs
domain-wide delegation + an admin subject to impersonate (see ``--impersonate`` /
``configs set workspace_admin_subject``).
"""

from __future__ import annotations

import importlib

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.resume import RunLedger, resolve_run_token, strip_resume_flag
from gcpwn.modules.workspace.common import (
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)

_LEDGER_TABLE = "workspace_enum_ledger"


def _extract_impersonate(user_args) -> str | None:
    """Pull the --impersonate value out of the raw arg list (this module doesn't argparse)."""
    args = list(user_args or [])
    for index, arg in enumerate(args):
        if arg == "--impersonate" and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--impersonate="):
            return arg.split("=", 1)[1]
    return None

# Dotted paths of the Workspace enumerators to run, in order. Each exposes the
# standard run_module(user_args, session). Grows as new Workspace modules land.
_WORKSPACE_MODULES: tuple[str, ...] = (
    "gcpwn.modules.workspace.cloud_identity.enumeration.enum_cloud_identity",
    "gcpwn.modules.workspace.directory.enumeration.enum_admin_roles",
    "gcpwn.modules.workspace.directory.enumeration.enum_org_units",
    "gcpwn.modules.workspace.directory.enumeration.enum_domains",
    "gcpwn.modules.workspace.directory.enumeration.enum_mobile_devices",
    "gcpwn.modules.workspace.directory.enumeration.enum_oauth_tokens",
    "gcpwn.modules.workspace.groups_settings.enumeration.enum_group_settings",
    "gcpwn.modules.workspace.data_transfer.enumeration.enum_data_transfers",
)


def run_module(user_args, session):
    """Run every registered Workspace enumerator once (tenant-scoped).

    Passes ``user_args`` straight through (each module parses what it needs).
    Returns -1 if any module reported failure, else 1. A module raising is caught
    and reported so one failure doesn't abort the rest.
    """
    user_args = list(user_args or [])
    run_id, is_resume = resolve_run_token(user_args)
    sub_args = strip_resume_flag(user_args)  # sub-enumerators' strict parsers reject --resume
    # Google Drive is heavy (per-user content download) -> OFF unless explicitly requested,
    # so nobody pulls Drive files by accident. The 8 directory enumerators don't define the
    # flag, so strip it from what they receive.
    download_drive = "--download-google-drive" in sub_args
    sub_args = [arg for arg in sub_args if arg != "--download-google-drive"]
    ledger = RunLedger(session, table=_LEDGER_TABLE, run_id=run_id)
    done_enumerators = ledger.done()

    # Up-front access status so the operator isn't left decoding a wall of per-module
    # 403s. Workspace is tenant-scoped: it needs a directoryCustomerId AND either an
    # admin-user cred or a SA impersonating an admin via domain-wide delegation.
    customer_id = resolve_directory_customer_id(session)
    subject = resolve_workspace_admin_subject(session, _extract_impersonate(user_args))
    print(
        f"{UtilityTools.BOLD}[*] Google Workspace enumeration{UtilityTools.RESET} -- "
        f"customer={customer_id or 'UNRESOLVED'}, "
        f"impersonating={subject or '(none; using the credential directly)'}"
    )
    print(
        f"{UtilityTools.BOLD}[*] Run token: {run_id}{UtilityTools.RESET}"
        f"  (interrupt-safe -- resume with:  modules run enum_google_workspace ... --resume {run_id})"
    )
    if not customer_id:
        print(
            f"{UtilityTools.YELLOW}[*] No Google Workspace tenant resolved (no directoryCustomerId).{UtilityTools.RESET}\n"
            "    Provide Workspace admin creds, OR for a service account set up domain-wide delegation and pass\n"
            "    `--impersonate admin@domain` (or `configs set workspace_admin_subject admin@domain`); set the tenant\n"
            "    explicitly with `configs set workspace_customer_id C...` if it can't be derived from the GCP org."
        )

    overall = 1
    had_failure = False
    for module_path in _WORKSPACE_MODULES:
        short = module_path.rsplit(".", 1)[-1]
        if short in done_enumerators:
            print(f"{UtilityTools.BOLD}[*] {UtilityTools.RESET}Workspace enumerator {short}: (resuming -- already done)")
            continue
        print(f"{UtilityTools.BOLD}[*] {UtilityTools.RESET}Workspace enumerator: {UtilityTools.BOLD}{short}{UtilityTools.RESET}")
        try:
            module = importlib.import_module(module_path)
            result = module.run_module(sub_args, session)
            if result == -1:
                overall = -1
                had_failure = True
                ledger.mark(short, "failed", error="module reported failure")  # re-runs on resume
            else:
                ledger.mark(short, "done")
        # SystemExit too: a module's argparse rejecting an arg it doesn't define must
        # not abort the remaining Workspace enumerators.
        except (Exception, SystemExit) as exc:  # one Workspace module failing shouldn't abort the rest
            print(
                f"{UtilityTools.YELLOW}[*] Workspace enumerator {short} failed: "
                f"{type(exc).__name__}: {exc}{UtilityTools.RESET}"
            )
            had_failure = True
            ledger.mark(short, "failed", error=f"{type(exc).__name__}: {exc}")  # re-runs on resume
    if download_drive:
        # Opt-in Google Drive list + content download for every cached user.
        print(f"{UtilityTools.BOLD}[*] Google Drive phase (--download-google-drive): enum_drive --all-users --download{UtilityTools.RESET}")
        try:
            from gcpwn.modules.workspace.apps.drive.enumeration.enum_drive import run_module as run_drive
            drive_args = ["--all-users", "--download"]
            if "-v" in user_args or "--debug" in user_args:
                drive_args.append("-v")
            if run_drive(drive_args, session) == -1:
                overall = -1
        except (Exception, SystemExit) as exc:
            print(f"{UtilityTools.YELLOW}[*] Google Drive phase failed: {type(exc).__name__}: {exc}{UtilityTools.RESET}")

    if not had_failure:
        ledger.clear()  # every enumerator finished -> nothing to resume; drop this run's token
    return overall
