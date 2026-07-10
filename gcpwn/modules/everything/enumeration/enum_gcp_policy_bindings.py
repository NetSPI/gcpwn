from __future__ import annotations

import argparse
import importlib
import traceback

from gcpwn.core.utils.resume import RunLedger, resolve_run_token
from gcpwn.modules.everything.utilities.iam_policy_bindings import IAMPolicyBindingsResource

_LEDGER_TABLE = "policy_bindings_ledger"

# Single source of truth for the service selectors: (binding-group key, CLI flag,
# help). This one list BOTH generates the argparse flags AND drives selection, so
# a flag and its internal group key are declared exactly once. The flag's dest is
# the group key (e.g. --cloud-run -> dest "cloudrun"), so args need no translation.
SERVICE_GROUP_FLAGS = (
    ("resource_manager", "--resource-manager", "Enumerate org/folder/project IAM policies"),
    ("storage", "--storage", "Enumerate Cloud Storage bucket IAM policies"),
    ("bigquery", "--bigquery", "Enumerate BigQuery dataset IAM policies"),
    ("functions", "--functions", "Enumerate Cloud Functions IAM policies"),
    ("compute", "--compute", "Enumerate Compute Engine instance IAM policies"),
    ("service_accounts", "--service-accounts", "Enumerate service account IAM policies"),
    ("secrets", "--secrets", "Enumerate Secret Manager IAM policies"),
    ("cloudrun", "--cloud-run", "Enumerate Cloud Run service/job IAM policies"),
    ("cloudtasks", "--cloud-tasks", "Enumerate Cloud Tasks queue IAM policies"),
    ("artifactregistry", "--artifact-registry", "Enumerate Artifact Registry repository IAM policies"),
    ("kms", "--cloud-kms", "Enumerate Cloud KMS keyring/cryptokey IAM policies"),
    ("pubsub", "--pubsub", "Enumerate Pub/Sub topic/subscription/snapshot/schema IAM policies"),
    ("servicedirectory", "--service-directory", "Enumerate Service Directory namespace/service IAM policies"),
)


def _parse_args(user_args):
    parser = argparse.ArgumentParser(description="Enumerate IAM allow-policy bindings across cached resources", allow_abbrev=False)
    parser.add_argument(
        "--ensure-tree",
        action="store_true",
        help="If Resource Manager hierarchy is missing, run enum_resources automatically before policy-binding collection.",
    )
    for group_key, flag, help_text in SERVICE_GROUP_FLAGS:
        parser.add_argument(flag, dest=group_key, action="store_true", help=help_text)
    scope_group = parser.add_mutually_exclusive_group(required=False)
    scope_group.add_argument(
        "--scope-hierarchy",
        dest="scope_hierarchy",
        action="store_true",
        help="Collect only org + folder node IAM policies (no project-level resources). Used to pipeline enum_all.",
    )
    scope_group.add_argument(
        "--scope-project",
        dest="scope_project",
        default=None,
        help="Collect IAM policies for a single project node and that project's cached resources only.",
    )
    scope_group.add_argument(
        "--scope-orphans",
        dest="scope_orphans",
        action="store_true",
        help="Collect IAM policies only for cached resources missing a project_id (reconciliation pass).",
    )
    parser.add_argument(
        "--no-sync-users",
        dest="no_sync_users",
        action="store_true",
        help="Skip the principal/user table rebuild at the end (the orchestrator runs it once after all nodes).",
    )
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Verbose low-level debug logging.")
    parser.add_argument(
        "--resume",
        default=None,
        help=(
            "Resume a prior run by its token (printed at that run's start): re-runs ONLY "
            "the service-group units that run left incomplete, instead of starting over."
        ),
    )
    return parser.parse_args(user_args)


def _scope_from_args(args) -> dict | None:
    if getattr(args, "scope_hierarchy", False):
        return {"hierarchy": True}
    project = str(getattr(args, "scope_project", None) or "").strip()
    if project:
        return {"project_id": project}
    if getattr(args, "scope_orphans", False):
        return {"orphans": True}
    return None


def _selected_service_groups(args) -> set[str] | None:
    selected = {group for group, _flag, _help in SERVICE_GROUP_FLAGS if bool(getattr(args, group, False))}
    return selected or None


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected_groups = _selected_service_groups(args)
    scope = _scope_from_args(args)

    setattr(session, "debug", bool(args.debug))

    # A scoped run is driven by the parallel orchestrator, which has already run
    # Resource Manager; don't re-run discovery on top of it.
    should_ensure_tree = scope is None and (
        bool(args.ensure_tree) or selected_groups is None or "resource_manager" in selected_groups
    )
    if should_ensure_tree:
        tree = session.get_data("abstract_tree_hierarchy", columns=["name"], conditions='type IN ("org","folder","project")') or []
        if not tree:
            try:
                module = importlib.import_module("gcpwn.modules.gcp.resourcemanager.enumeration.enum_resources")
                module_args = ["-v"] if getattr(args, "debug", False) else []
                module.run_module(module_args, session)
            except Exception:
                pass

    print("[*] Starting IAM policy binding enumeration")
    if selected_groups:
        print(f"[*] Service filter: {', '.join(sorted(selected_groups))}")
    if scope:
        scope_label = (
            "org + folder nodes" if scope.get("hierarchy")
            else f"project {scope['project_id']}" if scope.get("project_id")
            else "orphan resources" if scope.get("orphans")
            else "all"
        )
        print(f"[*] Scope: {scope_label}")
    print("[*] Capturing raw allow-policy JSON and normalized bindings for cached resources")
    if not getattr(args, "debug", False):
        print("[*] Tip: add --debug for low-level API traces")

    # Per-service-group units so an interrupted run resumes group-by-group. Units to
    # run = the selected filter, else all 13 groups. sync_users (principal rebuild +
    # member_permissions materialization) runs ONCE, on the LAST group of THIS
    # invocation -- it rebuilds from every cached binding, so it's correct whether the
    # run is fresh or resumed (previously-done groups' bindings are already cached).
    run_id, is_resume = resolve_run_token(user_args)
    ledger = RunLedger(session, table=_LEDGER_TABLE, run_id=run_id)
    done_groups = ledger.done()
    no_sync = bool(getattr(args, "no_sync_users", False))

    all_groups = sorted(selected_groups) if selected_groups else [group for group, _flag, _help in SERVICE_GROUP_FLAGS]
    to_run = [group for group in all_groups if group not in done_groups]

    print(f"[*] Run token: {run_id}  (interrupt-safe -- resume with --resume {run_id})")
    if is_resume and done_groups:
        print(f"[*] Resuming: {len(done_groups)} group(s) already done; {len(to_run)} remaining")

    resource = IAMPolicyBindingsResource(session)
    for index, group in enumerate(to_run):
        is_last = index == len(to_run) - 1
        try:
            resource.run(
                save_raw_policies=True,
                services={group},
                scope=scope,
                sync_users=(is_last and not no_sync),
            )
            ledger.mark(group, "done")
        except Exception:
            ledger.mark(group, "failed", error=traceback.format_exc())  # re-runs on resume
            raise
    ledger.clear()  # every requested group finished -> nothing to resume; drop this run's token
    return 1

