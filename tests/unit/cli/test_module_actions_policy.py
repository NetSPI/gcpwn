"""Coverage for the module execution-policy gating in cli/module_actions.py:
the unauth detection + the auth / run-once / project-flag resolution that decides
how every module is dispatched.
"""

from __future__ import annotations

from gcpwn.cli.module_actions import (
    _is_unauth_module,
    _should_prompt_all_projects,
    get_module_action,
)

_UNAUTH = "gcpwn.modules.gcp.cloudfunctions.unauthenticated.unauth_functionbrute"
_ENUM = "gcpwn.modules.gcp.iam.enumeration.enum_iam"
_EXPLOIT = "gcpwn.modules.gcp.iam.exploit.exploit_service_account_keys"

# All Workspace-tenant modules share the same run-once / no-project-flags policy.
_WORKSPACE_MODULE_PATHS = [
    "gcpwn.modules.everything.enumeration.enum_google_workspace",
    "gcpwn.modules.workspace.cloud_identity.enumeration.enum_cloud_identity",
    "gcpwn.modules.workspace.apps.drive.enumeration.enum_drive",
    "gcpwn.modules.workspace.directory.enumeration.enum_admin_roles",
    "gcpwn.modules.workspace.directory.enumeration.enum_org_units",
    "gcpwn.modules.workspace.directory.enumeration.enum_domains",
    "gcpwn.modules.workspace.directory.enumeration.enum_mobile_devices",
    "gcpwn.modules.workspace.directory.enumeration.enum_oauth_tokens",
    "gcpwn.modules.workspace.groups_settings.enumeration.enum_group_settings",
    "gcpwn.modules.workspace.data_transfer.enumeration.enum_data_transfers",
]


def test_is_unauth_module_detects_prefix_and_path_segment():
    assert _is_unauth_module(_UNAUTH) is True                                   # unauth_ name prefix
    assert _is_unauth_module("gcpwn.modules.gcp.x.unauthenticated.foo") is True  # .unauthenticated. segment
    assert _is_unauth_module(_ENUM) is False


def test_unauth_module_needs_no_auth_runs_once_no_project_flags():
    action = get_module_action(_UNAUTH)
    assert action.requires_auth is False
    assert action.run_once is True
    assert action.accepts_project_flags is False


def test_enum_module_requires_auth_and_accepts_project_flags():
    action = get_module_action(_ENUM)
    assert action.requires_auth is True
    assert action.accepts_project_flags is True


def test_all_projects_prompt_suppressed_for_exploit_and_unauth():
    # enum modules may fan out across projects; exploit/unauth default to current only.
    assert _should_prompt_all_projects(_ENUM) is True
    assert _should_prompt_all_projects(_EXPLOIT) is False
    assert _should_prompt_all_projects(_UNAUTH) is False


def test_workspace_modules_run_once_no_project_flags():
    """All Google Workspace / Cloud Identity modules must be run-once with no project flags.

    They are tenant-scoped (not per-GCP-project), so --project-id / --all-projects must
    not apply to them. Regression guard for the MODULE_POLICY_REGISTRY gap where these
    modules fell back to DEFAULT_MODULE_POLICY (per-project, with project flags).
    """
    for path in _WORKSPACE_MODULE_PATHS:
        action = get_module_action(path)
        short = path.rsplit(".", 1)[-1]
        assert action.run_once is True, f"{short}: expected run_once=True, got False"
        assert action.accepts_project_flags is False, (
            f"{short}: expected accepts_project_flags=False, got True"
        )
        assert action.requires_auth is True, f"{short}: expected requires_auth=True"
