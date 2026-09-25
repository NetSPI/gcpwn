"""Coverage for WorkspaceConfig (config.py) and the workspace REPL command helpers.

Tests focus on:
- add_or_update_tenant round-trips (credname + admin_subject survive to_json_string)
- remove_tenant on empty list does not crash
- swap_workspace_tenant --cred-also path: must NOT pass a string to swap_cred()
  (regression for AttributeError: 'str' object has no attribute 'credname')
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from gcpwn.core.config import WorkspaceConfig


# ---------------------------------------------------------------------------
# WorkspaceConfig helpers
# ---------------------------------------------------------------------------


def test_add_tenant_persists_credname_and_admin():
    """workspace add C0test --admin admin@test.com --cred mycred must survive round-trip."""
    cfg = WorkspaceConfig()
    cfg.add_or_update_tenant(
        {
            "customer_id": "C0test",
            "admin_subject": "admin@test.com",
            "credname": "mycred",
            "domain": None,
            "org_id": None,
        }
    )

    serialized = cfg.to_json_string()
    data = json.loads(serialized)
    tenants = data["workspace_tenants"]
    assert len(tenants) == 1
    assert tenants[0]["customer_id"] == "C0test"
    assert tenants[0]["admin_subject"] == "admin@test.com"
    assert tenants[0]["credname"] == "mycred"


def test_add_tenant_returns_true_for_new_false_for_update():
    cfg = WorkspaceConfig()
    assert cfg.add_or_update_tenant({"customer_id": "C0a"}) is True   # new
    assert cfg.add_or_update_tenant({"customer_id": "C0a"}) is False  # update


def test_get_tenant_returns_copy_so_mutation_is_safe():
    cfg = WorkspaceConfig()
    cfg.add_or_update_tenant({"customer_id": "C0b", "domain": "corp.com"})
    copy = cfg.get_tenant("C0b")
    assert copy is not None
    copy["domain"] = "hacked.com"
    # Original must be unchanged
    assert cfg.get_tenant("C0b")["domain"] == "corp.com"


def test_remove_tenant_on_empty_list_returns_false_no_crash():
    cfg = WorkspaceConfig()
    assert cfg.workspace_tenants == []
    assert cfg.remove_tenant("C0nonexistent") is False  # must not raise


def test_remove_tenant_clears_entry():
    cfg = WorkspaceConfig()
    cfg.add_or_update_tenant({"customer_id": "C0del"})
    assert cfg.remove_tenant("C0del") is True
    assert cfg.get_tenant("C0del") is None


def test_to_json_string_roundtrip_preserves_tenants():
    cfg = WorkspaceConfig()
    cfg.add_or_update_tenant({"customer_id": "C0rt", "admin_subject": "a@b.com", "credname": "cred1"})
    cfg.workspace_customer_id = "C0rt"

    serialized = cfg.to_json_string()
    cfg2 = WorkspaceConfig(json_data=serialized)

    assert cfg2.workspace_customer_id == "C0rt"
    assert len(cfg2.workspace_tenants) == 1
    t = cfg2.workspace_tenants[0]
    assert t["admin_subject"] == "a@b.com"
    assert t["credname"] == "cred1"


def test_print_json_formatted_does_not_crash_with_empty_tenants(capsys):
    """max(len(key) for key in data.keys()) must not raise on the fixed key set."""
    cfg = WorkspaceConfig()
    cfg.print_json_formatted()  # must not raise ValueError
    captured = capsys.readouterr()
    assert "workspace_tenants" in captured.out


# ---------------------------------------------------------------------------
# swap_workspace_tenant --cred-also: regression for AttributeError crash
# ---------------------------------------------------------------------------


def _make_processor_with_tenant(customer_id, credname):
    """Build a minimal CommandProcessor-like object with the fixed swap path.

    We don't instantiate CommandProcessor (it loads DB / module files on init).
    We test the exact lines in swap_workspace_tenant that previously crashed.
    """
    from gcpwn.core.config import WorkspaceConfig

    cfg = WorkspaceConfig()
    cfg.add_or_update_tenant(
        {"customer_id": customer_id, "credname": credname, "admin_subject": "admin@corp.com"}
    )
    cfg.workspace_customer_id = customer_id
    cfg.workspace_admin_subject = "admin@corp.com"

    session = MagicMock()
    session.workspace_config = cfg
    session.set_configs = MagicMock()
    return session


def test_swap_workspace_tenant_cred_also_calls_load_stored_creds_not_swap_cred():
    """--cred-also must call session.load_stored_creds(credname) directly.

    Regression: previously called self.swap_cred(credname_string) which crashed with
    AttributeError: 'str' object has no attribute 'credname'.
    """
    from gcpwn.cli.workspace_instructions import CommandProcessor

    session = _make_processor_with_tenant("C0credtest", "my_oauth_cred")
    session.load_stored_creds = MagicMock(return_value=True)

    # Patch out __init__ so we don't touch the DB or filesystem.
    with patch.object(CommandProcessor, "__init__", lambda *_a, **_kw: None):
        proc = CommandProcessor.__new__(CommandProcessor)
        proc.session = session

        # This must not raise AttributeError.
        proc.swap_workspace_tenant("C0credtest", cred_also=True)

    session.load_stored_creds.assert_called_once_with("my_oauth_cred")


def test_swap_workspace_tenant_cred_also_missing_credname_no_crash():
    """--cred-also with a tenant that has no credname must be a silent no-op."""
    from gcpwn.cli.workspace_instructions import CommandProcessor
    from gcpwn.core.config import WorkspaceConfig

    cfg = WorkspaceConfig()
    cfg.add_or_update_tenant({"customer_id": "C0nocred"})
    cfg.workspace_customer_id = "C0nocred"

    session = MagicMock()
    session.workspace_config = cfg
    session.set_configs = MagicMock()
    session.load_stored_creds = MagicMock()

    with patch.object(CommandProcessor, "__init__", lambda *_a, **_kw: None):
        proc = CommandProcessor.__new__(CommandProcessor)
        proc.session = session

        proc.swap_workspace_tenant("C0nocred", cred_also=True)

    session.load_stored_creds.assert_not_called()
