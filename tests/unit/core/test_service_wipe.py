"""Unit tests for DataController.plan_service_wipe + wipe_service_rows.

Confirms:
- plan_service_wipe correctly identifies workspace-scoped tables and counts rows
- plan_service_wipe is read-only (tables_with_rows from plan is usable for wipe)
- wipe_service_rows deletes rows in the target workspace, leaving other workspaces
- control-plane tables (workspaces, session, session_actions) are never enumerated
"""
from __future__ import annotations

from gcpwn.core.db import DataController


def _controller(tmp_path):
    """Build a minimal DataController with a service.db wired to conn/cursor."""
    dc = DataController.__new__(DataController)
    conn = dc._connect_database(str(tmp_path / "service.db"))
    dc.conn = conn
    dc.cursor = conn.cursor()
    dc._service_primary_key_cache = {}
    dc._tx_depth = 0
    dc._lock = __import__("threading").RLock()
    dc.database_path = str(tmp_path / "service.db")
    return dc


def _setup_tables(dc):
    """Create two service tables (with workspace_id) and one control-plane table."""
    dc.conn.executescript("""
        CREATE TABLE iam_service_accounts (workspace_id INTEGER, name TEXT PRIMARY KEY);
        INSERT INTO iam_service_accounts VALUES (1, 'sa-a');
        INSERT INTO iam_service_accounts VALUES (1, 'sa-b');
        INSERT INTO iam_service_accounts VALUES (2, 'sa-c');

        CREATE TABLE gcs_buckets (workspace_id INTEGER, name TEXT PRIMARY KEY);
        INSERT INTO gcs_buckets VALUES (1, 'bucket-1');

        CREATE TABLE no_workspace_col (name TEXT PRIMARY KEY);
        INSERT INTO no_workspace_col VALUES ('row-without-ws');

        CREATE TABLE workspaces (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO workspaces VALUES (1, 'ws1');
    """)
    dc.conn.commit()


def test_plan_identifies_candidate_and_non_workspace_tables(tmp_path):
    dc = _controller(tmp_path)
    _setup_tables(dc)

    plan = dc.plan_service_wipe(workspace_id=1)

    table_names_candidate = [e["table_name"] for e in plan["candidate_tables"]]
    assert "iam_service_accounts" in table_names_candidate
    assert "gcs_buckets" in table_names_candidate

    # workspaces is a control-plane table — must NOT appear in candidate_tables
    assert "workspaces" not in table_names_candidate

    # no_workspace_col has no workspace_id column -> non-workspace list
    assert "no_workspace_col" in plan["non_workspace_tables"]


def test_plan_counts_only_workspace_scoped_rows(tmp_path):
    dc = _controller(tmp_path)
    _setup_tables(dc)

    plan = dc.plan_service_wipe(workspace_id=1)

    # workspace_id=1 has 2 SAs and 1 bucket = 3 rows
    assert plan["total_rows"] == 3

    tables_with_rows = {e["table_name"]: e["row_count"] for e in plan["tables_with_rows"]}
    assert tables_with_rows.get("iam_service_accounts") == 2
    assert tables_with_rows.get("gcs_buckets") == 1


def test_plan_is_read_only_no_rows_deleted(tmp_path):
    dc = _controller(tmp_path)
    _setup_tables(dc)

    dc.plan_service_wipe(workspace_id=1)

    # After planning, rows are still there
    row = dc.conn.execute("SELECT COUNT(1) FROM iam_service_accounts").fetchone()
    assert row[0] == 3


def test_wipe_deletes_target_workspace_only(tmp_path):
    dc = _controller(tmp_path)
    _setup_tables(dc)

    plan = dc.plan_service_wipe(workspace_id=1)
    result = dc.wipe_service_rows(1, planned_tables_with_rows=plan["tables_with_rows"])

    assert result["deleted_rows"] == 3

    # workspace_id=2 row must be intact
    row = dc.conn.execute("SELECT COUNT(1) FROM iam_service_accounts WHERE workspace_id=2").fetchone()
    assert row[0] == 1

    # workspace_id=1 rows gone
    row = dc.conn.execute("SELECT COUNT(1) FROM iam_service_accounts WHERE workspace_id=1").fetchone()
    assert row[0] == 0


def test_plan_all_workspaces_counts_all_rows(tmp_path):
    dc = _controller(tmp_path)
    _setup_tables(dc)

    plan = dc.plan_service_wipe(workspace_id=1, all_workspaces=True)

    # all_workspaces: should count all 3 SAs (ws1+ws2) + 1 bucket = 4 rows
    assert plan["total_rows"] == 4
