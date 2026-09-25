"""Unit tests for collect_sqlite_export_bundle table_name filter.

Tests: filtering by table name, missing table, and no filter (all tables).
Uses an in-memory SQLite DB so these run without a real workspace.
"""
from __future__ import annotations

import sqlite3
import tempfile
import os


def _create_db_with_tables(path: str) -> None:
    """Create a small SQLite file with two service tables."""
    con = sqlite3.connect(path)
    with con:
        con.execute("CREATE TABLE iam_service_accounts (workspace_id INTEGER, name TEXT, email TEXT)")
        con.execute("INSERT INTO iam_service_accounts VALUES (1, 'sa-a', 'a@p.iam.gserviceaccount.com')")
        con.execute("INSERT INTO iam_service_accounts VALUES (1, 'sa-b', 'b@p.iam.gserviceaccount.com')")
        con.execute("CREATE TABLE gcs_buckets (workspace_id INTEGER, name TEXT, location TEXT)")
        con.execute("INSERT INTO gcs_buckets VALUES (1, 'bucket-1', 'US')")
    con.close()


def test_table_name_filter_returns_only_matching_table():
    from gcpwn.core.utils.module_helpers import collect_sqlite_export_bundle

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_db_with_tables(db_path)
        result = collect_sqlite_export_bundle(db_paths=[db_path], table_name="iam_service_accounts")
        assert result["summary"]["tables"] == 1
        assert result["summary"]["rows"] == 2
        # All records should be from the filtered table
        assert all(r["table_name"] == "iam_service_accounts" for r in result["records"])
    finally:
        os.unlink(db_path)


def test_table_name_filter_no_match_returns_empty():
    from gcpwn.core.utils.module_helpers import collect_sqlite_export_bundle

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_db_with_tables(db_path)
        result = collect_sqlite_export_bundle(db_paths=[db_path], table_name="nonexistent_table_xyz")
        assert result["summary"]["tables"] == 0
        assert result["summary"]["rows"] == 0
        assert result["records"] == []
    finally:
        os.unlink(db_path)


def test_no_table_name_filter_returns_all_tables():
    from gcpwn.core.utils.module_helpers import collect_sqlite_export_bundle

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        _create_db_with_tables(db_path)
        result = collect_sqlite_export_bundle(db_paths=[db_path], table_name=None)
        assert result["summary"]["tables"] == 2
        assert result["summary"]["rows"] == 3  # 2 SA + 1 bucket
    finally:
        os.unlink(db_path)


def test_empty_db_paths_returns_empty_bundle():
    from gcpwn.core.utils.module_helpers import collect_sqlite_export_bundle

    result = collect_sqlite_export_bundle(db_paths=[], table_name=None)
    assert result["summary"]["tables"] == 0
    assert result["summary"]["rows"] == 0


def test_nonexistent_db_file_skipped_without_crash():
    """iter_sqlite_tables_from_paths should warn and skip non-SQLite/missing files."""
    from gcpwn.core.utils.module_helpers import collect_sqlite_export_bundle

    result = collect_sqlite_export_bundle(db_paths=["/tmp/totally_does_not_exist_gcpwn_test.db"], table_name=None)
    # Must not raise; returns empty
    assert result["summary"]["rows"] == 0
