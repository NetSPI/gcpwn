"""Re-running a module must store the MOST RECENT value, not skip on PK conflict.

The default `save_service_row` write path upserts (INSERT ... ON CONFLICT(pk) DO
UPDATE), refreshing all non-PK columns -- so when a resource with the same id has
a changed property on a later run, the new value is stored (no stale-cache skip,
no duplicate row). `dont_change` columns are the explicit exception (preserved for
non-refetchable data like an HMAC secret).
"""

from __future__ import annotations

from gcpwn.core.db import DataController


def _controller_with_table(tmp_path):
    dc = DataController.__new__(DataController)
    conn = dc._connect_database(str(tmp_path / "service.db"))
    dc.conn = conn
    dc.cursor = conn.cursor()
    dc._service_primary_key_cache = {}
    conn.execute(
        'CREATE TABLE t (workspace_id INTEGER, name TEXT, state TEXT, secret TEXT, PRIMARY KEY (name))'
    )
    conn.commit()
    return dc, conn


def test_save_service_row_upserts_latest_value_on_rerun(tmp_path):
    dc, conn = _controller_with_table(tmp_path)
    dc.save_service_row("t", {"workspace_id": 1, "name": "r1", "state": "ENABLED", "secret": ""})
    # re-run: SAME id, a changed non-PK property
    dc.save_service_row("t", {"workspace_id": 1, "name": "r1", "state": "PAUSED", "secret": ""})
    rows = conn.execute("SELECT name, state FROM t").fetchall()
    assert len(rows) == 1                 # upsert, not a duplicate
    assert rows[0][1] == "PAUSED"         # latest value, not the stale first one


def test_save_service_row_dont_change_preserves_non_refetchable_value(tmp_path):
    dc, conn = _controller_with_table(tmp_path)
    dc.save_service_row("t", {"workspace_id": 1, "name": "r1", "state": "ENABLED", "secret": "S3CRET"})
    # a later run that can't re-read the secret must NOT blank it, while still
    # refreshing the other columns.
    dc.save_service_row(
        "t",
        {"workspace_id": 1, "name": "r1", "state": "PAUSED", "secret": ""},
        dont_change=["secret"],
    )
    row = conn.execute("SELECT state, secret FROM t").fetchone()
    assert row[0] == "PAUSED"             # refreshed
    assert row[1] == "S3CRET"             # preserved
