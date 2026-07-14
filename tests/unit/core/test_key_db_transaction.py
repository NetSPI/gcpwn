"""Regression tests for DataController.transaction() write-batching.

Batching turns per-row commits (one fsync each) into a single fsync for the whole
block -- the write-heavy-enum speedup. These lock in the semantics that make it safe:
deferred commit, one commit at block exit, rollback on error, read-your-writes inside
the batch (same connection), and nesting (inner blocks join the outer).
"""

from __future__ import annotations

import pytest

from gcpwn.core.db import DataController


def _controller_with_table(tmp_path):
    dc = DataController.__new__(DataController)
    conn = dc._connect_database(str(tmp_path / "service.db"))
    dc.conn = conn
    dc.cursor = conn.cursor()
    dc._service_primary_key_cache = {}
    conn.execute("CREATE TABLE t (workspace_id INTEGER, name TEXT, PRIMARY KEY (name))")
    conn.commit()
    return dc, conn


def _count(dc):
    return len(dc.select_rows("t", where={"workspace_id": 1}))


def test_batch_defers_commit_and_commits_once(tmp_path):
    dc, conn = _controller_with_table(tmp_path)
    with dc.transaction():
        for i in range(5):
            dc.save_service_row("t", {"workspace_id": 1, "name": f"r{i}"})
        # Mid-batch: a transaction is open and NOT yet committed.
        assert conn.in_transaction is True
    # After the block: committed exactly once, all rows durable.
    assert conn.in_transaction is False
    assert _count(dc) == 5


def test_read_your_writes_inside_batch(tmp_path):
    dc, _ = _controller_with_table(tmp_path)
    with dc.transaction():
        dc.save_service_row("t", {"workspace_id": 1, "name": "inside"})
        # Same connection -> the uncommitted row is visible to reads in the batch.
        got = dc.select_rows("t", where={"workspace_id": 1, "name": "inside"})
        assert got and got[0]["name"] == "inside"


def test_rollback_on_exception_discards_batch(tmp_path):
    dc, _ = _controller_with_table(tmp_path)
    dc.save_service_row("t", {"workspace_id": 1, "name": "keep"})
    with pytest.raises(RuntimeError):
        with dc.transaction():
            dc.save_service_row("t", {"workspace_id": 1, "name": "dropme"})
            raise RuntimeError("boom")
    names = {r["name"] for r in dc.select_rows("t", where={"workspace_id": 1})}
    assert names == {"keep"}  # the pre-batch row survives; the batched row is gone


def test_nested_transaction_joins_outer_single_commit(tmp_path):
    dc, conn = _controller_with_table(tmp_path)
    with dc.transaction():
        dc.save_service_row("t", {"workspace_id": 1, "name": "outer"})
        with dc.transaction():
            dc.save_service_row("t", {"workspace_id": 1, "name": "inner"})
            # Inner block does NOT commit -- the outer owns it.
            assert conn.in_transaction is True
        assert conn.in_transaction is True  # still open after inner exits
    assert conn.in_transaction is False
    assert _count(dc) == 2


def test_no_batch_commits_per_row(tmp_path):
    """Outside transaction() the behavior is unchanged: each save commits immediately."""
    dc, conn = _controller_with_table(tmp_path)
    dc.save_service_row("t", {"workspace_id": 1, "name": "r1"})
    assert conn.in_transaction is False  # committed, no lingering transaction
    assert _count(dc) == 1
