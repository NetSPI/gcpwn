"""enum_all must not report success over failed work.

Two linked guarantees:
  * a unit whose module reported failure is ledger-marked 'failed', not 'done',
    so --resume retries it instead of skipping it forever;
  * run_parallel returns -1 (and keeps the resume token) when any unit is
    incomplete, instead of printing a green "complete".
"""

from __future__ import annotations

from gcpwn.modules.everything.enumeration import enum_all


class _FakeSession:
    """Minimal session: the ledger helpers only need get_data/insert_data/delete_data."""

    def __init__(self):
        self.rows: list[dict] = []

    def get_data(self, _table, columns=None, where=None):
        matches = [r for r in self.rows if all(r.get(k) == v for k, v in (where or {}).items())]
        if columns:
            return [{c: r.get(c) for c in columns} for r in matches]
        return matches

    def insert_data(self, _table, payload, **_kwargs):
        self.rows.append(dict(payload))

    def delete_data(self, _table, where):
        self.rows = [r for r in self.rows if not all(r.get(k) == v for k, v in where.items())]


class TestLedgerIncompleteDetection:
    def test_all_done_is_complete(self):
        session = _FakeSession()
        for service in ("gke", "kms"):
            enum_all._ledger_mark(session, "proj", service, "done", "run-1")
        assert enum_all._ledger_incomplete(session, "run-1") is False

    def test_a_failed_unit_makes_the_run_incomplete(self):
        session = _FakeSession()
        enum_all._ledger_mark(session, "proj", "gke", "done", "run-1")
        enum_all._ledger_mark(session, "proj", "kms", "failed", "run-1", error="403 everywhere")
        assert enum_all._ledger_incomplete(session, "run-1") is True

    def test_a_pending_unit_makes_the_run_incomplete(self):
        session = _FakeSession()
        enum_all._ledger_mark(session, "proj", "gke", "running", "run-1")
        assert enum_all._ledger_incomplete(session, "run-1") is True

    def test_other_runs_do_not_leak_into_this_one(self):
        session = _FakeSession()
        enum_all._ledger_mark(session, "proj", "gke", "done", "run-1")
        enum_all._ledger_mark(session, "proj", "kms", "failed", "run-2")
        assert enum_all._ledger_incomplete(session, "run-1") is False
        assert enum_all._ledger_incomplete(session, "run-2") is True


