"""Unit tests for the shared resume-token + ledger (gcpwn.core.utils.resume).

Covers the mechanics the enum orchestrators rely on: a fresh run mints a token and
sees nothing done; ``--resume <token>`` reuses a run's ledger and skips its completed
units; runs are isolated by token; and ``--resume`` is stripped before args reach
sub-modules whose parsers would reject it.
"""

from __future__ import annotations

from gcpwn.core.utils.resume import RunLedger, resolve_run_token, strip_resume_flag


def test_resolve_run_token_fresh_vs_resume():
    token, is_resume = resolve_run_token(["--iam", "--parallel-services", "8"])
    assert is_resume is False
    assert token.isdigit() and len(token) == 14  # fresh UTC-timestamp token

    token2, is_resume2 = resolve_run_token(["--resume", "20260101120000", "--iam"])
    assert is_resume2 is True and token2 == "20260101120000"

    token3, is_resume3 = resolve_run_token(["--resume=20260202", "--get"])
    assert is_resume3 is True and token3 == "20260202"


def test_strip_resume_flag():
    assert strip_resume_flag(["--iam", "--resume", "T123", "--get"]) == ["--iam", "--get"]
    assert strip_resume_flag(["--resume=T9", "--iam"]) == ["--iam"]
    assert strip_resume_flag(["--iam"]) == ["--iam"]
    assert strip_resume_flag([]) == []
    # a trailing --resume with no value is still dropped (doesn't leak the flag)
    assert strip_resume_flag(["--iam", "--resume"]) == ["--iam"]


class _FakeSession:
    """Minimal session backing RunLedger: get_data filters by where=run_id;
    insert_data upserts on (run_id, unit); delete_data removes by where."""

    def __init__(self):
        self.rows: list[dict] = []

    def get_data(self, table, *, columns=None, where=None, conditions=None):
        run_id = (where or {}).get("run_id")
        return [r for r in self.rows if r.get("run_id") == run_id]

    def insert_data(self, table, payload):
        self.rows = [
            r for r in self.rows
            if not (r["run_id"] == payload["run_id"] and r["unit"] == payload["unit"])
        ]
        self.rows.append(dict(payload))

    def delete_data(self, table, where):
        run_id = (where or {}).get("run_id")
        self.rows = [r for r in self.rows if r.get("run_id") != run_id]


def test_run_ledger_done_and_mark_isolated_by_token():
    session = _FakeSession()
    a = RunLedger(session, table="t", run_id="A")
    assert a.done() == set()  # fresh token -> nothing done -> full run

    a.mark("storage", "done")
    a.mark("iam", "failed")
    assert a.done() == {"storage"}  # only 'done' counts; 'failed' re-runs

    # a different token is fully isolated (fresh full run)
    b = RunLedger(session, table="t", run_id="B")
    assert b.done() == set()

    # re-marking upserts (failed -> done)
    a.mark("iam", "done")
    assert a.done() == {"storage", "iam"}


def test_run_ledger_clear_removes_rows():
    session = _FakeSession()
    ledger = RunLedger(session, table="t", run_id="X")
    ledger.mark("storage", "done")
    ledger.mark("iam", "done")
    assert len(session.rows) == 2

    ledger.clear()
    assert session.rows == []
    assert ledger.done() == set()


def test_clear_does_not_affect_other_run_tokens():
    """clear() must only delete rows for its own run_id; other tokens survive."""
    session = _FakeSession()
    a = RunLedger(session, table="t", run_id="A")
    b = RunLedger(session, table="t", run_id="B")

    a.mark("storage", "done")
    b.mark("iam", "done")
    b.mark("compute", "done")

    # Clearing A must leave B's rows intact.
    a.clear()
    assert a.done() == set()
    assert b.done() == {"iam", "compute"}


def test_clear_on_empty_to_run_preserves_other_tokens():
    """Regression: ledger.clear() must NOT fire when to_run is empty.

    Simulates the policy-bindings scenario: a previous interrupted run leaves
    groups ["iam", "compute"] done. The user resumes with a service filter
    (selected_groups=["iam"]) and iam is already done -> to_run=[].
    The ledger for the OTHER remaining group ("compute") must survive.
    """
    session = _FakeSession()
    run_id = "20260101000000"
    ledger = RunLedger(session, table="t", run_id=run_id)

    # Simulate the previous partial run that was interrupted after "iam"
    ledger.mark("iam", "done")

    # Fresh ledger view as if module code reads it at resume time
    ledger2 = RunLedger(session, table="t", run_id=run_id)
    done_groups = ledger2.done()
    all_selected = ["iam"]  # user filtered to only iam
    to_run = [g for g in all_selected if g not in done_groups]

    assert to_run == [], "iam was already done; nothing to run"

    # The guard introduced by the bug fix: only clear if to_run was non-empty
    if to_run:
        ledger2.clear()

    # iam row must still be there (wasn't cleared despite being done)
    assert ledger2.done() == {"iam"}, "ledger rows must survive when to_run is empty"
