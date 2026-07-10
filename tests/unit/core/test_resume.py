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
    insert_data upserts on (run_id, unit)."""

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
