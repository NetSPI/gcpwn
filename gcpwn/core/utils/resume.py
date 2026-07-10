"""Shared resume-token + progress-ledger for the long-running enum orchestrators.

The "everything" enumerators (enum_all/enum_gcp via run_parallel, plus
enum_gcp_policy_bindings and enum_google_workspace) decompose their work into
independent units and record each unit's completion in an SQLite ledger keyed by a
per-run TOKEN. A plain run mints a fresh token and starts from scratch; passing
``--resume <token>`` reuses that run's ledger and skips the units it already
finished, so an interrupted run picks up where it left off.

There is NO server-side state -- the token IS the ledger key, scoped to the
workspace DB. ``resolve_run_token`` mints/parses it; ``RunLedger`` is the generic
(run_id, unit)-keyed table wrapper. enum_all keeps its own richer
(project_id, service) ledger but shares ``resolve_run_token`` from here.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone


def resolve_run_token(user_args) -> tuple[str, bool]:
    """Resolve the run/resume token for this invocation.

    ``--resume <token>`` reuses a prior run's ledger (skipping the units it already
    finished); with no ``--resume`` a fresh UTC-timestamp token is minted so the run
    starts from the beginning. Returns ``(run_id, is_resume)``. Tolerant of any other
    flags in ``user_args``.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--resume", dest="resume", default=None)
    parsed, _ = parser.parse_known_args(list(user_args or []))
    token = str(parsed.resume or "").strip()
    if token:
        return token, True
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"), False


def strip_resume_flag(user_args) -> list[str]:
    """Return ``user_args`` with ``--resume <token>`` removed.

    Orchestrators forward their args to sub-modules whose (strict) parsers would
    reject ``--resume``; strip it before delegating.
    """
    args = list(user_args or [])
    out: list[str] = []
    skip_next = False
    for i, token in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if token == "--resume":
            skip_next = i + 1 < len(args)  # drop the flag and its value
            continue
        if token.startswith("--resume="):
            continue
        out.append(token)
    return out


class RunLedger:
    """A per-(run_id, unit) resume ledger over one workspace-scoped service table.

    Units are opaque strings. ``done()`` returns the units marked ``"done"`` under
    this run_id; ``mark()`` upserts a unit's status. A fresh token sees no done units
    (full run); a resumed token re-reads that token's completed units so the caller
    can skip them. The table must have columns (run_id, unit, status, error) with PK
    (run_id, unit) -- see database_info.json.
    """

    def __init__(self, session, *, table: str, run_id: str) -> None:
        self.session = session
        self.table = table
        self.run_id = run_id

    def done(self) -> set[str]:
        rows = self.session.get_data(
            self.table, columns=["unit", "status"], where={"run_id": self.run_id}
        ) or []
        return {str(row.get("unit")) for row in rows if str(row.get("status") or "") == "done"}

    def mark(self, unit: str, status: str, *, error: str = "") -> None:
        self.session.insert_data(
            self.table,
            {"run_id": self.run_id, "unit": str(unit), "status": status, "error": str(error or "")[:2000]},
        )

    def clear(self) -> None:
        """Drop this run's ledger rows -- call on CLEAN completion. A finished run has
        nothing left to resume, so its token doesn't need to persist (keeps the ledger
        holding only interrupted/failed runs)."""
        self.session.delete_data(self.table, {"run_id": self.run_id})
