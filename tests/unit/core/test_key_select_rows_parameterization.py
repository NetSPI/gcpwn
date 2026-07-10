from __future__ import annotations

import sqlite3

from gcpwn.core.db import DataController


def _in_memory_controller() -> DataController:
    """A DataController whose service DB is an isolated in-memory SQLite.

    Built via __new__ so the constructor never opens the real on-disk databases.
    select_rows only needs the service cursor for db="service".
    """
    dc = DataController.__new__(DataController)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    dc.conn = conn
    dc.cursor = conn.cursor()
    dc._service_primary_key_cache = {}

    dc.cursor.execute(
        'CREATE TABLE "t" (workspace_id INTEGER, name TEXT, project_id TEXT)'
    )
    dc.cursor.executemany(
        'INSERT INTO "t" (workspace_id, name, project_id) VALUES (?, ?, ?)',
        [
            (1, "alpha", "p1"),
            (1, "beta", "p2"),
            (1, 'weird"name', "p1"),
            (2, "alpha", "p1"),
        ],
    )
    conn.commit()
    return dc


def test_where_dict_is_exact_equality_and_workspace_scoped() -> None:
    dc = _in_memory_controller()
    rows = dc.select_rows("t", db="service", where={"workspace_id": 1, "project_id": "p1"})
    assert {row["name"] for row in rows} == {"alpha", 'weird"name'}


def test_where_value_with_double_quote_matches_literally() -> None:
    dc = _in_memory_controller()
    rows = dc.select_rows("t", db="service", where={"name": 'weird"name'})
    assert len(rows) == 1
    assert rows[0]["name"] == 'weird"name'


def test_where_injection_payload_is_treated_as_a_literal_value() -> None:
    dc = _in_memory_controller()
    # A classic injection string must be bound as data, not break out of the
    # query. It matches no row and, critically, does not leak workspace 2.
    rows = dc.select_rows("t", db="service", where={"name": 'alpha" OR "1"="1'})
    assert rows == []


def test_conditions_params_and_where_combine_in_order() -> None:
    dc = _in_memory_controller()
    rows = dc.select_rows(
        "t",
        db="service",
        conditions="name LIKE ?",
        params=["al%"],
        where={"workspace_id": 1},
    )
    assert {row["name"] for row in rows} == {"alpha"}
