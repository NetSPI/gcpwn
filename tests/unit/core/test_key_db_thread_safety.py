from __future__ import annotations

import threading

from gcpwn.core.db import DataController


def _controller_with_temp_service(tmp_path) -> DataController:
    """A DataController backed by an isolated on-disk service DB.

    Built via __new__ so the constructor never touches the real databases/.
    The class-level _lock is inherited, which is exactly what we are testing.
    """
    dc = DataController.__new__(DataController)
    conn = dc._connect_database(str(tmp_path / "svc.db"))  # check_same_thread=False
    dc.conn = conn
    dc.cursor = conn.cursor()
    dc._service_primary_key_cache = {}
    dc.cursor.execute(
        'CREATE TABLE "t" (workspace_id INTEGER, name TEXT, val TEXT, '
        'PRIMARY KEY (workspace_id, name))'
    )
    conn.commit()
    return dc


def test_concurrent_reads_and_writes_are_thread_safe(tmp_path) -> None:
    dc = _controller_with_temp_service(tmp_path)
    errors: list[BaseException] = []
    rows_per_worker = 40
    worker_count = 8

    def worker(worker_id: int) -> None:
        try:
            for i in range(rows_per_worker):
                dc.save_service_row(
                    "t",
                    {"workspace_id": 1, "name": f"{worker_id}-{i}", "val": "x"},
                )
                # interleave reads with writes from the same threads
                dc.select_rows("t", db="service", where={"workspace_id": 1})
        except BaseException as exc:  # noqa: BLE001 - capture for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # No "SQLite objects created in a thread..." errors and no corruption.
    assert not errors, errors
    final_rows = dc.select_rows("t", db="service", where={"workspace_id": 1})
    assert len(final_rows) == worker_count * rows_per_worker
