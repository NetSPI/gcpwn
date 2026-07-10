from __future__ import annotations

import io
import threading

from gcpwn.core.utils.parallel_output import ParallelOutputManager
from gcpwn.core.utils.scoped_session import ProjectScopedSession


# --- ProjectScopedSession ---

class _FakeBase:
    def __init__(self):
        self.project_id = "base-project"
        self.workspace_id = 7
        self.credname = "cred"
        self.calls = []

    def get_data(self, table, **kwargs):
        # delegates here; uses base identity, returns project seen by caller
        self.calls.append(table)
        return [{"table": table}]

    def get_download_save_path(self, *, project_id=None, service_name="", **kwargs):
        return f"{project_id}/{service_name}"


def test_scoped_session_isolates_project_id_but_delegates_rest():
    base = _FakeBase()
    a = ProjectScopedSession(base, "proj-A")
    b = ProjectScopedSession(base, "proj-B")

    assert a.project_id == "proj-A"
    assert b.project_id == "proj-B"
    assert base.project_id == "base-project"  # base untouched

    # delegation: shared identity + methods
    assert a.workspace_id == 7
    assert b.credname == "cred"
    assert a.get_data("iam_roles") == [{"table": "iam_roles"}]


def test_scoped_session_writes_stay_local():
    base = _FakeBase()
    a = ProjectScopedSession(base, "proj-A")
    a.project_id = "proj-A2"
    a.scratch = 123
    assert a.project_id == "proj-A2"
    assert a.scratch == 123
    assert base.project_id == "base-project"  # not corrupted
    assert not hasattr(base, "scratch")


def test_scoped_session_download_path_uses_task_project():
    base = _FakeBase()
    a = ProjectScopedSession(base, "proj-A")
    # caller omits project_id -> task's project is injected
    assert a.get_download_save_path(service_name="storage") == "proj-A/storage"
    # explicit project_id wins
    assert a.get_download_save_path(project_id="explicit", service_name="storage") == "explicit/storage"


# --- ParallelOutputManager ---

def test_output_manager_buffers_per_task_and_flushes_atomically():
    sink = io.StringIO()
    mgr = ParallelOutputManager(total=2, real_stdout=sink, force_status=False)

    def task(label, lines):
        mgr.begin_task(label)
        for line in lines:
            print(line)  # goes through installed stdout -> per-thread buffer
        mgr.end_task()

    with mgr:
        threads = [
            threading.Thread(target=task, args=("storage", ["s1", "s2", "s3"])),
            threading.Thread(target=task, args=("iam", ["i1", "i2", "i3"])),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    output = sink.getvalue()
    # Each task's lines must appear as a contiguous block (no interleaving).
    assert "s1\ns2\ns3\n" in output
    assert "i1\ni2\ni3\n" in output


def test_output_manager_restores_stdout_and_counts_failures():
    import sys

    sink = io.StringIO()
    original = sys.stdout
    mgr = ParallelOutputManager(total=1, real_stdout=sink, force_status=False)
    with mgr:
        mgr.begin_task("svc")
        print("hello")
        mgr.end_task(failed=True)
    assert sys.stdout is original  # restored
    assert mgr._failed == 1
    assert "hello" in sink.getvalue()
