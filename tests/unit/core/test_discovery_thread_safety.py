"""Thread-safety tests for discovery client caching.

googleapiclient wraps httplib2.Http whose connection cache is shared mutable
state. When run_components fans a resource's list() across a thread pool using
one resource instance, two workers can drive the same HTTP/SSL connection,
causing corruption or crashes.

Both DiscoveryListResource.service and cached_discovery_service must build one
client per thread and cache it for reuse within that thread.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch


def _fake_session():
    return SimpleNamespace(project_id="proj-1", credentials=None)


def _make_resource():
    from gcpwn.core.resource import DiscoveryListResource

    builds: list[int] = []
    lock = threading.Lock()

    class _ProbeResource(DiscoveryListResource):
        DISCOVERY_API = "probe"
        DISCOVERY_VERSION = "v1"
        TABLE_NAME = "t"
        COLUMNS = ["name"]
        ACTION_RESOURCE_TYPE = "instances"
        LIST_PERMISSION = "probe.list"
        LIST_API_NAME = "probe.list"

        def _build_service(self, session):
            with lock:
                builds.append(1)
            return SimpleNamespace(built_by=threading.get_ident())

    with patch("gcpwn.core.resource.build_discovery_service", return_value=SimpleNamespace(built_by=0)):
        res = _ProbeResource(_fake_session())
    # reset so each test thread triggers its own build
    res._service_local = threading.local()
    res._build_service = _ProbeResource._build_service.__get__(res, type(res))
    return res, builds


def test_discovery_resource_service_is_per_thread():
    """Each thread gets its own client, built by that thread, cached on reuse."""
    res, builds = _make_resource()

    per_thread: dict[int, list[int]] = {}

    def worker(_):
        tid = threading.get_ident()
        c1 = res.service
        c2 = res.service  # second access — must return same object
        with threading.Lock():
            per_thread.setdefault(tid, []).append(id(c1))
            per_thread[tid].append(id(c2))
        assert c1.built_by == tid, "Client was not built by the thread using it"
        assert id(c1) == id(c2), "Client was rebuilt on second access in same thread"

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(16)))

    # each thread cached one client (same id on repeat access)
    for tid, ids in per_thread.items():
        assert len(set(ids)) == 1, f"Thread {tid} got multiple distinct clients"

    # one build per thread, no sharing
    all_client_ids = [ids[0] for ids in per_thread.values()]
    assert len(set(all_client_ids)) == len(per_thread), "Two threads shared a client"
    assert len(builds) == len(per_thread), "Build count doesn't match thread count"


def test_cached_discovery_service_is_per_thread():
    """cached_discovery_service() has the same per-thread guarantee."""
    from gcpwn.core.utils.service_runtime import cached_discovery_service

    builds: list[int] = []
    lock = threading.Lock()

    def fake_build(creds, service_name, version, scopes=None):
        with lock:
            builds.append(1)
        return SimpleNamespace(built_by=threading.get_ident())

    owner = SimpleNamespace(session=_fake_session())
    per_thread: dict[int, list[int]] = {}

    def worker(_):
        tid = threading.get_ident()
        with patch("gcpwn.core.utils.service_runtime.build_discovery_service", side_effect=fake_build):
            c1 = cached_discovery_service(owner, "probe", "v1")
            c2 = cached_discovery_service(owner, "probe", "v1")
        with lock:
            per_thread.setdefault(tid, []).append(id(c1))
            per_thread[tid].append(id(c2))
        assert c1.built_by == tid, "Client was not built by the thread using it"
        assert id(c1) == id(c2), "Client was rebuilt on second access in same thread"

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(16)))

    all_client_ids = [ids[0] for ids in per_thread.values()]
    assert len(set(all_client_ids)) == len(per_thread), "Two threads shared a client"
    assert len(builds) == len(per_thread), "Build count doesn't match thread count"


def test_thread_pool_client_count_bounded_by_workers():
    """A pool of N workers builds at most N clients regardless of task count."""
    res, builds = _make_resource()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: res.service, range(20)))

    assert len(builds) <= 4, (
        f"Expected ≤4 clients for a 4-worker pool, got {len(builds)}"
    )
