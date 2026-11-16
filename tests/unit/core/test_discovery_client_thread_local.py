"""Discovery clients must be per-thread, not per-resource-instance.

googleapiclient wraps one httplib2.Http whose connection cache is shared mutable
state. run_components fans a resource's list() over a region/nested-parent pool
using the same resource instance, so a per-instance client let two workers drive
one HTTP/SSL connection -- one closing it while the other read, which freed the
SSL object mid-write and crashed the interpreter natively.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from gcpwn.core.resource import DiscoveryListResource
from gcpwn.core.utils.service_runtime import cached_discovery_service


def _fake_session():
    return SimpleNamespace(project_id="proj-1", credentials=None)


class _ProbeDiscoveryResource(DiscoveryListResource):
    DISCOVERY_API = "probe"
    DISCOVERY_VERSION = "v1"

    def __init__(self, session):
        # Set these before super().__init__: on the unfixed base the service is
        # built eagerly inside __init__ and calls _build_service.
        self._lock = threading.Lock()
        self.builds = 0
        super().__init__(session)

    def _build_service(self, session):
        with self._lock:
            self.builds += 1
        return SimpleNamespace(owner_thread=threading.get_ident())


def test_discovery_resource_service_is_per_thread():
    resource = _ProbeDiscoveryResource(_fake_session())

    def _use(_):
        first = resource.service
        second = resource.service
        return threading.get_ident(), id(first), id(second), first

    with ThreadPoolExecutor(max_workers=4) as pool:
        observations = list(pool.map(_use, range(16)))

    by_thread: dict[int, int] = {}
    for thread_id, first_id, second_id, service in observations:
        assert first_id == second_id, "service must be cached within a thread"
        assert service.owner_thread == thread_id, "service must be built by its using thread"
        by_thread.setdefault(thread_id, first_id)
        assert by_thread[thread_id] == first_id, "each thread must keep its own client"

    assert len(set(by_thread.values())) == len(by_thread), "threads must not share a client"
    assert resource.builds == len(by_thread)


def test_cached_discovery_service_is_per_thread():
    owner = SimpleNamespace(session=_fake_session())
    built_by_thread: list[int] = []
    lock = threading.Lock()

    def _build(credentials, service_name, version, *, scopes=None):
        thread_id = threading.get_ident()
        with lock:
            built_by_thread.append(thread_id)
        return SimpleNamespace(owner_thread=thread_id)

    def _use(_):
        first = cached_discovery_service(owner, "probe", "v1")
        second = cached_discovery_service(owner, "probe", "v1")
        return threading.get_ident(), id(first), id(second), first

    with patch("gcpwn.core.utils.service_runtime.build_discovery_service", side_effect=_build):
        with ThreadPoolExecutor(max_workers=4) as pool:
            observations = list(pool.map(_use, range(16)))

    by_thread: dict[int, int] = {}
    for thread_id, first_id, second_id, service in observations:
        assert first_id == second_id, "service must be cached within a thread"
        assert service.owner_thread == thread_id
        by_thread.setdefault(thread_id, first_id)
        assert by_thread[thread_id] == first_id

    assert len(set(by_thread.values())) == len(by_thread), "threads must not share a client"
    assert sorted(built_by_thread) == sorted(by_thread.keys()), "one build per thread"