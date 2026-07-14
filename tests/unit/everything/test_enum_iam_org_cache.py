"""Regression: enum_iam lists an org's custom roles ONCE per run, even when enum_all
fans the per-project ``cloud_iam`` unit out across parallel ``ProjectScopedSession``
workers.

The bug: the run-scoped org cache was stored on ``session._enum_iam_org_cache``. Under
parallel enum_all each worker is a ``ProjectScopedSession`` whose ``__setattr__`` keeps
writes in its own ``_overrides`` dict, so every project's worker got a private empty
cache and re-listed the same org roles. The fix anchors the cache to the BASE session
(shared by all workers), seeded once per run by ``run_parallel``.

No GCP client is imported: ``IAMCustomRolesResource`` is monkeypatched with a counting
stub, so this asserts the caching/plumbing, not the API.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from gcpwn.core.utils.scoped_session import ProjectScopedSession
from gcpwn.modules.gcp.iam.enumeration import enum_iam

ORG = "organizations/1234567890"


class _FakeRole:
    def __init__(self, name):
        self.name = name
        self.title = "t"
        self.stage = None
        self.included_permissions = ["x.y.z"]


class _CountingRolesResource:
    """Stand-in for IAMCustomRolesResource that counts org- vs project-scoped lists."""

    TABLE_NAME = "iam_roles"
    org_list_calls = 0
    _lock = threading.Lock()

    def __init__(self, session):
        self.session = session

    def list(self, *, project_id=None, org_id=None, action_dict=None):
        if org_id:
            with _CountingRolesResource._lock:
                _CountingRolesResource.org_list_calls += 1
            return [_FakeRole(f"{ORG}/roles/CustomOrgRole")]
        return [_FakeRole(f"projects/{project_id}/roles/CustomProjRole")]

    def get(self, *, resource_id, action_dict=None, **_):
        return None

    def save(self, rows):
        pass


class _FakeSession:
    """Minimal base session: shares nothing special; workers wrap it in ProjectScopedSession."""

    def __init__(self):
        self.project_id = "base"
        self.debug = False

    def get_data(self, *a, **k):
        return []

    def insert_actions(self, *a, **k):
        pass


def _run_worker(base_session, project_id):
    scoped = ProjectScopedSession(base_session, project_id)
    args = SimpleNamespace(org=ORG, project=None, role_names=None, role_names_file=None, get=False)
    enum_iam._run_custom_roles(scoped, args, project_id)


@pytest.fixture
def _stub_resource(monkeypatch):
    _CountingRolesResource.org_list_calls = 0
    monkeypatch.setattr(enum_iam, "IAMCustomRolesResource", _CountingRolesResource)


def test_org_roles_listed_once_across_parallel_workers(_stub_resource):
    base = _FakeSession()
    # run_parallel seeds a fresh shared cache on the base session once per run.
    base._enum_iam_org_cache = set()

    projects = [f"proj-{i}" for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda p: _run_worker(base, p), projects))

    # All 8 workers share the base cache -> the org is listed exactly once.
    assert _CountingRolesResource.org_list_calls == 1


def test_org_cache_resets_between_runs_for_standalone(_stub_resource):
    """Standalone/sequential enum_iam (no ProjectScopedSession) resets at index 0 so a
    fresh run re-lists, but reuses within the same multi-project loop."""
    base = _FakeSession()

    # First run: index 0 seeds, index 1 reuses -> one org list total.
    base._module_run_context = {"index": 0, "total": 2}
    args = SimpleNamespace(org=ORG, project=None, role_names=None, role_names_file=None, get=False)
    enum_iam._run_custom_roles(base, args, "p0")
    base._module_run_context = {"index": 1, "total": 2}
    enum_iam._run_custom_roles(base, args, "p1")
    assert _CountingRolesResource.org_list_calls == 1

    # A brand-new run (index 0 again) resets the cache -> re-lists.
    base._module_run_context = {"index": 0, "total": 2}
    enum_iam._run_custom_roles(base, args, "p0")
    assert _CountingRolesResource.org_list_calls == 2
