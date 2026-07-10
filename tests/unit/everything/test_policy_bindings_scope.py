"""Unit coverage for the scoped IAM policy-binding collection that lets enum_all
pipeline bindings per hierarchy node instead of one end-of-run barrier.

These tests drive ``IAMPolicyBindingsResource.run()`` with a fake session that
records every ``get_data`` call and returns no rows, so no API client is ever
exercised -- we only assert which tables/filters each scope selects.
"""

from __future__ import annotations

from gcpwn.modules.everything.utilities.iam_policy_bindings import IAMPolicyBindingsResource


class _RecordingSession:
    def __init__(self) -> None:
        self.project_id = "proj-base"
        self.debug = False
        self.calls: list[tuple[str, str | None, dict | None, tuple]] = []
        self.sync_users_calls = 0

    def get_data(self, table, columns="*", conditions=None, *, where=None, params=None):
        self.calls.append((table, conditions, dict(where) if where else None, tuple(params or ())))
        return []

    def insert_actions(self, *args, **kwargs):  # pragma: no cover - never reached (no rows)
        raise AssertionError("insert_actions should not run when no rows are returned")

    def sync_users(self):
        self.sync_users_calls += 1


def _run_scope(scope, *, sync_users=True):
    session = _RecordingSession()
    resource = object.__new__(IAMPolicyBindingsResource)
    resource.session = session
    resource.clients = {}
    resource.storage_client = None
    resource.bigquery_client = None
    resource._discovery_clients = {}
    # Never build a real discovery client; empty resource loads make it a no-op.
    resource._discovery_resource_for_type = lambda _resource_type: None  # type: ignore[assignment]
    resource.run(save_raw_policies=True, scope=scope, sync_users=sync_users)

    tree_levels = [
        conditions
        for table, conditions, _where, _params in session.calls
        if table == "abstract_tree_hierarchy"
    ]
    project_node = [
        (conditions, where)
        for table, conditions, where, _params in session.calls
        if table == "abstract_tree_hierarchy" and conditions and "project" in conditions
    ]
    resource_loads = [
        (table, conditions, where, params)
        for table, conditions, where, params in session.calls
        if table != "abstract_tree_hierarchy"
    ]
    return session, tree_levels, project_node, resource_loads


def test_scope_none_sweeps_everything_and_syncs_users() -> None:
    session, tree_levels, _project_node, resource_loads = _run_scope(None)
    joined = " ".join(level or "" for level in tree_levels)
    assert "org" in joined and "folder" in joined and "project" in joined
    assert len(resource_loads) > 5  # every resource table is loaded
    assert all(where is None and params == () for _t, _c, where, params in resource_loads)
    assert session.sync_users_calls == 1


def test_scope_hierarchy_loads_org_and_folder_only() -> None:
    session, tree_levels, project_node, resource_loads = _run_scope({"hierarchy": True}, sync_users=False)
    joined = " ".join(level or "" for level in tree_levels)
    assert "org" in joined and "folder" in joined
    assert not project_node, "project node must be excluded from hierarchy scope"
    assert resource_loads == [], "no resource tables in hierarchy scope"
    assert session.sync_users_calls == 0


def test_scope_project_filters_node_and_resources_to_project() -> None:
    _session, _tree_levels, project_node, resource_loads = _run_scope(
        {"project_id": "proj-X"}, sync_users=False
    )
    assert len(project_node) == 1 and project_node[0][1] == {"project_id": "proj-X"}
    assert resource_loads, "project scope still loads resource tables"
    assert all(where == {"project_id": "proj-X"} for _t, _c, where, _p in resource_loads)


def test_scope_orphans_collects_unscoped_resources() -> None:
    # Plain orphan pass: only resources missing a project_id.
    _session, tree_levels, _project_node, resource_loads = _run_scope({"orphans": True}, sync_users=False)
    assert tree_levels == [], "no hierarchy nodes in orphan scope"
    assert resource_loads
    for _table, conditions, _where, params in resource_loads:
        assert "project_id IS NULL" in conditions
        assert params == ()


def test_scope_orphans_with_known_projects_excludes_in_scope_rows() -> None:
    # Reconciliation pass: everything NOT covered by the per-project tasks.
    _session, _tree_levels, _project_node, resource_loads = _run_scope(
        {"orphans": True, "known_projects": ["A", "B"]}, sync_users=False
    )
    assert resource_loads
    for _table, conditions, _where, params in resource_loads:
        assert "project_id NOT IN (?,?)" in conditions
        assert params == ("A", "B")
