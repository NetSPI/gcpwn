"""Service-table writes must never reach across workspaces (CLAUDE.md invariant #3).

Callers pass only the NATURAL key (``name``, ``node_id``) to save_service_row's
``only_if_missing``/``replace_on``. Those keys collide across workspaces by design:
Cloud Storage bucket names are globally unique in GCP, and two workspaces scanning
the same org produce identical OpenGraph node ids. If the key is not widened with
``workspace_id``, one workspace's scan silently deletes or suppresses another's rows.
"""

from __future__ import annotations

import pytest

from gcpwn.core.db import DataController


@pytest.fixture
def controller(tmp_path, monkeypatch):
    monkeypatch.setattr(DataController, "database_path", str(tmp_path / "gcpwn.db"))
    # workspaces is the FK parent of every service table, created by the
    # control-plane initializer rather than create_service_databases().
    DataController.create_initial_workspace_session_database()
    data_controller = DataController()
    data_controller.create_service_databases()
    yield data_controller
    data_controller.close()


@pytest.fixture
def two_workspaces(controller):
    """Service rows carry a workspaces(id) FK, so the parents must exist first."""
    ids = [controller.insert_workspace("ws_one"), controller.insert_workspace("ws_two")]
    return controller, ids


class TestKeyWidening:
    def test_workspace_id_is_appended_when_the_row_has_one(self):
        widened = DataController._workspace_scoped_keys(["name"], {"name": "b", "workspace_id": 1})
        assert widened == ["name", "workspace_id"]

    def test_not_duplicated_when_already_present(self):
        widened = DataController._workspace_scoped_keys(["name", "workspace_id"], {"name": "b", "workspace_id": 1})
        assert widened == ["name", "workspace_id"]

    def test_left_alone_when_the_row_is_not_workspace_scoped(self):
        assert DataController._workspace_scoped_keys(["name"], {"name": "b"}) == ["name"]

    def test_empty_keys_pass_through(self):
        assert DataController._workspace_scoped_keys(None, {"workspace_id": 1}) is None
        assert DataController._workspace_scoped_keys([], {"workspace_id": 1}) == []


class TestReplaceOnIsolation:
    """replace_on DELETEs before inserting -- unscoped, it wipes the other workspace."""

    def test_second_workspace_does_not_delete_the_first(self, two_workspaces):
        controller, (ws_a, ws_b) = two_workspaces
        shared_node = "serviceAccount:svc@proj.iam.gserviceaccount.com"
        for workspace_id in (ws_a, ws_b):
            controller.save_service_row(
                "opengraph_nodes",
                {"workspace_id": workspace_id, "node_id": shared_node, "node_type": "GCPServiceAccount"},
                replace_on=["node_id"],
            )

        for workspace_id in (ws_a, ws_b):
            rows = controller.select_rows(
                "opengraph_nodes", where={"workspace_id": workspace_id, "node_id": shared_node}
            )
            assert len(rows) == 1, f"workspace {workspace_id} lost its node row"

    def test_replace_on_still_overwrites_within_one_workspace(self, two_workspaces):
        controller, (ws_a, _) = two_workspaces
        for node_type in ("GCPServiceAccount", "GCPUpdatedType"):
            controller.save_service_row(
                "opengraph_nodes",
                {"workspace_id": ws_a, "node_id": "n1", "node_type": node_type},
                replace_on=["node_id"],
            )
        rows = controller.select_rows("opengraph_nodes", where={"workspace_id": ws_a, "node_id": "n1"})
        assert len(rows) == 1
        assert rows[0]["node_type"] == "GCPUpdatedType"


class TestOnlyIfMissingIsolation:
    """only_if_missing is first-write-wins -- unscoped, workspace B's row never lands."""

    def test_second_workspace_row_is_still_inserted(self, two_workspaces):
        controller, (ws_a, ws_b) = two_workspaces
        # Bucket names are globally unique in GCP, so this collision is guaranteed
        # whenever two workspaces enumerate the same org.
        for workspace_id in (ws_a, ws_b):
            controller.save_service_row(
                "cloudstorage_buckets",
                {"workspace_id": workspace_id, "name": "shared-bucket", "project_id": "p"},
                only_if_missing=["name"],
            )

        for workspace_id in (ws_a, ws_b):
            rows = controller.select_rows(
                "cloudstorage_buckets", where={"workspace_id": workspace_id, "name": "shared-bucket"}
            )
            assert len(rows) == 1, f"workspace {workspace_id} never got its bucket row"

    def test_first_write_still_wins_within_one_workspace(self, two_workspaces):
        controller, (ws_a, _) = two_workspaces
        for project in ("first", "second"):
            controller.save_service_row(
                "cloudstorage_buckets",
                {"workspace_id": ws_a, "name": "b", "project_id": project},
                only_if_missing=["name"],
            )
        rows = controller.select_rows("cloudstorage_buckets", where={"workspace_id": ws_a, "name": "b"})
        assert len(rows) == 1
        assert rows[0]["project_id"] == "first"
