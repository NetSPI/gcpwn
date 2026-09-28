"""Deleting a workspace must remove the workspace AND everything under it.

DataController.delete_workspace existed with the FK-cascade logic but had no caller,
so there was no way to delete a gcpwn workspace at all (the `workspace` command
manages Google Workspace TENANTS, a different thing). Now reachable as
`data delete-workspace`.
"""

from __future__ import annotations

import pytest

from gcpwn.core.db import DataController


@pytest.fixture
def controller(tmp_path, monkeypatch):
    monkeypatch.setattr(DataController, "database_path", str(tmp_path / "gcpwn.db"))
    DataController.create_initial_workspace_session_database()
    dc = DataController()
    dc.create_service_databases()
    yield dc
    dc.close()


def _populate(dc, workspace_id, node_id):
    dc.save_service_row(
        "opengraph_nodes",
        {"workspace_id": workspace_id, "node_id": node_id, "node_type": "GCPServiceAccount"},
        replace_on=["node_id"],
    )
    dc.save_service_row(
        "cloudstorage_buckets",
        {"workspace_id": workspace_id, "name": f"bucket-{workspace_id}", "project_id": "p"},
        only_if_missing=["name"],
    )


class TestCascade:
    def test_deletes_the_workspace_and_its_service_rows(self, controller):
        wid = controller.insert_workspace("doomed")
        _populate(controller, wid, "n1")
        assert controller.select_rows("opengraph_nodes", where={"workspace_id": wid})
        assert controller.select_rows("cloudstorage_buckets", where={"workspace_id": wid})

        assert controller.delete_workspace(wid) == 1

        assert [r for r in (controller.get_workspaces() or []) if int(r["id"]) == wid] == []
        assert controller.select_rows("opengraph_nodes", where={"workspace_id": wid}) == []
        assert controller.select_rows("cloudstorage_buckets", where={"workspace_id": wid}) == []

    def test_leaves_other_workspaces_untouched(self, controller):
        keep = controller.insert_workspace("keep")
        drop = controller.insert_workspace("drop")
        _populate(controller, keep, "keep-node")
        _populate(controller, drop, "drop-node")

        controller.delete_workspace(drop)

        assert len(controller.select_rows("opengraph_nodes", where={"workspace_id": keep})) == 1
        assert len(controller.select_rows("cloudstorage_buckets", where={"workspace_id": keep})) == 1
        assert [r for r in (controller.get_workspaces() or []) if int(r["id"]) == keep]

    def test_unknown_id_deletes_nothing(self, controller):
        controller.insert_workspace("present")
        assert controller.delete_workspace(999999) == 0
        assert controller.get_workspaces()


class TestReachableFromTheRepl:
    """The bug was that this cascade had no caller. Pin that it is wired up."""

    def test_registered_as_a_data_subcommand(self):
        from gcpwn.cli.workspace_instructions import CommandProcessor

        assert "delete-workspace" in CommandProcessor.DATA_SUBCOMMANDS

    def test_handler_exists_and_calls_delete_workspace(self):
        import inspect

        from gcpwn.cli.workspace_instructions import CommandProcessor

        handler = getattr(CommandProcessor, "handle_delete_workspace_command", None)
        assert callable(handler), "data delete-workspace has no handler"
        source = inspect.getsource(handler)
        assert "delete_workspace(" in source
        assert '"DELETE"' in source, "destructive command must require typed confirmation"
        assert "yes" in source, "must honour --yes for non-interactive use"
