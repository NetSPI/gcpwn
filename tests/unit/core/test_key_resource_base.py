from __future__ import annotations

from types import SimpleNamespace

from gcpwn.core.resource import GcpListResource


class _FakeClient:
    def list_things(self, *, parent):
        return [{"name": f"{parent}/things/a"}, {"name": f"{parent}/things/b"}]

    def get_thing(self, *, name):
        return {"name": name, "display_name": "got"}


class _ThingResource(GcpListResource):
    SERVICE_LABEL = "svc"
    TABLE_NAME = "svc_things"
    COLUMNS = ["location", "thing_id", "name"]
    ACTION_RESOURCE_TYPE = "things"
    LIST_PERMISSION = "svc.things.list"
    GET_PERMISSION = "svc.things.get"
    LIST_METHOD = "list_things"
    GET_METHOD = "get_thing"
    ID_FIELD = "thing_id"

    def _build_client(self, session):
        return _FakeClient()


def _session():
    return SimpleNamespace(project_id="proj-1", credentials=None)


def test_list_project_mode_builds_parent_and_returns_rows():
    resource = _ThingResource(_session())
    rows = resource.list(project_id="proj-1", location="global")
    assert [row["name"] for row in rows] == [
        "projects/proj-1/locations/global/things/a",
        "projects/proj-1/locations/global/things/b",
    ]


def test_list_parent_mode_uses_passed_parent():
    class _ParentResource(_ThingResource):
        PARENT_FROM_PROJECT_LOCATION = False

    resource = _ParentResource(_session())
    rows = resource.list(parent="projects/proj-1/locations/us/featurestores/fs", action_dict=None)
    assert rows[0]["name"].startswith("projects/proj-1/locations/us/featurestores/fs/things/")


def test_get_dispatches_to_configured_method():
    resource = _ThingResource(_session())
    row = resource.get(resource_id="projects/proj-1/locations/global/things/a")
    assert row == {"name": "projects/proj-1/locations/global/things/a", "display_name": "got"}
    assert resource.get(resource_id="") is None


def test_test_iam_permissions_short_circuits_without_config():
    # No TEST_IAM_PERMISSIONS configured -> returns [] without any client call.
    resource = _ThingResource(_session())
    assert resource.test_iam_permissions(resource_id="projects/proj-1/locations/global/things/a") == []
