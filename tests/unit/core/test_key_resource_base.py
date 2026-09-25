from __future__ import annotations

import contextlib
from types import SimpleNamespace

from gcpwn.core.resource import GcpListResource


def _fake_session(project_id="proj-1"):
    class _FakeSession(SimpleNamespace):
        @contextlib.contextmanager
        def batched_writes(self):
            yield
    return _FakeSession(project_id=project_id, credentials=None)


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
    return _fake_session()


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


# --------------------------------------------------------------------------- #
# save() — extra_builder / ID_FIELD injection
# --------------------------------------------------------------------------- #
def test_save_injects_id_field_as_path_tail():
    """save() must extract the ID_FIELD value from the resource name's tail."""
    from unittest.mock import patch

    resource = _ThingResource(_fake_session())
    row = {"name": "projects/proj-1/locations/global/things/my-thing"}

    captured = []
    with patch("gcpwn.core.resource.save_to_table") as mock_save:
        def record(*args, **kwargs):
            captured.append(kwargs)
        mock_save.side_effect = record
        resource.save([row], project_id="proj-1", location="global")

    assert mock_save.called
    eb = captured[0].get("extra_builder")
    assert eb is not None
    result = eb(row, {"name": "projects/proj-1/locations/global/things/my-thing"})
    assert result.get("thing_id") == "my-thing", f"expected thing_id='my-thing', got {result!r}"


def test_save_skips_id_field_when_empty():
    """save() must NOT inject an empty-string key when ID_FIELD is '' (default).

    An empty key in the extra_builder dict would produce SQL:
      INSERT INTO ... ("") VALUES (?)
    which SQLite rejects. The base class should guard with `if self.ID_FIELD`.
    """
    from unittest.mock import patch

    class _NoIdFieldResource(_ThingResource):
        ID_FIELD = ""  # explicitly cleared (the default in the base class)

    resource = _NoIdFieldResource(_fake_session())
    row = {"name": "projects/proj-1/locations/global/things/some-thing"}

    captured = []
    with patch("gcpwn.core.resource.save_to_table") as mock_save:
        def record(*args, **kwargs):
            captured.append(kwargs)
        mock_save.side_effect = record
        resource.save([row], project_id="proj-1", location="global")

    assert mock_save.called
    eb = captured[0].get("extra_builder")
    assert eb is not None
    result = eb(row, {"name": "projects/proj-1/locations/global/things/some-thing"})
    assert "" not in result, (
        f"extra_builder must not include empty-string key when ID_FIELD='': got {result!r}"
    )
