"""The folded App Engine get() must drive each collection's own SDK call.

services/versions/instances had three byte-identical get() bodies differing only
in the request class and client method, now config on the shared local base. These
tests prove each subclass still issues the right call and records the same
evidence -- the thing a config-driven fold can silently get wrong.
"""

from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture
def appengine(monkeypatch):
    """Import the helpers with a stub appengine_admin_v1 so no SDK is needed."""
    recorded = {}

    class _Request:
        def __init__(self, kind):
            self.kind = kind

        def __call__(self, name):
            recorded["request_class"] = self.kind
            recorded["request_name"] = name
            return {"_kind": self.kind, "name": name}

    stub = types.SimpleNamespace(
        GetServiceRequest=_Request("GetServiceRequest"),
        GetVersionRequest=_Request("GetVersionRequest"),
        GetInstanceRequest=_Request("GetInstanceRequest"),
        ServicesClient=lambda credentials=None: None,
        VersionsClient=lambda credentials=None: None,
        InstancesClient=lambda credentials=None: None,
        ApplicationsClient=lambda credentials=None: None,
    )
    google_cloud = sys.modules.setdefault("google.cloud", types.ModuleType("google.cloud"))
    monkeypatch.setattr(google_cloud, "appengine_admin_v1", stub, raising=False)

    from gcpwn.modules.gcp.appengine.utilities import helpers

    return helpers, stub, recorded


class _Session:
    project_id = "my-project"
    credentials = None


def _probe(helpers, cls, method_name, recorded):
    """Instantiate a resource with a client that records which method was called."""
    resource = cls.__new__(cls)
    resource.session = _Session()
    resource._appengine_admin_v1 = helpers  # replaced below by the stub namespace

    class Client:
        def __getattr__(self, item):
            def call(request=None):
                recorded["client_method"] = item
                recorded["client_request"] = request
                return {"name": request["name"]}
            return call

    resource.client = Client()
    return resource


class TestEachCollectionUsesItsOwnCall:
    @pytest.mark.parametrize(
        "class_name,expected_request,expected_method,resource_type",
        [
            ("AppEngineServicesResource", "GetServiceRequest", "get_service", "services"),
            ("AppEngineVersionsResource", "GetVersionRequest", "get_version", "versions"),
            ("AppEngineInstancesResource", "GetInstanceRequest", "get_instance", "instances"),
        ],
    )
    def test_config_drives_the_right_sdk_call(
        self, appengine, class_name, expected_request, expected_method, resource_type
    ):
        helpers, stub, recorded = appengine
        cls = getattr(helpers, class_name)
        assert cls.GET_REQUEST_CLASS == expected_request
        assert cls.GET_CLIENT_METHOD == expected_method
        assert cls.ACTION_RESOURCE_TYPE == resource_type

        resource = _probe(helpers, cls, expected_method, recorded)
        resource._appengine_admin_v1 = stub

        name = f"apps/my-project/{resource_type}/thing"
        actions: dict = {}
        row = resource.get(name=name, action_dict=actions)

        assert recorded["request_class"] == expected_request
        assert recorded["client_method"] == expected_method
        assert row == {"name": name}

    def test_resource_id_is_accepted_as_well_as_name(self, appengine):
        """run_components passes resource_id=, the old signature took name=."""
        helpers, stub, recorded = appengine
        cls = helpers.AppEngineServicesResource
        resource = _probe(helpers, cls, "get_service", recorded)
        resource._appengine_admin_v1 = stub
        row = resource.get(resource_id="apps/my-project/services/default", action_dict={})
        assert row == {"name": "apps/my-project/services/default"}

    def test_project_is_parsed_from_the_apps_scheme(self, appengine):
        """App Engine names are apps/<project>/..., not projects/<id>/..."""
        helpers, _stub, _recorded = appengine
        assert helpers._AppEngineBaseResource.project_id_from_name("apps/my-project/services/x") == "my-project"

    def test_apps_resource_keeps_its_own_get(self, appengine):
        """The singleton Application has a different signature and must not be folded."""
        helpers, _stub, _recorded = appengine
        assert "project_id" in helpers.AppEngineAppsResource.get.__code__.co_varnames
