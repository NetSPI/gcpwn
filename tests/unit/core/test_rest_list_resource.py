"""RestListResource: the shared base for services that list over raw REST.

Vertex AI, Firebase App Hosting, Application Integration and Integration
Connectors have no usable client library for these collections and each had
written the same list() body. These tests pin the shared behaviour, including the
one that matters most: a denied list must NOT record the list permission as
evidence, because that evidence feeds OpenGraph privilege-escalation edges.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from gcpwn.core.resource import RestListResource


class _Session:
    project_id = "my-project"
    credentials = None


class _Things(RestListResource):
    SERVICE_LABEL = "My Service"
    API_BASE = "https://myservice.googleapis.com/v1"
    API_PATH = "things"
    COLLECTION_KEY = "things"
    LIST_PERMISSION = "myservice.things.list"
    TABLE_NAME = "my_things"


@pytest.fixture
def resource():
    return _Things(_Session())


def _patched(rows):
    """Patch the shared pager, capturing the arguments the base passed it."""
    seen = {}

    def fake(session, url, items_key, **kwargs):
        seen.update(url=url, items_key=items_key, **kwargs)
        return rows

    return patch("gcpwn.core.resource.rest_list", side_effect=fake), seen


class TestClientIsNotRequired:
    def test_build_client_returns_none(self, resource):
        assert resource.client is None


class TestUrlConstruction:
    def test_builds_the_regional_parent_by_default(self, resource):
        patcher, seen = _patched([])
        with patcher:
            resource.list(project_id="p", location="us-central1", action_dict={})
        assert seen["url"] == "https://myservice.googleapis.com/v1/projects/p/locations/us-central1/things"
        assert seen["items_key"] == "things"

    def test_explicit_parent_wins(self, resource):
        patcher, seen = _patched([])
        with patcher:
            resource.list(parent="projects/p/locations/eu/clusters/c", action_dict={})
        assert seen["url"].endswith("/projects/p/locations/eu/clusters/c/things")

    def test_rest_parent_is_overridable(self):
        class Global(_Things):
            def _rest_parent(self, project_id, location):
                return f"projects/{project_id}"

        patcher, seen = _patched([])
        with patcher:
            Global(_Session()).list(project_id="p", location=None, action_dict={})
        assert seen["url"] == "https://myservice.googleapis.com/v1/projects/p/things"


class TestEvidenceRecording:
    def test_successful_list_records_the_permission(self, resource):
        actions: dict = {}
        patcher, _ = _patched([{"name": "a"}])
        with patcher, patch("gcpwn.core.resource.record_permissions") as rec:
            rows = resource.list(project_id="p", location="us", action_dict=actions)
        assert rows == [{"name": "a"}]
        assert rec.call_count == 1
        assert rec.call_args.kwargs["permissions"] == "myservice.things.list"
        assert rec.call_args.kwargs["scope_label"] == "p"

    def test_successful_but_empty_list_still_records(self, resource):
        """An empty project genuinely proves the caller holds list."""
        patcher, _ = _patched([])
        with patcher, patch("gcpwn.core.resource.record_permissions") as rec:
            assert resource.list(project_id="p", location="us", action_dict={}) == []
        assert rec.call_count == 1

    @pytest.mark.parametrize("failure", [None, "Not Enabled"])
    def test_failed_list_records_nothing_and_passes_the_sentinel_through(self, resource, failure):
        patcher, _ = _patched(failure)
        with patcher, patch("gcpwn.core.resource.record_permissions") as rec:
            result = resource.list(project_id="p", location="us", action_dict={})
        assert result is failure, "sentinel must reach run_components unchanged"
        assert rec.call_count == 0, "a failed list must not record permission evidence"


class TestNormalization:
    def test_rows_pass_through_normalize_row(self):
        class Upper(_Things):
            def _normalize_row(self, raw):
                return {"name": raw["name"].upper()}

        patcher, _ = _patched([{"name": "a"}, {"name": "b"}])
        with patcher, patch("gcpwn.core.resource.record_permissions"):
            rows = Upper(_Session()).list(project_id="p", location="us", action_dict={})
        assert rows == [{"name": "A"}, {"name": "B"}]

    def test_location_aware_hook_receives_the_location(self):
        """Several of these APIs omit the location from the payload."""
        class WithLocation(_Things):
            def _normalize_rest_row(self, raw, *, location=None):
                return {**raw, "location": location}

        patcher, _ = _patched([{"name": "a"}])
        with patcher, patch("gcpwn.core.resource.record_permissions"):
            rows = WithLocation(_Session()).list(project_id="p", location="us-central1", action_dict={})
        assert rows == [{"name": "a", "location": "us-central1"}]


class TestMigratedServicesAreWiredUp:
    """Each migrated service must still declare its own endpoint and response key."""

    @pytest.mark.parametrize(
        "module_path,class_name,api_path,collection_key",
        [
            ("gcpwn.modules.gcp.firebase.utilities.helpers", "FirebaseAppHostingBackendResource", "backends", "backends"),
            ("gcpwn.modules.gcp.applicationintegration.utilities.helpers", "IntegrationsResource", "integrations", "integrations"),
            ("gcpwn.modules.gcp.integration_connectors.utilities.helpers", "ConnectionsResource", "connections", "connections"),
        ],
    )
    def test_service_config(self, module_path, class_name, api_path, collection_key):
        import importlib

        module = importlib.import_module(module_path)
        cls = getattr(module, class_name, None)
        if cls is None:  # class renamed -- surface it rather than silently pass
            pytest.fail(f"{class_name} not found in {module_path}")
        assert issubclass(cls, RestListResource)
        assert cls.API_PATH == api_path
        assert cls.COLLECTION_KEY == collection_key
        assert cls.API_BASE.startswith("https://")
        assert cls.LIST_PERMISSION, "LIST_PERMISSION drives both evidence and the error message"
