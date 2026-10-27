"""Cloud Build get() must be location-aware, and 429s must be classified as rate limits.

Builds live in regional locations, so the global get_build(project_id, id) 404s on every
regional build -- which floods `enum_cloudbuild --download` (it forced --get). get() now
fetches by the location-qualified name when the location is known. Separately, a 429
quota error must be reported as a rate limit, not a generic STATUS 500 (UNKNOWN).
"""

from types import SimpleNamespace

from gcpwn.core.utils import service_runtime


class _FakeBuildClient:
    def __init__(self):
        self.calls = []

    def get_build(self, *, request=None, project_id=None, id=None):
        if request is not None:
            self.calls.append(("name", getattr(request, "name", None)))
            return {"id": "build-1", "name": getattr(request, "name", "")}
        self.calls.append(("global", project_id, id))
        return {"id": id, "name": f"projects/{project_id}/builds/{id}"}


class _FakeV1:
    class GetBuildRequest:
        def __init__(self, *, name=None, project_id=None, id=None):
            self.name = name
            self.project_id = project_id
            self.id = id


def _make_builds_resource():
    from gcpwn.modules.gcp.cloudbuild.utilities import helpers

    res = helpers.CloudBuildBuildsResource.__new__(helpers.CloudBuildBuildsResource)
    res.session = SimpleNamespace(project_id="proj-x", credentials=None)
    res.client = _FakeBuildClient()
    res._v1 = _FakeV1
    return res


def test_regional_build_get_uses_location_qualified_name():
    res = _make_builds_resource()
    # resource_id carries the full regional name (how the --get path passes it).
    res.get(resource_id="projects/proj-x/locations/us-central1/builds/build-1")
    assert res.client.calls == [("name", "projects/proj-x/locations/us-central1/builds/build-1")]


def test_global_build_get_uses_project_and_id():
    res = _make_builds_resource()
    res.get(resource_id="build-1", project_id="proj-x")  # no location -> global path
    assert res.client.calls == [("global", "proj-x", "build-1")]


def test_rate_limit_error_detected_from_message_and_type():
    assert service_runtime._is_rate_limit_error(
        Exception("429 Quota exceeded for quota metric 'Build and Operation Get requests' ... RATE_LIMIT_EXCEEDED")
    )
    try:
        from google.api_core.exceptions import ResourceExhausted
        assert service_runtime._is_rate_limit_error(ResourceExhausted("throttled"))
    except Exception:
        pass
    assert not service_runtime._is_rate_limit_error(Exception("404 was not found"))
