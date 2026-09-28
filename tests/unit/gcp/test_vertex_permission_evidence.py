"""A denied Vertex list must not be recorded as a held permission.

The permission-evidence tree feeds OpenGraph privilege-escalation edges, so
recording a list permission the credential does not hold invents attack paths that
do not exist. Vertex lists over REST; its pager originally returned an empty list
on a 403 that was indistinguishable from a successful empty read.

Vertex now lists through RestListResource -> service_runtime.rest_list, so these
tests exercise that path end to end for a real Vertex resource class. The generic
base behaviour is covered in tests/unit/core/test_rest_list_resource.py; this file
exists to pin the guarantee for the service that actually had the bug.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from gcpwn.core.resource import RestListResource
from gcpwn.modules.gcp.vertex.utilities import helpers as vertex_helpers


class _Response:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class _Session:
    project_id = "my-project"
    credentials = None


@pytest.fixture
def recorded(monkeypatch):
    """Capture anything written into the permission-evidence tree."""
    entries: list[dict] = []
    monkeypatch.setattr(
        "gcpwn.core.resource.record_permissions",
        lambda action_dict, **kwargs: entries.append(kwargs),
    )
    monkeypatch.setattr(vertex_helpers, "get_bearer_token", lambda _session: "token")
    monkeypatch.setattr(
        "gcpwn.core.utils.service_runtime.get_bearer_token", lambda _session: "token"
    )
    return entries


def _list(response):
    resource = vertex_helpers.VertexCustomJobsResource(_Session())
    with patch("requests.get", lambda *a, **k: response):
        return resource.list(project_id="p", location="us-central1", action_dict={})


class TestVertexIsOnTheSharedBase:
    def test_uses_rest_list_resource(self):
        assert issubclass(vertex_helpers._VertexRestResource, RestListResource)

    def test_local_pager_is_gone(self):
        assert not hasattr(vertex_helpers, "_list_paged"), "duplicate pager came back"

    def test_page_size_is_preserved(self):
        assert vertex_helpers._VertexRestResource.PAGE_SIZE == 100


class TestDeniedListRecordsNoEvidence:
    @pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
    def test_failure_records_nothing(self, recorded, status):
        result = _list(_Response(status, {"error": {"message": "denied"}}))
        assert result is None, "a failure must be distinguishable from an empty project"
        assert recorded == [], f"HTTP {status} must not record permission evidence"

    def test_disabled_api_records_nothing_and_short_circuits(self, recorded):
        result = _list(_Response(403, {"error": {"message": "API has not been used in project"}}))
        assert result == "Not Enabled"
        assert recorded == []


class TestSuccessfulListRecords:
    def test_empty_but_successful_read_records_the_permission(self, recorded):
        assert _list(_Response(200, {"customJobs": []})) == []
        assert len(recorded) == 1
        assert recorded[0]["permissions"] == "aiplatform.customJobs.list"
        assert recorded[0]["scope_label"] == "p"

    def test_rows_are_normalized_by_the_services_own_hook(self, recorded):
        payload = {
            "customJobs": [
                {
                    "name": "projects/p/locations/us-central1/customJobs/123",
                    "state": "JOB_STATE_SUCCEEDED",
                    "jobSpec": {"serviceAccount": "sa@p.iam.gserviceaccount.com"},
                    "createTime": "2026-09-25T12:00:00.000Z",
                }
            ]
        }
        rows = _list(_Response(200, payload))
        assert len(rows) == 1
        # _normalize (NOT renamed to _normalize_row, so get() keeps the base no-op)
        assert rows[0]["job_id"] == "123"
        assert rows[0]["service_account"] == "sa@p.iam.gserviceaccount.com"
        assert rows[0]["create_time"] == "2026-09-25T12:00:00"
        assert len(recorded) == 1


class TestNormalizeHookWiring:
    def test_subclasses_still_define_normalize(self):
        """The 7 subclasses keep _normalize; the base routes list rows to it."""
        for name in (
            "VertexCustomJobsResource",
            "VertexPipelineJobsResource",
            "VertexEndpointsResource",
            "VertexModelsResource",
            "VertexTuningJobsResource",
            "VertexReasoningEnginesResource",
            "VertexDeploymentResourcePoolsResource",
        ):
            cls = getattr(vertex_helpers, name)
            assert "_normalize" in cls.__dict__, f"{name} lost its _normalize hook"

    def test_get_still_uses_the_base_no_op_normalizer(self):
        """Renaming _normalize to _normalize_row would have changed get() too."""
        assert "_normalize_row" not in vertex_helpers.VertexCustomJobsResource.__dict__
