"""The shared REST pager must never make a failure look like an empty project.

Six services hand-rolled this pagination loop. Most returned None on a non-200
WITHOUT printing anything, and one broke out of the loop keeping partial rows, so
a 403 was reported to the operator as "No X found" -- a clean bill of health over
a denied API. rest_list centralizes both the paging and the classification.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from gcpwn.core.utils import service_runtime as sr


class _Response:
    def __init__(self, status_code, payload=None, *, bad_json=False):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class _Session:
    pass


@pytest.fixture
def no_auth(monkeypatch):
    monkeypatch.setattr(sr, "get_bearer_token", lambda _session: "token")


def _call(responses):
    """Run rest_list against a scripted sequence of responses."""
    queue = list(responses)
    with patch("requests.get", side_effect=lambda *a, **k: queue.pop(0)):
        return sr.rest_list(
            _Session(),
            "https://example.invalid/v1/things",
            "things",
            api_name="svc.things.list",
            service_label="Svc",
            project_id="p",
            resource_name="projects/p",
        )


class TestSuccess:
    def test_returns_rows(self, no_auth):
        assert _call([_Response(200, {"things": [{"a": 1}]})]) == [{"a": 1}]

    def test_genuine_empty_is_an_empty_list_not_an_error(self, no_auth):
        assert _call([_Response(200, {})]) == []

    def test_follows_page_tokens(self, no_auth):
        rows = _call([
            _Response(200, {"things": [{"n": 1}], "nextPageToken": "t1"}),
            _Response(200, {"things": [{"n": 2}], "nextPageToken": "t2"}),
            _Response(200, {"things": [{"n": 3}]}),
        ])
        assert rows == [{"n": 1}, {"n": 2}, {"n": 3}]


class TestFailureClassification:
    def test_disabled_api_returns_the_short_circuit_sentinel(self, no_auth):
        result = _call([_Response(403, {"error": {"message": "API has not been used in project 1 before"}})])
        assert result == "Not Enabled"

    @pytest.mark.parametrize("status", [401, 403])
    def test_denied_returns_none(self, no_auth, status):
        assert _call([_Response(status, {"error": {"message": "Permission denied"}})]) is None

    def test_not_found_returns_none(self, no_auth):
        assert _call([_Response(404, {"error": {"message": "nope"}})]) is None

    def test_server_error_returns_none(self, no_auth):
        assert _call([_Response(500, {"error": {"message": "backend boom"}})]) is None

    def test_transport_exception_returns_none(self, no_auth):
        with patch("requests.get", side_effect=OSError("connection reset")):
            result = sr.rest_list(
                _Session(), "https://example.invalid", "things",
                api_name="svc.things.list", service_label="Svc",
            )
        assert result is None

    def test_non_json_body_returns_none(self, no_auth):
        assert _call([_Response(200, bad_json=True)]) is None


class TestEveryFailurePrints:
    """The whole point: a failure must be visible, not silently empty."""

    @pytest.mark.parametrize(
        "response",
        [
            _Response(403, {"error": {"message": "Permission denied"}}),
            _Response(403, {"error": {"message": "API has not been used in project"}}),
            _Response(404, {"error": {"message": "nope"}}),
            _Response(500, {"error": {"message": "boom"}}),
            _Response(200, bad_json=True),
        ],
    )
    def test_failure_is_reported_to_the_operator(self, no_auth, capsys, response):
        _call([response])
        assert capsys.readouterr().out.strip(), "failure produced no output"

    def test_success_does_not_warn(self, no_auth, capsys):
        _call([_Response(200, {"things": []})])
        assert capsys.readouterr().out.strip() == ""


class TestMidPaginationFailure:
    def test_partial_pages_are_not_returned_as_if_complete(self, no_auth):
        """A page-2 failure must surface, not silently truncate to page 1."""
        result = _call([
            _Response(200, {"things": [{"n": 1}], "nextPageToken": "t1"}),
            _Response(500, {"error": {"message": "boom"}}),
        ])
        assert result is None
