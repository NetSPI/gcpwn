"""Contracts for the small shared helpers promoted out of per-service helpers.py.

Each of these existed as an identical copy in several service helpers. The tests
pin the behaviour the copies had, so folding them cannot have changed anything.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from gcpwn.core.utils.iam_permissions import call_rest_test_iam_permissions
from gcpwn.core.utils.serialization import resource_name_from_row
from gcpwn.core.utils.service_runtime import (
    CLOUD_PLATFORM_SCOPE,
    bearer_headers,
    cached_discovery_service,
    drain_list_next,
    rest_call,
)


class _Response:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class TestBearerHeaders:
    def test_includes_json_content_type_by_default(self):
        assert bearer_headers("T") == {"Authorization": "Bearer T", "Content-Type": "application/json"}

    def test_content_type_can_be_omitted(self):
        assert bearer_headers("T", json_content=False) == {"Authorization": "Bearer T"}


class TestRestCall:
    def test_normalizes_the_verb_and_passes_body_params_timeout(self):
        seen = {}

        def fake(method, url, **kwargs):
            seen.update(method=method, url=url, **kwargs)
            return _Response(200, {"ok": True})

        with patch("requests.request", fake):
            status, data = rest_call("post", "https://x/y", token="T", body={"a": 1}, params={"p": 2})

        assert (status, data) == (200, {"ok": True})
        assert seen["method"] == "POST"
        assert seen["json"] == {"a": 1}
        assert seen["params"] == {"p": 2}
        assert seen["timeout"] == 30
        assert seen["headers"]["Authorization"] == "Bearer T"

    def test_non_json_body_is_returned_as_raw_not_raised(self):
        with patch("requests.request", lambda *a, **k: _Response(500, None, "<html>boom</html>")):
            status, data = rest_call("GET", "https://x", token="T")
        assert status == 500
        assert data == {"_raw": "<html>boom</html>"}

    def test_error_status_is_returned_not_raised(self):
        with patch("requests.request", lambda *a, **k: _Response(403, {"error": {"message": "denied"}})):
            status, data = rest_call("GET", "https://x", token="T")
        assert status == 403
        assert data["error"]["message"] == "denied"


class TestRestTestIamPermissions:
    def test_returns_granted_permissions(self):
        with patch("requests.request", lambda *a, **k: _Response(200, {"permissions": ["a.b.get", " a.b.list "]})):
            granted = call_rest_test_iam_permissions(token="T", url="https://x:testIamPermissions", permissions=["a.b.get"])
        assert granted == ["a.b.get", "a.b.list"]

    def test_empty_response_means_nothing_granted(self):
        with patch("requests.request", lambda *a, **k: _Response(200, {})):
            assert call_rest_test_iam_permissions(token="T", url="https://x", permissions=["a.b.get"]) == []

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_failure_grants_nothing(self, status):
        with patch("requests.request", lambda *a, **k: _Response(status, {"error": {"message": "no"}})):
            assert call_rest_test_iam_permissions(token="T", url="https://x", permissions=["a.b.get"]) == []

    def test_sends_the_requested_permissions_in_the_body(self):
        seen = {}

        def fake(method, url, **kwargs):
            seen.update(kwargs)
            return _Response(200, {"permissions": []})

        with patch("requests.request", fake):
            call_rest_test_iam_permissions(token="T", url="https://x", permissions=("p1", "p2"))
        assert seen["json"] == {"permissions": ["p1", "p2"]}


class _Request:
    def __init__(self, payload):
        self._payload = payload

    def execute(self):
        return self._payload


class _Collection:
    """Discovery-style collection whose list_next walks a scripted page list."""

    def __init__(self, pages):
        self.pages = pages
        self.index = 0

    def first(self):
        return _Request(self.pages[0])

    def list_next(self, previous_request=None, previous_response=None):
        self.index += 1
        if self.index >= len(self.pages):
            return None
        return _Request(self.pages[self.index])


class TestDrainListNext:
    def test_follows_list_next_across_pages(self):
        collection = _Collection([{"items": [{"n": 1}]}, {"items": [{"n": 2}]}, {"items": [{"n": 3}]}])
        rows = drain_list_next(collection, collection.first(), "items")
        assert rows == [{"n": 1}, {"n": 2}, {"n": 3}]

    def test_single_page_when_list_next_returns_none(self):
        collection = _Collection([{"items": [{"n": 1}]}])
        assert drain_list_next(collection, collection.first(), "items") == [{"n": 1}]

    def test_missing_and_non_dict_items_are_skipped(self):
        collection = _Collection([{"items": [{"n": 1}, "junk", None]}])
        assert drain_list_next(collection, collection.first(), "items") == [{"n": 1}]

    def test_absent_items_key_yields_empty(self):
        collection = _Collection([{}])
        assert drain_list_next(collection, collection.first(), "items") == []

    def test_rebuild_mode_pages_on_next_page_token(self):
        """Custom methods with no list_next page via a rebuilt request."""
        pages = [
            {"items": [{"n": 1}], "nextPageToken": "t1"},
            {"items": [{"n": 2}]},
        ]
        calls = []

        def rebuild(token):
            calls.append(token)
            return _Request(pages[1])

        rows = drain_list_next(None, _Request(pages[0]), "items", rebuild=rebuild)
        assert rows == [{"n": 1}, {"n": 2}]
        assert calls == ["t1"]


class TestCachedDiscoveryService:
    def test_builds_once_and_caches_on_the_owner(self):
        built = []

        class Owner:
            session = type("S", (), {"credentials": object()})()

        with patch("gcpwn.core.utils.service_runtime.build_discovery_service",
                   side_effect=lambda *a, **k: built.append(a) or "SERVICE"):
            owner = Owner()
            first = cached_discovery_service(owner, "iam", "v1", scopes=(CLOUD_PLATFORM_SCOPE,))
            second = cached_discovery_service(owner, "iam", "v1", scopes=(CLOUD_PLATFORM_SCOPE,))

        assert first == second == "SERVICE"
        assert len(built) == 1, "discovery client rebuilt instead of cached"

    def test_separate_owners_get_their_own(self):
        class Owner:
            session = type("S", (), {"credentials": object()})()

        with patch("gcpwn.core.utils.service_runtime.build_discovery_service", side_effect=lambda *a, **k: object()):
            a = cached_discovery_service(Owner(), "iam", "v1")
            b = cached_discovery_service(Owner(), "iam", "v1")
        assert a is not b


class TestResourceNameFromRow:
    def test_reads_the_name_field_from_a_dict(self):
        assert resource_name_from_row({"name": "projects/p/things/t"}) == "projects/p/things/t"

    def test_plain_string_row_is_stripped(self):
        assert resource_name_from_row("  projects/p  ") == "projects/p"

    def test_missing_name_is_empty(self):
        assert resource_name_from_row({"other": 1}) == ""

    def test_reads_the_attribute_when_not_a_dict(self):
        row = type("Row", (), {"name": "projects/p/things/t"})()
        assert resource_name_from_row(row) == "projects/p/things/t"
