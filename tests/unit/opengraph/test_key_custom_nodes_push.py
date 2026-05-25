from __future__ import annotations

import json
import sys
import types

from gcpwn.modules.opengraph.utilities.helpers.ui_formatting import constants as ui_constants
from gcpwn.modules.opengraph.utilities.helpers.ui_formatting.custom_node_sync import push_custom_node_attributes


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_key_custom_nodes_push_skips_without_bearer_token() -> None:
    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080",
        custom_nodes_token="",
        auth_mode="bearer",
    )

    assert result == {"ok": False, "reason": "missing_token"}


def test_key_custom_nodes_push_skips_without_signature_credentials() -> None:
    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080",
        auth_mode="signature",
        custom_nodes_token_id="",
        custom_nodes_token_key="",
    )

    assert result == {"ok": False, "reason": "missing_signature_credentials"}


def test_key_custom_nodes_push_creates_missing_custom_type(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def _request(method, url, **kwargs):
        calls.append((str(method), str(url)))
        if method == "GET":
            return _FakeResponse(200, json.dumps({"data": []}))
        if method == "POST":
            return _FakeResponse(200, "ok")
        return _FakeResponse(500, "unexpected")

    fake_requests = types.SimpleNamespace(request=_request)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    monkeypatch.setattr(ui_constants, "CUSTOM_NODE_TYPES", {"UnitType": {"icon": "user", "color": "#ff0000"}})

    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080",
        custom_nodes_token="test-token",
        auth_mode="bearer",
    )

    assert result["ok"] is True
    assert result["created_kinds"] == 1
    assert result["updated_kinds"] == 0
    assert result["unchanged_kinds"] == 0
    assert calls[:2] == [
        ("GET", "http://127.0.0.1:8080/api/v2/custom-nodes"),
        ("POST", "http://127.0.0.1:8080/api/v2/custom-nodes"),
    ]


def test_key_custom_nodes_push_tries_alternate_collection_url_when_first_fails(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def _request(method, url, **kwargs):
        calls.append((str(method), str(url)))
        if url.endswith("/api/v2/custom-node-types") and method == "GET":
            return _FakeResponse(404, "not found")
        if url.endswith("/api/v2/custom-nodes") and method == "GET":
            return _FakeResponse(200, json.dumps({"data": []}))
        if url.endswith("/api/v2/custom-nodes") and method == "POST":
            return _FakeResponse(200, "ok")
        return _FakeResponse(500, "unexpected")

    fake_requests = types.SimpleNamespace(request=_request)
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    monkeypatch.setattr(ui_constants, "CUSTOM_NODE_TYPES", {"UnitType": {"icon": "user", "color": "#ff0000"}})

    result = push_custom_node_attributes(
        custom_nodes_url="http://127.0.0.1:8080/api/v2/custom-node-types",
        custom_nodes_token="test-token",
        auth_mode="bearer",
    )

    assert result["ok"] is True
    assert result["url"] == "http://127.0.0.1:8080/api/v2/custom-nodes"
    assert ("GET", "http://127.0.0.1:8080/api/v2/custom-node-types") in calls
    assert ("GET", "http://127.0.0.1:8080/api/v2/custom-nodes") in calls
