"""Consolidated service-location loading + the region resolver's discovery-first,
static-fallback precedence (replaces the scattered per-module locations.txt files).
"""

from __future__ import annotations

from types import SimpleNamespace

from gcpwn.core.utils import module_helpers
from gcpwn.core.utils.module_helpers import (
    load_service_locations,
    resolve_regions_from_module_data,
    static_locations,
)


def test_consolidated_file_has_every_migrated_service() -> None:
    sections = load_service_locations()
    for service in (
        "apigateway",
        "artifactregistry",
        "cloudbuild",
        "cloudcomposer",
        "cloudrun",
        "cloudtasks",
        "kms",
        "servicedirectory",
    ):
        assert sections.get(service), f"missing/empty section for {service}"
    # kms keeps its multi-region tokens (e.g. 'global', 'nam-eur-asia1')
    assert "global" in static_locations("kms")
    assert static_locations("unknown-service") == []


def _args(**kw):
    base = {"regions_list": None, "regions_file": None, "all_regions": False}
    base.update(kw)
    return SimpleNamespace(**base)


def _session(project_id="p", preferred=None):
    cfg = SimpleNamespace(preferred_regions=preferred) if preferred is not None else None
    return SimpleNamespace(project_id=project_id, credentials=object(), workspace_config=cfg)


def test_explicit_regions_list_wins_over_everything(monkeypatch) -> None:
    monkeypatch.setattr(module_helpers, "discover_service_locations", lambda *a, **k: ["zzz"])
    out = resolve_regions_from_module_data(
        _session(), _args(regions_list="us-central1, us-east1"), service="kms", discovery=("cloudkms", "v1")
    )
    assert out == ["us-central1", "us-east1"]


def test_discovery_used_first_when_no_explicit_flags(monkeypatch) -> None:
    calls = {}

    def fake_discover(credentials, api_name, api_version, project_id):
        calls["args"] = (api_name, api_version, project_id)
        return ["live-region-1", "live-region-2"]

    monkeypatch.setattr(module_helpers, "discover_service_locations", fake_discover)
    out = resolve_regions_from_module_data(_session(), _args(), service="kms", discovery=("cloudkms", "v1"))
    assert out == ["live-region-1", "live-region-2"]
    assert calls["args"] == ("cloudkms", "v1", "p")


def test_falls_back_to_static_when_discovery_empty(monkeypatch) -> None:
    monkeypatch.setattr(module_helpers, "discover_service_locations", lambda *a, **k: [])
    out = resolve_regions_from_module_data(_session(), _args(), service="cloudtasks", discovery=("cloudtasks", "v2"))
    assert out == static_locations("cloudtasks")
    assert out  # non-empty static fallback


def test_static_only_service_never_calls_discovery(monkeypatch) -> None:
    monkeypatch.setattr(
        module_helpers,
        "discover_service_locations",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("discovery must not run")),
    )
    out = resolve_regions_from_module_data(_session(), _args(), service="cloudrun")
    assert out == static_locations("cloudrun")


def test_preferred_regions_beat_static_but_not_discovery_path(monkeypatch) -> None:
    # preferred_regions short-circuits before the known-location lookup entirely.
    monkeypatch.setattr(
        module_helpers,
        "discover_service_locations",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("discovery must not run when preferred set")),
    )
    out = resolve_regions_from_module_data(
        _session(preferred=["europe-west1"]), _args(), service="kms", discovery=("cloudkms", "v1")
    )
    assert out == ["europe-west1"]
