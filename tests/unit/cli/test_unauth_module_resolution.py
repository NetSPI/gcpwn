"""Regression: an unauth-ALLOWED module that is not an unauth_-prefixed one (e.g. the
process_og_* file-reading tools) must resolve to its FULL import path for --module passthrough.
Returning the bare token made the importer fail with "missing '<token>'"."""
from gcpwn.cli.main import _resolve_unauth_module_path


def test_unauth_allowed_process_module_resolves_full_import_path():
    assert (
        _resolve_unauth_module_path("process_og_attack_paths")
        == "gcpwn.modules.opengraph.processing.process_og_attack_paths"
    )


def test_auth_required_module_is_rejected_for_unauth_passthrough():
    assert _resolve_unauth_module_path("enum_resources") == ""


def test_unknown_module_returns_empty():
    assert _resolve_unauth_module_path("not_a_real_module_xyz") == ""
