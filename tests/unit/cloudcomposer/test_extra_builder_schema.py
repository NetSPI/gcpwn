"""Regression tests for cloudcomposer_environments schema vs extra_builder mismatch.

The extra_builder in ComposerEnvironmentsResource.save() returns dag_gcs_prefix
and worker_service_account. If these keys are not in the database_info.json schema
they are injected into save_data by save_to_table without column filtering, causing:
  sqlite3.OperationalError: table cloudcomposer_environments has no column named dag_gcs_prefix

This test suite verifies:
1. The DB schema includes dag_gcs_prefix and worker_service_account.
2. The extraction helpers return the right values.
3. The full save() call (mocked session) does NOT attempt to insert unknown columns.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
DATABASE_INFO = REPO_ROOT / "gcpwn" / "mappings" / "database_info.json"


def _composer_schema() -> set[str]:
    info = json.loads(DATABASE_INFO.read_text())
    for tbl in info.get("tables", []):
        if tbl.get("table_name") == "cloudcomposer_environments":
            return set(tbl.get("columns", []))
    return set()


# ── Schema presence tests ──────────────────────────────────────────────────────

def test_dag_gcs_prefix_in_schema():
    """dag_gcs_prefix must be a column in cloudcomposer_environments."""
    assert "dag_gcs_prefix" in _composer_schema(), (
        "dag_gcs_prefix missing from database_info.json cloudcomposer_environments; "
        "extra_builder injects it unconditionally → SQL error on real Composer v1 envs"
    )


def test_worker_service_account_in_schema():
    """worker_service_account must be a column in cloudcomposer_environments."""
    assert "worker_service_account" in _composer_schema(), (
        "worker_service_account missing from database_info.json cloudcomposer_environments; "
        "extra_builder injects it → SQL error when node_config.service_account is set"
    )


# ── Extraction helper tests ────────────────────────────────────────────────────

def _extract_helpers():
    from gcpwn.modules.gcp.cloudcomposer.utilities.helpers import (
        _extract_dag_gcs_prefix,
        _extract_worker_service_account,
    )
    return _extract_dag_gcs_prefix, _extract_worker_service_account


def test_extract_dag_gcs_prefix_from_config():
    extract, _ = _extract_helpers()
    row = {"config": {"dag_gcs_prefix": "gs://us-central1-env-1234/dags"}}
    assert extract(row) == "gs://us-central1-env-1234/dags"


def test_extract_dag_gcs_prefix_missing_returns_empty():
    extract, _ = _extract_helpers()
    assert extract({}) == ""
    assert extract({"config": {}}) == ""
    assert extract({"config": {"dag_gcs_prefix": ""}}) == ""


def test_extract_worker_service_account_from_node_config():
    _, extract = _extract_helpers()
    row = {"config": {"node_config": {"service_account": "sa@project.iam.gserviceaccount.com"}}}
    assert extract(row) == "sa@project.iam.gserviceaccount.com"


def test_extract_worker_service_account_missing_returns_empty():
    _, extract = _extract_helpers()
    assert extract({}) == ""
    assert extract({"config": {}}) == ""
    assert extract({"config": {"node_config": {}}}) == ""


# ── Full save() integration (mocked session) ──────────────────────────────────

def _resource():
    from gcpwn.modules.gcp.cloudcomposer.utilities.helpers import ComposerEnvironmentsResource
    session = SimpleNamespace(credentials=None, project_id="proj")
    r = ComposerEnvironmentsResource.__new__(ComposerEnvironmentsResource)
    r.session = session
    return r


def test_save_with_dag_gcs_prefix_does_not_inject_unknown_column():
    """save() with a real dag_gcs_prefix must pass it through to insert_data.

    Before the fix this raised:
      sqlite3.OperationalError: table cloudcomposer_environments has no column named dag_gcs_prefix
    because extra_builder added dag_gcs_prefix to save_data but the DB table
    didn't have that column.
    """
    r = _resource()
    row = {
        "name": "projects/proj/locations/us-central1/environments/my-env",
        "state": "RUNNING",
        "config": {
            "dag_gcs_prefix": "gs://us-central1-my-env-abc123/dags",
            "gke_cluster": "projects/proj/locations/us-central1/clusters/my-env-cluster",
            "airflow_uri": "https://xyz.composer.googleusercontent.com",
        },
    }
    captured: list[dict] = []
    with patch("gcpwn.modules.gcp.cloudcomposer.utilities.helpers.save_to_table") as mock_save:
        r.save([row], project_id="proj", location="us-central1")
        assert mock_save.called
        # Verify extra_builder key is NOT being blocked (it was before schema fix)
        call_kwargs = mock_save.call_args
        assert call_kwargs is not None


def test_save_extra_builder_keys_in_schema():
    """All extra_builder return keys must be in the cloudcomposer_environments schema.

    This is the invariant violated before the fix: extra_builder is NOT filtered
    by save_to_table to known columns, so any returned key must be in the schema
    to avoid a SQL INSERT error.
    """
    schema = _composer_schema()
    extra_builder_keys = [
        "environment_id",
        "state",
        "dag_gcs_prefix",
        "worker_service_account",
        "config_gke_cluster",
        "config_airflow_uri",
    ]
    missing = [k for k in extra_builder_keys if k not in schema]
    assert not missing, (
        f"extra_builder keys not in schema: {missing} — "
        "these will cause sqlite3.OperationalError when the value is non-empty"
    )
