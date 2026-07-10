"""Unit tests for the action/permission MERGE in gcpwn.core.db.DataController.

This exercises the heart of the permission model: ``insert_actions`` plus the
``_merge_action_*`` helpers that build the evidence/provenance trees, and the
``get_actions`` read-back.

Isolation: a DataController is built via ``__new__`` so the real constructor
never touches ``databases/``. Only the session DB is wired up (against a
``tmp_path`` file), which is all the action API needs. No GCP creds/network.
"""

from __future__ import annotations

import json

import pytest

from gcpwn.core.action_schema import (
    ACTION_COLUMNS,
    ACTION_EVIDENCE_DIRECT_API,
    ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
    ACTION_PROVENANCE_COLUMN,
)
from gcpwn.core.db import DataController

WORKSPACE_ID = 1


def _make_controller(tmp_path) -> DataController:
    """A DataController backed by an isolated on-disk session DB only.

    Built via __new__ so the constructor never touches the real databases/.
    The session_actions schema mirrors create_initial_workspace_session_database.
    """
    dc = DataController.__new__(DataController)
    conn = dc._connect_database(str(tmp_path / "sessions.db"))
    dc.conn = conn
    dc.cursor = conn.cursor()
    dc._service_primary_key_cache = {}

    resource_columns = ", ".join(f"{column_name} TEXT" for column_name in ACTION_COLUMNS)
    conn.execute(
        f"""
        CREATE TABLE session_actions
        (
            workspace_id INTEGER, credname TEXT,
            {resource_columns},
            {ACTION_PROVENANCE_COLUMN} TEXT,
            PRIMARY KEY (workspace_id, credname)
        )
        """
    )
    conn.commit()
    return dc


def _read_row(dc: DataController, credname: str) -> dict:
    rows = dc.get_actions(WORKSPACE_ID, credname, include_provenance=True)
    assert len(rows) == 1
    return rows[0]


@pytest.fixture
def dc(tmp_path) -> DataController:
    return _make_controller(tmp_path)


# --------------------------------------------------------------------------- #
# Scope-level inserts land in the right column tree
# --------------------------------------------------------------------------- #


_SCOPE_COLUMNS = (
    "project_actions_allowed",
    "folder_actions_allowed",
    "organization_actions_allowed",
    "workspace_actions_allowed",
)


@pytest.mark.parametrize(
    "input_scope_key, expected_column, sample_value",
    [
        (
            "project_permissions",
            "project_actions_allowed",
            {"proj-a": ["storage.buckets.list"]},
        ),
        (
            "folder_permissions",
            "folder_actions_allowed",
            {"folders/123": ["resourcemanager.folders.get"]},
        ),
        (
            "organization_permissions",
            "organization_actions_allowed",
            {"organizations/9": ["resourcemanager.organizations.get"]},
        ),
    ],
    ids=["project", "folder", "organization"],
)
def test_scope_lands_in_right_column(
    dc: DataController, input_scope_key: str, expected_column: str, sample_value: dict
) -> None:
    ok = dc.insert_actions(WORKSPACE_ID, "alice", {input_scope_key: sample_value})
    assert ok is True

    row = _read_row(dc, "alice")
    assert row[expected_column] == sample_value
    # No bleed-over into the other scope columns.
    for column in _SCOPE_COLUMNS:
        if column != expected_column:
            assert row[column] == {}


def test_multiple_scopes_in_one_record(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {
            "project_permissions": {"proj-a": ["storage.buckets.list"]},
            "organization_permissions": {"organizations/9": ["iam.roles.list"]},
        },
    )
    row = _read_row(dc, "alice")
    assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}
    assert row["organization_actions_allowed"] == {"organizations/9": ["iam.roles.list"]}


# --------------------------------------------------------------------------- #
# Resource-level inserts (column_name -> resource_type/labels tree)
# --------------------------------------------------------------------------- #


def test_resource_level_lands_in_named_column(dc: DataController) -> None:
    # Resource records are a 3-deep tree:
    #   project_id -> permission -> resource_type -> [resource_names]
    # (mirrors how cloudstorage helpers build action_dict).
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"proj-a": {"storage.buckets.getIamPolicy": {"buckets": ["my-bucket", "other-bucket"]}}},
        column_name="storage_actions_allowed",
    )
    row = _read_row(dc, "alice")
    assert row["storage_actions_allowed"] == {
        "proj-a": {"storage.buckets.getIamPolicy": {"buckets": ["my-bucket", "other-bucket"]}}
    }
    # Scope columns remain empty when only a resource record is supplied.
    assert row["project_actions_allowed"] == {}


def test_resource_and_scope_in_same_record(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {
            "project_permissions": {"proj-a": ["storage.buckets.list"]},
            "proj-a": {"storage.buckets.getIamPolicy": {"buckets": ["my-bucket"]}},
        },
        column_name="storage_actions_allowed",
    )
    row = _read_row(dc, "alice")
    assert row["storage_actions_allowed"] == {
        "proj-a": {"storage.buckets.getIamPolicy": {"buckets": ["my-bucket"]}}
    }
    assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}


# --------------------------------------------------------------------------- #
# Merging two inserts for the SAME credential unions, never loses
# --------------------------------------------------------------------------- #


def test_repeated_scope_inserts_union_permissions(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.get"]}},
    )
    row = _read_row(dc, "alice")
    # Union, sorted, de-duplicated; nothing dropped.
    assert row["project_actions_allowed"] == {
        "proj-a": ["storage.buckets.get", "storage.buckets.list"]
    }


def test_merge_adds_new_scope_key_without_losing_old(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-b": ["compute.instances.list"]}},
    )
    row = _read_row(dc, "alice")
    assert row["project_actions_allowed"] == {
        "proj-a": ["storage.buckets.list"],
        "proj-b": ["compute.instances.list"],
    }


def test_duplicate_permission_is_deduped(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    row = _read_row(dc, "alice")
    assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}


def test_resource_level_merge_unions_labels_and_perms(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"proj-a": {"storage.buckets.getIamPolicy": {"buckets": ["bucket-1"]}}},
        column_name="storage_actions_allowed",
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {
            "proj-a": {
                # Same permission, new resource name -> union of the leaf list.
                "storage.buckets.getIamPolicy": {"buckets": ["bucket-2"]},
                # New permission under the same project.
                "storage.buckets.setIamPolicy": {"buckets": ["bucket-1"]},
            },
            # Brand new project key.
            "proj-b": {"storage.buckets.getIamPolicy": {"buckets": ["bucket-9"]}},
        },
        column_name="storage_actions_allowed",
    )
    row = _read_row(dc, "alice")
    assert row["storage_actions_allowed"] == {
        "proj-a": {
            "storage.buckets.getIamPolicy": {"buckets": ["bucket-1", "bucket-2"]},
            "storage.buckets.setIamPolicy": {"buckets": ["bucket-1"]},
        },
        "proj-b": {"storage.buckets.getIamPolicy": {"buckets": ["bucket-9"]}},
    }


# --------------------------------------------------------------------------- #
# No-op inserts do not error and do not corrupt existing data
# --------------------------------------------------------------------------- #


def test_empty_record_is_noop(dc: DataController) -> None:
    # Nothing exists yet; an empty record changes nothing and must not create a row.
    assert dc.insert_actions(WORKSPACE_ID, "alice", {}) is True
    assert dc.get_actions(WORKSPACE_ID, "alice") == []


def test_redundant_insert_after_existing_is_noop(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    # Re-inserting the same evidence + permission is a no-op but still succeeds.
    assert (
        dc.insert_actions(
            WORKSPACE_ID,
            "alice",
            {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        )
        is True
    )
    row = _read_row(dc, "alice")
    assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}


# --------------------------------------------------------------------------- #
# Provenance / evidence_type tagging
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "evidence_type",
    [ACTION_EVIDENCE_DIRECT_API, ACTION_EVIDENCE_TEST_IAM_PERMISSIONS],
    ids=["direct_api", "test_iam_permissions"],
)
def test_provenance_tag_records_evidence_type(dc: DataController, evidence_type) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        evidence_type=evidence_type,
    )
    row = _read_row(dc, "alice")
    assert row[ACTION_PROVENANCE_COLUMN] == {
        "project_actions_allowed": {
            "proj-a": {"storage.buckets.list": [evidence_type]}
        }
    }


def test_same_permission_two_evidence_types_both_recorded(dc: DataController) -> None:
    # Discover via direct API, then later via testIamPermissions: both tagged.
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        evidence_type=ACTION_EVIDENCE_DIRECT_API,
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
    )
    row = _read_row(dc, "alice")

    # The permission itself is recorded once.
    assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}

    # Provenance carries BOTH evidence types for that one permission.
    evidence = row[ACTION_PROVENANCE_COLUMN]["project_actions_allowed"]["proj-a"][
        "storage.buckets.list"
    ]
    assert sorted(evidence) == sorted(
        [ACTION_EVIDENCE_DIRECT_API, ACTION_EVIDENCE_TEST_IAM_PERMISSIONS]
    )


def test_distinct_permissions_keep_distinct_evidence(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        evidence_type=ACTION_EVIDENCE_DIRECT_API,
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.get"]}},
        evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
    )
    proj = _read_row(dc, "alice")[ACTION_PROVENANCE_COLUMN]["project_actions_allowed"]["proj-a"]
    assert proj == {
        "storage.buckets.list": [ACTION_EVIDENCE_DIRECT_API],
        "storage.buckets.get": [ACTION_EVIDENCE_TEST_IAM_PERMISSIONS],
    }


def test_resource_level_provenance_tags_permission_names(dc: DataController) -> None:
    # For resource records (leaf_depth=3) provenance keys on the project id and
    # tags the permission names (the second level), per _build_provenance_tree.
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"proj-a": {"storage.buckets.getIamPolicy": {"buckets": ["my-bucket"]}}},
        column_name="storage_actions_allowed",
        evidence_type=ACTION_EVIDENCE_DIRECT_API,
    )
    provenance = _read_row(dc, "alice")[ACTION_PROVENANCE_COLUMN]
    assert provenance == {
        "storage_actions_allowed": {
            "proj-a": {"storage.buckets.getIamPolicy": [ACTION_EVIDENCE_DIRECT_API]}
        }
    }


# --------------------------------------------------------------------------- #
# Per-credential isolation + credname_override (via SessionUtility wrapper)
# --------------------------------------------------------------------------- #


def test_distinct_crednames_are_isolated(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    dc.insert_actions(
        WORKSPACE_ID,
        "bob",
        {"project_permissions": {"proj-b": ["compute.instances.list"]}},
    )
    alice = _read_row(dc, "alice")
    bob = _read_row(dc, "bob")
    assert alice["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}
    assert bob["project_actions_allowed"] == {"proj-b": ["compute.instances.list"]}
    # And a workspace-wide read returns both, keyed by credname.
    everyone = {r["credname"]: r for r in dc.get_actions(WORKSPACE_ID)}
    assert set(everyone) == {"alice", "bob"}


class _FakeSession:
    """Minimal stand-in for SessionUtility wiring insert_actions -> DataController.

    Reproduces the real method body's credname resolution so we can verify
    credname_override attribution without building real credentials.
    """

    def __init__(self, data_master: DataController, credname: str) -> None:
        self.data_master = data_master
        self.workspace_id = WORKSPACE_ID
        self.credname = credname

    # Copied behavior from gcpwn.core.session.SessionUtility.insert_actions.
    def insert_actions(
        self,
        actions,
        project_id=None,
        column_name=None,
        evidence_type=ACTION_EVIDENCE_DIRECT_API,
        credname_override=None,
    ):
        _ = project_id
        target_crednames = credname_override or self.credname
        if isinstance(target_crednames, str):
            target_crednames = [target_crednames]
        for target_credname in [
            str(cred or "").strip()
            for cred in (target_crednames or [])
            if str(cred or "").strip()
        ]:
            self.data_master.insert_actions(
                self.workspace_id,
                target_credname,
                actions,
                column_name=column_name,
                evidence_type=evidence_type,
            )


def test_credname_override_attributes_to_other_credential(dc: DataController) -> None:
    session = _FakeSession(dc, credname="session-cred")
    session.insert_actions(
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        credname_override="impersonated-sa",
    )
    # The permission landed on the override credential, not the session credname.
    assert dc.get_actions(WORKSPACE_ID, "session-cred") == []
    target = _read_row(dc, "impersonated-sa")
    assert target["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}


def test_credname_override_list_fans_out_to_all(dc: DataController) -> None:
    session = _FakeSession(dc, credname="session-cred")
    session.insert_actions(
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
        credname_override=["sa-one", "sa-two"],
    )
    for cred in ("sa-one", "sa-two"):
        row = _read_row(dc, cred)
        assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}
    assert dc.get_actions(WORKSPACE_ID, "session-cred") == []


def test_no_override_uses_session_credname(dc: DataController) -> None:
    session = _FakeSession(dc, credname="session-cred")
    session.insert_actions({"project_permissions": {"proj-a": ["storage.buckets.list"]}})
    row = _read_row(dc, "session-cred")
    assert row["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}


# --------------------------------------------------------------------------- #
# Read-back shape / persistence
# --------------------------------------------------------------------------- #


def test_get_actions_without_provenance_omits_column(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    rows = dc.get_actions(WORKSPACE_ID, "alice", include_provenance=False)
    assert len(rows) == 1
    row = rows[0]
    assert ACTION_PROVENANCE_COLUMN not in row
    assert row["credname"] == "alice"
    # Every action column is present and JSON-decoded (defaulting to {}).
    for column_name in ACTION_COLUMNS:
        assert column_name in row
        assert isinstance(row[column_name], dict)


def test_stored_blob_is_valid_json(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    raw = dc.cursor.execute(
        "SELECT project_actions_allowed FROM session_actions WHERE credname = ?",
        ("alice",),
    ).fetchone()
    decoded = json.loads(raw["project_actions_allowed"])
    assert decoded == {"proj-a": ["storage.buckets.list"]}


def test_get_actions_unknown_credname_returns_empty(dc: DataController) -> None:
    dc.insert_actions(
        WORKSPACE_ID,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    assert dc.get_actions(WORKSPACE_ID, "nobody") == []


def test_workspace_scoping_separates_rows(dc: DataController) -> None:
    dc.insert_actions(
        1,
        "alice",
        {"project_permissions": {"proj-a": ["storage.buckets.list"]}},
    )
    dc.insert_actions(
        2,
        "alice",
        {"project_permissions": {"proj-z": ["compute.instances.list"]}},
    )
    ws1 = _read_row(dc, "alice")  # WORKSPACE_ID == 1
    assert ws1["project_actions_allowed"] == {"proj-a": ["storage.buckets.list"]}
    ws2 = dc.get_actions(2, "alice")
    assert len(ws2) == 1
    assert ws2[0]["project_actions_allowed"] == {"proj-z": ["compute.instances.list"]}
