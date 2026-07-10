"""BigQuery dataset IAM is the dataset ACL (access_entries), not getIamPolicy
(that is table/view only). These tests cover the ACL -> allow-policy conversion
that feeds the shared iam_allow_policies path.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gcpwn.modules.everything.utilities.iam_policy_bindings import IAMPolicyBindingsResource

bigquery = pytest.importorskip("google.cloud.bigquery")


def _resource():
    return object.__new__(IAMPolicyBindingsResource)


def _dataset(entries):
    return SimpleNamespace(project="my-project", etag="etag-123", access_entries=entries)


def test_dataset_acl_maps_basic_roles_and_entities() -> None:
    entries = [
        bigquery.AccessEntry("READER", "userByEmail", "alice@example.com"),
        bigquery.AccessEntry("WRITER", "groupByEmail", "eng@example.com"),
        bigquery.AccessEntry("OWNER", "specialGroup", "projectOwners"),
        bigquery.AccessEntry("READER", "specialGroup", "allAuthenticatedUsers"),
        bigquery.AccessEntry(
            "roles/bigquery.dataViewer", "iamMember", "serviceAccount:sa@my-project.iam.gserviceaccount.com"
        ),
    ]
    policy = _resource()._dataset_access_to_policy(_dataset(entries))
    bindings = {b["role"]: b["members"] for b in policy["bindings"]}

    assert bindings["roles/bigquery.dataViewer"] == [
        "allAuthenticatedUsers",
        "serviceAccount:sa@my-project.iam.gserviceaccount.com",
        "user:alice@example.com",
    ]
    assert bindings["roles/bigquery.dataEditor"] == ["group:eng@example.com"]
    # projectOwners special group -> IAM convenience member (graph-safe, skipped by OpenGraph)
    assert bindings["roles/bigquery.dataOwner"] == ["projectOwner:my-project"]
    assert policy["etag"] == "etag-123"


def test_dataset_acl_skips_authorized_views_and_roleless_entries() -> None:
    # Authorized views/routines/datasets grant no role to a principal -> excluded.
    view_entry = bigquery.AccessEntry(
        None, "view", {"projectId": "p", "datasetId": "d", "tableId": "v"}
    )
    entries = [view_entry, bigquery.AccessEntry("READER", "userByEmail", "bob@example.com")]
    policy = _resource()._dataset_access_to_policy(_dataset(entries))
    assert policy["bindings"] == [{"role": "roles/bigquery.dataViewer", "members": ["user:bob@example.com"]}]


def test_dataset_acl_empty_yields_empty_bindings() -> None:
    policy = _resource()._dataset_access_to_policy(_dataset([]))
    assert policy["bindings"] == []


def test_dataset_acl_special_group_without_project_is_dropped() -> None:
    # A projectOwners/Editors/Viewers special group is meaningless without its project;
    # with no project_id it must NOT emit a malformed bare "projectOwner" member.
    dataset = SimpleNamespace(project="", etag="e", access_entries=[
        bigquery.AccessEntry("OWNER", "specialGroup", "projectOwners"),
        bigquery.AccessEntry("READER", "userByEmail", "bob@example.com"),
    ])
    policy = _resource()._dataset_access_to_policy(dataset)
    bindings = {b["role"]: b["members"] for b in policy["bindings"]}
    assert "projectOwner" not in str(bindings)          # dropped, not malformed
    assert bindings.get("roles/bigquery.dataViewer") == ["user:bob@example.com"]
