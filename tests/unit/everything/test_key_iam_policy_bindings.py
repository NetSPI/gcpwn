from __future__ import annotations

from gcpwn.modules.everything.utilities.helpers import IAMPolicyBindingsResource


def test_key_iam_policy_bindings_append_member_existing_role() -> None:
    current_policy = {
        "bindings": [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]}
        ],
        "version": 1,
    }

    updated = IAMPolicyBindingsResource._policy_for_member_update(
        current_policy,
        member="serviceAccount:bot@demo-project.iam.gserviceaccount.com",
        role="roles/viewer",
        brute=False,
    )

    assert set(updated["bindings"][0]["members"]) == {
        "user:alice@example.com",
        "serviceAccount:bot@demo-project.iam.gserviceaccount.com",
    }


def test_key_iam_policy_bindings_add_new_role_binding() -> None:
    current_policy = {
        "bindings": [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]}
        ],
        "version": 1,
    }

    updated = IAMPolicyBindingsResource._policy_for_member_update(
        current_policy,
        member="user:bob@example.com",
        role="roles/editor",
        brute=False,
    )

    roles = {binding["role"] for binding in updated["bindings"]}
    assert roles == {"roles/viewer", "roles/editor"}


def test_key_iam_policy_bindings_brute_overwrite_replaces_bindings() -> None:
    current_policy = {
        "bindings": [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]}
        ],
        "version": 3,
        "etag": "BwYc123=",
    }

    updated = IAMPolicyBindingsResource._policy_for_member_update(
        current_policy,
        member="user:bob@example.com",
        role="roles/cloudtasks.admin",
        brute=True,
    )

    assert updated["bindings"] == [
        {"role": "roles/cloudtasks.admin", "members": ["user:bob@example.com"]}
    ]
    assert updated["version"] == 3
    assert updated["etag"] == "BwYc123="
