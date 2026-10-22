"""Regression tests for gcpwn.core.utils.iam_simplifier.

Focus: `_build_project_role_members` must expand owner/editor/viewer into the
projectOwner/Editor/Viewer convenience members ONLY for a grant on the project
itself (scope name exactly ``projects/<id>``) — never for a grant on a
sub-resource (``projects/<id>/serviceAccounts/<x>``, ``.../cryptoKeys/<k>``,
etc.), which would emit false project-wide edges (e.g. CAN_MODIFY_BUCKET_IAM on
every bucket from a member that merely owns one KMS key).
"""

from __future__ import annotations

from gcpwn.core.utils.iam_simplifier import (
    _build_project_role_members,
    _default_is_convenience_member,
)


def _record(role, scope_name, scope_type, project_id="proj-a"):
    return {
        "role_name": role,
        "attached_scope_name": scope_name,
        "attached_scope_type": scope_type,
        "project_id": project_id,
    }


def _index(member, record):
    return {member: {"res-key": {"direct_binding_records": [record], "inherited_binding_records": []}}}


def _build(index):
    return _build_project_role_members(
        index,
        normalize_member=lambda m: str(m or "").strip(),
        is_convenience_member=_default_is_convenience_member,
    )


def test_project_level_owner_is_expanded():
    out = _build(_index("user:real@x.com", _record("roles/owner", "projects/proj-a", "project")))
    assert out.get("proj-a", {}).get("roles/owner") == {"user:real@x.com"}


def test_subresource_owner_is_not_expanded_service_account():
    out = _build(_index(
        "serviceAccount:robot@proj-a.iam.gserviceaccount.com",
        _record("roles/owner", "projects/proj-a/serviceAccounts/x@proj-a.iam.gserviceaccount.com", "service-account"),
    ))
    assert out == {} or "roles/owner" not in out.get("proj-a", {})


def test_subresource_owner_is_not_expanded_cryptokey():
    out = _build(_index(
        "serviceAccount:robot@proj-a.iam.gserviceaccount.com",
        _record(
            "roles/owner",
            "projects/proj-a/locations/us/keyRings/r/cryptoKeys/gke-key",
            "kmscryptokey",
        ),
    ))
    assert out == {} or "roles/owner" not in out.get("proj-a", {})


def test_project_number_scope_name_is_expanded():
    out = _build(_index("user:real@x.com", _record("roles/editor", "projects/123456789012", "project", project_id="proj-a")))
    # indexed by both project_id and project number
    assert "user:real@x.com" in out.get("proj-a", {}).get("roles/editor", set())


def test_mixed_project_and_subresource_only_keeps_project():
    index = {
        "user:owner@x.com": {"k1": {"direct_binding_records": [_record("roles/owner", "projects/proj-a", "project")], "inherited_binding_records": []}},
        "serviceAccount:robot@proj-a.iam.gserviceaccount.com": {"k2": {"direct_binding_records": [_record("roles/owner", "projects/proj-a/serviceAccounts/x@proj-a.iam.gserviceaccount.com", "service-account")], "inherited_binding_records": []}},
    }
    out = _build(index)
    assert out.get("proj-a", {}).get("roles/owner") == {"user:owner@x.com"}
