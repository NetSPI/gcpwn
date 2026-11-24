from __future__ import annotations

import json

from gcpwn.modules.opengraph.utilities.stage_2_policy_bindings import (
    _compute_cf_build_capable_emails,
)

_THREE_BUILD_PERMS = [
    "artifactregistry.repositories.downloadArtifacts",
    "artifactregistry.repositories.uploadArtifacts",
    "logging.logEntries.create",
]


def _policy(role: str, member: str) -> str:
    return json.dumps({"bindings": [{"role": role, "members": [member]}]})


def _row(role: str, member: str, resource_type: str = "", resource_name: str = "") -> dict:
    return {
        "policy": _policy(role, member),
        "resource_type": resource_type,
        "resource_name": resource_name,
    }


# ---------------------------------------------------------------------------
# V1 tests (is_cf_build_capable) — predefined roles at project scope
# ---------------------------------------------------------------------------

def test_cf_build_capable_reads_policy_key() -> None:
    rows = [_row("roles/editor", "serviceAccount:runtime@proj.iam.gserviceaccount.com", "project", "projects/proj")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {})
    assert "runtime@proj.iam.gserviceaccount.com" in v1
    assert "runtime@proj.iam.gserviceaccount.com" in v2


def test_cf_build_capable_policy_json_fallback() -> None:
    rows = [{"policy_json": _policy("roles/owner", "serviceAccount:owner@proj.iam.gserviceaccount.com"),
             "resource_type": "project", "resource_name": "projects/proj"}]
    v1, v2 = _compute_cf_build_capable_emails(rows, {})
    assert "owner@proj.iam.gserviceaccount.com" in v1
    assert "owner@proj.iam.gserviceaccount.com" in v2


def test_cf_build_capable_cloudbuild_builder_role() -> None:
    rows = [_row("roles/cloudbuild.builds.builder", "serviceAccount:bld@proj.iam.gserviceaccount.com",
                 "project", "projects/proj")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {})
    assert "bld@proj.iam.gserviceaccount.com" in v1
    assert "bld@proj.iam.gserviceaccount.com" in v2


def test_cf_build_capable_custom_role_with_three_perms() -> None:
    role = "projects/proj/roles/customBuild"
    rows = [_row(role, "serviceAccount:custom@proj.iam.gserviceaccount.com", "project", "projects/proj")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {role: set(_THREE_BUILD_PERMS)})
    # Custom role without storage.objects.get: V1 capable, NOT V2 capable
    assert "custom@proj.iam.gserviceaccount.com" in v1
    assert "custom@proj.iam.gserviceaccount.com" not in v2


def test_cf_build_capable_predefined_role_on_resource_scope_excluded() -> None:
    """roles/owner on a KMS key (non-project scope) must NOT satisfy V1 build capability."""
    rows = [_row("roles/owner", "serviceAccount:gke-sa@proj.iam.gserviceaccount.com",
                 "kmscryptokey", "projects/proj/locations/us/keyRings/kr/cryptoKeys/k")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {})
    assert "gke-sa@proj.iam.gserviceaccount.com" not in v1
    assert "gke-sa@proj.iam.gserviceaccount.com" not in v2


def test_cf_build_capable_insufficient_role_excluded() -> None:
    rows = [_row("roles/viewer", "serviceAccount:nope@proj.iam.gserviceaccount.com", "project", "projects/proj")]
    v1, _ = _compute_cf_build_capable_emails(rows, {})
    assert "nope@proj.iam.gserviceaccount.com" not in v1


def test_cf_build_capable_non_sa_member_ignored() -> None:
    rows = [_row("roles/editor", "user:person@example.com", "project", "projects/proj")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {})
    assert v1 == frozenset()
    assert v2 == frozenset()


# ---------------------------------------------------------------------------
# V2 tests (is_cf_v2_build_capable) — bucket-level grant path
# ---------------------------------------------------------------------------

def test_cf_v2_build_capable_via_bucket_objectviewer() -> None:
    """3-perm custom role at project + objectViewer on gcf-v2-sources-* → V2 capable."""
    role = "projects/proj/roles/customBuild"
    rows = [
        _row(role, "serviceAccount:bld@proj.iam.gserviceaccount.com", "project", "projects/proj"),
        _row("roles/storage.objectViewer", "serviceAccount:bld@proj.iam.gserviceaccount.com",
             "bucket", "gcf-v2-sources-123456-us-central1"),
    ]
    v1, v2 = _compute_cf_build_capable_emails(rows, {role: set(_THREE_BUILD_PERMS)})
    assert "bld@proj.iam.gserviceaccount.com" in v1
    assert "bld@proj.iam.gserviceaccount.com" in v2


def test_cf_v2_build_not_capable_without_bucket_access() -> None:
    """3-perm custom role at project, no bucket grant → V1 only."""
    role = "projects/proj/roles/customBuild"
    rows = [_row(role, "serviceAccount:bld@proj.iam.gserviceaccount.com", "project", "projects/proj")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {role: set(_THREE_BUILD_PERMS)})
    assert "bld@proj.iam.gserviceaccount.com" in v1
    assert "bld@proj.iam.gserviceaccount.com" not in v2


def test_cf_v2_build_capable_via_custom_role_with_storage_at_project() -> None:
    """Custom role with storage.objects.get at project level → V2 capable."""
    role = "projects/proj/roles/customBuildStorage"
    perms = set(_THREE_BUILD_PERMS) | {"storage.objects.get"}
    rows = [_row(role, "serviceAccount:bld@proj.iam.gserviceaccount.com", "project", "projects/proj")]
    v1, v2 = _compute_cf_build_capable_emails(rows, {role: perms})
    assert "bld@proj.iam.gserviceaccount.com" in v1
    assert "bld@proj.iam.gserviceaccount.com" in v2


def test_cf_v2_build_capable_via_storage_viewer_at_project_level() -> None:
    """roles/storage.objectViewer at project level inherits to gcf-v2-sources-* → V2 capable."""
    role = "projects/proj/roles/customBuild"
    rows = [
        _row(role, "serviceAccount:bld@proj.iam.gserviceaccount.com", "project", "projects/proj"),
        _row("roles/storage.objectViewer", "serviceAccount:bld@proj.iam.gserviceaccount.com",
             "project", "projects/proj"),
    ]
    v1, v2 = _compute_cf_build_capable_emails(rows, {role: set(_THREE_BUILD_PERMS)})
    assert "bld@proj.iam.gserviceaccount.com" in v1
    assert "bld@proj.iam.gserviceaccount.com" in v2


def test_cf_v2_bucket_grant_on_non_gcf_bucket_ignored() -> None:
    """objectViewer on a non-gcf-v2-sources-* bucket does NOT satisfy V2."""
    role = "projects/proj/roles/customBuild"
    rows = [
        _row(role, "serviceAccount:bld@proj.iam.gserviceaccount.com", "project", "projects/proj"),
        _row("roles/storage.objectViewer", "serviceAccount:bld@proj.iam.gserviceaccount.com",
             "bucket", "my-other-bucket"),
    ]
    v1, v2 = _compute_cf_build_capable_emails(rows, {role: set(_THREE_BUILD_PERMS)})
    assert "bld@proj.iam.gserviceaccount.com" in v1
    assert "bld@proj.iam.gserviceaccount.com" not in v2
