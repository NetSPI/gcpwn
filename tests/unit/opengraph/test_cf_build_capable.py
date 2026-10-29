from __future__ import annotations

import json

from gcpwn.modules.opengraph.utilities.stage_2_policy_bindings import (
    _compute_cf_build_capable_emails,
)

_FOUR_BUILD_PERMS = [
    "artifactregistry.repositories.downloadArtifacts",
    "artifactregistry.repositories.uploadArtifacts",
    "storage.objects.create",
    "storage.objects.get",
]


def _policy(role: str, member: str) -> str:
    return json.dumps({"bindings": [{"role": role, "members": [member]}]})


def test_cf_build_capable_reads_policy_key() -> None:
    # Regression: enumerated DB rows (and CAI rows) carry the raw policy under "policy".
    # Reading "policy_json" alone matched nothing, so no SA was ever build-capable and
    # CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA could never fire.
    rows = [{"policy": _policy("roles/editor", "serviceAccount:runtime@proj.iam.gserviceaccount.com")}]
    capable = _compute_cf_build_capable_emails(rows, {})
    assert "runtime@proj.iam.gserviceaccount.com" in capable


def test_cf_build_capable_policy_json_fallback() -> None:
    rows = [{"policy_json": _policy("roles/owner", "serviceAccount:owner@proj.iam.gserviceaccount.com")}]
    capable = _compute_cf_build_capable_emails(rows, {})
    assert "owner@proj.iam.gserviceaccount.com" in capable


def test_cf_build_capable_cloudbuild_builder_role() -> None:
    rows = [{"policy": _policy("roles/cloudbuild.builds.builder", "serviceAccount:bld@proj.iam.gserviceaccount.com")}]
    capable = _compute_cf_build_capable_emails(rows, {})
    assert "bld@proj.iam.gserviceaccount.com" in capable


def test_cf_build_capable_custom_role_with_four_perms() -> None:
    role = "projects/proj/roles/customBuild"
    rows = [{"policy": _policy(role, "serviceAccount:custom@proj.iam.gserviceaccount.com")}]
    capable = _compute_cf_build_capable_emails(rows, {role: set(_FOUR_BUILD_PERMS)})
    assert "custom@proj.iam.gserviceaccount.com" in capable


def test_cf_build_capable_insufficient_role_excluded() -> None:
    rows = [{"policy": _policy("roles/viewer", "serviceAccount:nope@proj.iam.gserviceaccount.com")}]
    capable = _compute_cf_build_capable_emails(rows, {})
    assert "nope@proj.iam.gserviceaccount.com" not in capable


def test_cf_build_capable_non_sa_member_ignored() -> None:
    rows = [{"policy": _policy("roles/editor", "user:person@example.com")}]
    capable = _compute_cf_build_capable_emails(rows, {})
    assert capable == frozenset()
