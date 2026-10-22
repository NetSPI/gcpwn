"""Regression tests for `_filter_targets_requiring_perms`.

The combo filter keeps only target SAs that actually hold a rule's precondition
permission (e.g. CREATE_VERTEX_KFP_JOB_AS_SA requires aiplatform.metadataStores.get).
sa_project_perms_index is keyed by the grantee PRINCIPAL id (serviceAccount:<email>),
not the bare SA email -- a mismatch that previously dropped every target. These lock
in: principal-id keying, no-op when no precondition, and SA-home-project fallback.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    _filter_targets_requiring_perms,
    _sa_home_project_from_email,
)

_PERM = "aiplatform.metadataStores.get"


def _targets(*emails):
    return {
        ("service-account", email, ""): {"resource_name": email, "resource_type": "service-account", "project_id": ""}
        for email in emails
    }


def test_keeps_only_targets_holding_required_permission():
    holder = "has@proj-a.iam.gserviceaccount.com"
    non_holder = "lacks@proj-a.iam.gserviceaccount.com"
    index = {"proj-a": {f"serviceAccount:{holder}": frozenset({_PERM})}}
    out = _filter_targets_requiring_perms(
        _targets(holder, non_holder),
        required_perms={_PERM},
        project_id="proj-a",
        sa_project_perms_index=index,
    )
    kept = {t["resource_name"] for t in out.values()}
    assert kept == {holder}


def test_no_required_perms_is_passthrough():
    t = _targets("a@proj-a.iam.gserviceaccount.com")
    assert _filter_targets_requiring_perms(t, required_perms=set(), project_id="proj-a", sa_project_perms_index={}) == t


def test_falls_back_to_sa_home_project_when_actor_project_differs():
    # Target SA lives in proj-b; the acting grant's project is proj-a. The SA's perms are
    # indexed under its own home project, so the filter must consult proj-b.
    sa = "svc@proj-b.iam.gserviceaccount.com"
    index = {"proj-b": {f"serviceAccount:{sa}": frozenset({_PERM})}}
    out = _filter_targets_requiring_perms(
        _targets(sa), required_perms={_PERM}, project_id="proj-a", sa_project_perms_index=index
    )
    assert {t["resource_name"] for t in out.values()} == {sa}


def test_sa_home_project_from_email():
    assert _sa_home_project_from_email("x@proj-a.iam.gserviceaccount.com") == "proj-a"
    assert _sa_home_project_from_email("serviceAccount:x@proj-a.iam.gserviceaccount.com") == "proj-a"
    assert _sa_home_project_from_email("myproj@appspot.gserviceaccount.com") == "myproj"
    assert _sa_home_project_from_email("123-compute@developer.gserviceaccount.com") == ""
    assert _sa_home_project_from_email("not-an-email") == ""
