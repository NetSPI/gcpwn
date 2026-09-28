"""Impersonated credentials must be DETECTED so the DWD-via-delegation path runs.

apply_workspace_delegation used to identify an implicit-delegation credential by
testing for a ``target_principal`` attribute. google-auth exposes no such public
property, so the test never matched and the entire branch -- the warning and the
reconstruction with Workspace scopes + subject -- was dead code that looked correct.
Detection is now by type.
"""

from __future__ import annotations

import pytest
from google.auth import impersonated_credentials as imp

from gcpwn.modules.workspace.common import (
    DIRECTORY_SCOPES,
    _is_impersonated,
    _sa_email_from_credentials,
    apply_workspace_delegation,
)


class _Source:
    universe_domain = "googleapis.com"

    def with_scopes(self, scopes):
        return self


@pytest.fixture
def impersonated():
    return imp.Credentials(
        source_credentials=_Source(),
        target_principal="target@p.iam.gserviceaccount.com",
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        delegates=["hop1@p.iam.gserviceaccount.com"],
    )


class TestDetection:
    def test_impersonated_is_detected(self, impersonated):
        assert _is_impersonated(impersonated) is True

    def test_plain_object_is_not(self):
        assert _is_impersonated(_Source()) is False
        assert _is_impersonated(None) is False

    def test_public_target_principal_does_not_exist(self, impersonated):
        """Pins WHY detection is by type -- if this ever gains a public property,
        the attribute-based check would have worked and this note can be revisited."""
        assert getattr(impersonated, "target_principal", None) is None
        assert impersonated._target_principal == "target@p.iam.gserviceaccount.com"


class TestEffectiveEmail:
    def test_target_principal_is_the_effective_sa(self, impersonated):
        """The FINAL SA in the chain is the one whose DWD config matters."""
        assert _sa_email_from_credentials(impersonated) == "target@p.iam.gserviceaccount.com"

    def test_user_credential_has_no_sa_identity(self):
        assert _sa_email_from_credentials(_Source()) == ""


class TestReconstruction:
    def test_subject_and_workspace_scopes_are_applied(self, impersonated, capsys):
        result = apply_workspace_delegation(
            impersonated, "admin@corp.com", target_scopes=DIRECTORY_SCOPES
        )
        assert result is not impersonated, "credential was not reconstructed"
        assert result._subject == "admin@corp.com"
        assert list(result._target_scopes) == list(DIRECTORY_SCOPES)
        # chain preserved
        assert result._target_principal == "target@p.iam.gserviceaccount.com"
        assert list(result._delegates) == ["hop1@p.iam.gserviceaccount.com"]
        assert "DWD must be configured for the target SA" in capsys.readouterr().out

    def test_no_subject_is_a_no_op(self, impersonated):
        assert apply_workspace_delegation(impersonated, "", target_scopes=DIRECTORY_SCOPES) is impersonated

    def test_warns_even_without_scopes_to_rebuild_with(self, impersonated, capsys):
        result = apply_workspace_delegation(impersonated, "admin@corp.com")
        assert result is impersonated
        assert "DWD must be configured for the target SA" in capsys.readouterr().out
