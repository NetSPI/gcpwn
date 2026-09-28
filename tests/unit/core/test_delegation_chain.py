"""Both credential paths must honour the implicit delegation chain.

The stored ``delegates`` column is a JSON list: the LAST entry is the identity you
end up acting as, earlier entries are intermediaries. ``load_stored_creds`` applied
it; ``build_stored_credentials`` did not, so a delegated credential used as a
one-off (the Drive downloader) silently acted as the BASE identity instead of the
delegation target. A wrong-identity bug, not a failure -- the worst kind here,
because the operator's notes say one principal and the API saw another.
"""

from __future__ import annotations

import json

import pytest

from gcpwn.core.session import SessionUtility


class _Base:
    """Stand-in source credential.

    google.auth.impersonated_credentials wraps the source: it copies it, calls
    with_scopes on a Scoped credential, and reads universe_domain -- so the double
    has to satisfy all three.
    """

    universe_domain = "googleapis.com"

    def __init__(self):
        self.token = "base-token"

    def with_scopes(self, scopes):
        return self


@pytest.fixture
def chain():
    return ["hop1@p.iam.gserviceaccount.com", "target@p.iam.gserviceaccount.com"]


# NOTE google-auth's impersonated_credentials.Credentials exposes NO public
# target_principal property -- the chain lives in _target_principal / _delegates.
# Asserting on the private names is deliberate: an earlier attribute-presence check
# on the public name silently never matched.
class TestApplyDelegationChain:
    def test_wraps_with_last_entry_as_target_and_rest_as_delegates(self, chain, capsys):
        wrapped = SessionUtility.apply_delegation_chain(
            _Base(), json.dumps(chain), identity_label="base@p.iam.gserviceaccount.com"
        )
        assert wrapped.__class__.__name__ == "Credentials"
        assert wrapped._target_principal == "target@p.iam.gserviceaccount.com"
        assert list(wrapped._delegates) == ["hop1@p.iam.gserviceaccount.com"]
        assert "Implicit delegation active" in capsys.readouterr().out

    def test_single_entry_chain_has_no_intermediaries(self):
        wrapped = SessionUtility.apply_delegation_chain(
            _Base(), json.dumps(["only@p.iam.gserviceaccount.com"]), identity_label="base"
        )
        assert wrapped._target_principal == "only@p.iam.gserviceaccount.com"
        assert list(wrapped._delegates) == []

    @pytest.mark.parametrize("raw", [None, "", "[]"])
    def test_no_chain_returns_the_credential_untouched(self, raw):
        base = _Base()
        assert SessionUtility.apply_delegation_chain(base, raw, identity_label="x") is base

    def test_none_credential_is_passed_through(self):
        assert SessionUtility.apply_delegation_chain(None, '["a@b.com"]', identity_label="x") is None

    def test_malformed_chain_does_not_raise_and_keeps_the_base(self, capsys):
        base = _Base()
        result = SessionUtility.apply_delegation_chain(base, "{not json", identity_label="x")
        assert result is base
        assert "Failed to apply implicit delegation chain" in capsys.readouterr().out

    def test_target_scopes_are_cloud_platform(self, chain):
        wrapped = SessionUtility.apply_delegation_chain(_Base(), json.dumps(chain), identity_label="x")
        assert list(wrapped._target_scopes) == ["https://www.googleapis.com/auth/cloud-platform"]


class TestBuildStoredCredentialsHonoursTheChain:
    """This is the path that was silently dropping the chain."""

    def test_delegated_service_account_is_wrapped(self, monkeypatch, chain):
        session = SessionUtility.__new__(SessionUtility)
        session.workspace_id = 1

        class _Data:
            @staticmethod
            def get_credential(_ws, _name):
                return {
                    "credtype": "service",
                    "email": "base@p.iam.gserviceaccount.com",
                    "session_creds": "{}",
                    "delegates": json.dumps(chain),
                }

        session.data_master = _Data()
        monkeypatch.setattr(
            "gcpwn.core.session.service_account.Credentials.from_service_account_info",
            staticmethod(lambda _info: _Base()),
        )

        credentials, email = session.build_stored_credentials("orgcred")
        assert email == "base@p.iam.gserviceaccount.com"
        assert getattr(credentials, "_target_principal", None) == "target@p.iam.gserviceaccount.com", (
            "build_stored_credentials dropped the delegation chain again"
        )

    def test_undelegated_credential_is_returned_as_is(self, monkeypatch):
        session = SessionUtility.__new__(SessionUtility)
        session.workspace_id = 1
        base = _Base()

        class _Data:
            @staticmethod
            def get_credential(_ws, _name):
                return {"credtype": "service", "email": "e@x", "session_creds": "{}", "delegates": None}

        session.data_master = _Data()
        monkeypatch.setattr(
            "gcpwn.core.session.service_account.Credentials.from_service_account_info",
            staticmethod(lambda _info: base),
        )
        credentials, _ = session.build_stored_credentials("orgcred")
        assert credentials is base

    def test_missing_credential_still_returns_the_empty_contract(self):
        session = SessionUtility.__new__(SessionUtility)
        session.workspace_id = 1
        session.data_master = type("D", (), {"get_credential": staticmethod(lambda *a: None)})()
        assert session.build_stored_credentials("nope") == (None, "")
