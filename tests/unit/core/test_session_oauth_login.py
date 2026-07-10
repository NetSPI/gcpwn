"""OAuth "user" credential paths: `--token-file` / `--token` loading, and reload.

Google has no username/password token API, so a plain user (no service-account key)
gets into gcpwn via a pre-obtained authorized-user token (`--token-file`/`--token`),
stored under the "oauth2" credtype. These tests cover the credential-construction
branches and -- the one that actually caught a bug -- that reloading a
refresh-token-bearing "oauth2" cred reconstructs a renewable credential instead of a
bare, unrefreshable access token.
"""

from __future__ import annotations

import json

from gcpwn.core.session import SessionUtility


class _FakeDataMaster:
    def __init__(self, *, existing_credname: str | None = None, stored_cred: dict | None = None):
        self._existing_credname = existing_credname
        self._stored_cred = stored_cred
        self.inserted: list[dict] = []

    def get_credential(self, workspace_id, credname):
        if self._stored_cred is not None:
            return self._stored_cred
        if credname == self._existing_credname:
            return {"credname": credname}
        return None

    def insert_creds(self, workspace_id, credname, credtype, project_id, serialized_creds, email=None, scopes=None):
        self.inserted.append(
            {
                "workspace_id": workspace_id,
                "credname": credname,
                "credtype": credtype,
                "project_id": project_id,
                "serialized_creds": serialized_creds,
                "email": email,
                "scopes": scopes,
            }
        )


def _bare_session(*, existing_credname: str | None = None, stored_cred: dict | None = None) -> SessionUtility:
    # Bypass __init__ (which touches the real on-disk databases/ dir -- see the same
    # __new__ pattern in tests/unit/core/test_key_db_thread_safety.py for DataController).
    session = SessionUtility.__new__(SessionUtility)
    session.data_master = _FakeDataMaster(existing_credname=existing_credname, stored_cred=stored_cred)
    session.workspace_id = 1
    session.global_project_list = []
    return session


def _authorized_user_info(**overrides) -> dict:
    info = {
        "type": "authorized_user",
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "refresh_token": "1//test-refresh-token",
    }
    info.update(overrides)
    return info


# --- _load_new_oauth_credentials: precedence + credential shape ------------------


def test_load_from_authorized_info_carries_refresh_token():
    credentials, credtype, project_id = SessionUtility._load_new_oauth_credentials(
        None, authorized_info=_authorized_user_info()
    )
    assert credtype == "oauth2"
    assert project_id is None
    assert credentials.refresh_token == "1//test-refresh-token"


def test_load_from_token_file_carries_refresh_token(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps(_authorized_user_info()))

    credentials, credtype, _project_id = SessionUtility._load_new_oauth_credentials(
        None, token_file=str(token_path)
    )
    assert credtype == "oauth2"
    assert credentials.refresh_token == "1//test-refresh-token"


def test_load_from_bare_token_has_no_refresh_material():
    credentials, credtype, _project_id = SessionUtility._load_new_oauth_credentials(None, token="ya29.bare-token")
    assert credtype == "oauth2"
    assert credentials.token == "ya29.bare-token"
    assert credentials.refresh_token is None


def test_authorized_info_takes_precedence_over_token_file_and_token(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps(_authorized_user_info(refresh_token="1//from-file")))

    credentials, _credtype, _project_id = SessionUtility._load_new_oauth_credentials(
        None,
        authorized_info=_authorized_user_info(refresh_token="1//from-authorized-info"),
        token_file=str(token_path),
        token="ya29.ignored",
    )
    assert credentials.refresh_token == "1//from-authorized-info"


# --- load_stored_creds: reload must preserve refresh capability ------------------


def _stored_row(*, session_creds: dict) -> dict:
    return {
        "default_project": "Unknown",
        "credname": "mycred",
        "scopes": "[]",
        "email": "user@example.com",
        "credtype": "oauth2",
        "session_creds": json.dumps(session_creds),
    }


def test_reload_of_login_cred_reconstructs_refreshable_credentials(monkeypatch):
    # Mirrors what a `--token-file` cred looks like on disk. The
    # refresh attempt itself is a network call unrelated to what this test checks
    # (that reload *reconstructs a renewable credential* rather than a bare token),
    # so it's stubbed out rather than left to hit the blocked-network fixture.
    session_creds = _authorized_user_info(token="ya29.still-valid")
    session = _bare_session(stored_cred=_stored_row(session_creds=session_creds))
    monkeypatch.setattr(session, "attempt_cred_refresh", lambda auth_json: 1)

    status = session.load_stored_creds("mycred")

    assert status == 1
    assert session.credentials.refresh_token == "1//test-refresh-token"
    assert session.credentials.client_id == "test-client-id.apps.googleusercontent.com"


def test_reload_of_bare_token_cred_stays_unrefreshable():
    # A cred added via the older `--token ya29...` path: no refresh material stored,
    # so it must keep falling back to a bare (unrefreshable) token credential.
    session_creds = {"token": "ya29.bare-token"}
    session = _bare_session(stored_cred=_stored_row(session_creds=session_creds))

    status = session.load_stored_creds("mycred")

    assert status == 1
    assert session.credentials.token == "ya29.bare-token"
    assert session.credentials.refresh_token is None
