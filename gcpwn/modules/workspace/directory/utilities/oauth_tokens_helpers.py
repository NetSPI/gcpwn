"""Google Workspace 3rd-party OAuth app grants (Admin SDK Directory API).

Per-user enumeration of the 3rd-party OAuth applications a user has authorized and
the scopes they granted. Over-privileged or anomalous app grants are an attack-path
and data-exfiltration signal (e.g. an app with `mail.google.com` or admin scopes).

API (read-only): `tokens().list(userKey=<email>)` ->
  {"items":[{clientId, displayText, scopes:[...], anonymous, nativeApp, userKey}]}
Read-only scope: `https://www.googleapis.com/auth/admin.directory.user.security`.

Tokens are PER USER, so enumeration is N+1 over the user set (callers pass the emails,
typically from the cached workspace_users table). The Directory client is built once
and reused across users. Access model is the same as the rest of the package: a
Workspace admin user works directly; a service account needs domain-wide delegation +
an admin subject (see build_directory_service `subject=`).
"""

from __future__ import annotations

from typing import Any

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import (
    _http_error_details,
    build_directory_service,
    ensure_scoped_credentials,
)

USER_SECURITY_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user.security",
)


class WorkspaceOAuthTokensResource:
    """Admin SDK Directory API: `tokens().list(userKey=...)` per user (read-only)."""

    TABLE_NAME = "workspace_oauth_tokens"
    COLUMNS = [
        "customer_id",
        "user_email",
        "client_id",
        "display_text",
        "scopes",
        "anonymous",
        "native_app",
        "raw_json",
    ]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.last_call_ok: bool | None = None
        self.last_error_status: int | None = None
        self.last_error_message: str | None = None
        self._service = None  # built once, reused across users

    def _svc(self):
        if self._service is None:
            credentials = ensure_scoped_credentials(self.session.credentials, USER_SECURITY_SCOPES)
            self._service = build_directory_service(credentials, subject=self.subject)
        return self._service

    def list(self, *, user_key: str) -> list[dict[str, Any]]:
        """List one user's 3rd-party OAuth token grants (not paginated). Graceful -> []."""
        user_key = str(user_key or "").strip()
        if not user_key:
            return []
        self.last_error_status = None
        self.last_error_message = None
        try:
            response = self._svc().tokens().list(userKey=user_key).execute() or {}
            items = response.get("items", []) if isinstance(response, dict) else []
            self.last_call_ok = True
            return [dict(token) for token in items if isinstance(token, dict)]
        except Exception as exc:
            self.last_call_ok = False
            status, detail = _http_error_details(exc)
            self.last_error_status = status
            self.last_error_message = detail
            if status == 403:
                print(f"[*] Admin SDK user.security access denied for {user_key}; skipping its OAuth tokens.")
                return []
            if status == 404:
                return []  # user not found / no tokens -- not worth shouting about per-user
            print(f"[*] OAuth token enumeration failed for {user_key}: {type(exc).__name__}: {exc}")
            return []

    def save(self, tokens, *, customer_id: str, user_email: str) -> None:
        rows: list[dict[str, Any]] = []
        for token in tokens or []:
            if not isinstance(token, dict):
                continue
            client_id = str(token.get("clientId") or "").strip()
            if not client_id:
                continue
            rows.append(
                {
                    "customer_id": customer_id,
                    "user_email": user_email,
                    "client_id": client_id,
                    "display_text": str(token.get("displayText") or ""),
                    "scopes": token.get("scopes") if isinstance(token.get("scopes"), list) else [],
                    "anonymous": "true" if token.get("anonymous") else "false",
                    "native_app": "true" if token.get("nativeApp") else "false",
                    "raw_json": token,
                }
            )
        if rows:
            save_to_table(
                self.session,
                "workspace_oauth_tokens",
                rows,
                defaults={"customer_id": customer_id, "user_email": user_email},
            )
