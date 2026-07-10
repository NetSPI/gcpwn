"""Google Workspace Groups Settings helper (Groups Settings API, read-only).

API: ``groupssettings``/v1 -- ``groups.get(groupUniqueId=<group_email>)`` returns a
group's access + posting settings (whoCanJoin, whoCanPostMessage, allowExternalMembers,
whoCanViewMembership/Group, isArchived, ...). Security-relevant: externally-open groups,
anyone-can-post, anyone-can-join are all abuse surfaces.

Read-only scope: ``https://www.googleapis.com/auth/apps.groups.settings``.
Rows are stored in ``workspace_group_settings`` (customer-scoped).
"""

from __future__ import annotations

from typing import Any

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import build_workspace_service, handle_directory_error


GROUP_SETTINGS_SCOPES = ("https://www.googleapis.com/auth/apps.groups.settings",)


class WorkspaceGroupSettingsResource:
    TABLE_NAME = "workspace_group_settings"
    COLUMNS = [
        "group_email",
        "name",
        "who_can_join",
        "who_can_post_message",
        "who_can_view_membership",
        "who_can_view_group",
        "allow_external_members",
        "is_archived",
    ]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self._service = None
        self.last_call_ok: bool | None = None
        self.last_error_status: int | None = None

    @property
    def service(self):
        if self._service is None:
            self._service = build_workspace_service(
                self.session, "groupssettings", "v1", GROUP_SETTINGS_SCOPES, subject=self.subject
            )
        return self._service

    def get(self, *, group_email: str) -> dict[str, Any] | None:
        """Groups Settings API ``groups.get``. Returns raw settings dict, or None on error."""
        try:
            settings = self.service.groups().get(groupUniqueId=group_email).execute() or {}
            self.last_call_ok = True
            return settings if isinstance(settings, dict) else None
        except Exception as exc:
            self.last_call_ok = False
            self.last_error_status = handle_directory_error(exc, skipping=f"group settings for {group_email}")
            return None

    def save(self, settings: dict[str, Any], *, customer_id: str, group_email: str) -> None:
        if not isinstance(settings, dict):
            return
        row = {
            "group_email": str(settings.get("email") or group_email or "").strip(),
            "name": str(settings.get("name") or ""),
            "who_can_join": str(settings.get("whoCanJoin") or ""),
            "who_can_post_message": str(settings.get("whoCanPostMessage") or ""),
            "who_can_view_membership": str(settings.get("whoCanViewMembership") or ""),
            "who_can_view_group": str(settings.get("whoCanViewGroup") or ""),
            "allow_external_members": str(settings.get("allowExternalMembers") or ""),
            "is_archived": str(settings.get("isArchived") or ""),
            "raw_json": settings,
        }
        save_to_table(self.session, "workspace_group_settings", [row], defaults={"customer_id": customer_id})
