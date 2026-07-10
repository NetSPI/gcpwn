"""Google Workspace Data Transfer helper (Admin SDK Data Transfer API, read-only).

API: ``admin``/``datatransfer_v1`` -- ``transfers.list(customerId=<customer>)`` returns
data-ownership transfer requests (old owner -> new owner, per application, status).
Surfaces offboarding data movement (who inherited a departed user's Drive/data).

Read-only scope: ``https://www.googleapis.com/auth/admin.datatransfer.readonly``.
Rows are stored in ``workspace_data_transfers`` (customer-scoped).
"""

from __future__ import annotations

from typing import Any

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import build_workspace_service, handle_directory_error


DATA_TRANSFER_SCOPES = ("https://www.googleapis.com/auth/admin.datatransfer.readonly",)


class WorkspaceDataTransfersResource:
    TABLE_NAME = "workspace_data_transfers"
    COLUMNS = [
        "transfer_id",
        "old_owner_user_id",
        "new_owner_user_id",
        "overall_status",
        "request_time",
        "applications",
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
                self.session, "admin", "datatransfer_v1", DATA_TRANSFER_SCOPES, subject=self.subject
            )
        return self._service

    def list(self, *, customer: str | None = None) -> list[dict[str, Any]]:
        """Data Transfer API ``transfers.list`` (paged). Returns raw transfer dicts, [] on error."""
        try:
            collection = self.service.transfers()
            kwargs: dict[str, Any] = {}
            if customer:
                kwargs["customerId"] = customer
            request = collection.list(**kwargs)
            items: list[dict[str, Any]] = []
            while request is not None:
                response = request.execute() or {}
                items.extend([row for row in (response.get("dataTransfers") or []) if isinstance(row, dict)])
                request = collection.list_next(previous_request=request, previous_response=response)
            self.last_call_ok = True
            return items
        except Exception as exc:
            self.last_call_ok = False
            self.last_error_status = handle_directory_error(exc, skipping="data transfer enumeration")
            return []

    def save(self, transfers: list[dict[str, Any]], *, customer_id: str) -> None:
        rows: list[dict[str, Any]] = []
        for transfer in transfers or []:
            if not isinstance(transfer, dict):
                continue
            apps = transfer.get("applicationDataTransfers") or []
            app_ids = ",".join(
                str(app.get("applicationId") or "") for app in apps if isinstance(app, dict) and app.get("applicationId")
            )
            rows.append(
                {
                    "transfer_id": str(transfer.get("id") or ""),
                    "old_owner_user_id": str(transfer.get("oldOwnerUserId") or ""),
                    "new_owner_user_id": str(transfer.get("newOwnerUserId") or ""),
                    "overall_status": str(transfer.get("overallTransferStatusCode") or ""),
                    "request_time": str(transfer.get("requestTime") or ""),
                    "applications": app_ids,
                    "raw_json": transfer,
                }
            )
        if rows:
            save_to_table(self.session, "workspace_data_transfers", rows, defaults={"customer_id": customer_id})
