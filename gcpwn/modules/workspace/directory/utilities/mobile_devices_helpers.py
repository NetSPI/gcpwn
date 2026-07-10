"""
Google Workspace mobile-device enumeration helpers (Admin SDK Directory API).

Read-only. Uses the Admin SDK Directory API discovery client:
  `googleapiclient.discovery.build("admin", "directory_v1")`

Primary call:
- Directory: `mobiledevices.list(customerId=<customerId>)`
  - REST: `GET /admin/directory/v1/customer/<customerId>/devices/mobile?...`
  - Returns `{"mobiledevices": [{resourceId, deviceId, email, model, os, status, ...}]}`
  - Paged via `nextPageToken` (we use the discovery client's `list_next`).

Workspace access model: a Workspace admin USER works directly; a service account
needs domain-wide delegation configured in the Workspace Admin console plus an
admin user to impersonate (``--impersonate`` / ``configs set
workspace_admin_subject``). The Directory service is built lazily so the
credentials are scoped/delegated identically to the sibling Workspace resources.

We store rows in the ``workspace_mobile_devices`` table (customer-scoped).
"""

from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import (
    build_scoped_directory_service,
    handle_directory_error,
)


# mobiledevices.list requires this read-only scope; request it explicitly so a
# service-account domain-wide-delegation token is minted WITH it (the shared
# build_directory_service only requests the narrow user/group scopes).
MOBILE_DEVICE_SCOPES = ("https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",)


def list_mobile_devices(
    service,
    *,
    customer: str,
    max_results: int = 100,
    order_by: str | None = None,
    projection: str = "FULL",
) -> list[dict[str, Any]]:
    """
    Admin SDK Directory API: `mobiledevices.list`.

    Returns raw mobile-device dicts as returned by the API, paging through
    `nextPageToken` via the discovery client's `list_next`.
    """
    devices: list[dict[str, Any]] = []
    try:
        request = service.mobiledevices().list(
            customerId=customer,
            maxResults=int(max_results),
            projection=projection,
            orderBy=order_by,
        )
    except TypeError:
        request = service.mobiledevices().list(customerId=customer, maxResults=int(max_results))
    while request is not None:
        response = request.execute() or {}
        batch = response.get("mobiledevices", []) if isinstance(response, dict) else []
        if isinstance(batch, list):
            for device in batch:
                if isinstance(device, dict):
                    devices.append(device)
        request = service.mobiledevices().list_next(previous_request=request, previous_response=response)
    return devices


def mobile_device_to_row(*, customer_id: str, device: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Directory mobile-device dict into the table schema."""
    return {
        "customer_id": customer_id,
        "resource_id": str(device.get("resourceId") or "").strip(),
        "device_id": str(device.get("deviceId") or ""),
        "email": _first_email(device),
        "model": str(device.get("model") or ""),
        "os": str(device.get("os") or ""),
        "type": str(device.get("type") or ""),
        "status": str(device.get("status") or ""),
        "serial_number": str(device.get("serialNumber") or ""),
        "imei": str(device.get("imei") or ""),
        "last_sync": str(device.get("lastSync") or ""),
        "raw_json": device if isinstance(device, dict) else {},
    }


def _first_email(device: dict[str, Any]) -> str:
    """Directory returns `email` as a list of addresses; surface the first."""
    value = device.get("email")
    if isinstance(value, list):
        for entry in value:
            if str(entry).strip():
                return str(entry).strip()
        return ""
    return str(value or "").strip()


class WorkspaceMobileDevicesResource:
    TABLE_NAME = "workspace_mobile_devices"
    COLUMNS = ["resource_id", "device_id", "email", "model", "os", "type", "status"]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.last_call_ok: bool | None = None

    def list(
        self,
        *,
        customer: str,
        max_results: int = 100,
        order_by: str | None = None,
        projection: str = "FULL",
    ) -> list[dict[str, Any]]:
        """
        List mobile devices via the Admin SDK Directory API.

        Requires Workspace admin privileges and Directory scopes. On 403 prints a
        skip notice and returns []; on 404 or any other error returns [] (and sets
        ``last_call_ok=False``).
        """
        try:
            self.last_call_ok = True
            service = build_scoped_directory_service(self.session, MOBILE_DEVICE_SCOPES, subject=self.subject)
            return list_mobile_devices(
                service,
                customer=customer,
                max_results=max_results,
                order_by=order_by,
                projection=projection,
            )
        except Exception as exc:
            self.last_call_ok = False
            handle_directory_error(exc, skipping="mobile-device enumeration")
            return []

    def save(self, devices: Iterable[dict[str, Any]], *, customer_id: str) -> None:
        rows = [
            mobile_device_to_row(customer_id=customer_id, device=device)
            for device in devices or []
            if isinstance(device, dict)
        ]
        rows = [row for row in rows if row.get("resource_id")]
        if rows:
            save_to_table(
                self.session,
                "workspace_mobile_devices",
                rows,
                defaults={"customer_id": customer_id},
            )
