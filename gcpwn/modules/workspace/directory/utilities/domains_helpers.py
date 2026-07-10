"""
Google Workspace domains helpers (Admin SDK Directory API, read-only).

API:
  - Host: ``admin.googleapis.com``
  - Client: ``googleapiclient.discovery.build("admin", "directory_v1")``
  - Call: ``domains.list(customer=<customerId>)``
    - REST: ``GET /admin/directory/v1/customer/<customerId>/domains``
    - Response: ``{"domains": [{"domainName", "isPrimary", "verified", ...}]}``

This is the Workspace/Cloud Identity admin directory, *not* Cloud IAM. The
credential must be a Workspace admin USER, or a service account configured for
domain-wide delegation impersonating an admin (see ``--impersonate`` /
``configs set workspace_admin_subject admin@domain``). Required scope:
``https://www.googleapis.com/auth/admin.directory.domain.readonly``.

We store domains in the ``workspace_domains`` table (customer-scoped).
"""

from __future__ import annotations

from typing import Any

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import (
    _http_error_details,
    build_scoped_directory_service,
    handle_directory_error,
)


# domains.list requires this read-only scope; request it explicitly so a
# service-account domain-wide-delegation token is minted WITH it (the shared
# build_directory_service only requests the narrow user/group scopes).
DOMAINS_SCOPES = ("https://www.googleapis.com/auth/admin.directory.domain.readonly",)


class WorkspaceDomainsResource:
    TABLE_NAME = "workspace_domains"
    COLUMNS = [
        "domain_name",
        "is_primary",
        "verified",
        "creation_time",
    ]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self._service = None
        self.last_call_ok: bool | None = None
        self.last_method: str | None = None
        self.last_request: dict[str, Any] = {}
        self.last_error_status: int | None = None
        self.last_error_message: str | None = None

    @property
    def service(self):
        # Build the Admin SDK Directory API client lazily (and only once).
        if self._service is None:
            self._service = build_scoped_directory_service(self.session, DOMAINS_SCOPES, subject=self.subject)
        return self._service

    def list(self, *, customer: str) -> list[dict[str, Any]]:
        """
        Admin SDK Directory API: ``domains.list``.

        ``customer`` should be a Directory Customer ID (e.g. ``C046psxkn``) or the
        ``my_customer`` alias. Returns raw domain dicts. Graceful on errors:
        403 prints a skip notice and returns ``[]``; 404 / others return ``[]``.
        """
        self.last_method = "domains.list"
        self.last_request = {"customer": customer}
        self.last_error_status = None
        self.last_error_message = None
        try:
            response = self.service.domains().list(customer=str(customer)).execute() or {}
            self.last_call_ok = True
            domains = response.get("domains", []) if isinstance(response, dict) else []
            return [dict(row) for row in domains if isinstance(row, dict)]
        except Exception as exc:
            self.last_call_ok = False
            status, detail = _http_error_details(exc)
            self.last_error_status = status
            self.last_error_message = detail
            handle_directory_error(exc, skipping="domain enumeration")
            return []

    def save(self, rows: list[dict[str, Any]], *, customer_id: str) -> None:
        """Persist domain rows into the customer-scoped ``workspace_domains`` table."""
        normalized: list[dict[str, Any]] = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            domain_name = str(row.get("domainName") or row.get("domain_name") or "").strip()
            if not domain_name:
                continue
            normalized.append(
                {
                    "domain_name": domain_name,
                    "is_primary": "true" if row.get("isPrimary") or row.get("is_primary") else "false",
                    "verified": "true" if row.get("verified") else "false",
                    "creation_time": str(row.get("creationTime") or row.get("creation_time") or ""),
                    "raw_json": row,
                }
            )
        if normalized:
            save_to_table(
                self.session,
                "workspace_domains",
                normalized,
                defaults={"customer_id": customer_id},
            )
