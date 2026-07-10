from __future__ import annotations

from typing import Any

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import (
    build_scoped_directory_service,
    handle_directory_error,
)


ORG_UNIT_SCOPES = ("https://www.googleapis.com/auth/admin.directory.orgunit.readonly",)

"""
Google Workspace ORG UNITS helper.

Admin SDK Directory API:
- `orgunits.list(customerId=<customerId>, type="all")`
  - REST: `GET /admin/directory/v1/customer/<customerId>/orgunits?type=all`
  - Response: `{"organizationUnits": [{"orgUnitId", "orgUnitPath", "name",
    "parentOrgUnitPath", "description", "blockInheritance", ...}]}`

This is read-only enumeration (list only; no writes/mutations). The Directory
client may impersonate a Workspace admin via domain-wide delegation (`subject`)
exactly like the sibling `WorkspaceUsersResource`. Rows are stored in
`workspace_org_units`, scoped by `customer_id`.

Required scope (read-only): `https://www.googleapis.com/auth/admin.directory.orgunit.readonly`,
requested explicitly here (via `ensure_scoped_credentials`) so a service-account
domain-wide-delegation token is minted with it. An admin user works directly; a
service account needs domain-wide delegation + an admin subject to impersonate.
"""


def list_org_units(service, *, customer: str, org_unit_type: str = "all") -> list[dict[str, Any]]:
    """
    Admin SDK Directory API: `orgunits.list`.

    `customer` is the directory customer ID (e.g. `C046psxkn`) or the literal
    `my_customer`. `orgunits.list` is not a paged collection (it returns the full
    subtree in one response under `organizationUnits`).
    """
    request = service.orgunits().list(customerId=customer, type=org_unit_type)
    response = request.execute() or {}
    units: list[dict[str, Any]] = []
    if isinstance(response, dict):
        for unit in response.get("organizationUnits", []) or []:
            if isinstance(unit, dict):
                units.append(dict(unit))
    return units


def org_unit_to_row(*, customer_id: str, unit: dict[str, Any]) -> dict[str, Any]:
    """Normalize an org unit into the `workspace_org_units` table schema."""
    return {
        "customer_id": customer_id,
        "org_unit_id": str(unit.get("orgUnitId") or unit.get("org_unit_id") or ""),
        "org_unit_path": str(unit.get("orgUnitPath") or unit.get("org_unit_path") or ""),
        "name": str(unit.get("name") or ""),
        "parent_org_unit_path": str(unit.get("parentOrgUnitPath") or unit.get("parent_org_unit_path") or ""),
        "parent_org_unit_id": str(unit.get("parentOrgUnitId") or unit.get("parent_org_unit_id") or ""),
        "description": str(unit.get("description") or ""),
        "block_inheritance": "true" if unit.get("blockInheritance") else "false",
        "raw_json": unit if isinstance(unit, dict) else {},
    }


class WorkspaceOrgUnitsResource:
    TABLE_NAME = "workspace_org_units"
    COLUMNS = [
        "customer_id",
        "org_unit_id",
        "org_unit_path",
        "name",
        "parent_org_unit_path",
        "parent_org_unit_id",
        "description",
        "block_inheritance",
        "raw_json",
    ]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.last_call_ok: bool | None = None

    def list(self, *, customer: str, org_unit_type: str = "all") -> list[dict[str, Any]]:
        """
        List Workspace organizational units via the Admin SDK Directory API.

        Requires Workspace admin privileges and Directory scopes. If the caller
        does not have Admin SDK access, this returns an empty list (and sets
        ``last_call_ok=False``).
        """
        try:
            self.last_call_ok = True
            service = build_scoped_directory_service(self.session, ORG_UNIT_SCOPES, subject=self.subject)
            return list_org_units(service, customer=customer, org_unit_type=org_unit_type)
        except Exception as exc:
            self.last_call_ok = False
            handle_directory_error(exc, skipping="org unit enumeration")
            return []

    def save(self, rows: list[dict[str, Any]], *, customer_id: str) -> None:
        normalized_rows = [
            org_unit_to_row(customer_id=customer_id, unit=unit)
            for unit in rows or []
            if isinstance(unit, dict)
        ]
        if normalized_rows:
            save_to_table(
                self.session,
                "workspace_org_units",
                normalized_rows,
                defaults={"customer_id": customer_id},
            )
