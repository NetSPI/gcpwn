from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.module_helpers import extract_path_tail


def _domains():
    try:
        from google.cloud import domains_v1  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Cloud Domains enumeration requires the `google-cloud-domains` package. "
            "Install it with: pip install google-cloud-domains"
        ) from exc
    return domains_v1


_REG_IAM_PERMISSIONS = tuple(permissions_with_prefixes(
    "domains.registrations.",
    exclude_permissions=(
        "domains.registrations.create",
        "domains.registrations.list",
    ),
))


class DomainsRegistrationsResource(GcpListResource):
    """List/get Cloud Domains registrations for a project (all locations via wildcard parent)."""

    SERVICE_LABEL = "Cloud Domains"
    TABLE_NAME = "clouddomains_registrations"
    COLUMNS = [
        "name", "domain_name", "create_time", "expire_time", "state", "issues",
        "labels", "renewal_method", "transfer_lock_state",
        "dns_config_type", "registrant_email",
    ]
    ACTION_RESOURCE_TYPE = "registrations"
    LIST_PERMISSION = "domains.registrations.list"
    GET_PERMISSION = "domains.registrations.get"
    TEST_IAM_API_NAME = "domains.registrations.testIamPermissions"
    TEST_IAM_PERMISSIONS = _REG_IAM_PERMISSIONS
    ID_FIELD = "name"
    # Use PARENT_FROM_PROJECT so the list is treated as a project-scope permission.
    # We override _list_items to append /locations/- for the wildcard query.
    PARENT_FROM_PROJECT = True

    def _build_client(self, session):
        return _domains().DomainsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        # parent = projects/{project_id}; Domains requires /locations/-
        d = _domains()
        return self.client.list_registrations(
            request=d.ListRegistrationsRequest(parent=f"{parent}/locations/-")
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/locations/-/registrations/{resource_id}"
        return self.client.get_registration(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_tail(name) or name

    def _extra_save_fields(self, raw: dict) -> dict:
        mgmt = raw.get("management_settings") or {}
        if not isinstance(mgmt, dict):
            mgmt = {}
        dns = raw.get("dns_settings") or {}
        if not isinstance(dns, dict):
            dns = {}
        # Determine DNS config type
        if dns.get("custom_dns"):
            dns_type = "custom"
        elif dns.get("google_domains_dns"):
            dns_type = "google_domains"
        else:
            dns_type = ""

        # Registrant email (from contact_settings)
        contacts = raw.get("contact_settings") or {}
        if not isinstance(contacts, dict):
            contacts = {}
        reg_contact = contacts.get("registrant_contact") or {}
        if not isinstance(reg_contact, dict):
            reg_contact = {}
        email = str(reg_contact.get("email") or "")

        return {
            "renewal_method": str(mgmt.get("renewal_method") or ""),
            "transfer_lock_state": str(mgmt.get("transfer_lock_state") or ""),
            "dns_config_type": dns_type,
            "registrant_email": email,
        }

    def download_contacts(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        """Write a registration's contact settings (PII) to a JSON loot file.

        contact_settings contains registrant/admin/technical name, email, phone
        and mailing address. Returns the path written, or None when unavailable.
        """
        # Accept both in-memory enumeration rows (full proto dict) and DB rows
        # (which carry raw_json as a JSON string).
        raw = row.get("raw_json") or row
        if not raw:
            return None
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        contacts = raw.get("contact_settings") or {}
        pending = raw.get("pending_contact_settings") or {}
        if not contacts and not pending:
            return None

        domain = str(row.get("domain_name") or "").replace(".", "_").rstrip("_") or "domain"
        destination = Path(
            self.session.get_download_save_path(
                service_name="clouddomains",
                project_id=project_id,
                subdirs=["registrations"],
                filename=compact_filename_component(f"contacts_{domain}.json"),
            )
        )
        payload = {
            "domain_name": row.get("domain_name", ""),
            "contact_settings": contacts,
        }
        if pending:
            payload["pending_contact_settings"] = pending
        destination.write_text(
            json.dumps(payload, indent=2, default=str, sort_keys=True),
            encoding="utf-8",
        )
        return destination
