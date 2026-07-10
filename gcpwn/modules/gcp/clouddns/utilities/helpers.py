from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
from typing import Any, Iterable

from google.api_core.exceptions import NotFound
from google.cloud import dns

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import build_discovery_service, handle_discovery_error, handle_service_error
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.persistence import save_to_table, to_snake_key


def _normalize_keys(value: Any) -> Any:
    """Recursively convert dict keys (camelCase API repr) to snake_case.

    The google-cloud-dns client returns camelCase ``to_api_repr()`` payloads;
    this normalizes them so downstream code uses consistent snake_case keys.
    """
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


def _zone_resource_name(project_id: str, zone_name: str) -> str:
    return f"projects/{project_id}/managedZones/{zone_name}"


def _zone_to_dict(zone: Any) -> dict[str, Any]:
    """Flatten a managed-zone object into a stable row dict for the DB/table.

    Prefers the normalized to_api_repr() payload but falls back to attribute
    access, and derives a friendly ``type`` (Public/Private) from visibility.
    """
    payload: dict[str, Any] = {}
    if hasattr(zone, "to_api_repr"):
        try:
            payload = _normalize_keys(zone.to_api_repr() or {})
        except Exception:
            payload = {}
    visibility = str(payload.get("visibility") or getattr(zone, "visibility", "") or "").strip()
    return {
        "name": str(payload.get("name") or getattr(zone, "name", "") or "").strip(),
        "dns_name": str(
            payload.get("dns_name")
            or getattr(zone, "dns_name", "")
            or ""
        ).strip(),
        "description": str(payload.get("description") or getattr(zone, "description", "") or "").strip(),
        "visibility": visibility,
        "type": {"public": "Public", "private": "Private"}.get(visibility.lower(), visibility.title()),
        "labels": payload.get("labels") or getattr(zone, "labels", "") or "",
        "name_servers": (
            payload.get("name_servers")
            or getattr(zone, "name_servers", "")
            or ""
        ),
        "creation_time": str(
            payload.get("creation_time")
            or getattr(zone, "creation_time", "")
            or ""
        ).strip(),
    }


class CloudDnsManagedZonesResource:
    """List/get/testIamPermissions Cloud DNS managed zones, recording permission evidence.

    Hand-rolled resource using the google-cloud-dns client for list/get and a
    discovery service for testIamPermissions. list() returns the "Not Enabled"
    sentinel when the API is disabled (to short-circuit fan-out) and []/None on
    other errors. Recorded permissions are evidence (direct_api / test_iam).
    """

    TABLE_NAME = "clouddns_managed_zones"
    ACTION_RESOURCE_TYPE = "managed_zones"
    LIST_API_NAME = "dns.managedZones.list"
    GET_API_NAME = "dns.managedZones.get"
    TEST_IAM_API_NAME = "dns.managedZones.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("dns.managedZones.")
    COLUMNS = ["name", "dns_name", "visibility", "description"]

    def __init__(self, session) -> None:
        self.session = session
        self.discovery_service = build_discovery_service(session.credentials, "dns", "v1")

    def build_client(self, project_id: str) -> dns.Client:
        return dns.Client(project=project_id, credentials=self.session.credentials)

    def list(self, *, project_id: str, location: str | None = None, action_dict=None) -> list[Any] | str | None:
        try:
            client = self.build_client(project_id)
            rows = [_zone_to_dict(zone) for zone in client.list_zones()]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            result = handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=project_id,
                service_label="Cloud DNS",
                project_id=project_id,
            )
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str | None = None, resource_id: str, action_dict=None) -> Any | None:
        project_id = project_id or getattr(self.session, "project_id", None)
        try:
            client = self.build_client(project_id)
            zone = client.zone(resource_id)
            if hasattr(zone, "reload"):
                zone.reload()
            elif hasattr(zone, "exists") and not zone.exists():
                raise NotFound("Zone not found")
            row = _zone_to_dict(zone)
            record_permissions(
                action_dict,
                permissions=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_zone_resource_name(project_id, resource_id),
            )
            return row
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=resource_id,
                service_label="Cloud DNS",
                project_id=project_id,
                return_not_enabled=False,
            )
            return None

    def test_iam_permissions(self, *, project_id: str | None = None, resource_id: str, action_dict=None) -> list[str]:
        """Probe the caller's permissions on a managed zone via testIamPermissions.

        Returns the subset of TEST_IAM_PERMISSIONS the caller actually holds and
        records them as evidence with test_iam provenance. Returns [] on error.
        """
        project_id = project_id or getattr(self.session, "project_id", None)
        try:
            response = self.discovery_service.managedZones().testIamPermissions(
                project=project_id,
                managedZone=resource_id,
                body={"permissions": list(self.TEST_IAM_PERMISSIONS)},
            ).execute()
            permissions = [
                str(permission).strip()
                for permission in ((response or {}).get("permissions") or [])
                if str(permission).strip()
            ]
            if permissions:
                record_permissions(
                    action_dict,
                    permissions=permissions,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=_zone_resource_name(project_id, resource_id),
                )
            return permissions
        except Exception as exc:
            handle_discovery_error(
                self.session,
                self.TEST_IAM_API_NAME,
                _zone_resource_name(project_id, resource_id),
                exc,
                service_label="Cloud DNS",
            )
            return []

    def save(self, zones: Iterable[Any], *, project_id: str, location: str | None = None, **_) -> None:
        for zone in zones or []:
            save_to_table(
                self.session,
                "clouddns_managed_zones",
                zone if isinstance(zone, dict) else _zone_to_dict(zone),
                defaults={"project_id": project_id},
            )


class CloudDnsRecordSetsResource:
    """List/save/export the DNS record sets within a managed zone.

    Listing record sets is a permission on the parent managed zone (hence
    ACTION_RESOURCE_TYPE = managed_zones). download_record_sets writes a CSV-style
    loot file. list() returns the "Not Enabled" sentinel on a disabled API.
    """

    TABLE_NAME = "clouddns_record_sets"
    ACTION_RESOURCE_TYPE = "managed_zones"
    LIST_API_NAME = "dns.resourceRecordSets.list"
    COLUMNS = ["zone_name", "name", "type", "ttl", "rrdatas"]

    def __init__(self, session) -> None:
        self.session = session

    @staticmethod
    def _record_to_dict(record: Any, *, zone_name: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if hasattr(record, "to_api_repr"):
            try:
                payload = _normalize_keys(record.to_api_repr() or {})
            except Exception:
                payload = {}
        if not payload:
            payload = {
                "name": getattr(record, "name", ""),
                "type": getattr(record, "record_type", "") or getattr(record, "type", ""),
                "ttl": getattr(record, "ttl", ""),
                "rrdatas": getattr(record, "rrdatas", ""),
                "routing_policy": getattr(record, "routing_policy", ""),
                "signature_rrdatas": getattr(record, "signature_rrdatas", ""),
            }
        return {
            "zone_name": str(zone_name or payload.get("zone_name") or "").strip(),
            "name": str(payload.get("name") or "").strip(),
            "type": str(payload.get("type") or payload.get("record_type") or "").strip(),
            "ttl": payload.get("ttl") if payload.get("ttl") not in (None, "") else "",
            "rrdatas": payload.get("rrdatas") or [],
            "routing_policy": payload.get("routing_policy") or "",
            "signature_rrdatas": payload.get("signature_rrdatas") or [],
        }

    @staticmethod
    def _csv_text(records: Iterable[dict[str, Any]]) -> str:
        buffer = StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["name", "type", "ttl", "rrdatas"])
        for record in records or []:
            row = dict(record or {})
            writer.writerow(
                [
                    str(row.get("name") or "").strip(),
                    str(row.get("type") or "").strip(),
                    row.get("ttl") if row.get("ttl") not in (None, "") else "",
                    ";".join(str(item).strip() for item in (row.get("rrdatas") or []) if str(item).strip()),
                ]
            )
        return buffer.getvalue()

    def list(self, *, project_id: str | None = None, parent: str = "", zone: Any = None, record_type: str | None = None, location: str | None = None, action_dict=None) -> list[Any] | str | None:
        project_id = project_id or getattr(self.session, "project_id", None)
        if zone is None and parent:
            zone = dns.Client(project=project_id, credentials=self.session.credentials).zone(parent)
        if zone is None:
            return []
        try:
            iterator = zone.list_resource_record_sets()
            zone_name = getattr(zone, "name", "")
            records = [self._record_to_dict(record, zone_name=zone_name) for record in iterator]
            if zone_name:
                record_permissions(
                    action_dict,
                    permissions=self.LIST_API_NAME,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=_zone_resource_name(project_id, zone_name),
                )
            if record_type:
                wanted = str(record_type).strip().upper()
                records = [record for record in records if str(record.get("type") or "").upper() == wanted]
            return records
        except Exception as exc:
            result = handle_service_error(
                exc,
                api_name="dns.resourceRecordSets.list",
                resource_name=getattr(zone, "name", ""),
                service_label="Cloud DNS",
                project_id=self.session.project_id,
            )
            return "Not Enabled" if result == "Not Enabled" else []

    def save(self, records: Iterable[Any], *, project_id: str, zone: Any = None, parent: str = "", location: str | None = None, **_) -> None:
        zone_name = parent or getattr(zone, "name", "")
        for record in records or []:
            row = record if isinstance(record, dict) else self._record_to_dict(record, zone_name=zone_name)
            zone_name = zone_name or str(row.get("zone_name") or "").strip()
            save_to_table(
                self.session,
                "clouddns_record_sets",
                row,
                defaults={"project_id": project_id, "zone_name": zone_name},
            )

    def download_record_sets(self, *, project_id: str, zone_name: str, records: Iterable[Any]) -> Path | None:
        normalized_records = [
            record if isinstance(record, dict) else self._record_to_dict(record, zone_name=zone_name)
            for record in (records or [])
        ]
        if not normalized_records:
            return None
        destination = resolve_download_path(
            self.session,
            service_name="clouddns",
            project_id=project_id,
            filename=f"{zone_name}_record_sets.txt",
            sanitize_fallback=True,
        )
        destination.write_text(self._csv_text(normalized_records), encoding="utf-8")
        return destination
