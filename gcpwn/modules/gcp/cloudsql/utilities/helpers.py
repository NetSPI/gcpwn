from __future__ import annotations

from typing import Any

from gcpwn.core.resource import DiscoveryListResource
from gcpwn.core.utils.service_runtime import get_cached_rows


def _instance_settings(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    settings = (raw.get("settings") or {}) if isinstance(raw.get("settings"), dict) else {}
    ip_cfg = (settings.get("ip_configuration") or {}) if isinstance(settings.get("ip_configuration"), dict) else {}
    return settings, ip_cfg


def _instance_extra_columns(_obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested instance settings into top-level table columns.

    Surfaces security-relevant config (public ipv4, require_ssl, authorized
    networks, activation policy, tier) as flat columns so they're queryable and
    visible at a glance during review.
    """
    settings, ip_cfg = _instance_settings(raw)
    return {
        "name": raw.get("name") or raw.get("instance"),
        "connection_name": raw.get("connection_name"),
        "ip_addresses": raw.get("ip_addresses"),
        "settings_tier": settings.get("tier", ""),
        "settings_activation_policy": settings.get("activation_policy", ""),
        "settings_ip_configuration_ipv4_enabled": ip_cfg.get("ipv4_enabled", ""),
        "settings_ip_configuration_require_ssl": ip_cfg.get("require_ssl", ""),
        "settings_ip_configuration_authorized_networks": ip_cfg.get("authorized_networks", ""),
    }


class CloudSqlInstancesResource(DiscoveryListResource):
    """List/get Cloud SQL instances via sqladmin, recording permission evidence."""

    SERVICE_LABEL = "Cloud SQL Admin"
    TABLE_NAME = "cloudsql_instances"
    COLUMNS = ["name", "database_version", "region", "state"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "cloudsql.instances.list"
    GET_PERMISSION = "cloudsql.instances.get"
    LIST_API_NAME = "sqladmin.instances.list"
    GET_API_NAME = "sqladmin.instances.get"
    DISCOVERY_API = "sqladmin"
    DISCOVERY_VERSION = "v1beta4"

    def _list_request(self, *, project_id, parent, page_token=None, **_):
        # instances.list paginates -> forward the token so all pages are drained.
        return self.service.instances().list(project=project_id, pageToken=page_token)

    def _get_request(self, *, project_id, resource_id, **_):
        return self.service.instances().get(project=project_id, instance=resource_id)

    def _extra_save_fields(self, raw):
        return _instance_extra_columns(None, raw)

    def resolve_cached_targets(self, *, project_id: str) -> list[str]:
        rows = get_cached_rows(self.session, self.TABLE_NAME, project_id=project_id, columns=["name"])
        return [str(row.get("name") or "").strip() for row in rows or [] if str(row.get("name") or "").strip()]


class CloudSqlDatabasesResource(DiscoveryListResource):
    """List databases per Cloud SQL instance (list perm scoped to the instance)."""

    SERVICE_LABEL = "Cloud SQL Admin"
    TABLE_NAME = "cloudsql_databases"
    COLUMNS = ["instance", "name", "charset", "collation"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "cloudsql.databases.list"
    LIST_API_NAME = "sqladmin.databases.list"
    DISCOVERY_API = "sqladmin"
    DISCOVERY_VERSION = "v1beta4"
    LIST_PROJECT_SCOPE = False

    def _list_request(self, *, project_id, parent, page_token=None, **kwargs):
        # databases.list is single-response (no pageToken param) -> accept and ignore the token.
        return self.service.databases().list(project=project_id, instance=(kwargs.get("instance") or parent or ""))


class CloudSqlUsersResource(DiscoveryListResource):
    """List database users per Cloud SQL instance (potential cred targets)."""

    SERVICE_LABEL = "Cloud SQL Admin"
    TABLE_NAME = "cloudsql_users"
    COLUMNS = ["instance", "name", "host", "type"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "cloudsql.users.list"
    LIST_API_NAME = "sqladmin.users.list"
    DISCOVERY_API = "sqladmin"
    DISCOVERY_VERSION = "v1beta4"
    LIST_PROJECT_SCOPE = False

    def _list_request(self, *, project_id, parent, page_token=None, **kwargs):
        # users.list is single-response (no pageToken param) -> accept and ignore the token.
        return self.service.users().list(project=project_id, instance=(kwargs.get("instance") or parent or ""))


def _format_ip_addresses(ip_addresses: Any) -> str:
    """Render the instance ip_addresses list as a "type: addr; ..." display string."""
    entries = ip_addresses if isinstance(ip_addresses, list) else []
    formatted: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("ip_address") or "").strip()
        if not address:
            continue
        address_type = str(entry.get("type") or "").strip()
        formatted.append(f"{address_type}: {address}" if address_type else address)
    return "; ".join(formatted)


class CloudSqlConnectionsResource:
    """Read-only view over cached instance rows showing connection details/IPs.

    Does no API calls -- reads previously-enumerated cloudsql_instances rows from
    the workspace DB and formats IPs for display, optionally filtered to names.
    """

    TABLE_NAME = "cloudsql_instances"
    COLUMNS = [
        "name",
        "region",
        "connection_name",
        "ip_addresses_output",
    ]

    def __init__(self, session) -> None:
        self.session = session

    def list(self, *, project_id: str, instance_names: list[str] | None = None) -> list[dict[str, Any]]:
        rows = get_cached_rows(
            self.session,
            self.TABLE_NAME,
            project_id=project_id,
            columns=[
                "name",
                "region",
                "connection_name",
                "ip_addresses",
            ],
        ) or []
        rows = [
            {
                **row,
                "ip_addresses_output": _format_ip_addresses(row.get("ip_addresses")),
            }
            for row in rows
        ]
        if instance_names:
            allowed = set(instance_names)
            rows = [row for row in rows if str(row.get("name") or "").strip() in allowed]
        return rows


class CloudSqlConfigsResource:
    """Read-only view over cached instance rows surfacing security-config columns.

    No API calls -- reports tier/SSL/authorized-network settings from the cached
    cloudsql_instances rows for review, optionally filtered to given names.
    """

    TABLE_NAME = "cloudsql_instances"
    COLUMNS = [
        "name",
        "database_version",
        "region",
        "state",
        "ip_addresses_output",
    ]

    def __init__(self, session) -> None:
        self.session = session

    def list(self, *, project_id: str, instance_names: list[str] | None = None) -> list[dict[str, Any]]:
        rows = get_cached_rows(
            self.session,
            self.TABLE_NAME,
            project_id=project_id,
            columns=[
                "name",
                "database_version",
                "region",
                "state",
                "ip_addresses",
                "connection_name",
                "settings_tier",
                "settings_activation_policy",
                "settings_ip_configuration_ipv4_enabled",
                "settings_ip_configuration_require_ssl",
                "settings_ip_configuration_authorized_networks",
            ],
        ) or []
        rows = [
            {
                **row,
                "ip_addresses_output": _format_ip_addresses(row.get("ip_addresses")),
            }
            for row in rows
        ]
        if not instance_names:
            return rows
        allowed = set(instance_names)
        return [row for row in rows if str(row.get("name") or "").strip() in allowed]
