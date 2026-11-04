from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gcpwn.core.resource import GcpListResource
from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)

resolve_locations = region_resolver_for("datastream", ("datastream", "v1"))


def _ds():
    try:
        from google.cloud import datastream_v1  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Datastream enumeration requires the `google-cloud-datastream` package. "
            "Install it with: pip install google-cloud-datastream"
        ) from exc
    return datastream_v1


class _DatastreamResource(GcpListResource):
    SERVICE_LABEL = "Datastream"

    def _build_client(self, session):
        return _ds().DatastreamClient(credentials=session.credentials)


# ---------------------------------------------------------------------------
# Connection Profiles
# ---------------------------------------------------------------------------

# Datastream's Python GAPIC client does not expose test_iam_permissions;
# IAM probing is skipped for all Datastream resource types.
_CP_IAM_PERMISSIONS: tuple = ()

# Profile type keys present on a ConnectionProfile proto (one-of)
_PROFILE_TYPE_KEYS = (
    "oracle_profile", "gcs_profile", "mysql_profile", "bigquery_profile",
    "postgresql_profile", "sql_server_profile", "salesforce_profile",
    "mongodb_profile", "spanner_profile",
)


def _extract_profile_meta(raw: dict) -> dict:
    """Return profile_type, hostname, port, username from whichever sub-profile is set."""
    for key in _PROFILE_TYPE_KEYS:
        sub = raw.get(key)
        if sub is None:
            continue
        # Empty dict is valid — BigQuery/Spanner/GCS profiles have no mandatory fields
        if not isinstance(sub, dict):
            continue
        ptype = key.removesuffix("_profile")
        return {
            "profile_type": ptype,
            "hostname": str(sub.get("hostname") or sub.get("host") or ""),
            "port": str(sub.get("port") or ""),
            "username": str(sub.get("username") or ""),
        }
    return {"profile_type": "", "hostname": "", "port": "", "username": ""}


class DatastreamConnectionProfilesResource(_DatastreamResource):
    TABLE_NAME = "datastream_connection_profiles"
    COLUMNS = [
        "name", "display_name", "create_time", "update_time", "labels",
        "profile_type", "hostname", "port", "username",
        "has_forward_ssh", "has_private_connectivity",
    ]
    ACTION_RESOURCE_TYPE = "connectionProfiles"
    LIST_PERMISSION = "datastream.connectionProfiles.list"
    GET_PERMISSION = "datastream.connectionProfiles.get"
    ID_FIELD = "name"

    def _list_items(self, parent, **_):
        ds = _ds()
        return self.client.list_connection_profiles(
            request=ds.ListConnectionProfilesRequest(parent=parent)
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/connectionProfiles/{resource_id}"
        return self.client.get_connection_profile(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "connectionProfiles") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        meta = _extract_profile_meta(raw)
        return {
            **meta,
            "has_forward_ssh": "1" if raw.get("forward_ssh_connectivity") else "",
            "has_private_connectivity": "1" if raw.get("private_connectivity") else "",
        }

    def download_credentials(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        """Write a connection profile's credential summary to a JSON loot file.

        Passwords/keys are typically masked by the API; this captures whatever
        was returned (hostname, port, username, SSH config, SSL certs, VPC config).
        Returns the path written, or None when no data is available.
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
                raw = {"raw": raw}

        profile_id = (
            str(row.get("name") or "")
            .rsplit("/", 1)[-1]
            .replace(".", "_")
            or "profile"
        )
        destination = Path(
            self.session.get_download_save_path(
                service_name="datastream",
                project_id=project_id,
                subdirs=["connection_profiles"],
                filename=compact_filename_component(f"cp_{profile_id}.json"),
            )
        )
        destination.write_text(
            json.dumps(raw, indent=2, default=str, sort_keys=True),
            encoding="utf-8",
        )
        return destination


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------

class DatastreamStreamsResource(_DatastreamResource):
    TABLE_NAME = "datastream_streams"
    COLUMNS = [
        "name", "display_name", "create_time", "update_time", "labels", "state",
        "source_connection_profile", "destination_connection_profile",
        "customer_managed_encryption_key",
    ]
    ACTION_RESOURCE_TYPE = "streams"
    LIST_PERMISSION = "datastream.streams.list"
    GET_PERMISSION = "datastream.streams.get"
    ID_FIELD = "name"

    def _list_items(self, parent, **_):
        ds = _ds()
        return self.client.list_streams(
            request=ds.ListStreamsRequest(parent=parent)
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/streams/{resource_id}"
        return self.client.get_stream(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "streams") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        src_cfg = raw.get("source_config") or {}
        dst_cfg = raw.get("destination_config") or {}
        if not isinstance(src_cfg, dict):
            src_cfg = {}
        if not isinstance(dst_cfg, dict):
            dst_cfg = {}
        return {
            "source_connection_profile": str(src_cfg.get("source_connection_profile") or ""),
            "destination_connection_profile": str(dst_cfg.get("destination_connection_profile") or ""),
        }


# ---------------------------------------------------------------------------
# Private Connections
# ---------------------------------------------------------------------------

class DatastreamPrivateConnectionsResource(_DatastreamResource):
    TABLE_NAME = "datastream_private_connections"
    COLUMNS = [
        "name", "display_name", "create_time", "update_time", "labels", "state",
        "vpc_peering_config",
    ]
    ACTION_RESOURCE_TYPE = "privateConnections"
    LIST_PERMISSION = "datastream.privateConnections.list"
    GET_PERMISSION = "datastream.privateConnections.get"
    ID_FIELD = "name"

    def _list_items(self, parent, **_):
        ds = _ds()
        return self.client.list_private_connections(
            request=ds.ListPrivateConnectionsRequest(parent=parent)
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/privateConnections/{resource_id}"
        return self.client.get_private_connection(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "privateConnections") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        vpc_cfg = raw.get("vpc_peering_config")
        if isinstance(vpc_cfg, dict):
            return {"vpc_peering_config": json.dumps(vpc_cfg)}
        return {"vpc_peering_config": str(vpc_cfg or "")}


# ---------------------------------------------------------------------------
# Routes (nested under a private connection)
# ---------------------------------------------------------------------------

class DatastreamRoutesResource(_DatastreamResource):
    TABLE_NAME = "datastream_routes"
    COLUMNS = [
        "name", "display_name", "create_time", "update_time", "labels",
        "destination_address", "destination_port", "private_connection_name",
    ]
    ACTION_RESOURCE_TYPE = "routes"
    LIST_PERMISSION = "datastream.routes.list"
    GET_PERMISSION = "datastream.routes.get"
    ID_FIELD = "name"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a private connection parent

    def _list_items(self, parent, **_):
        ds = _ds()
        return self.client.list_routes(
            request=ds.ListRoutesRequest(parent=parent)
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/routes/{resource_id}"
        return self.client.get_route(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "routes") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        name = str(raw.get("name", "") or "")
        return {
            "private_connection_name": name.partition("/routes/")[0],
        }
