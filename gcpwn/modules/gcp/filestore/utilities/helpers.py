from __future__ import annotations

from typing import Any

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import region_resolver_for


resolve_locations = region_resolver_for("filestore", ("file", "v1"))


class _FilestoreResource(GcpListResource):
    SERVICE_LABEL = "Cloud Filestore"

    def _build_client(self, session):
        try:
            from google.cloud import filestore_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Filestore enumeration requires the `google-cloud-filestore` package."
            ) from exc
        return filestore_v1.CloudFilestoreManagerClient(credentials=session.credentials)


class FilestoreInstancesResource(_FilestoreResource):
    """Enumerate Filestore instances per location into ``filestore_instances``."""

    TABLE_NAME = "filestore_instances"
    COLUMNS = [
        "name", "description", "state", "status_message", "create_time",
        "tier", "labels", "kms_key_name", "protocol",
        "deletion_protection_enabled", "deletion_protection_reason",
    ]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "file.instances.list"
    GET_PERMISSION = "file.instances.get"
    TEST_IAM_API_NAME = "file.instances.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "file.instances.",
        exclude_permissions=("file.instances.create", "file.instances.list"),
    )
    LIST_METHOD = "list_instances"
    GET_METHOD = "get_instance"
    ID_FIELD = "name"


class FilestoreSnapshotsResource(_FilestoreResource):
    """Enumerate Filestore snapshots per instance into ``filestore_snapshots``."""

    TABLE_NAME = "filestore_snapshots"
    COLUMNS = ["name", "description", "state", "create_time", "labels", "filesystem_used_bytes"]
    ACTION_RESOURCE_TYPE = "snapshots"
    LIST_PERMISSION = "file.snapshots.list"
    GET_PERMISSION = "file.snapshots.get"
    LIST_METHOD = "list_snapshots"
    GET_METHOD = "get_snapshot"
    ID_FIELD = "name"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent instance

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = str(raw.get("name", "") or "")
        # name = projects/P/locations/L/instances/I/snapshots/S
        return {"instance_name": name.partition("/snapshots/")[0]}


class FilestoreBackupsResource(_FilestoreResource):
    """Enumerate Filestore backups per location into ``filestore_backups``."""

    TABLE_NAME = "filestore_backups"
    COLUMNS = [
        "name", "description", "state", "create_time", "labels",
        "capacity_gb", "storage_bytes", "source_instance", "source_file_share",
        "source_instance_tier", "kms_key", "file_system_protocol",
    ]
    ACTION_RESOURCE_TYPE = "backups"
    LIST_PERMISSION = "file.backups.list"
    GET_PERMISSION = "file.backups.get"
    LIST_METHOD = "list_backups"
    GET_METHOD = "get_backup"
    ID_FIELD = "name"
