from __future__ import annotations

from google.cloud import spanner_admin_database_v1, spanner_admin_instance_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment


class SpannerInstancesResource(GcpListResource):
    """List/get Cloud Spanner instances via the spanner_admin_instance_v1 GAPIC client.

    Instances are project-scoped (parent ``projects/<p>``, no location) and support
    ``testIamPermissions``. The offensively interesting columns are the IAM-bearing
    instance itself plus ``config`` (the placement of the data) -- a principal who
    can ``spanner.databases.read``/``select`` on an instance's databases can exfil
    every table; ``setIamPolicy`` on the instance grants that.
    """

    SERVICE_LABEL = "Cloud Spanner"
    TABLE_NAME = "spanner_instances"
    COLUMNS = ["instance_id", "name", "display_name", "state", "config", "node_count", "processing_units", "edition"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "spanner.instances.list"
    GET_PERMISSION = "spanner.instances.get"
    TEST_IAM_API_NAME = "spanner.instances.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "spanner.instances.",
        exclude_permissions=("spanner.instances.create", "spanner.instances.list"),
    )
    ID_FIELD = "instance_id"
    PARENT_FROM_PROJECT = True  # parent is projects/<p> (no location)

    def _build_client(self, session):
        return spanner_admin_instance_v1.InstanceAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_instances(request=spanner_admin_instance_v1.ListInstancesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_instance(request=spanner_admin_instance_v1.GetInstanceRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "instance_id": extract_path_segment(str(raw.get("name", "") or ""), "instances"),
            "display_name": raw.get("display_name") or "",
            "config": raw.get("config") or "",
            "node_count": raw.get("node_count") or 0,
            "processing_units": raw.get("processing_units") or 0,
            "edition": raw.get("edition") or "",
        }


class SpannerDatabasesResource(GcpListResource):
    """List/get Cloud Spanner databases, nested under each instance.

    Databases are listed under a parent instance (PARENT_FROM_PROJECT_LOCATION =
    False), so ``spanner.databases.list`` is recorded as a permission on the parent
    instance (LIST_RESOURCE_TYPE = instances). Databases support ``testIamPermissions``;
    the read-data permissions (``spanner.databases.read``/``select``) surfaced there
    are the exfiltration signal. ``enable_drop_protection`` and ``default_leader``
    are captured for blast-radius context.
    """

    SERVICE_LABEL = "Cloud Spanner"
    TABLE_NAME = "spanner_databases"
    COLUMNS = [
        "instance_id",
        "database_id",
        "name",
        "state",
        "database_dialect",
        "default_leader",
        "enable_drop_protection",
        "version_retention_period",
    ]
    ACTION_RESOURCE_TYPE = "databases"
    LIST_PERMISSION = "spanner.databases.list"
    LIST_RESOURCE_TYPE = "instances"  # listing databases is a permission on the parent instance
    GET_PERMISSION = "spanner.databases.get"
    TEST_IAM_API_NAME = "spanner.databases.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "spanner.databases.",
        exclude_permissions=("spanner.databases.create", "spanner.databases.list"),
    )
    ID_FIELD = "database_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent instance

    def _build_client(self, session):
        return spanner_admin_database_v1.DatabaseAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_databases(request=spanner_admin_database_v1.ListDatabasesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_database(request=spanner_admin_database_v1.GetDatabaseRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "instance_id": extract_path_segment(str(raw.get("name", "") or ""), "instances"),
            "database_id": extract_path_segment(str(raw.get("name", "") or ""), "databases"),
            "default_leader": raw.get("default_leader") or "",
            "enable_drop_protection": "yes" if raw.get("enable_drop_protection") else "no",
            "version_retention_period": raw.get("version_retention_period") or "",
        }
