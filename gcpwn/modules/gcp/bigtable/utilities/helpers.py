from __future__ import annotations

from google.cloud.bigtable_admin_v2.overlay.services.bigtable_table_admin import BigtableTableAdminClient
from google.cloud.bigtable_admin_v2.services.bigtable_instance_admin import BigtableInstanceAdminClient

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes


class BigtableInstancesResource(GcpListResource):
    """List/get Bigtable instances (parent is projects/<p>, no location)."""

    SERVICE_LABEL = "Cloud Bigtable"
    TABLE_NAME = "bigtable_instances"
    COLUMNS = ["instance_id", "name", "display_name", "state", "type", "labels"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "bigtable.instances.list"
    GET_PERMISSION = "bigtable.instances.get"
    TEST_IAM_API_NAME = "bigtable.instances.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigtable.instances.")
    GET_METHOD = "get_instance"
    ID_FIELD = "instance_id"
    PARENT_FROM_PROJECT = True  # parent is projects/<p> (no location)

    def _build_client(self, session):
        return BigtableInstanceAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        # list_instances returns a response wrapper, not a bare iterable.
        resp = self.client.list_instances(parent=parent)
        return list(getattr(resp, "instances", []) or [])


class BigtableTablesResource(GcpListResource):
    """List/get Bigtable tables under a parent instance (list perm is on the instance)."""

    SERVICE_LABEL = "Cloud Bigtable"
    TABLE_NAME = "bigtable_tables"
    COLUMNS = ["table_id", "name", "granularity", "deletion_protection"]
    ACTION_RESOURCE_TYPE = "tables"
    LIST_PERMISSION = "bigtable.tables.list"
    LIST_RESOURCE_TYPE = "instances"  # listing tables is a permission on the instance
    GET_PERMISSION = "bigtable.tables.get"
    TEST_IAM_API_NAME = "bigtable.tables.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigtable.tables.")
    LIST_METHOD = "list_tables"
    GET_METHOD = "get_table"
    ID_FIELD = "table_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return BigtableTableAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return list(self.client.list_tables(parent=parent))


class BigtableBackupsResource(GcpListResource):
    """List/get Bigtable backups, enumerating across all clusters via a wildcard.

    Backups live under clusters, so _list_items appends ``/clusters/-`` to the
    instance parent to sweep every cluster in one call.
    """

    SERVICE_LABEL = "Cloud Bigtable"
    TABLE_NAME = "bigtable_backups"
    COLUMNS = ["backup_id", "name", "source_table", "state", "expire_time", "start_time", "end_time", "size_bytes"]
    ACTION_RESOURCE_TYPE = "backups"
    LIST_PERMISSION = "bigtable.backups.list"
    LIST_RESOURCE_TYPE = "instances"
    GET_PERMISSION = "bigtable.backups.get"
    GET_METHOD = "get_backup"
    ID_FIELD = "backup_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return BigtableTableAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        # Backups are scoped to clusters; "-" enumerates across all clusters.
        return list(self.client.list_backups(parent=f"{str(parent).rstrip('/')}/clusters/-"))


class BigtableAuthorizedViewsResource(GcpListResource):
    """List/get Bigtable authorized views under a parent table (list perm on the table)."""

    SERVICE_LABEL = "Cloud Bigtable"
    TABLE_NAME = "bigtable_authorized_views"
    COLUMNS = ["authorized_view_id", "name", "table_name", "deletion_protection"]
    ACTION_RESOURCE_TYPE = "authorized_views"
    LIST_PERMISSION = "bigtable.authorizedViews.list"
    LIST_RESOURCE_TYPE = "tables"
    GET_PERMISSION = "bigtable.authorizedViews.get"
    GET_METHOD = "get_authorized_view"
    ID_FIELD = "authorized_view_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return BigtableTableAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return list(self.client.list_authorized_views(parent=parent))
