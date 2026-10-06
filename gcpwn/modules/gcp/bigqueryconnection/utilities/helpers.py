from __future__ import annotations

from google.cloud import bigquery_connection_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, resolve_regions_args


resolve_locations = resolve_regions_args


class BigQueryConnectionsResource(GcpListResource):
    """List/get BigQuery external data connections per project+location.

    Each connection is backed by a GCP service account (cloud_resource type) or
    stores external credentials (cloud_sql, cloud_spanner, aws, azure, spark,
    salesforce_data_cloud). Enumerating connections reveals which SAs have
    cross-service data access and which external systems the project pulls from.
    ``has_credential`` is set whenever the connection stores an actual secret.
    """

    SERVICE_LABEL = "BigQuery Connection"
    TABLE_NAME = "bigqueryconnection_connections"
    COLUMNS = [
        "location",
        "connection_id",
        "name",
        "friendly_name",
        "description",
        "connection_type",
        "has_credential",
    ]
    ACTION_RESOURCE_TYPE = "connections"
    LIST_PERMISSION = "bigquery.connections.list"
    GET_PERMISSION = "bigquery.connections.get"
    TEST_IAM_API_NAME = "bigquery.connections.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigquery.connections.")
    ID_FIELD = "connection_id"

    def _build_client(self, session):
        return bigquery_connection_v1.ConnectionServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_connections(
            request=bigquery_connection_v1.ListConnectionsRequest(
                parent=parent,
                page_size=1000,
            )
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_connection(
            request=bigquery_connection_v1.GetConnectionRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_tail(name) or name

    def _extra_save_fields(self, raw: dict) -> dict:
        # Detect which credential type is populated (first non-None wins).
        _type_keys = (
            "cloud_sql", "aws", "azure", "cloud_spanner",
            "cloud_resource", "spark", "salesforce_data_cloud",
        )
        connection_type = next(
            (k for k in _type_keys if raw.get(k)),
            "",
        )
        return {
            "connection_id": extract_path_tail(str(raw.get("name", "") or "")),
            "friendly_name": str(raw.get("friendly_name", "") or ""),
            "description": str(raw.get("description", "") or ""),
            "connection_type": connection_type,
            "has_credential": str(bool(raw.get("has_credential"))),
        }
