from __future__ import annotations

from typing import Any

from google.cloud import oracledatabase_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("oracledatabase", ("oracledatabase", "v1"))


class OracleAutonomousDatabasesResource(GcpListResource):

    SERVICE_LABEL = "Oracle Autonomous Databases"
    TABLE_NAME = "oracle_autonomous_databases"
    COLUMNS = ["location", "db_id", "name", "display_name", "state", "db_workload", "cpu_core_count", "data_storage_size_gb"]
    LIST_PERMISSION = "oracledatabase.autonomousDatabases.list"
    GET_PERMISSION = "oracledatabase.autonomousDatabases.get"
    ID_FIELD = "db_id"

    def _build_client(self, session):
        return oracledatabase_v1.OracleDatabaseClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_autonomous_databases(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_autonomous_database(name=resource_id)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        props = raw.get("properties") or {}
        return {
            "db_id": extract_path_tail(str(raw.get("name", "") or "")),
            "display_name": str(raw.get("display_name") or "").strip(),
            "state": str(raw.get("state") or "").strip(),
            "db_workload": str(props.get("db_workload") or "").strip(),
            "cpu_core_count": props.get("cpu_core_count") or 0,
            "data_storage_size_gb": props.get("data_storage_size_gb") or 0,
        }


class OracleExadataInfrastructuresResource(GcpListResource):

    SERVICE_LABEL = "Oracle Cloud Exadata Infrastructures"
    TABLE_NAME = "oracle_exadata_infras"
    COLUMNS = ["location", "exadata_id", "name", "display_name", "state", "shape"]
    LIST_PERMISSION = "oracledatabase.cloudExadataInfrastructures.list"
    GET_PERMISSION = "oracledatabase.cloudExadataInfrastructures.get"
    ID_FIELD = "exadata_id"

    def _build_client(self, session):
        return oracledatabase_v1.OracleDatabaseClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_cloud_exadata_infrastructures(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_cloud_exadata_infrastructure(name=resource_id)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        props = raw.get("properties") or {}
        return {
            "exadata_id": extract_path_tail(str(raw.get("name", "") or "")),
            "display_name": str(raw.get("display_name") or "").strip(),
            "state": str(raw.get("state") or "").strip(),
            "shape": str(props.get("shape") or "").strip(),
        }


class OracleVmClustersResource(GcpListResource):

    SERVICE_LABEL = "Oracle Cloud VM Clusters"
    TABLE_NAME = "oracle_vm_clusters"
    COLUMNS = ["location", "cluster_id", "name", "display_name", "state", "exadata_infrastructure", "cpu_core_count"]
    LIST_PERMISSION = "oracledatabase.cloudVmClusters.list"
    GET_PERMISSION = "oracledatabase.cloudVmClusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return oracledatabase_v1.OracleDatabaseClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_cloud_vm_clusters(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_cloud_vm_cluster(name=resource_id)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        props = raw.get("properties") or {}
        return {
            "cluster_id": extract_path_tail(str(raw.get("name", "") or "")),
            "display_name": str(raw.get("display_name") or "").strip(),
            "state": str(raw.get("state") or "").strip(),
            "exadata_infrastructure": str((props.get("cloud_exadata_infrastructure") or "")).strip(),
            "cpu_core_count": props.get("cpu_core_count") or 0,
        }
