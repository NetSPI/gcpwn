from __future__ import annotations

from google.cloud import alloydb_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)


resolve_locations = region_resolver_for("alloydb", ("alloydb", "v1"))


class AlloyDBClustersResource(GcpListResource):
    """List/get AlloyDB clusters via the alloydb_v1 AlloyDBAdminClient.

    The CMEK key name on a cluster (``encryption_config.kms_key_name``) is the
    offensively interesting derived field: a principal who can read the cluster
    and decrypt with that KMS key controls the data-at-rest boundary. The cluster
    also pins the VPC ``network`` it is reachable on. AlloyDB's GAPIC admin client
    exposes no per-cluster testIamPermissions, so the component runs with
    ``supports_iam=False``.
    """

    SERVICE_LABEL = "AlloyDB"
    TABLE_NAME = "alloydb_clusters"
    COLUMNS = [
        "location",
        "cluster_id",
        "name",
        "state",
        "cluster_type",
        "database_version",
        "network",
        "kms_key_name",
        "initial_user",
    ]
    ACTION_RESOURCE_TYPE = "clusters"
    LIST_PERMISSION = "alloydb.clusters.list"
    GET_PERMISSION = "alloydb.clusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return alloydb_v1.AlloyDBAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_clusters(request=alloydb_v1.ListClustersRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_cluster(request=alloydb_v1.GetClusterRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        network_config = raw.get("network_config") if isinstance(raw.get("network_config"), dict) else {}
        encryption_config = raw.get("encryption_config") if isinstance(raw.get("encryption_config"), dict) else {}
        initial_user = raw.get("initial_user") if isinstance(raw.get("initial_user"), dict) else {}
        return {
            "cluster_id": extract_path_segment(str(raw.get("name", "") or ""), "clusters"),
            "cluster_type": str(raw.get("cluster_type", "") or ""),
            "network": str(network_config.get("network") or raw.get("network") or "").strip(),
            "kms_key_name": str(encryption_config.get("kms_key_name") or "").strip(),
            "initial_user": str(initial_user.get("user") or "").strip(),
        }


class AlloyDBInstancesResource(GcpListResource):
    """List/get AlloyDB instances under a parent cluster.

    Instances are listed per parent cluster (PARENT_FROM_PROJECT_LOCATION = False),
    so the list call carries ``alloydb.instances.list`` as a permission on the
    parent cluster (LIST_RESOURCE_TYPE = clusters). The public IP address is the
    offensively interesting derived field: a reachable ``public_ip_address`` widens
    the attack surface beyond the cluster's private VPC. AlloyDB exposes no
    per-instance testIamPermissions, so the component runs ``supports_iam=False``.
    """

    SERVICE_LABEL = "AlloyDB"
    TABLE_NAME = "alloydb_instances"
    COLUMNS = [
        "location",
        "cluster_id",
        "instance_id",
        "name",
        "state",
        "instance_type",
        "availability_type",
        "gce_zone",
        "ip_address",
        "public_ip_address",
    ]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "alloydb.instances.list"
    LIST_RESOURCE_TYPE = "clusters"  # listing instances is a permission on the parent cluster
    GET_PERMISSION = "alloydb.instances.get"
    ID_FIELD = "instance_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent cluster

    def _build_client(self, session):
        return alloydb_v1.AlloyDBAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_instances(request=alloydb_v1.ListInstancesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_instance(request=alloydb_v1.GetInstanceRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "cluster_id": extract_path_segment(str(raw.get("name", "") or ""), "clusters"),
            "instance_id": extract_path_segment(str(raw.get("name", "") or ""), "instances"),
            "instance_type": str(raw.get("instance_type", "") or ""),
            "availability_type": str(raw.get("availability_type", "") or ""),
            "gce_zone": str(raw.get("gce_zone", "") or ""),
            "ip_address": str(raw.get("ip_address", "") or "").strip(),
            "public_ip_address": str(raw.get("public_ip_address", "") or "").strip(),
        }
