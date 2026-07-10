from __future__ import annotations

from google.cloud import redis_cluster_v1

from gcpwn.core.resource import GcpListResource


class MemorystoreRedisClusterResource(GcpListResource):
    """List/get Memorystore for Redis *Cluster* instances via the redis_cluster_v1 GAPIC client.

    Same PRODUCT as the basic Memorystore Redis instances (so it lives in this
    module), but a DISTINCT API (``google.cloud.redis_cluster_v1`` /
    ``CloudRedisClusterClient`` vs ``redis_v1`` / ``CloudRedisClient``). Clusters
    list per location (scope=REGION). A Cluster has no run-as service account, so the
    offensive columns are security-posture signals: ``authorization_mode``
    (AUTH_MODE_DISABLED == no data-plane auth) and ``transit_encryption_mode``
    (DISABLED == cleartext on the wire), plus sizing/topology for blast radius.
    No per-cluster testIamPermissions on the client -> supports_iam=False.
    """

    SERVICE_LABEL = "Memorystore Redis Cluster"
    TABLE_NAME = "memorystore_redis_clusters"
    COLUMNS = [
        "location",
        "cluster_id",
        "name",
        "state",
        "node_type",
        "shard_count",
        "replica_count",
        "size_gb",
        "authorization_mode",
        "transit_encryption_mode",
    ]
    ACTION_RESOURCE_TYPE = "clusters"
    LIST_PERMISSION = "redis.clusters.list"
    GET_PERMISSION = "redis.clusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return redis_cluster_v1.CloudRedisClusterClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_clusters(request=redis_cluster_v1.ListClustersRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_cluster(request=redis_cluster_v1.GetClusterRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        def _num(value):
            return value if value is not None else ""
        return {
            "state": str(raw.get("state", "") or ""),
            "node_type": str(raw.get("node_type", "") or ""),
            "shard_count": _num(raw.get("shard_count")),
            "replica_count": _num(raw.get("replica_count")),
            "size_gb": _num(raw.get("size_gb")),
            "authorization_mode": str(raw.get("authorization_mode", "") or ""),
            "transit_encryption_mode": str(raw.get("transit_encryption_mode", "") or ""),
        }
