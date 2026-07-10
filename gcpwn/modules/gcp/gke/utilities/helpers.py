from __future__ import annotations

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_segment,
    extract_path_tail,
    extract_project_id_from_resource,
    resolve_regions_args,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict


resolve_regions = resolve_regions_args


def _container_client(session):
    try:
        from google.cloud import container_v1  # type: ignore

        return container_v1.ClusterManagerClient(credentials=session.credentials)
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("GKE enumeration requires the `google-cloud-container` package.") from exc


class GkeClustersResource(GcpListResource):
    """List/get GKE clusters via container_v1, surfacing endpoint and privacy posture.

    Captures the API endpoint and whether it's a private cluster -- both decide
    whether the control plane is reachable for follow-on kube access. The container
    API returns short cluster names, so ``_list_items`` rewrites them to full
    resource paths (``{parent}/clusters/{name}``) so downstream saves and node-pool
    parents are well-formed. Permissions are recorded as evidence (direct_api).
    """

    SERVICE_LABEL = "GKE"
    TABLE_NAME = "gke_clusters"
    COLUMNS = ["location", "cluster_id", "name", "status", "endpoint", "master_version", "node_count", "private_cluster"]
    ACTION_RESOURCE_TYPE = "clusters"
    LIST_PERMISSION = "container.projects.locations.clusters.list"
    GET_PERMISSION = "container.projects.locations.clusters.get"
    LIST_API_NAME = "container.clusters.list"
    GET_API_NAME = "container.clusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return _container_client(session)

    def _list_items(self, parent, **_):
        # list_clusters returns a response wrapper (.clusters) of Cluster objects
        # whose `name` is the bare cluster id -> rewrite to the full resource path.
        resp = self.client.list_clusters(parent=parent)
        rows = []
        for cluster in getattr(resp, "clusters", []):
            row = resource_to_dict(cluster)
            bare = str(row.get("name") or "").strip()
            if bare and not bare.startswith("projects/"):
                row["name"] = f"{parent}/clusters/{bare}"
            if row:
                rows.append(row)
        return rows

    def _get_item(self, resource_id, **_):
        return self.client.get_cluster(name=resource_id)

    def _extra_save_fields(self, raw):
        private_cluster_config = raw.get("private_cluster_config")
        return {
            "private_cluster": bool(private_cluster_config.get("enable_private_nodes"))
            if isinstance(private_cluster_config, dict) else False,
            "node_count": raw.get("current_node_count") or "",
            "master_version": raw.get("current_master_version") or raw.get("master_version") or "",
        }


class GkeNodePoolsResource(GcpListResource):
    """List/get GKE node pools under a parent cluster (list/get parent = cluster path).

    Node-pool listing is a permission on the parent cluster's project
    (LIST_PROJECT_SCOPE). save() reconstructs the owning cluster path from each
    node pool's resource name when possible. Returns None on error; permissions
    recorded as evidence.
    """

    SERVICE_LABEL = "GKE"
    TABLE_NAME = "gke_node_pools"
    COLUMNS = ["location", "cluster_name", "node_pool_id", "name", "status", "version", "initial_node_count"]
    ACTION_RESOURCE_TYPE = "node_pools"
    LIST_PERMISSION = "container.projects.locations.clusters.nodePools.list"
    GET_PERMISSION = "container.projects.locations.clusters.nodePools.get"
    LIST_API_NAME = "container.nodePools.list"
    GET_API_NAME = "container.nodePools.get"
    ID_FIELD = "node_pool_id"
    PARENT_FROM_PROJECT_LOCATION = False
    LIST_PROJECT_SCOPE = True

    def _build_client(self, session):
        return _container_client(session)

    def _list_items(self, parent, **_):
        # list_node_pools returns NodePool objects whose `name` is the bare pool id
        # (e.g. "default-pool") -> rewrite to the full resource path, exactly like
        # GkeClustersResource does. Without this, _get_item / --get calls
        # get_node_pool(name="default-pool"), an invalid path that 404s for every pool.
        resp = self.client.list_node_pools(parent=parent)
        rows = []
        for node_pool in getattr(resp, "node_pools", []):
            row = resource_to_dict(node_pool)
            bare = str(row.get("name") or "").strip()
            if bare and not bare.startswith("projects/"):
                row["name"] = f"{parent}/nodePools/{bare}"
            if row:
                rows.append(row)
        return rows

    def _get_item(self, resource_id, **_):
        return self.client.get_node_pool(name=resource_id)

    def save(self, rows, *, project_id, cluster_name):
        location = extract_location_from_resource_name(cluster_name, include_zones=True)
        for row in rows or []:
            name = str(row.get("name", "") or "")
            parsed_project = extract_project_id_from_resource(name)
            parsed_location = extract_location_from_resource_name(name, include_zones=True)
            parsed_cluster_id = extract_path_segment(name, "clusters")
            inferred_cluster_name = (
                f"projects/{parsed_project}/locations/{parsed_location}/clusters/{parsed_cluster_id}"
                if parsed_project and parsed_location and parsed_cluster_id
                else name.partition("/nodePools/")[0] if "/nodePools/" in name else cluster_name
            )
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": location or extract_location_from_resource_name(name, include_zones=True),
                    "cluster_name": inferred_cluster_name,
                },
                extra_builder=lambda _obj, raw: {
                    "node_pool_id": extract_path_tail(raw.get("name", ""), default=str(raw.get("name", "") or "")),
                    "version": raw.get("version") or "",
                    "initial_node_count": raw.get("initial_node_count") or "",
                },
            )
