from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_segment,
    extract_path_tail,
    extract_project_id_from_resource,
    resolve_regions_args,
)
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict


def _normalize_row(value: Any) -> dict[str, Any]:
    return resource_to_dict(value)


resolve_regions = resolve_regions_args


class GkeClustersResource:
    TABLE_NAME = "gke_clusters"
    COLUMNS = ["location", "cluster_id", "name", "status", "endpoint", "master_version", "node_count", "private_cluster"]

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import container_v1  # type: ignore

            self.client = container_v1.ClusterManagerClient(credentials=session.credentials)
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("GKE enumeration requires the `google-cloud-container` package.") from exc

    def list(self, *, project_id: str, location: str, action_dict=None) -> list[dict[str, Any]] | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            resp = self.client.list_clusters(parent=parent)
            clusters = [_normalize_row(cluster) for cluster in getattr(resp, "clusters", [])]
            record_permissions(
                action_dict,
                permissions="container.projects.locations.clusters.list",
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return [c for c in clusters if isinstance(c, dict) and c]
        except Exception:
            return None

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            row = _normalize_row(self.client.get_cluster(name=resource_id))
            record_permissions(
                action_dict,
                permissions="container.projects.locations.clusters.get",
                project_id=extract_project_id_from_resource(resource_id, fallback_project=str(getattr(self.session, "project_id", "")),),
                resource_type="clusters",
                resource_label=resource_id,
            )
            return row if row else None
        except Exception:
            return None

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            name = str(row.get("name", "") or "")
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "location": location or extract_location_from_resource_name(name, include_zones=True)},
                extra_builder=lambda _obj, raw: {
                    "cluster_id": extract_path_tail(raw.get("name", ""), default=str(raw.get("name", "") or "")),
                    "private_cluster": bool(((raw.get("private_cluster_config") or {}).get("enable_private_nodes")) if isinstance(raw.get("private_cluster_config"), dict) else False),
                    "node_count": raw.get("current_node_count") or "",
                    "master_version": raw.get("current_master_version") or raw.get("master_version") or "",
                },
            )


class GkeNodePoolsResource:
    TABLE_NAME = "gke_node_pools"
    COLUMNS = ["location", "cluster_name", "node_pool_id", "name", "status", "version", "initial_node_count"]

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import container_v1  # type: ignore

            self.client = container_v1.ClusterManagerClient(credentials=session.credentials)
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("GKE enumeration requires the `google-cloud-container` package.") from exc

    def list(self, *, cluster_name: str, action_dict=None) -> list[dict[str, Any]] | None:
        try:
            resp = self.client.list_node_pools(parent=cluster_name)
            node_pools = [_normalize_row(pool) for pool in getattr(resp, "node_pools", [])]
            record_permissions(
                action_dict,
                permissions="container.projects.locations.clusters.nodePools.list",
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    cluster_name,
                    fallback_project=str(getattr(self.session, "project_id", "")),
                ),
            )
            return [pool for pool in node_pools if isinstance(pool, dict) and pool]
        except Exception:
            return None

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            row = _normalize_row(self.client.get_node_pool(name=resource_id))
            record_permissions(
                action_dict,
                permissions="container.projects.locations.clusters.nodePools.get",
                project_id=extract_project_id_from_resource(resource_id, fallback_project=str(getattr(self.session, "project_id", ""))),
                resource_type="node_pools",
                resource_label=resource_id,
            )
            return row if row else None
        except Exception:
            return None

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, cluster_name: str) -> None:
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
