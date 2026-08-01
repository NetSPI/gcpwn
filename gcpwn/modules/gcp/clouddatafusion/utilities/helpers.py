from __future__ import annotations

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import extract_path_segment, region_resolver_for


def _data_fusion():
    """Lazily import google.cloud.data_fusion_v1."""
    try:
        from google.cloud import data_fusion_v1
    except ImportError as exc:
        raise RuntimeError(
            "Cloud Data Fusion enumeration requires the `google-cloud-data-fusion` package. "
            "Install it with: pip install google-cloud-data-fusion"
        ) from exc
    return data_fusion_v1


resolve_locations = region_resolver_for("datafusion", ("datafusion", "v1"))


class DataFusionInstancesResource(GcpListResource):
    """List/get Cloud Data Fusion instances per project+location."""

    SERVICE_LABEL = "Cloud Data Fusion"
    TABLE_NAME = "datafusion_instances"
    COLUMNS = [
        "location", "instance_id", "name", "state", "type",
        "dataproc_service_account", "service_endpoint", "api_endpoint",
    ]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "datafusion.instances.list"
    GET_PERMISSION = "datafusion.instances.get"
    LIST_API_NAME = "datafusion.projects.locations.instances.list"
    GET_API_NAME = "datafusion.projects.locations.instances.get"
    ID_FIELD = "instance_id"

    def _build_client(self, session):
        return _data_fusion().DataFusionClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        df = _data_fusion()
        return self.client.list_instances(
            request=df.ListInstancesRequest(parent=parent)
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/instances/{resource_id}"
        return self.client.get_instance(name=name)

    def _extra_save_fields(self, raw: dict) -> dict:
        return {
            "state": str(raw.get("state") or ""),
            "type": str(raw.get("type") or ""),
            "dataproc_service_account": str(raw.get("dataproc_service_account") or ""),
            "service_endpoint": str(raw.get("service_endpoint") or ""),
            "api_endpoint": str(raw.get("api_endpoint") or ""),
        }

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "instances") or name

    def create(self, *, parent: str, instance_id: str, instance) -> object:
        df = _data_fusion()
        return self.client.create_instance(
            request=df.CreateInstanceRequest(
                parent=parent,
                instance_id=instance_id,
                instance=instance,
            )
        )

    def get(self, *, name: str) -> object:
        return self.client.get_instance(name=name)

    def delete(self, *, name: str) -> None:
        self.client.delete_instance(name=name)
