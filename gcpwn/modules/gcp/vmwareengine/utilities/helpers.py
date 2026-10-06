from __future__ import annotations

from google.cloud import vmwareengine_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("vmwareengine", ("vmwareengine", "v1"))


class VmwareEnginePrivateCloudsResource(GcpListResource):

    SERVICE_LABEL = "VMware Engine Private Clouds"
    TABLE_NAME = "vmwareengine_private_clouds"
    COLUMNS = ["location", "private_cloud_id", "name", "state", "type", "uid", "vcenter_fqdn", "nsx_fqdn"]
    LIST_PERMISSION = "vmwareengine.privateClouds.list"
    GET_PERMISSION = "vmwareengine.privateClouds.get"
    ID_FIELD = "private_cloud_id"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("vmwareengine.privateClouds.")

    def _build_client(self, session):
        return vmwareengine_v1.VmwareEngineClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_private_clouds(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_private_cloud(name=resource_id)

    def _extra_save_fields(self, raw):
        return {
            "private_cloud_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
            "type": str(raw.get("type", "") or ""),
            "uid": str(raw.get("uid", "") or ""),
            "vcenter_fqdn": str((raw.get("vcenter") or {}).get("fqdn", "") or ""),
            "nsx_fqdn": str((raw.get("nsx") or {}).get("fqdn", "") or ""),
        }


class VmwareEngineClustersResource(GcpListResource):

    SERVICE_LABEL = "VMware Engine Clusters"
    TABLE_NAME = "vmwareengine_clusters"
    COLUMNS = ["location", "cluster_id", "name", "private_cloud", "state", "uid", "management"]
    LIST_PERMISSION = "vmwareengine.clusters.list"
    GET_PERMISSION = "vmwareengine.clusters.get"
    ID_FIELD = "cluster_id"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("vmwareengine.clusters.")

    def _build_client(self, session):
        return vmwareengine_v1.VmwareEngineClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_clusters(parent=parent)

    def _extra_save_fields(self, raw):
        return {
            "cluster_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
            "uid": str(raw.get("uid", "") or ""),
            "management": str(bool(raw.get("management", False))),
            "private_cloud": extract_path_segment(str(raw.get("name", "") or ""), "privateClouds"),
        }


class VmwareEngineHcxActivationKeysResource(GcpListResource):

    SERVICE_LABEL = "VMware Engine HCX Activation Keys"
    TABLE_NAME = "vmwareengine_hcx_activation_keys"
    COLUMNS = ["location", "hcx_key_id", "name", "private_cloud", "state", "uid", "activation_key"]
    LIST_PERMISSION = "vmwareengine.hcxActivationKeys.list"
    GET_PERMISSION = "vmwareengine.hcxActivationKeys.get"
    ID_FIELD = "hcx_key_id"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("vmwareengine.hcxActivationKeys.")

    def _build_client(self, session):
        return vmwareengine_v1.VmwareEngineClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_hcx_activation_keys(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_hcx_activation_key(name=resource_id)

    def _extra_save_fields(self, raw):
        return {
            "hcx_key_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
            "uid": str(raw.get("uid", "") or ""),
            "activation_key": str(raw.get("activation_key", "") or ""),
            "private_cloud": extract_path_segment(str(raw.get("name", "") or ""), "privateClouds"),
        }
