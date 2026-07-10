from __future__ import annotations

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)


def _workstations():
    """Import the workstations_v1 GAPIC module lazily.

    Deferring the import keeps this module importable (for contract tests /
    enum_all listing) even if the optional ``google-cloud-workstations`` package
    is not installed; the clear RuntimeError only surfaces if someone actually
    runs the module without the library present.
    """
    try:
        from google.cloud import workstations_v1
    except Exception as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            "Cloud Workstations enumeration requires the `google-cloud-workstations` package. "
            "Install it (pip install google-cloud-workstations) to enumerate Cloud Workstations resources."
        ) from exc
    return workstations_v1


resolve_locations = region_resolver_for("workstations", ("workstations", "v1"))


class WorkstationsClustersResource(GcpListResource):
    """List/get Cloud Workstations clusters via the workstations_v1 WorkstationsClient.

    A workstation cluster is the regional VPC-attached container for workstation
    configs/workstations. It exposes no per-workstation service account itself
    (that lives on the config's GCE host), so the offensively-useful columns are
    the cluster identity plus its attached network and control-plane IP. Clusters
    are listed per region (projects/<p>/locations/<loc>), so this runs scope=REGION
    with the default PARENT_FROM_PROJECT_LOCATION. supports_iam=False (the cluster
    name is not a testIamPermissions target on the GAPIC client).
    """

    SERVICE_LABEL = "Cloud Workstations"
    TABLE_NAME = "workstations_clusters"
    COLUMNS = ["location", "cluster_id", "name", "network", "control_plane_ip"]
    ACTION_RESOURCE_TYPE = "workstationClusters"
    LIST_PERMISSION = "workstations.workstationClusters.list"
    GET_PERMISSION = "workstations.workstationClusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return _workstations().WorkstationsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workstation_clusters(
            request=_workstations().ListWorkstationClustersRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_workstation_cluster(
            request=_workstations().GetWorkstationClusterRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw):
        return {
            "network": str(raw.get("network", "") or ""),
            "control_plane_ip": str(raw.get("control_plane_ip", "") or ""),
        }


class WorkstationsConfigsResource(GcpListResource):
    """List/get Cloud Workstations configs (nested under a cluster).

    A workstation config is the template that backing workstation VMs are created
    from. Its GCE host carries the service account every workstation built from
    this config runs as (``host.gce_instance.service_account``) -- the priv-esc
    signal: a principal who can create/update a config, or create a workstation
    from it, gains an oracle to act as that SA. Configs are listed under a parent
    cluster (PARENT_FROM_PROJECT_LOCATION=False); listing them is a permission on
    the parent cluster (LIST_RESOURCE_TYPE=workstationClusters). The
    WorkstationsClient exposes testIamPermissions, so supports_iam=True.
    """

    SERVICE_LABEL = "Cloud Workstations"
    TABLE_NAME = "workstations_configs"
    COLUMNS = ["location", "cluster_id", "config_id", "name", "service_account", "machine_type"]
    ACTION_RESOURCE_TYPE = "workstationConfigs"
    LIST_PERMISSION = "workstations.workstationConfigs.list"
    LIST_RESOURCE_TYPE = "workstationClusters"  # listing configs is a permission on the parent cluster
    GET_PERMISSION = "workstations.workstationConfigs.get"
    TEST_IAM_API_NAME = "workstations.workstationConfigs.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "workstations.workstationConfigs.",
        exclude_permissions=("workstations.workstationConfigs.create", "workstations.workstationConfigs.list"),
    )
    ID_FIELD = "config_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent cluster

    def _build_client(self, session):
        return _workstations().WorkstationsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workstation_configs(
            request=_workstations().ListWorkstationConfigsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_workstation_config(
            request=_workstations().GetWorkstationConfigRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw):
        gce_instance = {}
        host = raw.get("host")
        if isinstance(host, dict):
            candidate = host.get("gce_instance")
            if isinstance(candidate, dict):
                gce_instance = candidate
        return {
            "cluster_id": extract_path_segment(str(raw.get("name", "") or ""), "workstationClusters"),
            "service_account": str(gce_instance.get("service_account", "") or ""),
            "machine_type": str(gce_instance.get("machine_type", "") or ""),
        }


class WorkstationsWorkstationsResource(GcpListResource):
    """List/get individual Cloud Workstations (nested under a config).

    A workstation is a running developer VM created from a config. Capturing its
    state and host (the per-workstation FQDN used to reach the running instance)
    surfaces reachable dev environments. Workstations are listed under a parent
    config (PARENT_FROM_PROJECT_LOCATION=False); listing them is a permission on
    the parent config (LIST_RESOURCE_TYPE=workstationConfigs). The
    WorkstationsClient exposes testIamPermissions, so supports_iam=True.
    """

    SERVICE_LABEL = "Cloud Workstations"
    TABLE_NAME = "workstations_workstations"
    COLUMNS = ["location", "cluster_id", "config_id", "workstation_id", "name", "state", "host"]
    ACTION_RESOURCE_TYPE = "workstations"
    LIST_PERMISSION = "workstations.workstations.list"
    LIST_RESOURCE_TYPE = "workstationConfigs"  # listing workstations is a permission on the parent config
    GET_PERMISSION = "workstations.workstations.get"
    TEST_IAM_API_NAME = "workstations.workstations.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "workstations.workstations.",
        exclude_permissions=("workstations.workstations.create", "workstations.workstations.list"),
    )
    ID_FIELD = "workstation_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent config

    def _build_client(self, session):
        return _workstations().WorkstationsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workstations(
            request=_workstations().ListWorkstationsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_workstation(
            request=_workstations().GetWorkstationRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw):
        name = str(raw.get("name", "") or "")
        return {
            "cluster_id": extract_path_segment(name, "workstationClusters"),
            "config_id": extract_path_segment(name, "workstationConfigs"),
            "state": str(raw.get("state", "") or ""),
            "host": str(raw.get("host", "") or ""),
        }
