from __future__ import annotations

from typing import Any

from google.api_core.client_options import ClientOptions
from google.cloud import dataproc_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("dataproc", ("dataproc", "v1"))


def _project_of(parent: str) -> str:
    return extract_path_segment(str(parent or ""), "projects") or ""


def _region_of(parent: str) -> str:
    # Workflow Template paths use /regions/{region}; Batch/Cluster paths use /locations/{region}.
    return (
        extract_path_segment(str(parent or ""), "locations")
        or extract_path_segment(str(parent or ""), "regions")
        or "global"
    )


class _DataprocRegionalResource(GcpListResource):
    """Base for Dataproc resources.

    Dataproc's controllers are REGION-scoped and require a regional endpoint
    (``{region}-dataproc.googleapis.com``), so the client is built lazily per
    region in ``_list_items`` (the framework builds one client per resource, but
    Dataproc needs one per region). ``list_clusters`` returns full ``Cluster``
    objects, so ``--get`` adds nothing (components set ``supports_get=False``); and
    because ``self.client`` is intentionally unset (per-region clients only), the
    components also run ``supports_iam=False``.
    """

    CLIENT_CLASS: type | None = None

    def _build_client(self, session):
        self._clients: dict[str, Any] = {}
        return None

    def _client_for_region(self, region: str):
        if region not in self._clients:
            self._clients[region] = self.CLIENT_CLASS(
                credentials=self.session.credentials,
                client_options=ClientOptions(api_endpoint=f"{region}-dataproc.googleapis.com:443"),
            )
        return self._clients[region]


class DataprocClustersResource(_DataprocRegionalResource):
    """List Dataproc clusters. Each cluster runs on Compute VMs as
    ``config.gce_cluster_config.service_account`` -- the impersonation target a
    principal who can submit jobs (``dataproc.jobs.create``) executes code as."""

    SERVICE_LABEL = "Cloud Dataproc"
    TABLE_NAME = "dataproc_clusters"
    COLUMNS = ["location", "cluster_name", "name", "state", "service_account", "cluster_uuid"]
    ACTION_RESOURCE_TYPE = "clusters"
    LIST_PERMISSION = "dataproc.clusters.list"
    GET_PERMISSION = "dataproc.clusters.get"
    ID_FIELD = "cluster_name"
    CLIENT_CLASS = dataproc_v1.ClusterControllerClient

    def _list_items(self, parent, **_):
        region = _region_of(parent)
        return self._client_for_region(region).list_clusters(project_id=_project_of(parent), region=region)

    def _normalize_row(self, row):
        # A Cluster has no path-style "name"; synthesize one from cluster_name so
        # the shared save()/summary (which key on "name") work.
        if not row.get("name"):
            row["name"] = str(row.get("cluster_name", "") or "")
        return row

    def _extra_save_fields(self, raw):
        gce = ((raw.get("config") or {}).get("gce_cluster_config")) or {}
        return {
            "cluster_name": str(raw.get("cluster_name", "") or ""),
            "state": str((raw.get("status") or {}).get("state", "") or ""),
            "service_account": str(gce.get("service_account", "") or ""),
            "cluster_uuid": str(raw.get("cluster_uuid", "") or ""),
        }


class DataprocBatchesResource(_DataprocRegionalResource):
    """List Dataproc Serverless (Spark) batches. Each batch runs arbitrary code as
    ``environment_config.execution_config.service_account`` -- a low-footprint
    code-exec-as-SA primitive (``dataproc.batches.create`` + actAs)."""

    SERVICE_LABEL = "Cloud Dataproc Serverless"
    TABLE_NAME = "dataproc_batches"
    COLUMNS = ["location", "batch_id", "name", "state", "creator", "service_account"]
    ACTION_RESOURCE_TYPE = "batches"
    LIST_PERMISSION = "dataproc.batches.list"
    GET_PERMISSION = "dataproc.batches.get"
    ID_FIELD = "batch_id"
    CLIENT_CLASS = dataproc_v1.BatchControllerClient

    def _list_items(self, parent, **_):
        return self._client_for_region(_region_of(parent)).list_batches(parent=parent)

    def _extra_save_fields(self, raw):
        exec_cfg = ((raw.get("environment_config") or {}).get("execution_config")) or {}
        return {
            "batch_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
            "creator": str(raw.get("creator", "") or ""),
            "service_account": str(exec_cfg.get("service_account", "") or ""),
        }

    def create(self, parent: str, batch_id: str, batch: Any) -> None:
        region = _region_of(parent)
        self._client_for_region(region).create_batch(
            request=dataproc_v1.CreateBatchRequest(
                parent=parent,
                batch=batch,
                batch_id=batch_id,
            )
        )

    def delete(self, name: str) -> None:
        try:
            self._client_for_region(_region_of(name)).delete_batch(name=name)
        except Exception as e:
            print(f"[!] Cleanup warning — delete_batch({name}): {e}")


class DataprocWorkflowTemplatesResource(_DataprocRegionalResource):
    """List/exploit Dataproc Workflow Templates.

    A Workflow Template bundles a managed cluster spec (with
    ``gce_cluster_config.service_account``) and PySpark jobs into a single
    instantiable object.  Requires ``dataproc.workflowTemplates.create`` +
    ``iam.serviceAccounts.actAs`` on the target SA.
    """

    SERVICE_LABEL = "Cloud Dataproc Workflow Templates"
    TABLE_NAME = "dataproc_workflow_templates"
    COLUMNS = ["location", "template_id", "name", "version", "service_account"]
    ACTION_RESOURCE_TYPE = "workflowTemplates"
    LIST_PERMISSION = "dataproc.workflowTemplates.list"
    GET_PERMISSION = "dataproc.workflowTemplates.get"
    ID_FIELD = "template_id"
    CLIENT_CLASS = dataproc_v1.WorkflowTemplateServiceClient

    def _list_items(self, parent, **_):
        return self._client_for_region(_region_of(parent)).list_workflow_templates(parent=parent)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        placement = raw.get("placement") or {}
        managed = placement.get("managed_cluster") or {}
        config = managed.get("config") or {}
        gce = config.get("gce_cluster_config") or {}
        return {
            "template_id": extract_path_tail(str(raw.get("name", "") or "")),
            "version": str(raw.get("version", "") or ""),
            "service_account": str(gce.get("service_account", "") or ""),
        }

    def create_template(self, parent: str, template: Any) -> Any:
        return self._client_for_region(_region_of(parent)).create_workflow_template(
            request=dataproc_v1.CreateWorkflowTemplateRequest(
                parent=parent,
                template=template,
            )
        )

    def instantiate(self, name: str) -> Any:
        return self._client_for_region(_region_of(name)).instantiate_workflow_template(
            request=dataproc_v1.InstantiateWorkflowTemplateRequest(name=name)
        )

    def delete(self, name: str) -> None:
        try:
            self._client_for_region(_region_of(name)).delete_workflow_template(name=name)
        except Exception as e:
            print(f"[!] Cleanup warning — delete_workflow_template({name}): {e}")
