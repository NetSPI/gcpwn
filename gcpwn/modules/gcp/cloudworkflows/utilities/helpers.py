from __future__ import annotations

from google.cloud import workflows_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)


resolve_locations = region_resolver_for("cloudworkflows", ("workflows", "v1"))


class CloudWorkflowsWorkflowsResource(GcpListResource):
    """List/get Cloud Workflows workflows via the workflows_v1 GAPIC client.

    Cloud Workflows exposes no per-workflow testIamPermissions on the GAPIC
    client, so the component runs with ``supports_iam=False``.

    The offensively interesting field is ``service_account``: a workflow runs
    *as that SA*, so a principal who can create or update a workflow
    (``workflows.workflows.create``/``.update``) gains an oracle to act as it.
    Enumerating existing workflows surfaces which SAs are already wired up as
    workflow identities -- a direct priv-esc signal.
    """

    SERVICE_LABEL = "Cloud Workflows"
    TABLE_NAME = "cloudworkflows_workflows"
    COLUMNS = ["location", "workflow_id", "name", "state", "revision_id", "service_account", "call_log_level", "crypto_key_name"]
    ACTION_RESOURCE_TYPE = "workflows"
    LIST_PERMISSION = "workflows.workflows.list"
    GET_PERMISSION = "workflows.workflows.get"
    ID_FIELD = "workflow_id"

    def _build_client(self, session):
        return workflows_v1.WorkflowsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workflows(request=workflows_v1.ListWorkflowsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_workflow(request=workflows_v1.GetWorkflowRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "workflow_id": extract_path_segment(str(raw.get("name", "") or ""), "workflows"),
            "service_account": str(raw.get("service_account", "") or "").strip(),
            "crypto_key_name": str(raw.get("crypto_key_name", "") or "").strip(),
        }
