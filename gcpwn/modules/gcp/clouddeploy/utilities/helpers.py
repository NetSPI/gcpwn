from __future__ import annotations

from typing import Any

from google.cloud import deploy_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("clouddeploy", ("clouddeploy", "v1"))


# The five oneof members of Target.deployment_target, in declaration order. Whichever
# one is set names the runtime the pipeline deploys into.
_DEPLOY_TARGET_TYPES = ("gke", "run", "anthos_cluster", "multi_target", "custom_target")


def _deploy_target_type(raw: dict[str, Any]) -> str:
    """Return the destination oneof that is set on a Target ("gke"/"run"/...)."""
    for target_type in _DEPLOY_TARGET_TYPES:
        if raw.get(target_type) not in (None, "", [], {}):
            return target_type
    return ""


def _execution_service_account(raw: dict[str, Any]) -> str:
    """Return the first execution config's service_account -- the deploy-as identity.

    A Cloud Deploy Target runs each rollout *as* the service account in its
    ExecutionConfig, so a principal who can create or modify targets/pipelines
    (clouddeploy.targets.update, etc.) gains an oracle to act as that SA. The
    enumerated value surfaces which SAs are already wired up as deploy identities.
    """
    configs = raw.get("execution_configs")
    if isinstance(configs, list):
        for config in configs:
            if isinstance(config, dict):
                sa = str(config.get("service_account") or "").strip()
                if sa:
                    return sa
    return ""


class CloudDeployDeliveryPipelinesResource(GcpListResource):
    """List/get Cloud Deploy delivery pipelines via the deploy_v1 GAPIC client."""

    SERVICE_LABEL = "Cloud Deploy"
    TABLE_NAME = "clouddeploy_delivery_pipelines"
    COLUMNS = ["location", "pipeline_id", "name", "uid", "suspended"]
    ACTION_RESOURCE_TYPE = "deliveryPipelines"
    LIST_PERMISSION = "clouddeploy.deliveryPipelines.list"
    GET_PERMISSION = "clouddeploy.deliveryPipelines.get"
    TEST_IAM_API_NAME = "clouddeploy.deliveryPipelines.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "clouddeploy.deliveryPipelines.",
        exclude_permissions=("clouddeploy.deliveryPipelines.create", "clouddeploy.deliveryPipelines.list"),
    )
    ID_FIELD = "pipeline_id"

    def _build_client(self, session):
        return deploy_v1.CloudDeployClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_delivery_pipelines(request=deploy_v1.ListDeliveryPipelinesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_delivery_pipeline(request=deploy_v1.GetDeliveryPipelineRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {"pipeline_id": extract_path_tail(str(raw.get("name", "") or ""))}


class CloudDeployTargetsResource(GcpListResource):
    """List/get Cloud Deploy targets via the deploy_v1 GAPIC client.

    The execution config's service_account is the offensively interesting field --
    rollouts to this target run as that SA (see _execution_service_account).
    """

    SERVICE_LABEL = "Cloud Deploy"
    TABLE_NAME = "clouddeploy_targets"
    COLUMNS = ["location", "target_id", "name", "deploy_target_type", "service_account", "require_approval"]
    ACTION_RESOURCE_TYPE = "targets"
    LIST_PERMISSION = "clouddeploy.targets.list"
    GET_PERMISSION = "clouddeploy.targets.get"
    TEST_IAM_API_NAME = "clouddeploy.targets.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "clouddeploy.targets.",
        exclude_permissions=("clouddeploy.targets.create", "clouddeploy.targets.list"),
    )
    ID_FIELD = "target_id"

    def _build_client(self, session):
        return deploy_v1.CloudDeployClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_targets(request=deploy_v1.ListTargetsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_target(request=deploy_v1.GetTargetRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "target_id": extract_path_tail(str(raw.get("name", "") or "")),
            "deploy_target_type": _deploy_target_type(raw),
            "service_account": _execution_service_account(raw),
        }
