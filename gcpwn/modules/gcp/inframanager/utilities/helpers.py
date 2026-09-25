from google.cloud import config_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_tail, region_resolver_for


resolve_locations = region_resolver_for("inframanager", ("config", "v1"))


class InfraManagerDeploymentsResource(GcpListResource):
    """List/get Infra Manager deployments via the config_v1 GAPIC client."""

    SERVICE_LABEL = "Infrastructure Manager"
    TABLE_NAME = "inframanager_deployments"
    COLUMNS = ["location", "deployment_id", "name", "service_account", "gcs_source", "state"]
    ACTION_RESOURCE_TYPE = "deployments"
    LIST_PERMISSION = "config.deployments.list"
    LIST_API_NAME = "config.projects.locations.deployments.list"
    GET_PERMISSION = "config.deployments.get"
    GET_API_NAME = "config.projects.locations.deployments.get"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("config.deployments.")
    TEST_IAM_API_NAME = "config.projects.locations.deployments.testIamPermissions"
    ID_FIELD = "deployment_id"

    def _build_client(self, session):
        return config_v1.ConfigClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_deployments(request=config_v1.ListDeploymentsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_deployment(request=config_v1.GetDeploymentRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        tb = raw.get("terraform_blueprint") or {}
        gcs_source = tb.get("gcs_source") if isinstance(tb, dict) else ""
        return {
            "deployment_id": extract_path_tail(str(raw.get("name", "") or "")),
            "service_account": str(raw.get("service_account") or ""),
            "gcs_source": str(gcs_source or ""),
        }

    def create_deployment(self, parent: str, deployment_id: str, deployment):
        return self.client.create_deployment(request=config_v1.CreateDeploymentRequest(
            parent=parent, deployment=deployment, deployment_id=deployment_id,
        ))

    def delete_deployment(self, name: str, *, force: bool = True):
        return self.client.delete_deployment(request=config_v1.DeleteDeploymentRequest(
            name=name, force=force,
        ))

    def get_revision(self, name: str):
        return self.client.get_revision(request=config_v1.GetRevisionRequest(name=name))
