from __future__ import annotations

from google.cloud import securesourcemanager_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    extract_project_id_from_resource,
    resolve_regions_args,
)
from gcpwn.core.utils.action_recording import record_permissions


resolve_locations = resolve_regions_args


class SSMInstancesResource(GcpListResource):
    """List/get Secure Source Manager instances per project+location.

    SSM instances are managed Git hosting environments. Each instance is
    a git server with its own endpoint; ``kms_key`` reveals the CMEK key
    protecting data at rest.
    """

    SERVICE_LABEL = "Secure Source Manager"
    TABLE_NAME = "securesourcemanager_instances"
    COLUMNS = [
        "location",
        "instance_id",
        "name",
        "state",
        "kms_key",
        "html_uri",
        "api_uri",
        "git_http_uri",
        "git_ssh_uri",
    ]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "securesourcemanager.instances.list"
    GET_PERMISSION = "securesourcemanager.instances.get"
    TEST_IAM_API_NAME = "securesourcemanager.instances.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("securesourcemanager.instances.")
    ID_FIELD = "instance_id"

    def _build_client(self, session):
        return securesourcemanager_v1.SecureSourceManagerClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_instances(
            request=securesourcemanager_v1.ListInstancesRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_instance(
            request=securesourcemanager_v1.GetInstanceRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "instances") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        host_config = raw.get("host_config") if isinstance(raw.get("host_config"), dict) else {}
        return {
            "instance_id": extract_path_segment(str(raw.get("name", "") or ""), "instances"),
            "state": str(raw.get("state", "") or ""),
            "kms_key": str(raw.get("kms_key", "") or ""),
            "html_uri": str(host_config.get("html", "") or ""),
            "api_uri": str(host_config.get("api", "") or ""),
            "git_http_uri": str(host_config.get("git_http", "") or ""),
            "git_ssh_uri": str(host_config.get("git_ssh", "") or ""),
        }


class SSMRepositoriesResource(GcpListResource):
    """List/get Secure Source Manager repositories under a parent instance.

    Repositories are listed per instance (``PARENT_FROM_PROJECT_LOCATION=False``).
    The ``service_account`` on a repo is the identity Git operations run as.
    ``uris`` exposes the clone URLs.

    SSM repos have their own IAM surface via ``testIamPermissionsRepo`` (a separate
    GAPIC method from the instance-level ``testIamPermissions``). The override below
    routes calls to that method.
    """

    SERVICE_LABEL = "Secure Source Manager"
    TABLE_NAME = "securesourcemanager_repositories"
    COLUMNS = [
        "location",
        "instance_id",
        "repository_id",
        "name",
        "description",
        "service_account",
        "html_uri",
        "clone_http_uri",
        "clone_ssh_uri",
    ]
    ACTION_RESOURCE_TYPE = "repositories"
    LIST_PERMISSION = "securesourcemanager.repositories.list"
    GET_PERMISSION = "securesourcemanager.repositories.get"
    LIST_RESOURCE_TYPE = "instances"
    TEST_IAM_API_NAME = "securesourcemanager.repositories.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("securesourcemanager.repositories.")
    ID_FIELD = "repository_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return securesourcemanager_v1.SecureSourceManagerClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_repositories(
            request=securesourcemanager_v1.ListRepositoriesRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_repository(
            request=securesourcemanager_v1.GetRepositoryRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "repositories") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        uris = raw.get("uris") if isinstance(raw.get("uris"), dict) else {}
        return {
            "instance_id": extract_path_segment(str(raw.get("name", "") or ""), "instances"),
            "repository_id": extract_path_segment(str(raw.get("name", "") or ""), "repositories"),
            "description": str(raw.get("description", "") or ""),
            "service_account": str(raw.get("service_account", "") or ""),
            "html_uri": str(uris.get("html", "") or ""),
            "clone_http_uri": str(uris.get("clone_http", "") or ""),
            "clone_ssh_uri": str(uris.get("clone_ssh", "") or ""),
        }

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        """Route to test_iam_permissions_repo (separate GAPIC method for repo IAM)."""
        if not self.TEST_IAM_PERMISSIONS:
            return []
        project_id = extract_project_id_from_resource(resource_id, fallback_project=self._fallback_project())
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label=self.SERVICE_LABEL,
            project_id=project_id,
            caller=lambda req: self.client.test_iam_permissions_repo(request=req),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions
