from __future__ import annotations

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, region_resolver_for

_REPO_PERMISSIONS = tuple(permissions_with_prefixes(
    "dataform.repositories.",
    # collection-level perms (create/list apply to the parent, not the resource)
    exclude_permissions=["dataform.repositories.create", "dataform.repositories.list"],
))
_WS_PERMISSIONS = tuple(permissions_with_prefixes(
    "dataform.workspaces.",
    # collection-level perms (create/list apply to the parent, not the resource)
    exclude_permissions=["dataform.workspaces.create", "dataform.workspaces.list"],
))


def _dataform():
    try:
        from google.cloud import dataform_v1beta1
    except ImportError as exc:
        raise RuntimeError(
            "Cloud Dataform enumeration requires the `google-cloud-dataform` package. "
            "Install it with: pip install google-cloud-dataform"
        ) from exc
    return dataform_v1beta1


resolve_locations = region_resolver_for("dataform", ("dataform", "v1beta1"))


class DataformRepositoriesResource(GcpListResource):
    """List/get/IAM-probe Dataform repositories per project+location."""

    SERVICE_LABEL = "Cloud Dataform"
    TABLE_NAME = "dataform_repositories"
    COLUMNS = [
        "name", "location", "service_account", "display_name",
        "git_remote_url", "workspace_compilation_overrides",
    ]
    ACTION_RESOURCE_TYPE = "repositories"
    LIST_PERMISSION = "dataform.repositories.list"
    GET_PERMISSION = "dataform.repositories.get"
    TEST_IAM_API_NAME = "dataform.projects.locations.repositories.testIamPermissions"
    TEST_IAM_PERMISSIONS = _REPO_PERMISSIONS
    ID_FIELD = "name"

    def _build_client(self, session):
        return _dataform().DataformClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        df = _dataform()
        return self.client.list_repositories(
            request=df.ListRepositoriesRequest(parent=parent)
        )

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/repositories/{resource_id}"
        return self.client.get_repository(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "repositories") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        git_settings = raw.get("git_remote_settings") or {}
        if not isinstance(git_settings, dict):
            git_settings = {}
        git_url = str(git_settings.get("url") or "")
        overrides = raw.get("workspace_compilation_overrides")
        return {
            "service_account": str(raw.get("service_account") or ""),
            "display_name": str(raw.get("display_name") or ""),
            "git_remote_url": git_url,
            "workspace_compilation_overrides": str(overrides)[:200] if overrides else "",
        }


class DataformWorkspacesResource(GcpListResource):
    """List Dataform workspaces across all repositories in a location."""

    SERVICE_LABEL = "Cloud Dataform"
    TABLE_NAME = "dataform_workspaces"
    COLUMNS = ["name", "location", "repository_name"]
    ACTION_RESOURCE_TYPE = "workspaces"
    LIST_PERMISSION = "dataform.workspaces.list"
    GET_PERMISSION = "dataform.workspaces.get"
    TEST_IAM_API_NAME = "dataform.projects.locations.repositories.workspaces.testIamPermissions"
    TEST_IAM_PERMISSIONS = _WS_PERMISSIONS
    ID_FIELD = "name"

    def _build_client(self, session):
        return _dataform().DataformClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        df = _dataform()
        workspaces = []
        try:
            repos = list(self.client.list_repositories(
                request=df.ListRepositoriesRequest(parent=parent)
            ))
        except Exception:
            return workspaces
        for repo in repos:
            try:
                workspaces.extend(list(self.client.list_workspaces(
                    request=df.ListWorkspacesRequest(parent=repo.name)
                )))
            except Exception:
                pass
        return workspaces

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/workspaces/{resource_id}"
        return self.client.get_workspace(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "workspaces") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        full_name = str(raw.get("name") or "")
        return {
            "repository_name": extract_path_segment(full_name, "repositories"),
        }


class DataformWorkflowConfigsResource(GcpListResource):
    """List Dataform workflow configs across all repositories in a location."""

    SERVICE_LABEL = "Cloud Dataform"
    TABLE_NAME = "dataform_workflow_configs"
    COLUMNS = [
        "name", "location", "repository_name",
        "cron_schedule", "time_zone", "release_config",
        "invocation_service_account", "raw_json",
    ]
    ACTION_RESOURCE_TYPE = "workflowConfigs"
    LIST_PERMISSION = "dataform.workflowConfigs.list"
    GET_PERMISSION = "dataform.workflowConfigs.get"
    ID_FIELD = "name"

    def _build_client(self, session):
        return _dataform().DataformClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        df = _dataform()
        configs = []
        try:
            repos = list(self.client.list_repositories(
                request=df.ListRepositoriesRequest(parent=parent)
            ))
        except Exception:
            return configs
        for repo in repos:
            try:
                configs.extend(list(self.client.list_workflow_configs(
                    request=df.ListWorkflowConfigsRequest(parent=repo.name)
                )))
            except Exception:
                pass
        return configs

    def _get_item(self, resource_id, parent=None, **_):
        name = resource_id if "/" in resource_id else f"{parent}/workflowConfigs/{resource_id}"
        return self.client.get_workflow_config(name=name)

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "workflowConfigs") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        full_name = str(raw.get("name") or "")
        inv_config = raw.get("invocation_config") or {}
        if not isinstance(inv_config, dict):
            inv_config = {}
        return {
            "repository_name": extract_path_segment(full_name, "repositories"),
            "cron_schedule": str(raw.get("cron_schedule") or ""),
            "time_zone": str(raw.get("time_zone") or ""),
            "release_config": extract_path_segment(str(raw.get("release_config") or ""), "releaseConfigs"),
            "invocation_service_account": str(inv_config.get("service_account") or ""),
        }
