from __future__ import annotations

from google.cloud import developerconnect_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import extract_path_segment, resolve_regions_args


resolve_locations = resolve_regions_args


class DevConnectConnectionsResource(GcpListResource):
    """List/get Developer Connect connections per project+location.

    Developer Connect manages OAuth connections to GitHub, GitLab, Bitbucket,
    and Secure Source Manager. Each connection stores an installation token that
    links the GCP project to external SCM repos. The ``installation_state`` shows
    whether the OAuth grant is active; ``disabled`` marks connections that have
    been revoked.
    """

    SERVICE_LABEL = "Developer Connect"
    TABLE_NAME = "developerconnect_connections"
    COLUMNS = [
        "location",
        "connection_id",
        "name",
        "connection_provider",
        "installation_state",
        "disabled",
        "reconciling",
    ]
    ACTION_RESOURCE_TYPE = "connections"
    LIST_PERMISSION = "developerconnect.connections.list"
    GET_PERMISSION = "developerconnect.connections.get"
    ID_FIELD = "connection_id"

    def _build_client(self, session):
        return developerconnect_v1.DeveloperConnectClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_connections(
            request=developerconnect_v1.ListConnectionsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_connection(
            request=developerconnect_v1.GetConnectionRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "connections") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        # Detect the provider from which oneof config key is populated.
        _provider_keys = (
            "github_config", "github_enterprise_config",
            "gitlab_config", "gitlab_enterprise_config",
            "bitbucket_data_center_config", "bitbucket_cloud_config",
            "secure_source_manager_instance_config",
        )
        provider = next((k for k in _provider_keys if raw.get(k)), "")
        inst_state = raw.get("installation_state") if isinstance(raw.get("installation_state"), dict) else {}
        return {
            "connection_id": extract_path_segment(str(raw.get("name", "") or ""), "connections"),
            "connection_provider": provider,
            "installation_state": str(inst_state.get("stage", "") or ""),
            "disabled": str(bool(raw.get("disabled"))),
            "reconciling": str(bool(raw.get("reconciling"))),
        }


class DevConnectRepoLinksResource(GcpListResource):
    """List/get Developer Connect Git repository links under a parent connection.

    Each ``GitRepositoryLink`` exposes the clone URI for one external repository
    that has been linked to the connection. The ``git_proxy_uri`` (when set) is
    the GCP-side proxy URL for authenticated git operations.

    Repo links are listed per parent connection (``PARENT_FROM_PROJECT_LOCATION=False``).
    """

    SERVICE_LABEL = "Developer Connect"
    TABLE_NAME = "developerconnect_repo_links"
    COLUMNS = [
        "location",
        "connection_id",
        "link_id",
        "name",
        "clone_uri",
        "git_proxy_uri",
        "reconciling",
    ]
    ACTION_RESOURCE_TYPE = "gitRepositoryLinks"
    LIST_PERMISSION = "developerconnect.gitRepositoryLinks.list"
    GET_PERMISSION = "developerconnect.gitRepositoryLinks.get"
    LIST_RESOURCE_TYPE = "connections"
    ID_FIELD = "link_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return developerconnect_v1.DeveloperConnectClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_git_repository_links(
            request=developerconnect_v1.ListGitRepositoryLinksRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_git_repository_link(
            request=developerconnect_v1.GetGitRepositoryLinkRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "gitRepositoryLinks") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        return {
            "connection_id": extract_path_segment(str(raw.get("name", "") or ""), "connections"),
            "link_id": extract_path_segment(str(raw.get("name", "") or ""), "gitRepositoryLinks"),
            "clone_uri": str(raw.get("clone_uri", "") or ""),
            "git_proxy_uri": str(raw.get("git_proxy_uri", "") or ""),
            "reconciling": str(bool(raw.get("reconciling"))),
        }
