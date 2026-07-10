from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
    region_resolver_for,
)
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import DownloadBudget, handle_service_error


resolve_regions = region_resolver_for("artifactregistry", ("artifactregistry", "v1"))


def _normalize_repository_row(row: dict[str, Any]) -> dict[str, Any]:
    # The Repository proto uses `format`, but the generated Python field name is
    # `format_`. Our DB mapping and enum logic standardize on `format`.
    if not isinstance(row, dict):
        return {}
    if "format" not in row and "format_" in row:
        row["format"] = row.get("format_")
    return row


class _ArtifactRegistryResource(GcpListResource):
    """Base for Artifact Registry resources: shared client + Request()-style calls.

    Subclasses set LIST_REQUEST/GET_REQUEST (the *_v1 Request class names) plus
    LIST_METHOD/GET_METHOD (client methods). `limit` flows through list_kwargs.
    """

    SERVICE_LABEL = "Artifact Registry"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    LIST_REQUEST = ""
    GET_REQUEST = ""

    def _build_client(self, session):
        try:
            from google.cloud import artifactregistry_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Artifact Registry enumeration requires the `google-cloud-artifact-registry` package."
            ) from exc
        self._artifactregistry_v1 = artifactregistry_v1
        return artifactregistry_v1.ArtifactRegistryClient(credentials=session.credentials)

    def _list_items(self, parent, *, limit=0, **_):
        request = getattr(self._artifactregistry_v1, self.LIST_REQUEST)(parent=parent)
        items = list(getattr(self.client, self.LIST_METHOD)(request=request))
        return items[:limit] if limit and limit > 0 else items

    def _get_item(self, resource_id, **_):
        request = getattr(self._artifactregistry_v1, self.GET_REQUEST)(name=resource_id)
        return getattr(self.client, self.GET_METHOD)(request=request)

    def resource_name(self, row: Any) -> str:
        payload = resource_to_dict(row)
        return field_from_row(row, payload, "name")

    def _ensure_scoped_credentials(self, credentials):
        """Return credentials widened to the cloud-platform scope for raw-HTTP artifact downloads.

        The REST download endpoint needs an explicit cloud-platform scope; falls back
        through with_scopes_if_required -> with_scopes -> the original creds unchanged.
        """
        if credentials is None:
            return None
        try:
            import google.auth.credentials

            return google.auth.credentials.with_scopes_if_required(credentials, (self.CLOUD_PLATFORM_SCOPE,))
        except Exception:
            try:
                return credentials.with_scopes([self.CLOUD_PLATFORM_SCOPE])  # type: ignore[attr-defined]
            except Exception:
                return credentials


class ArtifactRegistryRepositoriesResource(_ArtifactRegistryResource):
    """Enumerate Artifact Registry repositories per location into ``artifactregistry_repositories``."""

    TABLE_NAME = "artifactregistry_repositories"
    COLUMNS = ["location", "repository_id", "format_", "name"]
    ACTION_RESOURCE_TYPE = "repositories"
    LIST_PERMISSION = "artifactregistry.repositories.list"
    GET_PERMISSION = "artifactregistry.repositories.get"
    TEST_IAM_API_NAME = "artifactregistry.repositories.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "artifactregistry.repositories.",
        exclude_permissions=("artifactregistry.repositories.create", "artifactregistry.repositories.list"),
    )
    LIST_REQUEST = "ListRepositoriesRequest"
    LIST_METHOD = "list_repositories"
    GET_REQUEST = "GetRepositoryRequest"
    GET_METHOD = "get_repository"
    ID_FIELD = "repository_id"

    def _normalize_row(self, row):
        """Map the proto ``format_`` field back to ``format`` so DB/enum logic is consistent."""
        return _normalize_repository_row(row)

    def _extra_save_fields(self, raw):
        """Persist the repository ``format`` (docker/maven/...) handling the ``format_`` alias."""
        return {"format": raw.get("format") or raw.get("format_") or ""}


class ArtifactRegistryPackagesResource(_ArtifactRegistryResource):
    """Enumerate packages within repositories into ``artifactregistry_packages`` (parent = repository)."""

    TABLE_NAME = "artifactregistry_packages"
    COLUMNS = ["location", "repository", "package_id"]
    ACTION_RESOURCE_TYPE = "packages"
    LIST_PERMISSION = "artifactregistry.packages.list"
    LIST_PROJECT_SCOPE = True
    GET_PERMISSION = "artifactregistry.packages.get"
    LIST_REQUEST = "ListPackagesRequest"
    LIST_METHOD = "list_packages"
    GET_REQUEST = "GetPackageRequest"
    GET_METHOD = "get_package"
    ID_FIELD = "package_id"
    PARENT_FROM_PROJECT_LOCATION = False


class ArtifactRegistryVersionsResource(_ArtifactRegistryResource):
    """Enumerate package versions into ``artifactregistry_versions`` (parent = package)."""

    TABLE_NAME = "artifactregistry_versions"
    COLUMNS = ["location", "package", "version_id", "name"]
    ACTION_RESOURCE_TYPE = "versions"
    LIST_PERMISSION = "artifactregistry.versions.list"
    LIST_PROJECT_SCOPE = True
    GET_PERMISSION = "artifactregistry.versions.get"
    LIST_REQUEST = "ListVersionsRequest"
    LIST_METHOD = "list_versions"
    GET_REQUEST = "GetVersionRequest"
    GET_METHOD = "get_version"
    ID_FIELD = "version_id"
    PARENT_FROM_PROJECT_LOCATION = False


class ArtifactRegistryDockerImagesResource(_ArtifactRegistryResource):
    """List/get Docker images for download discovery (not persisted to a table)."""

    # List/get only (download discovery); not persisted to a table.
    ACTION_RESOURCE_TYPE = "docker_images"
    LIST_PERMISSION = "artifactregistry.dockerImages.list"
    LIST_PROJECT_SCOPE = True
    GET_PERMISSION = "artifactregistry.dockerImages.get"
    LIST_REQUEST = "ListDockerImagesRequest"
    LIST_METHOD = "list_docker_images"
    GET_REQUEST = "GetDockerImageRequest"
    GET_METHOD = "get_docker_image"
    PARENT_FROM_PROJECT_LOCATION = False


class ArtifactRegistryPythonPackagesResource(_ArtifactRegistryResource):
    """List/get PyPI packages in a repository for download discovery (not persisted)."""

    ACTION_RESOURCE_TYPE = "python_packages"
    LIST_PERMISSION = "artifactregistry.pythonPackages.list"
    LIST_PROJECT_SCOPE = True
    GET_PERMISSION = "artifactregistry.pythonPackages.get"
    LIST_REQUEST = "ListPythonPackagesRequest"
    LIST_METHOD = "list_python_packages"
    GET_REQUEST = "GetPythonPackageRequest"
    GET_METHOD = "get_python_package"
    PARENT_FROM_PROJECT_LOCATION = False


class ArtifactRegistryNpmPackagesResource(_ArtifactRegistryResource):
    """List/get npm packages in a repository for download discovery (not persisted)."""

    ACTION_RESOURCE_TYPE = "npm_packages"
    LIST_PERMISSION = "artifactregistry.npmPackages.list"
    LIST_PROJECT_SCOPE = True
    GET_PERMISSION = "artifactregistry.npmPackages.get"
    LIST_REQUEST = "ListNpmPackagesRequest"
    LIST_METHOD = "list_npm_packages"
    GET_REQUEST = "GetNpmPackageRequest"
    GET_METHOD = "get_npm_package"
    PARENT_FROM_PROJECT_LOCATION = False


class ArtifactRegistryMavenArtifactsResource(_ArtifactRegistryResource):
    """List/get Maven artifacts in a repository for download discovery (not persisted)."""

    ACTION_RESOURCE_TYPE = "maven_artifacts"
    LIST_PERMISSION = "artifactregistry.mavenArtifacts.list"
    LIST_PROJECT_SCOPE = True
    GET_PERMISSION = "artifactregistry.mavenArtifacts.get"
    LIST_REQUEST = "ListMavenArtifactsRequest"
    LIST_METHOD = "list_maven_artifacts"
    GET_REQUEST = "GetMavenArtifactRequest"
    GET_METHOD = "get_maven_artifact"
    PARENT_FROM_PROJECT_LOCATION = False


class ArtifactRegistryFilesResource(_ArtifactRegistryResource):
    """List repository files and download their raw bytes (loot exfil); not persisted to a table.

    Listing is gated by ``artifactregistry.files.list``; downloads use a separately-scoped
    raw REST call (see ``download``) rather than the GAPIC client.
    """

    ACTION_RESOURCE_TYPE = "repositories"
    LIST_PERMISSION = "artifactregistry.files.list"
    LIST_PROJECT_SCOPE = True
    LIST_REQUEST = "ListFilesRequest"
    LIST_METHOD = "list_files"
    PARENT_FROM_PROJECT_LOCATION = False
    DOWNLOAD_API_NAME = "artifactregistry.repositories.downloadArtifacts"

    def _list_items(self, parent, *, filter_text="", limit=0, **_):
        request = self._artifactregistry_v1.ListFilesRequest(parent=parent, filter=filter_text or "")
        items = list(self.client.list_files(request=request))
        return items[:limit] if limit and limit > 0 else items

    def list_by_owner(self, *, parent: str, owner: str, limit: int = 0, action_dict=None):
        """List files filtered to a single owning resource (e.g. a package/version) by its name."""
        normalized_owner = str(owner or "").strip()
        filter_text = f'owner="{normalized_owner}"' if normalized_owner else ""
        return self.list(parent=parent, filter_text=filter_text, limit=limit, action_dict=action_dict)

    def _files_download_budget(self) -> DownloadBudget:
        # Lazily created once per resource instance (the caller constructs one
        # ArtifactRegistryFilesResource per project run and calls download() in a loop
        # over matched files), so this caps total wall-clock time for the file-download
        # loop without needing a budget object threaded in from the caller.
        budget = getattr(self, "_download_budget", None)
        if budget is None:
            budget = DownloadBudget(self.session, label="artifact registry files")
            self._download_budget = budget
        return budget

    def download(
        self,
        *,
        file_name: str,
        project_id: str,
        download_subdir: str = "Files",
        action_dict=None,
    ) -> Path | None:
        """Download a registry file's raw bytes via the REST :download endpoint to the loot dir.

        Uses a hand-built authenticated HTTP GET (not GAPIC) because download requires the
        cloud-platform scope and ``alt=media`` streaming. Handles token acquisition and a
        one-shot 401 refresh; routes 403/404/other failures through handle_service_error and
        returns None. On success records the ``downloadArtifacts`` permission as evidence in
        ``action_dict`` (when provided) and returns the written path.

        Returns None for malformed names (missing ``/files/``) or any download failure, and
        once this instance's --download-timeout budget for "artifact registry files" is spent.
        """
        if self._files_download_budget().exceeded():
            return None
        normalized_name = str(file_name or "").strip()
        if not normalized_name or "/files/" not in normalized_name:
            return None

        try:
            import google.auth.transport.requests
            import requests
        except Exception as exc:  # pragma: no cover
            handle_service_error(
                exc,
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )
            return None

        credentials = self._ensure_scoped_credentials(getattr(self.session, "credentials", None))
        if credentials is None:
            return None

        repository_name, _, raw_file_id = normalized_name.partition("/files/")
        normalized_file_id = unquote(raw_file_id)
        encoded_file_id = quote(normalized_file_id, safe="")

        request_session = requests.Session()
        auth_request = google.auth.transport.requests.Request(session=request_session)

        def _refresh_access_token() -> str:
            if hasattr(credentials, "refresh"):
                credentials.refresh(auth_request)
            refreshed = str(getattr(credentials, "token", "") or "").strip()
            if refreshed and hasattr(self.session, "access_token"):
                self.session.access_token = refreshed
            return refreshed

        def _submit(access_token: str):
            return request_session.get(
                f"https://artifactregistry.googleapis.com/download/v1/{repository_name}/files/{encoded_file_id}:download?alt=media",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=120,
                stream=True,
            )

        try:
            access_token = str(
                getattr(credentials, "token", "") or getattr(self.session, "access_token", "") or ""
            ).strip()
            if not access_token:
                access_token = _refresh_access_token()
            if not access_token:
                raise RuntimeError("Unable to acquire an access token for Artifact Registry downloads.")
            response = _submit(access_token)
            if response.status_code == 401:
                refreshed_token = _refresh_access_token()
                if not refreshed_token:
                    raise RuntimeError("Unable to refresh an access token for Artifact Registry downloads.")
                response = _submit(refreshed_token)
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )
            return None

        if response.status_code in (403, 404) or not response.ok:
            handle_service_error(
                RuntimeError(response.text),
                api_name=self.DOWNLOAD_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
                return_not_enabled=False,
                not_found_label=normalized_name if response.status_code == 404 else None,
            )
            return None

        location = extract_location_from_resource_name(repository_name)
        repository_id = extract_path_tail(repository_name, default=repository_name)
        relative_name = normalized_file_id.replace("/", "_") or "artifact"
        destination = Path(
            self.session.get_download_save_path(
                service_name="artifactregistry",
                project_id=project_id,
                subdirs=[str(download_subdir or "Files").strip() or "Files"],
                filename=compact_filename_component(f"{location}_{repository_id}_{relative_name}"),
            )
        )
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                handle.write(chunk)

        if action_dict is not None:
            record_permissions(
                action_dict,
                permissions=self.DOWNLOAD_API_NAME,
                project_id=extract_project_id_from_resource(
                    normalized_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type="repositories",
                resource_label=repository_name,
            )
        return destination
