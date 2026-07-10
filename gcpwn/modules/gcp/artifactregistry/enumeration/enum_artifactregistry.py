from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, run_components
from gcpwn.core.utils.module_helpers import (
    dedupe_strs,
    extract_location_from_resource_name,
    extract_path_tail,
    extract_path_segment,
    name_from_input,
    normalize_str_set,
    resource_name_from_value,
)
from gcpwn.core.utils.service_runtime import (
    parallel_map,
    parse_component_args,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.gcp.artifactregistry.utilities.helpers import (
    ArtifactRegistryDockerImagesResource,
    ArtifactRegistryFilesResource,
    ArtifactRegistryMavenArtifactsResource,
    ArtifactRegistryNpmPackagesResource,
    ArtifactRegistryPackagesResource,
    ArtifactRegistryPythonPackagesResource,
    ArtifactRegistryRepositoriesResource,
    ArtifactRegistryVersionsResource,
    resolve_regions,
)

REPOSITORY_SUMMARY_COLUMNS = ["location", "repository_id", "repository_type"]
PACKAGE_SUMMARY_COLUMNS = ["location", "repository_id", "repository_type", "package_id"]
VERSION_SUMMARY_COLUMNS = ["location", "repository_id", "repository_type", "package_id", "version_id"]

DOWNLOAD_FOLDER_BY_SCOPE = {
    "packages": "Packages",
    "python_packages": "PythonPackages",
    "npm_packages": "NpmPackages",
    "maven_artifacts": "MavenArtifacts",
    "apt_artifacts": "AptArtifacts",
    "yum_artifacts": "YumArtifacts",
    "docker_images": "DockerImages",
}
RESOURCE_ID_SEGMENTS = {
    "packages": "packages",
    "apt_artifacts": "packages",
    "yum_artifacts": "packages",
    "python_packages": "pythonPackages",
    "npm_packages": "npmPackages",
    "maven_artifacts": "mavenArtifacts",
    "docker_images": "dockerImages",
}
DOWNLOAD_SCOPE_ALIASES = {
    "all": "all",
    "apt": "apt_artifacts",
    "apt_artifact": "apt_artifacts",
    "apt_artifacts": "apt_artifacts",
    "docker": "docker_images",
    "docker_image": "docker_images",
    "docker_images": "docker_images",
    "list_docker_images": "docker_images",
    "list_packages": "packages",
    "maven": "maven_artifacts",
    "maven_artifact": "maven_artifacts",
    "maven_artifacts": "maven_artifacts",
    "npm": "npm_packages",
    "npm_package": "npm_packages",
    "npm_packages": "npm_packages",
    "package": "packages",
    "packages": "packages",
    "python": "python_packages",
    "python_package": "python_packages",
    "python_packages": "python_packages",
    "yum": "yum_artifacts",
    "yum_artifact": "yum_artifacts",
    "yum_artifacts": "yum_artifacts",
}
ALL_DOWNLOAD_SCOPES = [
    "packages",
    "python_packages",
    "npm_packages",
    "maven_artifacts",
    "apt_artifacts",
    "yum_artifacts",
    "docker_images",
]
SCOPE_TO_REPOSITORY_FORMAT = {
    "apt_artifacts": {"apt"},
    "docker_images": {"docker"},
    "maven_artifacts": {"maven"},
    "npm_packages": {"npm"},
    "python_packages": {"python"},
    "yum_artifacts": {"yum"},
}

REPOSITORY_TEMPLATE = ("projects", "{project_id}", "locations", 0, "repositories", 1)


def _normalize_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _extract_repository_name(value: Any) -> str:
    name = resource_name_from_value(value, "name") if not isinstance(value, str) else str(value or "").strip()
    if not name:
        return ""
    if "/repositories/" not in name:
        return name
    head, _, tail = name.partition("/repositories/")
    repository_id = tail.split("/", 1)[0]
    return f"{head}/repositories/{repository_id}" if repository_id else name


def _repository_name_from_row(row: dict[str, Any]) -> str:
    if not isinstance(row, dict):
        return ""
    repository = resource_name_from_value(row, "repository")
    if repository:
        return _extract_repository_name(repository)
    package = resource_name_from_value(row, "package")
    if package:
        return _extract_repository_name(package)
    return _extract_repository_name(resource_name_from_value(row, "name"))


class _RepositoryTypeIndex:
    """Repository name -> normalized format ('docker', 'maven', ...), shared across
    components so package/version/typed summaries can show repository_type. Falls back
    to the cached repositories table, then a live get, when a repo was not enumerated
    this run."""

    def __init__(self, session, repositories_resource) -> None:
        self.session = session
        self.repositories_resource = repositories_resource
        self.by_name: dict[str, str] = {}

    def remember(self, rows: list[dict[str, Any]]) -> None:
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            name = resource_name_from_value(row, "name")
            fmt = _normalize_token(row.get("format") or row.get("format_"))
            if name and fmt:
                self.by_name[name] = fmt

    def format_for(self, repository_name: str) -> str:
        name = str(repository_name or "").strip()
        if not name:
            return ""
        if name in self.by_name:
            return self.by_name[name]
        cached = self.session.get_data(
            self.repositories_resource.TABLE_NAME, columns=["name", "format_"], where={"name": name}
        ) or []
        for row in cached:
            fmt = _normalize_token(row.get("format_") or row.get("format"))
            if fmt:
                self.by_name[name] = fmt
                return fmt
        fetched = self.repositories_resource.get(resource_id=name)
        fmt = _normalize_token((fetched or {}).get("format") or (fetched or {}).get("format_")) if isinstance(fetched, dict) else ""
        if fmt:
            self.by_name[name] = fmt
        return fmt


def _annotate_summary_fields(row: dict[str, Any], *, resource_type: str, index: _RepositoryTypeIndex) -> None:
    """Add the derived display columns (location/repository_id/repository_type and
    package_id/version_id) onto a row so the framework's summary renders them."""
    name = resource_name_from_value(row, "name")
    repository_name = resource_name_from_value(row, "repository") or _extract_repository_name(name)
    package_name = resource_name_from_value(row, "package")
    reference_name = package_name or repository_name or name

    repository_type = _normalize_token(row.get("repository_type"))
    if not repository_type and repository_name:
        repository_type = index.format_for(repository_name)
    if not repository_type:
        repository_type = _normalize_token(row.get("format") or row.get("format_"))
    row["repository_type"] = repository_type
    row["location"] = str(row.get("location") or "").strip() or extract_location_from_resource_name(reference_name or name)
    row["repository_id"] = str(row.get("repository_id") or "").strip() or extract_path_segment(
        repository_name or package_name or name, "repositories"
    )

    if resource_type == "versions":
        row["package_id"] = str(row.get("package_id") or "").strip() or extract_path_segment(package_name or name, "packages")
        row["version_id"] = str(row.get("version_id") or "").strip() or extract_path_segment(name, "versions")
    elif resource_type == "docker_images":
        row["package_id"] = str(row.get("package_id") or "").strip() or extract_path_tail(name, default=name)
    elif resource_type != "repositories":
        segment = RESOURCE_ID_SEGMENTS.get(resource_type, "packages")
        row["package_id"] = (
            str(row.get("package_id") or "").strip()
            or extract_path_segment(name, segment)
            or extract_path_segment(package_name or name, "packages")
        )


def _annotator(resource_type: str, index: _RepositoryTypeIndex):
    def _enrich(rows, *, resource, args, api_actions):
        if resource_type == "repositories":
            index.remember(rows)
        for row in rows or []:
            if isinstance(row, dict):
                _annotate_summary_fields(row, resource_type=resource_type, index=index)
        return rows

    return _enrich


def _format_filter(scope_name: str):
    allowed = SCOPE_TO_REPOSITORY_FORMAT.get(scope_name)
    if not allowed:
        return None

    def _filter(repository_row) -> bool:
        return _normalize_token((repository_row or {}).get("format_") or (repository_row or {}).get("format")) in allowed

    return _filter


def _build_components(index: _RepositoryTypeIndex) -> list[Component]:
    typed = [
        ("docker_images", ArtifactRegistryDockerImagesResource, "Docker images (per Docker repository)"),
        ("python_packages", ArtifactRegistryPythonPackagesResource, "Python packages (per Python repository)"),
        ("npm_packages", ArtifactRegistryNpmPackagesResource, "Npm packages (per npm repository)"),
        ("maven_artifacts", ArtifactRegistryMavenArtifactsResource, "Maven artifacts (per Maven repository)"),
        ("apt_artifacts", ArtifactRegistryPackagesResource, "Apt artifacts (per apt repository)"),
        ("yum_artifacts", ArtifactRegistryPackagesResource, "Yum artifacts (per yum repository)"),
    ]
    components = [
        Component(
            "repositories", ArtifactRegistryRepositoriesResource, "Artifact Registry Repositories", "Repositories",
            help_text="Enumerate Artifact Registry repositories", scope=REGION,
            columns=REPOSITORY_SUMMARY_COLUMNS, enrich_fn=_annotator("repositories", index),
            manual_id_arg="repository_ids", manual_template=REPOSITORY_TEMPLATE,
            manual_error=(
                "Invalid repository ID format. Use LOCATION/REPOSITORY_ID or "
                "projects/PROJECT_ID/locations/LOCATION/repositories/REPOSITORY_ID."
            ),
            manual_help="Repositories as LOCATION/REPOSITORY_ID or full resource names.",
        ),
        Component(
            "packages", ArtifactRegistryPackagesResource, "Artifact Registry Packages", "Packages",
            help_text="Enumerate Artifact Registry packages (per repository)", scope=NESTED,
            parent_key="repositories", dependency_label="Repositories", save_parent_kwarg="repository",
            columns=PACKAGE_SUMMARY_COLUMNS, supports_iam=False, enrich_fn=_annotator("packages", index),
        ),
        Component(
            "versions", ArtifactRegistryVersionsResource, "Artifact Registry Versions", "Versions",
            help_text="Enumerate Artifact Registry package versions (per package)", scope=NESTED,
            parent_key="packages", dependency_label="Packages", save_parent_kwarg="package",
            columns=VERSION_SUMMARY_COLUMNS, supports_iam=False, enrich_fn=_annotator("versions", index),
            manual_id_arg="package_names",
            manual_help="Packages as projects/.../repositories/.../packages/<id> (parents of versions).",
        ),
    ]
    for key, resource_cls, label in typed:
        components.append(
            Component(
                key, resource_cls, f"Artifact Registry {label}", label,
                help_text=f"Enumerate Artifact Registry {label}", scope=NESTED,
                parent_key="repositories", dependency_label="Repositories",
                parent_filter=_format_filter(key), persist=False, supports_iam=False,
                columns=PACKAGE_SUMMARY_COLUMNS, primary_sort_key="location",
                enrich_fn=_annotator(key, index),
            )
        )
    return components


CORE_KEYS = ["repositories", "packages", "versions"]
OPTIONAL_KEYS = ["docker_images", "python_packages", "npm_packages", "maven_artifacts", "apt_artifacts", "yum_artifacts"]


def _parse_download_scopes(raw_value: str | None) -> list[str]:
    normalized = str(raw_value or "").strip().lower()
    if not normalized:
        return []
    selected: list[str] = []
    for raw_token in [part for part in normalized.split(",") if part.strip()]:
        mapped = DOWNLOAD_SCOPE_ALIASES.get(_normalize_token(raw_token))
        if mapped is None:
            raise ValueError(
                "Invalid --download scope. Use a comma-separated list from: "
                + ", ".join(sorted(DOWNLOAD_SCOPE_ALIASES.keys()))
            )
        expanded = ALL_DOWNLOAD_SCOPES if mapped == "all" else [mapped]
        for scope in expanded:
            if scope not in selected:
                selected.append(scope)
    return selected


def _parse_args(user_args, components):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group(required=False)
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all known Artifact Registry regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument("--limit", type=int, default=0, help="Optional cap per parent listing")
        for component_key, help_text in [(c.key, c.help_text) for c in components if c.key in OPTIONAL_KEYS]:
            parser.add_argument(f"--{component_key.replace('_', '-')}", dest=component_key, action="store_true", help=help_text)
        # Full-resource-name repository inputs (in addition to --repository-ids LOCATION/ID form).
        repo_names_group = parser.add_mutually_exclusive_group(required=False)
        repo_names_group.add_argument("--repository-names", dest="repository_names", required=False, help="Repository full resource names (comma-separated).")
        repo_names_group.add_argument("--repository-names-file", dest="repository_names_file", required=False, help="File of repository full resource names.")
        parser.add_argument(
            "--download",
            nargs="?",
            const="all",
            default=None,
            help=(
                "Download artifact files for the given scopes (comma-separated, or 'all'): "
                "packages, python_packages, npm_packages, maven_artifacts, apt_artifacts, yum_artifacts, docker_images. "
                "Note: Docker repos are references-only (writes image-ref .txt files); no Docker layer/blob bytes are downloaded."
            ),
        )

    return parse_component_args(
        user_args,
        description="Enumerate Artifact Registry resources",
        components=[(c.key, c.help_text) for c in components if c.key in CORE_KEYS],
        add_extra_args=build_extra_args(components, extra=_add_extra_args),
        standard_args=("iam", "get", "debug", "threads"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on repositories"}},
    )


def run_module(user_args, session):
    project_id = session.project_id
    repositories_resource = ArtifactRegistryRepositoriesResource(session)
    index = _RepositoryTypeIndex(session, repositories_resource)
    components = _build_components(index)

    args = _parse_args(user_args, components)
    try:
        download_scopes = _parse_download_scopes(getattr(args, "download", None))
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    # Resolve repository name inputs. --repository-ids is templated (LOCATION/ID);
    # --repository-names carries full resource names. Fold both into the framework's
    # repository_ids manual list as full names so they hydrate the same way.
    repository_id_tokens = parse_csv_file_args(getattr(args, "repository_ids", None), getattr(args, "repository_ids_file", None))
    manual_repository_names = parse_csv_file_args(getattr(args, "repository_names", None), getattr(args, "repository_names_file", None))
    try:
        templated_repo_names = [
            name_from_input(token, project_id=project_id, template=REPOSITORY_TEMPLATE,
                            error_message=components[0].manual_error)
            for token in repository_id_tokens
        ]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1
    combined_repo_names = dedupe_strs([*templated_repo_names, *manual_repository_names])
    if combined_repo_names:
        # Hand the framework full names (template=None path) for the repositories manual list.
        args.repository_ids = ",".join(combined_repo_names)
        args.repository_ids_file = None
        components[0].manual_template = None

    package_names = parse_csv_file_args(getattr(args, "package_names", None), getattr(args, "package_names_file", None))

    # Selection: core defaults to all-when-none; optional + downloads are opt-in but
    # imply repository enumeration (their parents). Manual inputs imply their level.
    core_selected = resolve_selected_components(args, CORE_KEYS)
    optional_selected = {key: bool(getattr(args, key, False)) for key in OPTIONAL_KEYS}
    if combined_repo_names:
        core_selected["repositories"] = True
    if manual_repository_names:
        core_selected["packages"] = True
    if package_names:
        core_selected["versions"] = True
    if any(optional_selected.values()) or (download_scopes and not combined_repo_names):
        core_selected["repositories"] = True

    selection = {**core_selected, **optional_selected}
    for key, value in selection.items():
        setattr(args, key, value)

    run_components(
        session, args, components=components, column_name="artifactregistry_actions_allowed",
        region_resolver=resolve_regions, module_name="enum_artifactregistry",
    )

    if download_scopes:
        _run_downloads(session, args, project_id, download_scopes, index, repositories_resource)
    return 1


def _run_downloads(session, args, project_id, download_scopes, index, repositories_resource):
    packages_resource = ArtifactRegistryPackagesResource(session)
    versions_resource = ArtifactRegistryVersionsResource(session)
    files_resource = ArtifactRegistryFilesResource(session)
    scope_actions = {"project_permissions": defaultdict(set), "folder_permissions": {}, "organization_permissions": {}}
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    threads = getattr(args, "threads", 3)
    limit = getattr(args, "limit", 0)

    repo_parents = [
        str(row.get("name") or "").strip()
        for row in (session.get_data(repositories_resource.TABLE_NAME, columns=["name"], where={"project_id": project_id}) or [])
        if str(row.get("name") or "").strip()
    ]
    if not repo_parents:
        print("[*] No Artifact Registry repositories were available for download.")
        return

    def _list_packages(parents):
        rows: list[dict[str, Any]] = []
        for parent, listed in parallel_map(
            parents, lambda p: (p, packages_resource.list(parent=p, limit=limit, action_dict=scope_actions)), threads=threads
        ):
            if listed in ("Not Enabled", None) or not listed:
                continue
            for row in listed:
                if isinstance(row, dict):
                    row.setdefault("repository", parent)
                    _annotate_summary_fields(row, resource_type="packages", index=index)
            rows.extend(listed)
        return rows

    def _list_versions(package_rows):
        package_parents = [str(r.get("name") or "").strip() for r in package_rows if isinstance(r, dict) and r.get("name")]
        rows: list[dict[str, Any]] = []
        for parent, listed in parallel_map(
            package_parents, lambda p: (p, versions_resource.list(parent=p, limit=limit, action_dict=scope_actions)), threads=threads
        ):
            if listed in ("Not Enabled", None) or not listed:
                continue
            for row in listed:
                if isinstance(row, dict):
                    row.setdefault("package", parent)
                    _annotate_summary_fields(row, resource_type="versions", index=index)
            rows.extend(listed)
        return rows

    version_targets = _list_versions(_list_packages(repo_parents))
    docker_versions = [r for r in version_targets if _normalize_token(r.get("repository_type")) == "docker"]
    non_docker_versions = [r for r in version_targets if _normalize_token(r.get("repository_type")) != "docker"]

    matched_files_by_name: dict[str, str] = {}

    def _collect_owned_files(scope_name: str, rows: list[dict[str, Any]]) -> None:
        owners = [
            (str(row.get("repository") or "").strip() or _extract_repository_name(str(row.get("name") or "").strip()), str(row.get("name") or "").strip())
            for row in rows
            if isinstance(row, dict) and str(row.get("name") or "").strip()
            and ("/packages/" in str(row.get("name") or "") or "/versions/" in str(row.get("name") or ""))
        ]
        for _target, listed in parallel_map(
            owners, lambda t: (t, files_resource.list_by_owner(parent=t[0], owner=t[1], limit=limit, action_dict=scope_actions)), threads=threads
        ):
            if listed in ("Not Enabled", None) or not listed:
                continue
            for file_row in listed:
                file_name = str(file_row.get("name") or "").strip()
                if file_name:
                    matched_files_by_name[file_name] = DOWNLOAD_FOLDER_BY_SCOPE[scope_name]

    if "packages" in download_scopes:
        _collect_owned_files("packages", non_docker_versions)
    for scope_name in [name for name in download_scopes if name not in ("packages", "docker_images")]:
        allowed_formats = SCOPE_TO_REPOSITORY_FORMAT.get(scope_name)
        if not allowed_formats:
            continue
        filtered = [r for r in non_docker_versions if _normalize_token(r.get("repository_type")) in allowed_formats]
        if filtered:
            _collect_owned_files(scope_name, filtered)

    docker_ref_files = 0
    if docker_versions and ("docker_images" in download_scopes or "packages" in download_scopes):
        docker_ref_files = len(_write_docker_refs(session, project_id, docker_versions))

    downloaded_artifacts = 0
    for file_name in sorted(matched_files_by_name):
        download_path = files_resource.download(
            file_name=file_name, project_id=project_id, download_subdir=matched_files_by_name[file_name], action_dict=api_actions
        )
        if download_path is None:
            continue
        print(f"[*] Wrote Artifact Registry file to {download_path}")
        downloaded_artifacts += 1

    if docker_ref_files:
        print(f"[*] Wrote {docker_ref_files} Docker image reference file(s) for project {project_id}.")
    if downloaded_artifacts:
        print(f"[*] Downloaded {downloaded_artifacts} Artifact Registry file(s) for project {project_id}.")
    elif matched_files_by_name:
        print(f"[*] No Artifact Registry files were downloaded for project {project_id}.")
    else:
        print(f"[*] No Artifact Registry files matched the requested download scopes for project {project_id}.")


def _write_docker_refs(session, project_id, rows) -> list[Path]:
    by_repo: dict[str, list[str]] = defaultdict(list)
    for row in rows or []:
        name = str(row.get("name") or "").strip()
        package_name = str(row.get("package") or "").strip()
        repository_name = str(row.get("repository") or "").strip() or _extract_repository_name(package_name or name)
        if not repository_name:
            continue
        location = extract_location_from_resource_name(repository_name)
        repo_id = extract_path_segment(repository_name, "repositories")
        version_id = extract_path_segment(name, "versions")
        package_id = extract_path_segment(package_name or name, "packages")
        if not (location and repo_id and package_id and version_id):
            continue
        package_id = unquote(package_id)
        by_repo[repository_name].append(f"{location}-docker.pkg.dev/{project_id}/{repo_id}/{package_id}@{version_id}")

    written: list[Path] = []
    for repository_name, lines in by_repo.items():
        location = extract_location_from_resource_name(repository_name)
        repo_id = extract_path_segment(repository_name, "repositories")
        filename = f"{location}_{repo_id}_image_refs.txt".replace("/", "_")
        dest = Path(
            session.get_download_save_path(
                service_name="artifactregistry", project_id=project_id,
                subdirs=[DOWNLOAD_FOLDER_BY_SCOPE["docker_images"]], filename=filename,
            )
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        unique = sorted(normalize_str_set(lines))
        dest.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")
        print(f"[*] Wrote Artifact Registry Docker image refs to {dest}")
        written.append(dest)
    return written
