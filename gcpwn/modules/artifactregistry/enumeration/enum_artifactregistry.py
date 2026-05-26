from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import (
    dedupe_strs,
    extract_location_from_resource_name,
    extract_path_tail,
    extract_path_segment,
    name_from_input,
    resource_name_from_value,
)
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_component_args,
    parse_csv_file_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.artifactregistry.utilities.helpers import (
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


COMPONENTS = [
    ("repositories", "Enumerate Artifact Registry repositories"),
    ("packages", "Enumerate Artifact Registry packages (per repository)"),
    ("versions", "Enumerate Artifact Registry package versions (per package)"),
]
OPTIONAL_COMPONENTS = [
    ("docker_images", "Enumerate Artifact Registry Docker images (per Docker repository)"),
    ("python_packages", "Enumerate Artifact Registry Python packages (per Python repository)"),
    ("npm_packages", "Enumerate Artifact Registry npm packages (per npm repository)"),
    ("maven_artifacts", "Enumerate Artifact Registry Maven artifacts (per Maven repository)"),
    ("apt_artifacts", "Enumerate Artifact Registry apt artifacts via v1 package/file resources"),
    ("yum_artifacts", "Enumerate Artifact Registry yum artifacts via v1 package/file resources"),
]

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


def _normalize_token(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _extract_repository_name(value: Any) -> str:
    name = str(value or "").strip()
    if "/repositories/" not in name:
        return ""
    prefix = name.partition("/repositories/")[0]
    repository_id = extract_path_segment(name, "repositories")
    return f"{prefix}/repositories/{repository_id}"


def _repository_name_from_row(row: dict[str, Any]) -> str:
    if not isinstance(row, dict):
        return ""
    return resource_name_from_value(row, "repository") or _extract_repository_name(resource_name_from_value(row, "name"))


def _summary_rows(
    rows: list[dict[str, Any]],
    *,
    resource_type: str,
    repository_type_lookup: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue

        name = resource_name_from_value(row, "name")
        repository_name = resource_name_from_value(row, "repository") or _extract_repository_name(name)
        package_name = resource_name_from_value(row, "package")
        reference_name = package_name or repository_name or name
        repository_type = _normalize_token(row.get("repository_type"))
        if not repository_type and repository_name and repository_type_lookup:
            repository_type = _normalize_token(repository_type_lookup.get(repository_name))
        if not repository_type:
            repository_type = _normalize_token(row.get("format") or row.get("format_"))
        summary_row = {
            "location": str(row.get("location") or "").strip() or extract_location_from_resource_name(reference_name or name),
            "repository_id": str(row.get("repository_id") or "").strip()
            or extract_path_segment(repository_name or package_name or name, "repositories"),
            "repository_type": repository_type,
        }

        if resource_type == "versions":
            summary_row["package_id"] = str(row.get("package_id") or "").strip() or extract_path_segment(
                package_name or name,
                "packages",
            )
            summary_row["version_id"] = str(row.get("version_id") or "").strip() or extract_path_segment(name, "versions")
        elif resource_type == "docker_images":
            summary_row["package_id"] = str(row.get("package_id") or "").strip() or extract_path_tail(name, default=name)
        elif resource_type != "repositories":
            segment = RESOURCE_ID_SEGMENTS.get(resource_type, "packages")
            summary_row["package_id"] = (
                str(row.get("package_id") or "").strip()
                or extract_path_segment(name, segment)
                or extract_path_segment(package_name or name, "packages")
            )

        if any(value for value in summary_row.values()):
            output.append(summary_row)
    return output


def _parse_download_scopes(raw_value: str | None) -> list[str]:
    normalized = str(raw_value or "").strip()
    if not normalized:
        return []

    requested: list[str] = []
    seen: set[str] = set()
    for raw_token in [part for part in normalized.split(",") if part.strip()]:
        mapped = DOWNLOAD_SCOPE_ALIASES.get(_normalize_token(raw_token))
        if not mapped:
            raise ValueError(
                "Invalid --download scope. Use a comma-separated list from: "
                "packages, python_packages, npm_packages, maven_artifacts, apt_artifacts, yum_artifacts, docker_images."
            )
        expanded = ALL_DOWNLOAD_SCOPES if mapped == "all" else [mapped]
        for scope in expanded:
            if scope in seen:
                continue
            seen.add(scope)
            requested.append(scope)
    return requested


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all known Artifact Registry regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument("--limit", type=int, default=0, help="Optional cap per parent listing")
        for component_key, help_text in OPTIONAL_COMPONENTS:
            parser.add_argument(
                f"--{component_key.replace('_', '-')}",
                dest=component_key,
                action="store_true",
                help=help_text,
            )
        parser.add_argument(
            "--repository-ids",
            required=False,
            help=(
                "Repository IDs in comma-separated format. Accepts LOCATION/REPOSITORY_ID "
                "pairs or full names like "
                "`projects/PROJECT_ID/locations/LOCATION/repositories/REPOSITORY_ID`."
            ),
        )
        parser.add_argument(
            "--repository-ids-file",
            required=False,
            help="File containing repository IDs, one per line or comma-separated, using the same formats as --repository-ids.",
        )
        parser.add_argument(
            "--repository-names",
            required=False,
            help="Comma-separated repository resource names for child enumeration (projects/.../locations/.../repositories/...)",
        )
        parser.add_argument(
            "--repository-names-file",
            required=False,
            help="File containing repository resource names, one per line or comma-separated, using the same formats as --repository-names.",
        )
        parser.add_argument(
            "--package-names",
            required=False,
            help="Comma-separated package resource names for version enumeration (projects/.../locations/.../repositories/.../packages/...)",
        )
        parser.add_argument(
            "--package-names-file",
            required=False,
            help="File containing package resource names, one per line or comma-separated, using the same formats as --package-names.",
        )
        parser.add_argument(
            "--download",
            nargs="?",
            const="all",
            required=False,
            help=(
                "Download Artifact Registry files into type-specific folders. Optional CSV scopes: "
                "packages, python_packages, npm_packages, maven_artifacts, apt_artifacts, yum_artifacts, docker_images. "
                "Note: Docker repos are references-only (writes image-ref .txt files); no Docker layer/blob bytes are downloaded."
            ),
        )

    return parse_component_args(
        user_args,
        description="Enumerate Artifact Registry resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on repositories"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id
    try:
        download_scopes = _parse_download_scopes(getattr(args, "download", None))
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    repository_ids = parse_csv_file_args(getattr(args, "repository_ids", None), getattr(args, "repository_ids_file", None))
    manual_repository_names = parse_csv_file_args(getattr(args, "repository_names", None), getattr(args, "repository_names_file", None))
    package_names = parse_csv_file_args(getattr(args, "package_names", None), getattr(args, "package_names_file", None))
    explicit_repository_parents = dedupe_strs([*repository_ids, *manual_repository_names])
    optional_selected = {
        component_key: bool(getattr(args, component_key, False))
        for component_key, _help_text in OPTIONAL_COMPONENTS
    }

    if repository_ids:
        args.repositories = True
    if manual_repository_names:
        args.packages = True
    if package_names:
        args.versions = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    try:
        repository_names = [
            name_from_input(
                token,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "repositories", 1),
                error_message=(
                    "Invalid repository ID format. Use LOCATION/REPOSITORY_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/repositories/REPOSITORY_ID."
                ),
            )
            for token in repository_ids
        ]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    repositories_resource = ArtifactRegistryRepositoriesResource(session)
    packages_resource = ArtifactRegistryPackagesResource(session)
    versions_resource = ArtifactRegistryVersionsResource(session)

    typed_resource_cache: dict[str, Any] = {}

    def _get_typed_resource(scope_name: str):
        if scope_name not in typed_resource_cache:
            factory = {
                "docker_images": ArtifactRegistryDockerImagesResource,
                "python_packages": ArtifactRegistryPythonPackagesResource,
                "npm_packages": ArtifactRegistryNpmPackagesResource,
                "maven_artifacts": ArtifactRegistryMavenArtifactsResource,
                "files": ArtifactRegistryFilesResource,
            }.get(scope_name)
            if factory is None:
                return None
            typed_resource_cache[scope_name] = factory(session)
        return typed_resource_cache.get(scope_name)

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    repositories_rows: list[dict[str, Any]] = []
    repository_rows_by_name: dict[str, dict[str, Any]] = {}
    repository_type_lookup: dict[str, str] = {}
    packages_rows: list[dict[str, Any]] = []
    all_versions: list[dict[str, Any]] = []

    def _remember_repositories(rows: list[dict[str, Any]]) -> None:
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip()
            if name:
                repository_rows_by_name[name] = row
                repository_type = _normalize_token(row.get("format") or row.get("format_"))
                if repository_type:
                    repository_type_lookup[name] = repository_type

    def _repository_format_for(repository_name: str) -> str:
        normalized_name = str(repository_name or "").strip()
        if not normalized_name:
            return ""
        row = repository_rows_by_name.get(normalized_name)
        if row is None:
            fetched = repositories_resource.get(resource_id=normalized_name, action_dict=api_actions)
            if isinstance(fetched, dict) and fetched:
                repository_rows_by_name[normalized_name] = fetched
                row = fetched
        return _normalize_token((row or {}).get("format") or (row or {}).get("format_"))

    def _repository_parents_for_children() -> list[str]:
        repo_parents = dedupe_strs(
            [
                *repository_names,
                *manual_repository_names,
                *[
                    str(row.get("name") or "").strip()
                    for row in repositories_rows
                    if isinstance(row, dict) and row.get("name")
                ],
            ]
        )
        return [parent for parent in repo_parents if parent]

    def _filter_repo_parents(repo_parents: list[str], *, scope_name: str) -> list[str]:
        allowed_formats = SCOPE_TO_REPOSITORY_FORMAT.get(scope_name)
        if not allowed_formats:
            return repo_parents
        filtered: list[str] = []
        for parent in repo_parents:
            repository_format = _repository_format_for(parent)
            if repository_format in allowed_formats:
                filtered.append(parent)
        return filtered

    def _enumerate_package_rows_for_scope(
        *,
        scope_name: str,
        repo_parents: list[str],
        resource,
    ) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        listed_by_parent = parallel_map(
            repo_parents,
            lambda parent: (
                parent,
                resource.list(parent=parent, limit=args.limit, action_dict=scope_actions),
            ),
            threads=getattr(args, "threads", 3),
        )
        for parent, listed in listed_by_parent:
            if listed in ("Not Enabled", None) or not listed:
                continue
            for row in listed:
                if isinstance(row, dict) and parent and not str(row.get("repository") or "").strip():
                    row["repository"] = parent
            if args.get and hasattr(resource, "get"):
                listed = hydrate_get_request_rows(
                    listed,
                    lambda _row, payload: resource.get(
                        resource_id=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )
            targets.extend(listed)
        return targets

    def _annotate_repository_type(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            repository_name = _repository_name_from_row(row)
            repository_type = _normalize_token(row.get("repository_type"))
            if not repository_type and repository_name:
                repository_type = _repository_format_for(repository_name)
            if repository_type:
                row["repository_type"] = repository_type
        return rows

    def _enumerate_versions_for_package_rows(package_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        package_parents = [
            str(row.get("name") or "").strip()
            for row in package_rows
            if isinstance(row, dict) and row.get("name")
        ]
        if not package_parents:
            return []

        version_rows: list[dict[str, Any]] = []
        listed_by_parent = parallel_map(
            package_parents,
            lambda parent: (
                parent,
                versions_resource.list(parent=parent, limit=args.limit, action_dict=scope_actions),
            ),
            threads=getattr(args, "threads", 3),
        )
        for parent, listed in listed_by_parent:
            if listed in ("Not Enabled", None) or not listed:
                continue
            for row in listed:
                if isinstance(row, dict) and not str(row.get("package") or "").strip():
                    row["package"] = parent
            _annotate_repository_type(listed)
            version_rows.extend(listed)
        return version_rows

    should_enumerate_repositories = bool(
        selected.get("repositories", False)
        or any(optional_selected.values())
        or (download_scopes and not explicit_repository_parents)
    )
    if should_enumerate_repositories:
        manual_repository_ids_requested = bool(repository_names)
        regions = resolve_regions(session, args)

        if manual_repository_ids_requested and args.get:
            for name in repository_names:
                row = repositories_resource.get(resource_id=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    repositories_rows.append(row)
        elif not manual_repository_ids_requested:
            listed_by_region = map_regions_with_disabled_short_circuit(
                regions,
                lambda region: repositories_resource.list(
                    project_id=project_id,
                    location=region,
                    action_dict=scope_actions,
                ),
                threads=getattr(args, "threads", 3),
            )
            for region, listed in listed_by_region:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                if args.get:
                    listed = hydrate_get_request_rows(
                        listed,
                        lambda _row, payload: repositories_resource.get(
                            resource_id=str(payload.get("name") or "").strip(),
                            action_dict=api_actions,
                        ),
                    )
                repositories_resource.save(listed, project_id=project_id, location=region)
                repositories_rows.extend(listed)

        if repositories_rows and manual_repository_ids_requested:
            for row in repositories_rows:
                repositories_resource.save(
                    [row],
                    project_id=project_id,
                    location=str(row.get("location") or "").strip(),
                )

        _remember_repositories(repositories_rows)

        if args.iam:
            repository_targets = repository_names if manual_repository_ids_requested else [
                str(row.get("name") or "").strip()
                for row in repositories_rows
                if isinstance(row, dict) and row.get("name")
            ]
            for name in repository_targets:
                repositories_resource.test_iam_permissions(name=name, action_dict=iam_actions)

        show_repository_summary = bool(repositories_rows) or not manual_repository_ids_requested
        if show_repository_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "Artifact Registry Repositories",
                _summary_rows(repositories_rows, resource_type="repositories", repository_type_lookup=repository_type_lookup),
                REPOSITORY_SUMMARY_COLUMNS,
                primary_resource="Repositories",
                primary_sort_key="location",
            )
        elif args.get:
            print("[*] No Artifact Registry repositories found for the supplied --repository-ids.")
        else:
            print("[*] Manual --repository-ids supplied without --get; skipping repository summary.")

    if selected.get("packages", False):
        repo_parents = _repository_parents_for_children()
        if not repo_parents:
            print_missing_dependency(
                component_name="Artifact Registry packages",
                dependency_name="Repositories",
                module_name="enum_artifactregistry",
                manual_flags=["--repository-names", "--repository-ids"],
            )
        else:
            packages_rows = _enumerate_package_rows_for_scope(
                scope_name="packages",
                repo_parents=repo_parents,
                resource=packages_resource,
            )
            _annotate_repository_type(packages_rows)
            if packages_rows:
                for parent in repo_parents:
                    parent_rows = [
                        row
                        for row in packages_rows
                        if str(row.get("repository") or "").strip() == parent
                    ]
                    if parent_rows:
                        packages_resource.save(
                            parent_rows,
                            project_id=project_id,
                            repository=parent,
                        )

        UtilityTools.summary_wrapup(
            project_id,
            "Artifact Registry Packages",
            _summary_rows(packages_rows, resource_type="packages", repository_type_lookup=repository_type_lookup),
            PACKAGE_SUMMARY_COLUMNS,
            primary_resource="Packages",
            primary_sort_key="location",
        )

    if selected.get("versions", False):
        package_parents = package_names
        if not package_parents and packages_rows:
            package_parents = [str(row.get("name") or "").strip() for row in packages_rows if isinstance(row, dict) and row.get("name")]

        if not package_parents:
            print_missing_dependency(
                component_name="Artifact Registry versions",
                dependency_name="Packages",
                module_name="enum_artifactregistry",
                manual_flags=["--package-names"],
            )
        else:
            listed_by_parent = parallel_map(
                package_parents,
                lambda parent: (
                    parent,
                    versions_resource.list(parent=parent, limit=args.limit, action_dict=scope_actions),
                ),
                threads=getattr(args, "threads", 3),
            )
            for parent, listed in listed_by_parent:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                if args.get:
                    listed = hydrate_get_request_rows(
                        listed,
                        lambda _row, payload: versions_resource.get(
                            resource_id=str(payload.get("name") or "").strip(),
                            action_dict=api_actions,
                        ),
                    )
                _annotate_repository_type(listed)
                versions_resource.save(
                    listed,
                    project_id=project_id,
                    package=parent,
                )
                all_versions.extend(listed)

        UtilityTools.summary_wrapup(
            project_id,
            "Artifact Registry Versions",
            _summary_rows(
                all_versions,
                resource_type="versions",
                repository_type_lookup=repository_type_lookup,
            ),
            VERSION_SUMMARY_COLUMNS,
            primary_resource="Versions",
            primary_sort_key="location",
        )

    for component_key, label in OPTIONAL_COMPONENTS:
        if not optional_selected.get(component_key, False):
            continue
        repo_parents = _repository_parents_for_children()
        repo_parents = _filter_repo_parents(repo_parents, scope_name=component_key)
        if not repo_parents:
            print_missing_dependency(
                component_name=f"Artifact Registry {label.split('Artifact Registry ', 1)[-1].lower()}",
                dependency_name="Repositories",
                module_name="enum_artifactregistry",
                manual_flags=["--repository-names", "--repository-ids"],
            )
            continue

        resource = packages_resource if component_key in {"apt_artifacts", "yum_artifacts"} else _get_typed_resource(component_key)
        rows = _enumerate_package_rows_for_scope(
            scope_name=component_key,
            repo_parents=repo_parents,
            resource=resource,
        )
        _annotate_repository_type(rows)
        UtilityTools.summary_wrapup(
            project_id,
            f"Artifact Registry {label.split('Artifact Registry ', 1)[-1]}",
            _summary_rows(rows, resource_type=component_key, repository_type_lookup=repository_type_lookup),
            PACKAGE_SUMMARY_COLUMNS,
            primary_resource=label.split("Enumerate Artifact Registry ", 1)[-1],
            primary_sort_key="location",
        )

    if download_scopes:
        repo_parents = _repository_parents_for_children()
        if not repo_parents:
            print("[*] No Artifact Registry repositories were available for download.")
        else:
            files_resource = _get_typed_resource("files")
            matched_files_by_name: dict[str, str] = {}

            def _collect_owned_files(scope_name: str, rows: list[dict[str, Any]]) -> None:
                files_by_owner = parallel_map(
                    [
                        (
                            str(row.get("repository") or "").strip() or _extract_repository_name(str(row.get("name") or "").strip()),
                            str(row.get("name") or "").strip(),
                        )
                        for row in rows
                        if isinstance(row, dict)
                        and str(row.get("name") or "").strip()
                        and ("/packages/" in str(row.get("name") or "") or "/versions/" in str(row.get("name") or ""))
                    ],
                    lambda target: (
                        target,
                        files_resource.list_by_owner(
                            parent=target[0],
                            owner=target[1],
                            limit=args.limit,
                            action_dict=scope_actions,
                        ),
                    ),
                    threads=getattr(args, "threads", 3),
                )
                for _target, listed in files_by_owner:
                    if listed in ("Not Enabled", None) or not listed:
                        continue
                    for file_row in listed:
                        file_name = str(file_row.get("name") or "").strip()
                        if file_name:
                            matched_files_by_name[file_name] = DOWNLOAD_FOLDER_BY_SCOPE[scope_name]

            package_targets = packages_rows
            if not package_targets:
                package_targets = _enumerate_package_rows_for_scope(
                    scope_name="packages",
                    repo_parents=repo_parents,
                    resource=packages_resource,
                )
                _annotate_repository_type(package_targets)

            version_targets = all_versions or _enumerate_versions_for_package_rows(package_targets)

            # Always avoid downloading Artifact Registry file bytes for DOCKER repos.
            # Instead, we output package@version references to a single file per repository.
            docker_versions = [
                row
                for row in version_targets
                if isinstance(row, dict) and _normalize_token(row.get("repository_type")) == "docker"
            ]
            non_docker_versions = [
                row
                for row in version_targets
                if isinstance(row, dict) and _normalize_token(row.get("repository_type")) != "docker"
            ]

            def _write_docker_refs(rows: list[dict[str, Any]]) -> list[Path]:
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
                    line = f"{location}-docker.pkg.dev/{project_id}/{repo_id}/{package_id}@{version_id}"
                    by_repo[repository_name].append(line)

                written: list[Path] = []
                for repository_name, lines in by_repo.items():
                    location = extract_location_from_resource_name(repository_name)
                    repo_id = extract_path_segment(repository_name, "repositories")
                    filename = f"{location}_{repo_id}_image_refs.txt"
                    dest = Path(
                        session.get_download_save_path(
                            service_name="artifactregistry",
                            project_id=project_id,
                            subdirs=[DOWNLOAD_FOLDER_BY_SCOPE["docker_images"]],
                            filename=filename.replace("/", "_"),
                        )
                    )
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    unique = sorted({str(line).strip() for line in lines if str(line).strip()})
                    dest.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")
                    print(f"[*] Wrote Artifact Registry Docker image refs to {dest}")
                    written.append(dest)
                return written

            if "packages" in download_scopes:
                _collect_owned_files("packages", non_docker_versions)

            for scope_name in [name for name in download_scopes if name != "packages"]:
                if scope_name == "docker_images":
                    # Docker downloads are references-only. No file downloads.
                    continue
                allowed_formats = SCOPE_TO_REPOSITORY_FORMAT.get(scope_name)
                if not allowed_formats:
                    continue
                filtered_versions = [
                    row
                    for row in non_docker_versions
                    if isinstance(row, dict)
                    and _normalize_token(row.get("repository_type")) in allowed_formats
                ]
                if filtered_versions:
                    _collect_owned_files(scope_name, filtered_versions)

            downloaded_artifacts = 0
            docker_ref_files = 0
            if docker_versions and ("docker_images" in download_scopes or "packages" in download_scopes):
                docker_written = _write_docker_refs(docker_versions)
                docker_ref_files = len(docker_written)

            for file_name in sorted(matched_files_by_name):
                download_path = files_resource.download(
                    file_name=file_name,
                    project_id=project_id,
                    download_subdir=matched_files_by_name[file_name],
                    action_dict=api_actions,
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

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="artifactregistry_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="artifactregistry_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="artifactregistry_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
