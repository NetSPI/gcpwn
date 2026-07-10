from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
    region_resolver_for,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import DownloadBudget, handle_service_error


resolve_regions = region_resolver_for("cloudcomposer")


def _normalize_environment_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = str(row.get("name") or "").strip()
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("environment_id", extract_path_tail(name, default=name))
    return row


def _format_section(title: str, values: dict[str, Any]) -> list[str]:
    lines = [title, "=" * len(title)]
    if not values:
        lines.append("(none)")
        return lines
    for key in sorted(values):
        lines.append(f"{key}={values[key]}")
    return lines


def _software_config_text(row: dict[str, Any]) -> str:
    config = row.get("config") if isinstance(row, dict) else None
    config = config if isinstance(config, dict) else {}
    software_config = config.get("software_config") if isinstance(config, dict) else None
    software_config = software_config if isinstance(software_config, dict) else {}

    airflow_config_overrides = software_config.get("airflow_config_overrides")
    airflow_config_overrides = airflow_config_overrides if isinstance(airflow_config_overrides, dict) else {}
    env_variables = software_config.get("env_variables")
    env_variables = env_variables if isinstance(env_variables, dict) else {}

    sections = [
        _format_section("Airflow Config Overrides", airflow_config_overrides),
        [""],
        _format_section("Environment Variables", env_variables),
    ]
    return "\n".join(line for section in sections for line in section)


class ComposerEnvironmentsResource:
    TABLE_NAME = "cloudcomposer_environments"
    COLUMNS = ["location", "environment_id", "name", "state", "config_gke_cluster", "config_airflow_uri"]
    SERVICE_LABEL = "Cloud Composer"
    LIST_PERMISSION = "composer.environments.list"
    GET_PERMISSION = "composer.environments.get"
    ACTION_RESOURCE_TYPE = "composer"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud.orchestration.airflow import service_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Composer enumeration requires the `google-cloud-orchestration-airflow` package."
            ) from exc
        self._service_v1 = service_v1
        self.client = service_v1.EnvironmentsClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._service_v1.ListEnvironmentsRequest(parent=parent)
            rows = [_normalize_environment_row(resource_to_dict(env)) for env in self.client.list_environments(request=request)]
            record_permissions(action_dict, permissions=self.LIST_PERMISSION, scope_key="project_permissions", scope_label=project_id)
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_PERMISSION,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._service_v1.GetEnvironmentRequest(name=resource_id)
            row = _normalize_environment_row(resource_to_dict(self.client.get_environment(request=request)))
            record_permissions(action_dict, permissions=self.GET_PERMISSION,
                               project_id=extract_project_id_from_resource(resource_id),
                               resource_type=self.ACTION_RESOURCE_TYPE, resource_label=resource_id)
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            normalized_row = _normalize_environment_row(dict(row or {}))
            name = str(normalized_row.get("name", "") or "")
            save_to_table(
                self.session,
                self.TABLE_NAME,
                normalized_row,
                defaults={"project_id": project_id, "location": location or extract_location_from_resource_name(name)},
                extra_builder=lambda _obj, raw: {
                    "environment_id": str(raw.get("environment_id") or "").strip() or extract_path_tail(raw.get("name", "")),
                    "state": raw.get("state") or "",
                },
            )

    def _configs_download_budget(self) -> DownloadBudget:
        # Lazily created once per resource instance (the caller constructs one
        # ComposerEnvironmentsResource per project run and calls download_environment_configs
        # per environment in a loop), so this caps total wall-clock time for the
        # "composer configs" download type without a caller-threaded budget.
        budget = getattr(self, "_download_budget", None)
        if budget is None:
            budget = DownloadBudget(self.session, label="composer configs")
            self._download_budget = budget
        return budget

    def download_environment_configs(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        if self._configs_download_budget().exceeded():
            return None
        normalized_row = _normalize_environment_row(dict(row or {}))
        environment_id = str(normalized_row.get("environment_id") or "").strip()
        if not environment_id:
            return None
        destination = resolve_download_path(
            self.session,
            service_name="cloudcomposer",
            project_id=project_id,
            filename=f"{environment_id}_configs.txt",
            sanitize_fallback=True,
        )
        destination.write_text(_software_config_text(normalized_row), encoding="utf-8")
        return destination
