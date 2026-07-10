from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_service_account_email,
    extract_path_tail,
    extract_path_segment,
    extract_project_id_from_resource,
    parse_string_list,
    region_resolver_for,
    resource_name_from_value,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import DownloadBudget, handle_service_error


resolve_regions = region_resolver_for("cloudbuild")


def _normalize_connection_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = resource_name_from_value(row, "name")
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("connection_id", extract_path_segment(name, "connections"))
    return row


def _normalize_trigger_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    resource_name = resource_name_from_value(row, "resource_name")
    if resource_name:
        row.setdefault("location", extract_location_from_resource_name(resource_name))
        row.setdefault("trigger_id", extract_path_segment(resource_name, "triggers"))
    elif row.get("id"):
        row.setdefault("trigger_id", str(row.get("id") or "").strip())
    return row


def _normalize_build_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = resource_name_from_value(row, "name")
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("build_id", extract_path_segment(name, "builds"))
    elif row.get("id"):
        row.setdefault("build_id", str(row.get("id") or "").strip())
    service_account = row.get("service_account")
    normalized_service_account = _normalize_service_account_value(service_account)
    if normalized_service_account:
        row["service_account"] = normalized_service_account
    return row


def _normalize_service_account_value(value: Any) -> str:
    """Reduce a build's service_account field to a bare SA email when it's a path.

    Cloud Build may report the SA as a ``projects/.../serviceAccounts/<email>``
    resource path; this extracts the email so the runtime SA is legible (it's the
    identity builds run as -- a key privilege-escalation signal).
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "/serviceAccounts/" in text or text.startswith("projects/"):
        return extract_service_account_email(text) or text
    return text


def _string_list(value: Any) -> list[str]:
    # A scalar-or-list -> stripped, non-empty list. Env/secret_env values are already
    # parsed lists, so the JSON/literal decoders stay off (a stray "[...]" string is a
    # single token, not a list) to preserve exact behavior.
    return parse_string_list(value, allow_json=False, allow_python_literal=False, fallback_to_single=True)


def _format_key_value_section(title: str, values: dict[str, Any]) -> list[str]:
    lines = [title, "=" * len(title)]
    if not values:
        lines.append("(none)")
        return lines

    for key in sorted(values):
        lines.append(f"{key}={values[key]}")
    return lines


def _build_env_summary_text(row: dict[str, Any]) -> str:
    """Render a build's substitutions and env vars as a readable loot summary.

    Splits user (``_``-prefixed) vs built-in substitutions and collects global and
    per-step env / secret_env. Offensively valuable: build env vars and secret_env
    references frequently leak credentials or point at secrets to harvest.
    """
    substitutions = row.get("substitutions")
    substitutions = substitutions if isinstance(substitutions, dict) else {}
    user_substitutions = {
        str(key).strip(): value
        for key, value in substitutions.items()
        if str(key).strip().startswith("_")
    }
    built_in_substitutions = {
        str(key).strip(): value
        for key, value in substitutions.items()
        if str(key).strip() and not str(key).strip().startswith("_")
    }

    env_lines = ["Environment Variables", "=" * len("Environment Variables")]
    has_environment = False

    options = row.get("options")
    options = options if isinstance(options, dict) else {}
    global_env = _string_list(options.get("env"))
    global_secret_env = _string_list(options.get("secret_env"))
    if global_env or global_secret_env:
        has_environment = True
        env_lines.append("[Global]")
        env_lines.extend(global_env or ["env: (none)"])
        if global_secret_env:
            env_lines.append("")
            env_lines.append("secret_env:")
            env_lines.extend(global_secret_env)
        env_lines.append("")

    steps = row.get("steps")
    if isinstance(steps, list):
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            step_env = _string_list(step.get("env"))
            step_secret_env = _string_list(step.get("secret_env"))
            if not step_env and not step_secret_env:
                continue
            has_environment = True
            step_name = str(step.get("name") or "").strip() or "(unnamed)"
            env_lines.append(f"[Step {index}] {step_name}")
            env_lines.extend(step_env or ["env: (none)"])
            if step_secret_env:
                env_lines.append("")
                env_lines.append("secret_env:")
                env_lines.extend(step_secret_env)
            env_lines.append("")

    if not has_environment:
        env_lines.append("(none)")
    elif env_lines and env_lines[-1] == "":
        env_lines.pop()

    sections = [
        _format_key_value_section("User Substitutions", user_substitutions),
        [""],
        _format_key_value_section("Built-in Substitutions", built_in_substitutions),
        [""],
        env_lines,
    ]
    return "\n".join(line for section in sections for line in section)


def _build_step_arguments_text(row: dict[str, Any]) -> str:
    """Render each build step's command/script/args as a readable loot summary.

    Reconstructs the effective command per step (inline ``script`` or
    entrypoint+args joined shell-safely via shlex). Useful for spotting injected
    or sensitive commands a build runs.
    """
    lines = ["Arguments By Step", "=" * len("Arguments By Step")]
    steps = row.get("steps")
    if not isinstance(steps, list) or not steps:
        lines.append("(none)")
        return "\n".join(lines)

    has_arguments = False
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        step_name = str(step.get("name") or "").strip() or "(unnamed)"
        lines.append(f"Step {index}: {step_name}")
        lines.append("-" * len(lines[-1]))
        script = str(step.get("script") or "").strip()
        entrypoint = str(step.get("entrypoint") or "").strip()
        arguments = _string_list(step.get("args"))
        command_parts = ([entrypoint] if entrypoint else []) + arguments
        if script:
            has_arguments = True
            lines.append(script)
        elif command_parts:
            has_arguments = True
            lines.append(shlex.join(command_parts))
        else:
            lines.append("(none)")
        if index != len(steps):
            lines.append("")

    if not has_arguments:
        return "\n".join(["Arguments By Step", "=" * len("Arguments By Step"), "(none)"])
    return "\n".join(lines)


def _cloudbuild_v1_module():
    try:
        from google.cloud.devtools import cloudbuild_v1  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Cloud Build enumeration requires the `google-cloud-build` package.") from exc
    return cloudbuild_v1


def _cloudbuild_v2_module():
    from google.cloud.devtools import cloudbuild_v2  # type: ignore

    return cloudbuild_v2


class CloudBuildConnectionsResource(GcpListResource):
    """List/get/testIamPermissions Cloud Build v2 source-repo connections per location.

    Uses the v2 RepositoryManagerClient (kept as self.client so the base's
    testIamPermissions probe runs against it).
    """

    SERVICE_LABEL = "Cloud Build"
    TABLE_NAME = "cloudbuild_connections"
    COLUMNS = ["location", "connection_id", "name", "disabled"]
    ACTION_RESOURCE_TYPE = "connections"
    LIST_PERMISSION = "cloudbuild.connections.list"
    GET_PERMISSION = "cloudbuild.connections.get"
    TEST_IAM_API_NAME = "cloudbuild.connections.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("cloudbuild.connections.")
    ID_FIELD = "connection_id"
    _normalize_row = staticmethod(_normalize_connection_row)

    def _build_client(self, session):
        self._v2 = _cloudbuild_v2_module()
        return self._v2.RepositoryManagerClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_connections(request=self._v2.ListConnectionsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_connection(request=self._v2.GetConnectionRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "connection_id": str(raw.get("connection_id") or "").strip()
            or extract_path_segment(str(raw.get("name", "")).strip(), "connections"),
        }


class CloudBuildTriggersResource(GcpListResource):
    """List/get Cloud Build triggers per location, surfacing their runtime service account.

    Triggers are gated by cloudbuild.builds.* permissions, not trigger-specific
    ones (see LIST_PERMISSION). The trigger's service_account is the identity its
    builds run as -- a privilege-escalation target. get()/save() keep trigger-
    specific handling (get by trigger_id, not resource name; id/location parsed
    from the ``resource_name`` field), so they override the base bodies.
    """

    SERVICE_LABEL = "Cloud Build"
    TABLE_NAME = "cloudbuild_triggers"
    COLUMNS = ["location", "name", "disabled", "service_account"]
    ACTION_RESOURCE_TYPE = "triggers"
    LIST_PERMISSION = "cloudbuild.builds.list"
    GET_PERMISSION = "cloudbuild.builds.get"
    _normalize_row = staticmethod(_normalize_trigger_row)

    def _build_client(self, session):
        self._v1 = _cloudbuild_v1_module()
        return self._v1.CloudBuildClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        project_id = extract_project_id_from_resource(parent, fallback_project=self._fallback_project())
        return self.client.list_build_triggers(
            request=self._v1.ListBuildTriggersRequest(project_id=project_id, parent=parent)
        )

    def get(self, *, project_id: str | None = None, trigger_id: str = "", resource_id: str = "", action_dict=None) -> dict[str, Any] | None:
        trigger_id = trigger_id or extract_path_segment(resource_id, "triggers") or resource_id
        project_id = project_id or extract_project_id_from_resource(resource_id) or getattr(self.session, "project_id", None)
        if not trigger_id:
            return None
        try:
            request = self._v1.GetBuildTriggerRequest(project_id=project_id, trigger_id=trigger_id)
            row = _normalize_trigger_row(resource_to_dict(self.client.get_build_trigger(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(row.get("id") or row.get("name") or trigger_id).strip(),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=trigger_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    @staticmethod
    def _resource_id_from_row(row: Any) -> str:
        """Extract a bare trigger id from a row dict, full path, or object."""
        if isinstance(row, str):
            token = str(row).strip()
            if token.startswith("projects/"):
                return extract_path_segment(token, "triggers")
            if "/" in token:
                return extract_path_tail(token, default=token)
            return token
        if isinstance(row, dict):
            return (
                str(row.get("id") or row.get("trigger_id") or "").strip()
                or extract_path_segment(resource_name_from_value(row, "resource_name"), "triggers")
            )
        return str(getattr(row, "id", "") or getattr(row, "trigger_id", "") or "").strip()

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(
                        resource_name_from_value(row, "resource_name")
                    ),
                },
                extra_builder=lambda _obj, raw: {
                    "trigger_id": raw.get("trigger_id")
                    or raw.get("id")
                    or extract_path_segment(
                        resource_name_from_value(raw, "resource_name"),
                        "triggers",
                    )
                    or "",
                    "service_account": raw.get("service_account") or "",
                },
            )


class CloudBuildBuildsResource(GcpListResource):
    """List/get Cloud Build builds and export their env/step details to loot files.

    Captures each build's runtime service_account and produced images, and can
    dump substitutions/env-vars and per-step commands (download_build_* methods)
    where credentials and sensitive commands commonly surface. get()/save() keep
    build-specific handling (get by build id, not resource name), so they override
    the base bodies.
    """

    SERVICE_LABEL = "Cloud Build"
    TABLE_NAME = "cloudbuild_builds"
    COLUMNS = ["location", "build_id", "status", "service_account", "images"]
    ACTION_RESOURCE_TYPE = "builds"
    LIST_PERMISSION = "cloudbuild.builds.list"
    GET_PERMISSION = "cloudbuild.builds.get"
    _normalize_row = staticmethod(_normalize_build_row)

    def _build_client(self, session):
        self._v1 = _cloudbuild_v1_module()
        return self._v1.CloudBuildClient(credentials=session.credentials)

    def _list_items(self, parent, *, page_size: int = 50, **_):
        project_id = extract_project_id_from_resource(parent, fallback_project=self._fallback_project())
        return self.client.list_builds(
            request=self._v1.ListBuildsRequest(project_id=project_id, parent=parent, page_size=int(page_size or 50))
        )

    def get(self, *, project_id: str | None = None, build_id: str = "", resource_id: str = "", action_dict=None, **_) -> dict[str, Any] | None:
        build_id = build_id or extract_path_segment(resource_id, "builds") or resource_id
        project_id = project_id or extract_project_id_from_resource(resource_id) or getattr(self.session, "project_id", None)
        if not build_id:
            return None
        try:
            row = _normalize_build_row(resource_to_dict(self.client.get_build(project_id=project_id, id=build_id)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(row.get("id") or row.get("name") or build_id).strip(),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=build_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    @staticmethod
    def _resource_id_from_row(row: Any) -> str:
        if isinstance(row, str):
            token = str(row).strip()
            if token.startswith("projects/"):
                return extract_path_segment(token, "builds")
            if "/" in token:
                return extract_path_tail(token, default=token)
            return token
        if isinstance(row, dict):
            return (
                str(row.get("id") or row.get("build_id") or "").strip()
                or extract_path_segment(resource_name_from_value(row, "name"), "builds")
            )
        return str(getattr(row, "id", "") or getattr(row, "build_id", "") or "").strip()

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(resource_name_from_value(row, "name")),
                },
                extra_builder=lambda _obj, raw: {
                    "build_id": raw.get("build_id")
                    or raw.get("id")
                    or extract_path_segment(resource_name_from_value(raw, "name"), "builds")
                    or "",
                    "create_time": raw.get("create_time") or "",
                    "finish_time": raw.get("finish_time") or "",
                    "log_url": raw.get("log_url") or "",
                    "service_account": raw.get("service_account") or "",
                },
            )

    def _logs_download_budget(self) -> DownloadBudget:
        # Lazily created once per resource instance (the caller constructs one
        # CloudBuildBuildsResource per project run and calls the two download_build_*
        # methods per build in a loop), so this caps total wall-clock time across both
        # methods for the "cloud build logs" download type without a caller-threaded budget.
        budget = getattr(self, "_download_budget", None)
        if budget is None:
            budget = DownloadBudget(self.session, label="cloud build logs")
            self._download_budget = budget
        return budget

    def download_build_env_summary(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        if self._logs_download_budget().exceeded():
            return None
        normalized_row = _normalize_build_row(dict(row or {}))
        build_id = self._resource_id_from_row(normalized_row)
        if not build_id:
            return None
        location = str(normalized_row.get("location") or "").strip() or "global"
        destination = resolve_download_path(
            self.session,
            service_name="cloudbuild",
            project_id=project_id,
            filename=f"{location}_{build_id}_env_summary",
            sanitize_fallback=True,
        )
        destination.write_text(_build_env_summary_text(normalized_row), encoding="utf-8")
        return destination

    def download_build_step_arguments(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        if self._logs_download_budget().exceeded():
            return None
        normalized_row = _normalize_build_row(dict(row or {}))
        build_id = self._resource_id_from_row(normalized_row)
        if not build_id:
            return None
        location = str(normalized_row.get("location") or "").strip() or "global"
        destination = resolve_download_path(
            self.session,
            service_name="cloudbuild",
            project_id=project_id,
            filename=f"{location}_{build_id}_step_arguments",
            sanitize_fallback=True,
        )
        destination.write_text(_build_step_arguments_text(normalized_row), encoding="utf-8")
        return destination
