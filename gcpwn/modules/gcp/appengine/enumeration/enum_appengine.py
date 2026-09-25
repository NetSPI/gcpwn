from __future__ import annotations

import argparse
import json

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.appengine.utilities.helpers import (
    AppEngineAppsResource,
    AppEngineInstancesResource,
    AppEngineServicesResource,
    AppEngineVersionsResource,
)


COMPONENTS = [
    Component("app", AppEngineAppsResource, "App Engine Application", "App",
              help_text="Enumerate App Engine application", scope=PROJECT, primary_sort_key="location_id",
              supports_iam=False, manual_id_arg="app_name", manual_template=("apps", 0),
              manual_help="Application name as apps/PROJECT_ID or plain PROJECT_ID."),
    Component("services", AppEngineServicesResource, "App Engine Services", "Services",
              help_text="Enumerate App Engine services", scope=PROJECT, primary_sort_key="service_id",
              supports_iam=False, manual_id_arg="service_ids",
              manual_template=("apps", "{project_id}", "services", 0),
              manual_help="Service IDs as SERVICE_ID or apps/PROJECT_ID/services/SERVICE_ID."),
    Component("versions", AppEngineVersionsResource, "App Engine Versions", "Versions",
              help_text="Enumerate App Engine versions (per service)", scope=NESTED, parent_key="services",
              dependency_label="Services", save_parent_kwarg="service_name", primary_sort_key="version_id",
              supports_iam=False, manual_id_arg="version_ids",
              manual_template=("apps", "{project_id}", "services", 0, "versions", 1),
              manual_help="Version IDs as SERVICE_ID/VERSION_ID or full names."),
    Component("instances", AppEngineInstancesResource, "App Engine Instances", "Instances",
              help_text="Enumerate App Engine instances (per version)", scope=NESTED, parent_key="versions",
              dependency_label="Versions", save_parent_kwarg="version_name", primary_sort_key="instance_id",
              supports_iam=False, manual_id_arg="instance_ids",
              manual_template=("apps", "{project_id}", "services", 0, "versions", 1, "instances", 2),
              manual_help="Instance IDs as SERVICE_ID/VERSION_ID/INSTANCE_ID or full names."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--download", action="store_true", default=False,
            help="Download version env_variables, beta_settings, and entrypoint to loot files (implies --get versions).",
        )

    return parse_component_args(
        user_args,
        description="Enumerate App Engine resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.get = True
        args.services = True
        args.versions = True

    discovered = run_components(session, args, components=COMPONENTS, column_name="appengine_actions_allowed",
                                module_name="enum_appengine")

    if getattr(args, "download", False):
        project_id = session.project_id or ""
        budget = DownloadBudget(session, label="appengine version configs")
        downloaded = []
        for version in discovered.get("versions", []):
            if budget.exceeded():
                break
            name = version.get("name", "") if isinstance(version, dict) else getattr(version, "name", "")
            if not name:
                continue
            # Extract path components: apps/{app}/services/{svc}/versions/{ver}
            parts = name.split("/")
            svc_id = parts[3] if len(parts) > 3 else "unknown_service"
            ver_id = parts[5] if len(parts) > 5 else "unknown_version"
            payload = {
                k: (version[k] if isinstance(version, dict) else getattr(version, k, None))
                for k in ("env_variables", "beta_settings", "entrypoint", "env", "runtime", "service_account")
                if (version.get(k) if isinstance(version, dict) else getattr(version, k, None))
            }
            if not payload:
                continue
            dest = resolve_download_path(
                session,
                service_name="appengine",
                project_id=project_id,
                subdirs=["versions", svc_id],
                filename=f"{ver_id}.json",
            )
            dest.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
            downloaded.append(str(dest))
        for path in downloaded:
            print(f"[*] Wrote App Engine version config to {path}")
        if downloaded:
            print(f"[*] Downloaded {len(downloaded)} App Engine version config(s) for project {project_id}.")
    return 1
