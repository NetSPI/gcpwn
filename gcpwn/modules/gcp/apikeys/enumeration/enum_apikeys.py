from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.apikeys.utilities.helpers import (
    ApiKeysKeysResource,
    attach_key_strings,
    key_row_names,
)


def _enrich_key_strings(rows, *, resource, args, api_actions):
    # Sensitive: fetch each key's secret string when explicitly requested.
    if not (getattr(args, "include_key_string", False) or getattr(args, "download", False)):
        return rows
    targets = key_row_names(resource, rows)
    return attach_key_strings(resource, targets, rows, api_actions, require_key_string=False)


COMPONENTS = [
    Component("keys", ApiKeysKeysResource, "API Keys", "Keys", help_text="Enumerate API Keys",
              scope=PROJECT, primary_sort_key="display_name", supports_iam=False,
              manual_id_arg="key_ids",
              manual_template=("projects", "{project_id}", "locations", "global", "keys", 0),
              manual_help="Key IDs (short `my-key` or full projects/.../keys/KEY_ID).",
              enrich_fn=_enrich_key_strings),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--include-key-string", action="store_true", required=False,
                            help="Include API key strings (sensitive) when available.")

    return parse_component_args(
        user_args,
        description="Enumerate API Keys surfaces",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "include_key_string", False) or getattr(args, "download", False):
        args.get = True  # key-string/download both need the hydrated key payload

    discovered = run_components(session, args, components=COMPONENTS, column_name="apikeys_actions_allowed",
                                module_name="enum_apikeys")

    if getattr(args, "download", False):
        project_id = session.project_id
        resource = ApiKeysKeysResource(session)
        downloaded_paths = []
        budget = DownloadBudget(session, label="api key content")
        for row in discovered.get("keys", []):
            if budget.exceeded():  # per --download-timeout: stop and move on
                break
            download_path = resource.download_key_string(row=row, project_id=project_id)
            if download_path is not None:
                downloaded_paths.append(str(download_path))
        for download_path in downloaded_paths:
            print(f"[*] Wrote API key content to {download_path}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} API key content file(s) for project {project_id}.")
        elif discovered.get("keys"):
            print(f"[*] No API key content was present on the retrieved keys for project {project_id}.")
    return 1
