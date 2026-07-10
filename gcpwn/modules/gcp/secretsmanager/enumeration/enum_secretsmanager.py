from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args, resolve_selected_components
from gcpwn.modules.gcp.secretsmanager.utilities.helpers import SecretsResource, SecretVersionsResource


def _access_values(rows, *, resource, args, api_actions):
    # Sensitive: read secret payloads when --values or --download requested.
    if not (getattr(args, "values", False) or getattr(args, "download", False)):
        return rows
    session = resource.session
    budget = DownloadBudget(session, label="secret values")
    for version in rows:
        if budget.exceeded():
            break
        name = str(version.get("name") or "").strip()
        if not name:
            continue
        value = resource.access_value(resource_id=name, action_dict=api_actions)
        if not value:
            continue
        payload = value.payload.data
        if getattr(args, "values", False):
            version["secret_value"] = payload.decode("utf-8", errors="replace")
        session.insert_data(
            "secretsmanager_secretversions",
            {"primary_keys_to_match": {"name": name}, "data_to_insert": {"secret_value": payload}},
            update_only=True,
        )
        if getattr(args, "download", False):
            secret_name = name.split("/secrets/", 1)[1].split("/", 1)[0] if "/secrets/" in name else ""
            resource.download(project_id=session.project_id, secret_name=secret_name,
                              version=extract_path_tail(name, default=name), payload=payload)
    return rows


COMPONENTS = [
    Component("secrets", SecretsResource, "Secret Manager Secrets", "Secrets",
              help_text="Enumerate secret metadata", scope=PROJECT, primary_sort_key="name",
              manual_id_arg="secret_names",
              manual_help="Secrets as projects/<project_number>/secrets/<secret_name>."),
    Component("versions", SecretVersionsResource, "Secret Manager Versions", "Versions",
              help_text="Enumerate secret versions (per secret)", scope=NESTED, parent_key="secrets",
              dependency_label="Secrets", save_parent_kwarg="parent", primary_sort_key="name",
              enrich_fn=_access_values),
]

ALL_KEYS = ["secrets", "versions", "values"]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--values", action="store_true", help="Attempt to access secret values (sensitive)")
        parser.add_argument("--version-range", type=str, required=False, help="(reserved) Version range like 1-5,7,latest")

    return parse_component_args(
        user_args,
        description="Enumerate Secret Manager resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on secrets and versions"},
            "download": {"help": "Download secret values to local files"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    sel = resolve_selected_components(args, ALL_KEYS)
    if sel["values"] or getattr(args, "download", False):
        sel["versions"] = True
    for key in ALL_KEYS:
        setattr(args, key, sel[key])

    if sel["secrets"] or sel["versions"]:
        run_components(session, args, components=COMPONENTS, column_name="secret_actions_allowed",
                       module_name="enum_secretsmanager")
    return 1
