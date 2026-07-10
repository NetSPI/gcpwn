from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.apigateway.utilities.helpers import (
    ApiGatewayApisResource,
    ApiGatewayConfigsResource,
    ApiGatewayGatewaysResource,
    resolve_regions,
)


COMPONENTS = [
    Component("apis", ApiGatewayApisResource, "API Gateway APIs", "APIs",
              help_text="Enumerate API Gateway APIs", scope=PROJECT, primary_sort_key="name",
              manual_id_arg="api_ids",
              manual_template=("projects", "{project_id}", "locations", "global", "apis", 0),
              manual_help="API IDs (short `my-api` or full projects/.../apis/API_ID)."),
    Component("gateways", ApiGatewayGatewaysResource, "API Gateway Gateways", "Gateways",
              help_text="Enumerate API Gateway gateways", scope=REGION, primary_sort_key="name",
              manual_id_arg="gateway_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "gateways", 1),
              manual_error="Invalid gateway ID format. Use LOCATION/GATEWAY_ID or projects/PROJECT_ID/locations/LOCATION/gateways/GATEWAY_ID.",
              manual_help="Gateway IDs as LOCATION/GATEWAY_ID or full resource names."),
    Component("configs", ApiGatewayConfigsResource, "API Gateway API Configs", "Configs",
              help_text="Enumerate API Gateway API configs (per API)", scope=NESTED, parent_key="apis",
              dependency_label="API parents", save_parent_kwarg="api_name", primary_sort_key="api_name",
              manual_id_arg="config_ids",
              manual_template=("projects", "{project_id}", "locations", "global", "apis", 0, "configs", 1),
              manual_error="Invalid config ID format. Use API_ID/CONFIG_ID or projects/PROJECT_ID/locations/global/apis/API_ID/configs/CONFIG_ID."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all known API Gateway regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate API Gateway surfaces",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on gateways, APIs, and configs"},
            "download": {"help": "Download API config OpenAPI documents"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.get = True  # OpenAPI documents live on the hydrated config payload

    discovered = run_components(session, args, components=COMPONENTS, column_name="apigateway_actions_allowed",
                                region_resolver=resolve_regions, module_name="enum_apigateway")

    if getattr(args, "download", False):
        project_id = session.project_id
        cfg_resource = ApiGatewayConfigsResource(session)
        downloaded = []
        for row in discovered.get("configs", []):
            for path in cfg_resource.download_openapi_documents(row=row, project_id=project_id):
                downloaded.append(str(path))
        for path in downloaded:
            print(f"[*] Wrote API Gateway OpenAPI document to {path}")
        if downloaded:
            print(f"[*] Downloaded {len(downloaded)} API Gateway OpenAPI document(s) for project {project_id}.")
        elif discovered.get("configs"):
            print(f"[*] No OpenAPI documents were present on the retrieved API configs for project {project_id}.")
    return 1
