from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import name_from_input
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_component_args,
    parse_csv_file_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.apigateway.utilities.helpers import (
    ApiGatewayApisResource,
    ApiGatewayConfigsResource,
    ApiGatewayGatewaysResource,
    resolve_regions,
)


COMPONENTS = [
    ("apis", "Enumerate API Gateway APIs"),
    ("gateways", "Enumerate API Gateway gateways"),
    ("configs", "Enumerate API Gateway API configs (per API)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all known API Gateway regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument(
            "--gateway-ids",
            required=False,
            help=(
                "Gateway IDs in comma-separated format. Accepts LOCATION/GATEWAY_ID "
                "pairs like `us-central1/my-gateway` or full names like "
                "`projects/PROJECT_ID/locations/LOCATION/gateways/GATEWAY_ID`."
            ),
        )
        parser.add_argument(
            "--gateway-ids-file",
            required=False,
            help="File containing gateway IDs, one per line or comma-separated, using the same formats as --gateway-ids.",
        )
        parser.add_argument(
            "--api-ids",
            required=False,
            help=(
                "API IDs in comma-separated format. Accepts short IDs like "
                "`my-api` or full names like "
                "`projects/PROJECT_ID/locations/global/apis/API_ID`."
            ),
        )
        parser.add_argument(
            "--api-ids-file",
            required=False,
            help="File containing API IDs, one per line or comma-separated, using the same formats as --api-ids.",
        )
        parser.add_argument(
            "--config-ids",
            required=False,
            help=(
                "Config IDs in comma-separated format. Accepts `API_ID/CONFIG_ID` "
                "pairs like `my-api/my-config` or full names like "
                "`projects/PROJECT_ID/locations/global/apis/API_ID/configs/CONFIG_ID`."
            ),
        )
        parser.add_argument(
            "--config-ids-file",
            required=False,
            help="File containing config IDs, one per line or comma-separated, using the same formats as --config-ids.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate API Gateway surfaces",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "download", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on gateways, APIs, and configs"},
            "download": {"help": "Download API config OpenAPI documents"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id

    gateway_ids = parse_csv_file_args(getattr(args, "gateway_ids", None), getattr(args, "gateway_ids_file", None))
    api_ids = parse_csv_file_args(getattr(args, "api_ids", None), getattr(args, "api_ids_file", None))
    config_ids = parse_csv_file_args(getattr(args, "config_ids", None), getattr(args, "config_ids_file", None))

    if gateway_ids:
        args.gateways = True
    if api_ids:
        args.apis = True
    if config_ids:
        args.configs = True

    component_keys = [component_key for component_key, _help_text in COMPONENTS]
    selected = resolve_selected_components(args, component_keys)

    try:
        gateway_names = [
            name_from_input(
                gateway_id,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "gateways", 1),
                error_message=(
                    "Invalid gateway ID format. Use LOCATION/GATEWAY_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/gateways/GATEWAY_ID."
                ),
            )
            for gateway_id in gateway_ids
        ]
        api_names = [
            name_from_input(
                api_id,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", "global", "apis", 0),
            )
            for api_id in api_ids
        ]
        config_names = [
            name_from_input(
                config_id,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", "global", "apis", 0, "configs", 1),
                error_message=(
                    "Invalid config ID format. Use API_ID/CONFIG_ID or "
                    "projects/PROJECT_ID/locations/global/apis/API_ID/configs/CONFIG_ID."
                ),
            )
            for config_id in config_ids
        ]
    except ValueError as exc:
        print(f"[X] {exc}")
        return -1

    apis: list[dict] = []

    try:
        gw_resource = ApiGatewayGatewaysResource(session)
        apis_resource = ApiGatewayApisResource(session)
        cfg_resource = ApiGatewayConfigsResource(session)
    except RuntimeError as exc:
        print(f"[X] {exc}")
        return -1

    # Action storage follows the same split used by modules like Compute/Storage:
    # - `scope_actions` stores project/folder/org-wide permissions such as `*.list`.
    #   Those land in the standard scope columns (`project_actions_allowed`, etc.), even when
    #   we pass `column_name="apigateway_actions_allowed"` to `insert_actions(...)`.
    # Each resource helper mutates these accumulators itself after a successful API call.
    # That keeps the recording logic next to the actual list/get/testIamPermissions request
    # instead of re-implementing the same "what counts as success?" rules in the outer enum loop.
    #
    # - `api_actions` stores resource-scoped direct API successes under:
    #   {project_id: {permission_name: {resource_type: {resource_label}}}}
    # - `iam_actions` stores resource-scoped TestIamPermissions results in that same nested shape.
    #
    # Example:
    # scope_actions["project_permissions"]["proj-1"] == {"apigateway.gateways.list"}
    # This means the caller successfully listed gateways for project `proj-1`, so that permission
    # is scoped at the project level rather than any single gateway resource.
    # iam_actions["proj-1"]["apigateway.gateways.update"]["gateways"] ==
    #     {"projects/proj-1/locations/global/gateways/gw-1"}
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    downloaded_config_paths: list[str] = []
    config_download_message = ""

    if selected.get("apis", False):
        manual_apis_requested = bool(api_names)
        apis = []

        if manual_apis_requested and args.get:
            for name in api_names:
                row = apis_resource.get(name=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    apis.append(row)
        elif not manual_apis_requested:
            apis = apis_resource.list(project_id=project_id, action_dict=scope_actions) or []
            if not isinstance(apis, list):
                apis = []
            if args.get:
                apis = hydrate_get_request_rows(
                    apis,
                    lambda _row, payload: apis_resource.get(
                        name=str(payload.get("name") or "").strip(),
                        action_dict=api_actions,
                    ),
                )

        if args.iam:
            api_targets = api_names if manual_apis_requested else [apis_resource.resource_name(row) for row in apis]
            for name in api_targets:
                apis_resource.test_iam_permissions(name=str(name or "").strip(), action_dict=iam_actions)

        if apis:
            apis_resource.save(apis, project_id=project_id)

        show_api_summary = bool(apis) or not manual_apis_requested
        if show_api_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "API Gateway APIs",
                apis,
                apis_resource.COLUMNS,
                primary_resource="APIs",
                primary_sort_key="name",
                )
            if not apis:
                print(f"[*] No API Gateway APIs found in project {project_id}.")
        elif args.get:
            print("[*] No API Gateway APIs found for the supplied --api-ids.")
        else:
            print("[*] Manual --api-ids supplied without --get; skipping API summary.")

    if selected.get("gateways", False):
        manual_gateways_requested = bool(gateway_names)
        rows = []
        regions = resolve_regions(session, args)

        if manual_gateways_requested and args.get:
            for name in gateway_names:
                row = gw_resource.get(name=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    rows.append(row)
        elif not manual_gateways_requested:
            listed_by_region = map_regions_with_disabled_short_circuit(
                regions,
                lambda region: gw_resource.list(
                    project_id=project_id,
                    location=region,
                    action_dict=scope_actions,
                ),
                threads=getattr(args, "threads", 3),
            )
            for _region, listed in listed_by_region:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                if args.get:
                    listed = hydrate_get_request_rows(
                        listed,
                        lambda _row, payload: gw_resource.get(
                            name=str(payload.get("name") or "").strip(),
                            action_dict=api_actions,
                        ),
                    )
                rows.extend(listed)

        if args.iam:
            gateway_targets = gateway_names if manual_gateways_requested else [gw_resource.resource_name(row) for row in rows]
            for name in gateway_targets:
                gw_resource.test_iam_permissions(name=str(name or "").strip(), action_dict=iam_actions)

        if rows:
            gw_resource.save(rows, project_id=project_id)

        show_gateway_summary = bool(rows) or not manual_gateways_requested
        if show_gateway_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "API Gateway Gateways",
                rows,
                gw_resource.COLUMNS,
                primary_resource="Gateways",
                primary_sort_key="name",
                )
            if not rows:
                print(f"[*] No API Gateway gateways found in project {project_id}.")
        elif args.get:
            print("[*] No API Gateway gateways found for the supplied --gateway-ids.")
        else:
            print("[*] Manual --gateway-ids supplied without --get; skipping gateway summary.")

    if selected.get("configs", False):
        manual_config_ids_requested = bool(config_names)
        manual_config_parent_apis_requested = bool(api_names)
        fetch_config_details = bool(args.get or args.download)
        all_cfg = []
        config_parent_data_available = False

        if manual_config_ids_requested:
            if fetch_config_details:
                for name in config_names:
                    row = cfg_resource.get(name=name, action_dict=api_actions)
                    if isinstance(row, dict) and row:
                        all_cfg.append(row)
                if all_cfg:
                    cfg_resource.save(all_cfg, project_id=project_id, api_name="")
            if args.iam:
                for name in config_names:
                    cfg_resource.test_iam_permissions(name=name, action_dict=iam_actions)
        elif manual_config_parent_apis_requested:
            for api_name in api_names:
                rows = cfg_resource.list(api_name=api_name, action_dict=scope_actions) or []
                if not isinstance(rows, list):
                    rows = []
                if fetch_config_details:
                    rows = hydrate_get_request_rows(
                        rows,
                        lambda _row, payload: cfg_resource.get(
                            name=str(payload.get("name") or "").strip(),
                            action_dict=api_actions,
                        ),
                    )
                if args.iam:
                    for row in rows:
                        cfg_resource.test_iam_permissions(
                            name=cfg_resource.resource_name(row),
                            action_dict=iam_actions,
                        )
                if rows:
                    cfg_resource.save(rows, project_id=project_id, api_name=api_name)
                    all_cfg.extend(rows)
        else:
            config_parent_apis = apis or (
                []
                if selected.get("apis", False)
                else session.get_data(
                    apis_resource.TABLE_NAME,
                    columns=apis_resource.COLUMNS,
                    conditions=f'project_id="{project_id}"',
                ) or []
            )

            if not config_parent_apis:
                print_missing_dependency(
                    component_name="API Gateway configs",
                    dependency_name="API parents",
                    module_name="enum_apigateway",
                    manual_flags=["--api-ids", "--api-ids-file"],
                )
            else:
                config_parent_data_available = True
                for api in config_parent_apis:
                    api_name = str((api or {}).get("name") or "").strip() if isinstance(api, dict) else ""
                    if not api_name:
                        continue
                    rows = cfg_resource.list(api_name=api_name, action_dict=scope_actions) or []
                    if not isinstance(rows, list):
                        rows = []
                    if fetch_config_details:
                        rows = hydrate_get_request_rows(
                            rows,
                            lambda _row, payload: cfg_resource.get(
                                name=str(payload.get("name") or "").strip(),
                                action_dict=api_actions,
                            ),
                        )
                    if args.iam:
                        for row in rows:
                            cfg_resource.test_iam_permissions(
                                name=cfg_resource.resource_name(row),
                                action_dict=iam_actions,
                            )
                    if rows:
                        cfg_resource.save(rows, project_id=project_id, api_name=api_name)
                        all_cfg.extend(rows)

        if args.download:
            downloaded_count = 0
            for row in all_cfg:
                download_paths = cfg_resource.download_openapi_documents(row=row, project_id=project_id)
                for download_path in download_paths:
                    downloaded_config_paths.append(str(download_path))
                downloaded_count += len(download_paths)
            if downloaded_count:
                config_download_message = (
                    f"[*] Downloaded {downloaded_count} API Gateway OpenAPI document(s) for project {project_id}."
                )
            elif all_cfg:
                config_download_message = (
                    f"[*] No OpenAPI documents were present on the retrieved API configs for project {project_id}."
                )

        if all_cfg:
            UtilityTools.summary_wrapup(
                project_id,
                "API Gateway API Configs",
                all_cfg,
                cfg_resource.COLUMNS,
                primary_resource="Configs",
                primary_sort_key="api_name",
                )
        elif manual_config_ids_requested and args.get:
            print("[*] No API Gateway configs found for the supplied --config-ids.")
        elif manual_config_ids_requested:
            print("[*] Manual --config-ids supplied without --get; skipping config summary.")
        elif manual_config_parent_apis_requested:
            print("[*] No API Gateway configs found for the supplied --api-ids.")
        elif config_parent_data_available:
            print("[*] No API Gateway configs found for the discovered/cached APIs.")

        if args.download:
            for download_path in downloaded_config_paths:
                print(f"[*] Wrote API Gateway OpenAPI document to {download_path}")
            if config_download_message:
                print(config_download_message)

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="apigateway_actions_allowed")

    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="apigateway_actions_allowed")

    if args.iam and has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="apigateway_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
