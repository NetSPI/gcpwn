from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import extract_path_segment
from gcpwn.core.utils.service_runtime import (
    get_cached_rows,
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_component_args,
    resolve_selected_components,
)
from gcpwn.modules.servicedirectory.utilities.helpers import (
    ServiceDirectoryEndpointsResource,
    ServiceDirectoryNamespacesResource,
    ServiceDirectoryServicesResource,
    resolve_regions,
)


COMPONENTS = [
    ("namespaces", "Enumerate Service Directory namespaces"),
    ("services", "Enumerate Service Directory services (per namespace)"),
    ("endpoints", "Enumerate Service Directory endpoints (per service)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Service Directory resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on namespaces and services"},
        },
    )


def _resource_name(row) -> str:
    if isinstance(row, dict):
        return str(row.get("name", "") or "").strip()
    return str(getattr(row, "name", "") or "").strip()


def _location_id(row) -> str:
    if isinstance(row, dict):
        location_id = str(row.get("location_id", "") or "").strip()
        if location_id:
            return location_id
    name = _resource_name(row)
    if "/locations/" in name:
        return extract_path_segment(name, "locations")
    return ""


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])

    project_id = session.project_id
    regions = resolve_regions(session, args)

    namespaces_resource = ServiceDirectoryNamespacesResource(session)
    services_resource = ServiceDirectoryServicesResource(session)
    endpoints_resource = ServiceDirectoryEndpointsResource(session)
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    namespaces_by_region = defaultdict(list)
    services_by_region = defaultdict(list)
    endpoints_by_region = defaultdict(list)

    if selected.get("namespaces", False):
        region_batches = map_regions_with_disabled_short_circuit(
            regions,
            lambda region: namespaces_resource.list(
                parent=f"projects/{project_id}/locations/{region}",
                project_id=project_id,
                location_id=region,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        namespaces_by_region = defaultdict(list)
        for region, region_namespaces in region_batches:
            if region_namespaces in ("Not Enabled", None) or not region_namespaces:
                continue
            namespaces_resource.save(region_namespaces, project_id=project_id, location_id=region)
            namespaces_by_region[region].extend(list(region_namespaces))
    elif selected.get("services", False) or selected.get("endpoints", False):
        cached_namespaces = get_cached_rows(
            session,
            namespaces_resource.TABLE_NAME,
            project_id=project_id,
            columns=namespaces_resource.COLUMNS,
        ) or []
        for row in cached_namespaces:
            namespaces_by_region[str(row.get("location_id", ""))].append(row)

    if selected.get("services", False):
        namespace_targets = [ns for region_rows in namespaces_by_region.values() for ns in region_rows]
        if not namespace_targets:
            print("[*] No cached namespace parent data available for service enumeration. Run this module with --namespaces.")
        else:
            service_batches = parallel_map(
                namespace_targets,
                lambda namespace: (
                    namespace,
                    services_resource.list(
                        parent=_resource_name(namespace),
                        project_id=project_id,
                        location_id=_location_id(namespace),
                        action_dict=scope_actions,
                    ),
                ),
                threads=getattr(args, "threads", 3),
            )
            for namespace, region_services in service_batches:
                if region_services in ("Not Enabled", None) or not region_services:
                    continue
                location_id = _location_id(namespace)
                namespace_name = _resource_name(namespace)
                for service in region_services:
                    services_resource.save([service], project_id=project_id, location_id=location_id, namespace_name=namespace_name)
                services_by_region[location_id].extend(list(region_services))

    if selected.get("endpoints", False):
        service_targets = [svc for region_rows in services_by_region.values() for svc in region_rows]
        if not service_targets and not selected.get("services", False):
            cached_services = get_cached_rows(
                session,
                services_resource.TABLE_NAME,
                project_id=project_id,
                columns=services_resource.COLUMNS,
            ) or []
            for row in cached_services:
                services_by_region[str(row.get("location_id", ""))].append(row)
            service_targets = [svc for region_rows in services_by_region.values() for svc in region_rows]

        if not service_targets:
            print("[*] No cached service parent data available for endpoint enumeration. Run this module with --services.")
        else:
            endpoint_batches = parallel_map(
                service_targets,
                lambda service: (
                    service,
                    endpoints_resource.list(
                        parent=_resource_name(service),
                        project_id=project_id,
                        location_id=_location_id(service),
                    ),
                ),
                threads=getattr(args, "threads", 3),
            )
            for service, region_endpoints in endpoint_batches:
                if region_endpoints in ("Not Enabled", None) or not region_endpoints:
                    continue
                location_id = _location_id(service)
                service_name = _resource_name(service)
                for endpoint in region_endpoints:
                    endpoints_resource.save([endpoint], project_id=project_id, location_id=location_id, service_name=service_name)
                endpoints_by_region[location_id].extend(list(region_endpoints))

    if args.iam and selected.get("namespaces", False):
        for namespace in [ns for namespace_rows in namespaces_by_region.values() for ns in namespace_rows]:
            namespaces_resource.test_iam_permissions(
                resource_id=_resource_name(namespace),
                action_dict=iam_actions,
            )

    if args.iam and (selected.get("services", False) or selected.get("endpoints", False)):
        for service in [svc for service_rows in services_by_region.values() for svc in service_rows]:
            services_resource.test_iam_permissions(
                resource_id=_resource_name(service),
                action_dict=iam_actions,
            )

    if selected.get("namespaces", False):
        all_namespaces = [ns for region in namespaces_by_region for ns in namespaces_by_region[region]]
        UtilityTools.summary_wrapup(
            project_id,
            "Service Directory Namespaces",
            all_namespaces,
            ["location_id", "namespace_id", "name", "labels"],
            primary_resource="Namespaces",
            primary_sort_key="location_id",
            )

    if selected.get("services", False):
        all_services = [svc for region in services_by_region for svc in services_by_region[region]]
        UtilityTools.summary_wrapup(
            project_id,
            "Service Directory Services",
            all_services,
            ["location_id", "service_id", "name", "namespace_name", "labels"],
            primary_resource="Services",
            primary_sort_key="location_id",
            )

    if selected.get("endpoints", False):
        all_endpoints = [ep for region in endpoints_by_region for ep in endpoints_by_region[region]]
        UtilityTools.summary_wrapup(
            project_id,
            "Service Directory Endpoints",
            all_endpoints,
            ["location_id", "endpoint_id", "name", "service_name", "address", "port", "network"],
            primary_resource="Endpoints",
            primary_sort_key="location_id",
            )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="servicedirectory_actions_allowed")
    if args.iam and has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="servicedirectory_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
