from __future__ import annotations

import argparse
import inspect
from collections import defaultdict

from google.cloud import compute_v1

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail
from gcpwn.core.utils.serialization import hydrate_get_request_rows
from gcpwn.core.utils.service_runtime import (
    get_cached_rows,
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_component_args,
    parse_csv_file_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.gcp.cloudcompute.utilities.helpers import (
    CLOUDCOMPUTE_DISCOVERY_RESOURCE_SPECS,
    CloudComputeDisksResource,
    CloudComputeInstancesResource,
    CloudComputeInstanceGroupManagersResource,
    CloudComputeInstanceGroupsResource,
    CloudComputeInstanceTemplatesResource,
    CloudComputeProjectsResource,
    CloudComputeReservationBlocksResource,
    CloudComputeReservationSubBlocksResource,
    HashableComputeProject,
    HashableInstance,
    _list_all_compute_regions,
    cloudcompute_gapic_resource,
)


_DISCOVERY_SPECS_BY_KEY = {spec.component_key: spec for spec in CLOUDCOMPUTE_DISCOVERY_RESOURCE_SPECS}

_TYPED_COMPONENTS = [
    ("projects", "Enumerate Compute project metadata"),
    ("instances", "Enumerate Compute instances"),
    ("instant_snapshots", "Enumerate Compute instant snapshots"),
    ("machine_images", "Enumerate Compute machine images"),
    ("node_groups", "Enumerate Compute node groups"),
    ("node_templates", "Enumerate Compute node templates"),
    ("region_disks", "Enumerate Compute regional disks"),
    ("region_instant_snapshots", "Enumerate Compute regional instant snapshots"),
    ("reservations", "Enumerate Compute reservations"),
    ("reservation_blocks", "Enumerate Compute reservation blocks"),
    ("reservation_sub_blocks", "Enumerate Compute reservation sub-blocks"),
    ("resource_policies", "Enumerate Compute resource policies"),
    ("storage_pools", "Enumerate Compute storage pools"),
    ("disks", "Enumerate Compute disks"),
    ("images", "Enumerate Compute images"),
    ("instance_templates", "Enumerate Compute instance templates"),
    ("snapshots", "Enumerate Compute snapshots"),
    ("instance_groups", "Enumerate Compute instance groups (zonal + regional)"),
    ("instance_group_managers", "Enumerate Compute instance group managers (zonal + regional)"),
]

COMPONENTS = [
    *_TYPED_COMPONENTS,
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        zones_group = parser.add_mutually_exclusive_group()
        zones_group.add_argument("--all-zones", action="store_true", required=False, help="Try every known zone")
        zones_group.add_argument("--zones-list", required=False, help="Zones in comma-separated format")
        zones_group.add_argument("--zones-file", required=False, help="File containing zones, one per line")

        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try every known region")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

        instance_group = parser.add_mutually_exclusive_group(required=False)
        instance_group.add_argument("--instance-names", type=str, help="Instances in format projects/<pid>/zones/<zone>/instances/<name>")
        instance_group.add_argument("--instance-names-file", type=str, help="File with instance resource names")

        parser.add_argument("--take-screenshot", action="store_true", required=False, help="Take screenshot when possible")
        parser.add_argument("--download-serial", action="store_true", required=False, help="Download serial log when possible")
        parser.add_argument("--output", type=str, required=False, help="Output path for screenshot or serial artifacts")

    return parse_component_args(
        user_args,
        description="Enumerate Compute Engine resource-plane objects",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "download", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on supported Compute resources"},
        },
    )


def _only_selected_component(selected: dict[str, bool], key: str) -> bool:
    return bool(selected.get(key, False)) and not any(
        selected.get(component_key, False) for component_key, _help_text in COMPONENTS if component_key != key
    )


def _resolve_zones(args, session, instances_resource: CloudComputeInstancesResource, *, require_all: bool = False) -> list[str]:
    if getattr(args, "all_zones", False):
        return instances_resource.all_zones()
    if getattr(args, "zones_list", None):
        return parse_csv_file_args(args.zones_list, getattr(args, "zones_file", None))
    if getattr(args, "zones_file", None):
        return parse_csv_file_args(None, args.zones_file)
    configured = list(getattr(session, "config_zones_list", None) or [])
    if configured:
        return configured
    return instances_resource.all_zones() if require_all else []


def _resolve_regions(args, session, *, project_id: str, require_all: bool = False) -> list[str]:
    if getattr(args, "regions_list", None):
        return parse_csv_file_args(args.regions_list, getattr(args, "regions_file", None))
    if getattr(args, "regions_file", None):
        return parse_csv_file_args(None, args.regions_file)
    configured = list(getattr(session, "config_regions_list", None) or [])
    if configured:
        return configured
    if getattr(args, "all_regions", False) or require_all:
        return _list_all_compute_regions(session, project_id=project_id)
    return []


def _summary_for_empty(project_id: str, primary_resource: str) -> None:
    print(f"[*] No {primary_resource} found in project {project_id}.")


def _load_dependency_rows(*, spec, discovery_rows_by_key, session, project_id: str):
    parent_key = str(spec.parent_dependency or "").strip()
    if not parent_key:
        return [], True

    rows = discovery_rows_by_key.get(parent_key) or []
    if rows:
        return rows, True

    parent_spec = _DISCOVERY_SPECS_BY_KEY.get(parent_key)
    if parent_spec is None:
        return [], False

    cached = get_cached_rows(
        session,
        parent_spec.table_name,
        project_id=project_id,
        columns=list(parent_spec.summary_columns),
    ) or []
    if cached:
        return cached, True

    print_missing_dependency(
        component_name=spec.summary_title,
        dependency_name=parent_key.replace("_", " "),
        module_name="enum_cloudcompute_resources",
    )
    return [], False


def _method_kwargs(method, kwargs: dict[str, object]) -> dict[str, object]:
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return dict(kwargs)
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
        return dict(kwargs)
    return {key: value for key, value in kwargs.items() if key in signature.parameters}


def _process_nested_existing_resource(
    *,
    selected_key: str,
    title: str,
    primary_resource: str,
    resource,
    parent_component_key: str,
    parent_dependency_name: str,
    args,
    selected,
    session,
    project_id: str,
    scope_actions,
    api_actions,
    iam_actions,
    discovery_rows_by_key,
    sort_key: str = "name",
):
    if not selected.get(selected_key, False):
        return []

    use_cache = not args.get and not args.iam
    rows = (
        get_cached_rows(
            session,
            resource.TABLE_NAME,
            project_id=project_id,
            columns=resource.COLUMNS,
        ) or []
    ) if use_cache else []

    if not rows:
        parent_rows = discovery_rows_by_key.get(parent_component_key) or []
        if not parent_rows:
            print_missing_dependency(
                component_name=title,
                dependency_name=parent_dependency_name,
                module_name="enum_cloudcompute_resources",
            )
            discovery_rows_by_key[selected_key] = []
            return []

        print(f"[*] Enumerating {title}...")
        work_items = []
        for parent_row in parent_rows:
            reference = resource.reference_from_row(parent_row)
            parent_name = str(reference.get("parent_name") or "").strip()
            zone = str(reference.get("zone") or "").strip()
            if not parent_name or not zone:
                continue
            work_items.append((zone, parent_name))

        listed_by_parent = parallel_map(
            work_items,
            lambda item: resource.list(
                project_id=project_id,
                zone=item[0],
                parent_name=item[1],
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
            progress_label=title,
        )
        rows = []
        for batch in listed_by_parent:
            if batch not in ("Not Enabled", None):
                rows.extend(batch or [])

    if rows and args.get and getattr(resource, "SUPPORTS_GET", False):
        rows = hydrate_get_request_rows(
            rows,
            lambda row, _payload: resource.get(
                project_id=project_id,
                action_dict=api_actions,
                **_method_kwargs(resource.get, resource.reference_from_row(row)),
            ),
        )

    if rows and (not use_cache or args.get):
        with resource.session.batched_writes():
            resource.save(rows, project_id=project_id)

    if rows and args.iam and getattr(resource, "SUPPORTS_IAM", False):
        for row in rows:
            reference = resource.reference_from_row(row)
            resource_id = str(reference.get("resource_id") or "").strip()
            if not resource_id:
                continue
            resource.get_iam_permissions(
                project_id=project_id,
                action_dict=iam_actions,
                **_method_kwargs(resource.get_iam_permissions, reference),
            )

    discovery_rows_by_key[selected_key] = rows
    if rows:
        UtilityTools.summary_wrapup(
            project_id,
            title,
            rows,
            resource.COLUMNS,
            primary_resource=primary_resource,
            primary_sort_key=sort_key,
        )
    else:
        _summary_for_empty(project_id, primary_resource)
    return rows


def _process_existing_resource(
    *,
    selected_key: str,
    title: str,
    primary_resource: str,
    enumeration_label: str | None = None,
    resource,
    list_callback,
    args,
    selected,
    session,
    project_id: str,
    scope_actions,
    api_actions,
    iam_actions,
    sort_key: str = "name",
):
    if not selected.get(selected_key, False):
        return []

    use_cache = not args.get and not args.iam and not getattr(args, "download", False)
    rows = (
        get_cached_rows(
            session,
            resource.TABLE_NAME,
            project_id=project_id,
            columns=resource.COLUMNS,
        ) or []
    ) if use_cache else []

    if not rows:
        print(f"[*] Enumerating {enumeration_label or title}...")
        listed = list_callback(scope_actions)
        if listed not in ("Not Enabled", None):
            rows = listed or []

    if rows and args.get and getattr(resource, "SUPPORTS_GET", False):
        rows = hydrate_get_request_rows(
            rows,
            lambda row, _payload: resource.get(
                project_id=project_id,
                action_dict=api_actions,
                **_method_kwargs(resource.get, resource.reference_from_row(row)),
            ),
        )

    if rows and (not use_cache or args.get):
        with resource.session.batched_writes():
            resource.save(rows, project_id=project_id)

    if rows and args.iam and getattr(resource, "SUPPORTS_IAM", False):
        for row in rows:
            reference = resource.reference_from_row(row)
            resource_id = str(reference.get("resource_id") or "").strip()
            if not resource_id:
                continue
            resource.get_iam_permissions(
                project_id=project_id,
                action_dict=iam_actions,
                **_method_kwargs(resource.get_iam_permissions, reference),
            )

    if rows and hasattr(resource, "normalize_summary_rows"):
        rows = resource.normalize_summary_rows(rows)

    if rows:
        UtilityTools.summary_wrapup(
            project_id,
            title,
            rows,
            resource.COLUMNS,
            primary_resource=primary_resource,
            primary_sort_key=sort_key,
        )
    else:
        _summary_for_empty(project_id, primary_resource)
    return rows


def _list_discovery_rows(
    resource,
    spec,
    *,
    project_id: str,
    zones: list[str],
    regions: list[str],
    scope_actions,
    discovery_rows_by_key,
    session,
    threads: int = 3,
):
    parent_rows, dependency_ready = _load_dependency_rows(
        spec=spec,
        discovery_rows_by_key=discovery_rows_by_key,
        session=session,
        project_id=project_id,
    )
    if not dependency_ready:
        return []

    if getattr(spec, "parent_dependency", None):
        work_items: list[dict[str, str]] = []
        for parent_row in parent_rows:
            reference = resource.reference_from_row(parent_row)
            parent_name = str(reference.get("parent_name") or "").strip()
            zone = str(reference.get("zone") or "").strip()
            region = str(reference.get("region") or "").strip()
            if not parent_name:
                continue
            work_items.append(
                {
                    "parent_name": parent_name,
                    "zone": zone,
                    "region": region,
                }
            )

        listed_batches = parallel_map(
            work_items,
            lambda item: resource.list(
                project_id=project_id,
                zone=item.get("zone") or None,
                region=item.get("region") or None,
                parent_name=item.get("parent_name") or None,
                action_dict=scope_actions,
            ),
            threads=threads,
            progress_label=spec.summary_title,
        )
        rows: list[dict] = []
        for batch in listed_batches:
            if batch not in ("Not Enabled", None):
                rows.extend(batch or [])
        return rows

    location_scope = str(getattr(spec, "location_scope", "") or "").strip().lower()
    if location_scope == "zone" and zones:
        listed_batches = map_regions_with_disabled_short_circuit(
            zones,
            lambda zone: resource.list(
                project_id=project_id,
                zone=zone,
                action_dict=scope_actions,
            ),
            threads=threads,
            progress_label=spec.summary_title,
        )
        rows: list[dict] = []
        for _zone, batch in listed_batches:
            if batch not in ("Not Enabled", None):
                rows.extend(batch or [])
        return rows

    if location_scope == "region" and regions:
        listed_batches = map_regions_with_disabled_short_circuit(
            regions,
            lambda region: resource.list(
                project_id=project_id,
                region=region,
                action_dict=scope_actions,
            ),
            threads=threads,
            progress_label=spec.summary_title,
        )
        rows: list[dict] = []
        for _region, batch in listed_batches:
            if batch not in ("Not Enabled", None):
                rows.extend(batch or [])
        return rows

    listed = resource.list(project_id=project_id, action_dict=scope_actions)
    if listed in ("Not Enabled", None):
        return []
    return list(listed or [])


def _process_discovery_resource(
    *,
    resource,
    spec,
    args,
    selected,
    session,
    project_id: str,
    zones: list[str],
    regions: list[str],
    scope_actions,
    api_actions,
    iam_actions,
    discovery_rows_by_key,
):
    if not selected.get(spec.component_key, False):
        return []

    use_cache = not args.get and not args.iam and not getattr(args, "download", False)
    rows = (
        get_cached_rows(
            session,
            spec.table_name,
            project_id=project_id,
            columns=list(spec.summary_columns),
        ) or []
    ) if use_cache else []

    if not rows:
        print(f"[*] Enumerating {spec.summary_title}...")
        rows = _list_discovery_rows(
            resource,
            spec,
            project_id=project_id,
            zones=zones,
            regions=regions,
            scope_actions=scope_actions,
            discovery_rows_by_key=discovery_rows_by_key,
            session=session,
            threads=getattr(args, "threads", 3),
        )

    if rows and args.get and getattr(resource, "SUPPORTS_GET", False):
        rows = hydrate_get_request_rows(
            rows,
            lambda row, _payload: resource.get(
                project_id=project_id,
                action_dict=api_actions,
                **_method_kwargs(resource.get, resource.reference_from_row(row)),
            ),
        )

    if rows and (not use_cache or args.get):
        with resource.session.batched_writes():
            resource.save(rows, project_id=project_id)

    if rows and args.iam and getattr(resource, "SUPPORTS_IAM", False):
        for row in rows:
            reference = resource.reference_from_row(row)
            resource_id = str(reference.get("resource_id") or "").strip()
            if not resource_id:
                continue
            resource.get_iam_permissions(
                project_id=project_id,
                action_dict=iam_actions,
                **_method_kwargs(resource.get_iam_permissions, reference),
            )

    discovery_rows_by_key[spec.component_key] = rows
    if rows:
        UtilityTools.summary_wrapup(
            project_id,
            spec.summary_title,
            rows,
            list(spec.summary_columns),
            primary_resource=spec.primary_resource,
            primary_sort_key=getattr(spec, "primary_sort_key", "name"),
        )
    else:
        _summary_for_empty(project_id, spec.primary_resource)
    return rows


def _collect_scoped_batches(
    scopes: list[str],
    worker,
    *,
    threads: int,
    progress_label: str,
) -> list[dict]:
    listed_batches = map_regions_with_disabled_short_circuit(
        scopes,
        worker,
        threads=threads,
        progress_label=progress_label,
    )
    rows: list[dict] = []
    for _scope, batch in listed_batches:
        if batch in ("Not Enabled", None):
            continue
        rows.extend(batch or [])
    return rows


def run_module(user_args, session):
    args = _parse_args(user_args)
    if args.instance_names or args.instance_names_file:
        args.instances = True

    component_keys = [component_key for component_key, _help_text in COMPONENTS]
    selected = resolve_selected_components(args, component_keys)
    project_id = session.project_id
    explicit_zone_scope = bool(args.all_zones or args.zones_list or args.zones_file)
    explicit_region_scope = bool(args.all_regions or args.regions_list or args.regions_file)

    projects_resource = CloudComputeProjectsResource(session)
    instances_resource = CloudComputeInstancesResource(session)
    disks_resource = CloudComputeDisksResource(session)
    instant_snapshots_resource = (
        cloudcompute_gapic_resource(session, "instant_snapshots") if selected.get("instant_snapshots", False) else None
    )
    machine_images_resource = (
        cloudcompute_gapic_resource(session, "machine_images") if selected.get("machine_images", False) else None
    )
    node_groups_resource = (
        cloudcompute_gapic_resource(session, "node_groups") if selected.get("node_groups", False) else None
    )
    node_templates_resource = (
        cloudcompute_gapic_resource(session, "node_templates") if selected.get("node_templates", False) else None
    )
    region_disks_resource = (
        cloudcompute_gapic_resource(session, "region_disks") if selected.get("region_disks", False) else None
    )
    region_instant_snapshots_resource = (
        cloudcompute_gapic_resource(session, "region_instant_snapshots")
        if selected.get("region_instant_snapshots", False)
        else None
    )
    reservations_resource = (
        cloudcompute_gapic_resource(session, "reservations") if selected.get("reservations", False) else None
    )
    reservation_blocks_resource = (
        CloudComputeReservationBlocksResource(session) if selected.get("reservation_blocks", False) else None
    )
    reservation_sub_blocks_resource = (
        CloudComputeReservationSubBlocksResource(session) if selected.get("reservation_sub_blocks", False) else None
    )
    resource_policies_resource = (
        cloudcompute_gapic_resource(session, "resource_policies") if selected.get("resource_policies", False) else None
    )
    storage_pools_resource = (
        cloudcompute_gapic_resource(session, "storage_pools") if selected.get("storage_pools", False) else None
    )
    snapshots_resource = cloudcompute_gapic_resource(session, "snapshots")
    images_resource = cloudcompute_gapic_resource(session, "images")
    templates_resource = CloudComputeInstanceTemplatesResource(session)
    groups_resource = CloudComputeInstanceGroupsResource(session)
    managers_resource = CloudComputeInstanceGroupManagersResource(session)

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    # Action storage mirrors the newer API Gateway / Cloud Build split:
    # - `scope_actions` captures project-scoped successes such as `*.list`.
    # - `api_actions` captures direct resource-scoped API calls such as `*.get`,
    #   screenshots, serial log pulls, and other non-TestIamPermissions wins.
    # - `iam_actions` captures TestIamPermissions results in the same nested
    #   {project -> permission -> resource_type -> labels} shape.
    #
    # Example:
    # scope_actions["project_permissions"]["proj-1"] == {"compute.backendBuckets.list"}
    # api_actions["proj-1"]["compute.backendBuckets.get"]["backend_buckets"] ==
    #     {"backend-bucket-1"}
    # iam_actions["proj-1"]["compute.backendBuckets.setIamPolicy"]["backend_buckets"] ==
    #     {"backend-bucket-1"}
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    discovery_rows_by_key: dict[str, list[dict]] = {}

    zonal_components = {
        "instances",
        "disks",
        "instant_snapshots",
        "reservations",
        "reservation_blocks",
        "reservation_sub_blocks",
        "instance_groups",
        "instance_group_managers",
    }
    regional_components = {
        "region_disks",
        "region_instant_snapshots",
        "resource_policies",
    }

    zones = _resolve_zones(
        args,
        session,
        instances_resource,
        require_all=any(selected.get(key, False) for key in zonal_components),
    )
    regions = _resolve_regions(
        args,
        session,
        project_id=project_id,
        require_all=any(selected.get(key, False) for key in regional_components),
    )

    if selected.get("projects", False):
        print("[*] Enumerating Compute Projects...")
        compute_projects = projects_resource.list(project_id=project_id, action_dict=scope_actions) or []
        if compute_projects:
            with projects_resource.session.batched_writes():
                projects_resource.save(compute_projects)
        wrapped_projects = [HashableComputeProject(project) for project in compute_projects]
        if wrapped_projects:
            UtilityTools.summary_wrapup(
                project_id,
                "Compute Project",
                {
                    project: [
                        f"KEY: {item.key} - VALUE: {item.value}"
                        for item in project.common_instance_metadata.items
                    ] if getattr(project, "common_instance_metadata", None) and getattr(project.common_instance_metadata, "items", None) else []
                    for project in wrapped_projects
                },
                ["id", "name", "description"],
                primary_resource="Compute Projects",
                secondary_title_name="metadata",
            )
        else:
            _summary_for_empty(project_id, "Compute Projects")
        if args.download:
            downloaded_paths = []
            for project in compute_projects:
                download_path = projects_resource.download_metadata(row=project, project_id=project_id)
                if download_path is None:
                    continue
                downloaded_paths.append(str(download_path))
            for download_path in downloaded_paths:
                print(f"[*] Wrote Compute project metadata to {download_path}")
            if downloaded_paths:
                print(f"[*] Downloaded {len(downloaded_paths)} Compute project metadata file(s) for project {project_id}.")
            elif compute_projects:
                print(f"[*] No Compute project metadata files were downloaded for project {project_id}.")
            else:
                print(f"[*] No Compute projects were available to download metadata from in project {project_id}.")

    if selected.get("instances", False):
        print("[*] Enumerating Compute Instances...")
        all_instances = defaultdict(set)
        downloaded_metadata_paths: list[str] = []
        downloaded_screenshot_paths: list[str] = []
        downloaded_serial_paths: list[str] = []
        if (
            not (args.instance_names or args.instance_names_file)
            and not explicit_zone_scope
            and not args.get
            and not args.download
            and not args.iam
            and not args.take_screenshot
            and not args.download_serial
            and _only_selected_component(selected, "instances")
        ):
            cached = get_cached_rows(
                session,
                instances_resource.TABLE_NAME,
                project_id=project_id,
                columns=instances_resource.COLUMNS,
            ) or []
            if cached:
                UtilityTools.summary_wrapup(
                    project_id,
                    "Compute Instances",
                    cached,
                    instances_resource.COLUMNS,
                    primary_resource="Instances",
                    primary_sort_key="zone",
                )
                return 1

        if args.instance_names or args.instance_names_file:
            instance_names = parse_csv_file_args(
                getattr(args, "instance_names", None),
                getattr(args, "instance_names_file", None),
            )
            for line in instance_names:
                pid = extract_path_segment(line, "projects")
                zone = extract_path_segment(line, "zones")
                name = extract_path_segment(line, "instances")
                all_instances[pid].add(HashableInstance(compute_v1.Instance(name=name, zone=f"zones/{zone}"), validated=False))
        else:
            if explicit_zone_scope and zones:
                listed_by_zone = map_regions_with_disabled_short_circuit(
                    zones,
                    lambda zone: instances_resource.list(
                        project_id=project_id,
                        zone=zone,
                        action_dict=scope_actions,
                    ),
                    threads=getattr(args, "threads", 3),
                    progress_label="Compute Instances",
                )
                for _zone, listed in listed_by_zone:
                    if listed == "Not Enabled":
                        break
                    if listed:
                        with instances_resource.session.batched_writes():
                            instances_resource.save(listed, project_id=project_id)
                        for instance in listed:
                            all_instances[project_id].add(HashableInstance(instance))
            else:
                listed = instances_resource.list(project_id=project_id, action_dict=scope_actions)
                if listed and listed != "Not Enabled":
                    with instances_resource.session.batched_writes():
                        instances_resource.save(listed, project_id=project_id)
                    for instance in listed:
                        all_instances[project_id].add(HashableInstance(instance))

        for target_project_id, wrapped_instances in all_instances.items():
            for wrapped_instance in list(wrapped_instances):
                validated = wrapped_instance.validated
                zone = extract_path_tail(wrapped_instance.zone, default=str(wrapped_instance.zone or ""))
                name = wrapped_instance.name
                hydrated_instance = getattr(wrapped_instance, "_instance", wrapped_instance)

                if args.get or args.download:
                    result = instances_resource.get(
                        project_id=target_project_id,
                        zone=zone,
                        resource_id=name,
                        action_dict=api_actions,
                    )
                    if result:
                        hydrated_instance = result
                        if (args.instance_names or args.instance_names_file) and not validated:
                            wrapped_instances.discard(wrapped_instance)
                            wrapped_instances.add(HashableInstance(result))
                        instances_resource.save([result], project_id=target_project_id)

                if args.download:
                    download_path = instances_resource.download_metadata(
                        row=hydrated_instance,
                        project_id=target_project_id,
                        zone=zone,
                    )
                    if download_path is not None:
                        downloaded_metadata_paths.append(str(download_path))

                if args.iam:
                    permissions = instances_resource.get_iam_permissions(
                        project_id=target_project_id,
                        zone=zone,
                        resource_id=name,
                        action_dict=iam_actions,
                    )
                    if permissions and (args.instance_names or args.instance_names_file) and not validated:
                        wrapped_instance.validated = True

                if args.take_screenshot or args.download:
                    screenshot_path = instances_resource.download_screenshot(
                        project_id=target_project_id,
                        zone=zone,
                        resource_id=name,
                        output=args.output,
                        action_dict=api_actions,
                    )
                    if screenshot_path:
                        downloaded_screenshot_paths.append(str(screenshot_path))
                        if (args.instance_names or args.instance_names_file) and not validated:
                            wrapped_instance.validated = True

                if args.download_serial or args.download:
                    serial_path = instances_resource.download_serial(
                        project_id=target_project_id,
                        zone=zone,
                        resource_id=name,
                        output=args.output,
                        action_dict=api_actions,
                    )
                    if serial_path:
                        downloaded_serial_paths.append(str(serial_path))
                        if (args.instance_names or args.instance_names_file) and not validated:
                            wrapped_instance.validated = True

        for target_project_id, wrapped_instances in all_instances.items():
            final_instances = list(wrapped_instances)
            if args.instance_names or args.instance_names_file:
                final_instances = [instance for instance in final_instances if instance.validated]
            instances_resource.normalize_summary_rows(final_instances)
            if final_instances:
                UtilityTools.summary_wrapup(
                    target_project_id,
                    "Compute Instances",
                    final_instances,
                    instances_resource.COLUMNS,
                    primary_resource="Instances",
                    primary_sort_key="zone",
                )
            else:
                _summary_for_empty(target_project_id, "Instances")
        if args.download:
            for download_path in downloaded_metadata_paths:
                print(f"[*] Wrote Compute instance metadata to {download_path}")
            for download_path in downloaded_screenshot_paths:
                print(f"[*] Wrote Compute instance screenshot to {download_path}")
            for download_path in downloaded_serial_paths:
                print(f"[*] Wrote Compute instance serial output to {download_path}")
            if downloaded_metadata_paths or downloaded_screenshot_paths or downloaded_serial_paths:
                print(
                    "[*] Downloaded "
                    f"{len(downloaded_metadata_paths)} Compute instance metadata file(s), "
                    f"{len(downloaded_screenshot_paths)} screenshot(s), and "
                    f"{len(downloaded_serial_paths)} serial log(s) for project {project_id}."
                )
            elif any(all_instances.values()):
                print(f"[*] No Compute instance artifacts were downloaded for project {project_id}.")
            else:
                print(f"[*] No Compute instances were available to download artifacts from in project {project_id}.")

    _process_existing_resource(
        selected_key="machine_images",
        title="Compute Machine Images",
        primary_resource="Machine Images",
        resource=machine_images_resource,
        list_callback=lambda action_dict: machine_images_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )

    _process_existing_resource(
        selected_key="node_groups",
        title="Compute Node Groups",
        primary_resource="Node Groups",
        resource=node_groups_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                zones,
                lambda zone: node_groups_resource.list(
                    project_id=project_id,
                    zone=zone,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Node Groups",
            ) if explicit_zone_scope and zones else node_groups_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )

    _process_existing_resource(
        selected_key="node_templates",
        title="Compute Node Templates",
        primary_resource="Node Templates",
        resource=node_templates_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                regions,
                lambda region: node_templates_resource.list(
                    project_id=project_id,
                    region=region,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Node Templates",
            ) if explicit_region_scope and regions else node_templates_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )

    _process_existing_resource(
        selected_key="region_disks",
        title="Compute Region Disks",
        primary_resource="Region Disks",
        resource=region_disks_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                regions,
                lambda region: region_disks_resource.list(
                    project_id=project_id,
                    region=region,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Region Disks",
            ) if explicit_region_scope and regions else region_disks_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )

    _process_existing_resource(
        selected_key="instant_snapshots",
        title="Compute Instant Snapshots",
        primary_resource="Instant Snapshots",
        resource=instant_snapshots_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                zones,
                lambda zone: instant_snapshots_resource.list(
                    project_id=project_id,
                    zone=zone,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Instant Snapshots",
            ) if explicit_zone_scope and zones else instant_snapshots_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )

    _process_existing_resource(
        selected_key="region_instant_snapshots",
        title="Compute Region Instant Snapshots",
        primary_resource="Region Instant Snapshots",
        resource=region_instant_snapshots_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                regions,
                lambda region: region_instant_snapshots_resource.list(
                    project_id=project_id,
                    region=region,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Region Instant Snapshots",
            ) if explicit_region_scope and regions else region_instant_snapshots_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )

    reservations = _process_existing_resource(
        selected_key="reservations",
        title="Compute Reservations",
        primary_resource="Reservations",
        resource=reservations_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                zones,
                lambda zone: reservations_resource.list(
                    project_id=project_id,
                    zone=zone,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Reservations",
            ) if explicit_zone_scope and zones else reservations_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )
    discovery_rows_by_key["reservations"] = reservations or []

    reservation_blocks = _process_nested_existing_resource(
        selected_key="reservation_blocks",
        title="Compute Reservation Blocks",
        primary_resource="Reservation Blocks",
        resource=reservation_blocks_resource,
        parent_component_key="reservations",
        parent_dependency_name="reservations",
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        discovery_rows_by_key=discovery_rows_by_key,
        sort_key="zone",
    )
    discovery_rows_by_key["reservation_blocks"] = reservation_blocks or []

    _process_nested_existing_resource(
        selected_key="reservation_sub_blocks",
        title="Compute Reservation Sub-Blocks",
        primary_resource="Reservation Sub-Blocks",
        resource=reservation_sub_blocks_resource,
        parent_component_key="reservation_blocks",
        parent_dependency_name="reservation blocks",
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        discovery_rows_by_key=discovery_rows_by_key,
        sort_key="zone",
    )

    _process_existing_resource(
        selected_key="resource_policies",
        title="Compute Resource Policies",
        primary_resource="Resource Policies",
        resource=resource_policies_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                regions,
                lambda region: resource_policies_resource.list(
                    project_id=project_id,
                    region=region,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Resource Policies",
            ) if explicit_region_scope and regions else resource_policies_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )

    _process_existing_resource(
        selected_key="storage_pools",
        title="Compute Storage Pools",
        primary_resource="Storage Pools",
        resource=storage_pools_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                zones,
                lambda zone: storage_pools_resource.list(
                    project_id=project_id,
                    zone=zone,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Storage Pools",
            ) if explicit_zone_scope and zones else storage_pools_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )

    _process_existing_resource(
        selected_key="disks",
        title="Compute Disks",
        primary_resource="Disks",
        resource=disks_resource,
        list_callback=lambda action_dict: (
            _collect_scoped_batches(
                zones,
                lambda zone: disks_resource.list(
                    project_id=project_id,
                    zone=zone,
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
                progress_label="Compute Disks",
            ) if explicit_zone_scope and zones else disks_resource.list(project_id=project_id, action_dict=action_dict)
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )

    _process_existing_resource(
        selected_key="images",
        title="Compute Images",
        primary_resource="Images",
        resource=images_resource,
        list_callback=lambda action_dict: images_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )

    template_rows = _process_existing_resource(
        selected_key="instance_templates",
        title="Compute Instance Templates",
        primary_resource="Templates",
        resource=templates_resource,
        list_callback=lambda action_dict: templates_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    if args.download:
        downloaded_paths = []
        for row in template_rows:
            download_path = templates_resource.download_metadata(row=row, project_id=project_id)
            if download_path is None:
                continue
            downloaded_paths.append(str(download_path))
        for download_path in downloaded_paths:
            print(f"[*] Wrote Compute instance template metadata to {download_path}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} Compute instance template file(s) for project {project_id}.")
        elif template_rows:
            print(f"[*] No Compute instance template files were downloaded for project {project_id}.")
        elif selected.get("instance_templates", False):
            print(f"[*] No Compute instance templates were available to download in project {project_id}.")

    _process_existing_resource(
        selected_key="snapshots",
        title="Compute Snapshots",
        primary_resource="Snapshots",
        resource=snapshots_resource,
        list_callback=lambda action_dict: snapshots_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )

    _process_existing_resource(
        selected_key="instance_groups",
        title="Compute Instance Groups",
        primary_resource="Groups",
        resource=groups_resource,
        list_callback=lambda action_dict: groups_resource.list(
            project_id=project_id,
            zones=zones if explicit_zone_scope else [],
            regions=regions if explicit_region_scope else [],
            threads=getattr(args, "threads", 3),
            action_dict=action_dict,
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )

    _process_existing_resource(
        selected_key="instance_group_managers",
        title="Compute Instance Group Managers",
        primary_resource="Managers",
        resource=managers_resource,
        list_callback=lambda action_dict: managers_resource.list(
            project_id=project_id,
            zones=zones if explicit_zone_scope else [],
            regions=regions if explicit_region_scope else [],
            threads=getattr(args, "threads", 3),
            action_dict=action_dict,
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="zone",
    )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="compute_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="compute_actions_allowed")
    if args.iam and has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="compute_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
