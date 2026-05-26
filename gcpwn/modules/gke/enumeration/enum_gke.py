from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import extract_path_segment, name_from_input
from gcpwn.core.utils.service_runtime import (
    get_cached_rows,
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.gke.utilities.helpers import GkeClustersResource, GkeNodePoolsResource, resolve_regions


COMPONENTS = [
    ("clusters", "Enumerate GKE clusters"),
    ("node_pools", "Enumerate GKE node pools"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try wildcard location (-) when supported")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations, one per line")
        parser.add_argument(
            "--cluster-names",
            required=False,
            help=(
                "Cluster names in comma-separated format. Accepts LOCATION/CLUSTER_ID "
                "pairs or full names like "
                "`projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER_ID`."
            ),
        )
        parser.add_argument(
            "--cluster-names-file",
            required=False,
            help="File containing cluster names, one per line or comma-separated, using the same formats as --cluster-names.",
        )
        parser.add_argument(
            "--node-pool-names",
            required=False,
            help=(
                "Node pool names in comma-separated format. Accepts "
                "LOCATION/CLUSTER_ID/NODE_POOL_ID triples or full names like "
                "`projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER_ID/nodePools/NODE_POOL_ID`."
            ),
        )
        parser.add_argument(
            "--node-pool-names-file",
            required=False,
            help="File containing node pool names, one per line or comma-separated, using the same formats as --node-pool-names.",
        )

    return parse_component_args(
        user_args,
        description="Enumerate GKE (Container API) resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    project_id = session.project_id
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    cluster_name_inputs = parse_csv_file_args(getattr(args, "cluster_names", None), getattr(args, "cluster_names_file", None))
    node_pool_name_inputs = parse_csv_file_args(getattr(args, "node_pool_names", None), getattr(args, "node_pool_names_file", None))
    if cluster_name_inputs:
        args.clusters = True
    if node_pool_name_inputs:
        args.node_pools = True

    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not any(selected.values()):
        return 1

    try:
        cluster_names = [
            name_from_input(
                token,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "clusters", 1),
                error_message=(
                    "Invalid cluster name format. Use LOCATION/CLUSTER_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER_ID."
                ),
            )
            for token in cluster_name_inputs
        ]
        node_pool_names = [
            name_from_input(
                token,
                project_id=project_id,
                template=("projects", "{project_id}", "locations", 0, "clusters", 1, "nodePools", 2),
                error_message=(
                    "Invalid node pool name format. Use LOCATION/CLUSTER_ID/NODE_POOL_ID or "
                    "projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER_ID/nodePools/NODE_POOL_ID."
                ),
            )
            for token in node_pool_name_inputs
        ]
    except ValueError as exc:
        UtilityTools.print_error(str(exc))
        return -1

    clusters_resource = GkeClustersResource(session)
    node_pools_resource = GkeNodePoolsResource(session)
    regions = resolve_regions(session, args)

    all_clusters: list[dict] = []

    if selected.get("clusters", False):
        manual_cluster_names_requested = bool(cluster_names)
        if manual_cluster_names_requested and args.get:
            for name in cluster_names:
                row = clusters_resource.get(resource_id=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    all_clusters.append(row)
        elif not manual_cluster_names_requested:
            listed_by_location = map_regions_with_disabled_short_circuit(
                regions,
                lambda location: clusters_resource.list(
                    project_id=project_id,
                    location=location,
                    action_dict=scope_actions,
                ),
                threads=getattr(args, "threads", 3),
            )
            for location, listed in listed_by_location:
                if listed in ("Not Enabled", None) or not listed:
                    continue
                if args.get:
                    listed = [clusters_resource.get(resource_id=row.get("name", ""), action_dict=api_actions) or row for row in listed]
                clusters_resource.save(listed, project_id=project_id, location=location)
                all_clusters.extend(listed)

        if all_clusters and manual_cluster_names_requested:
            for row in all_clusters:
                clusters_resource.save(
                    [row],
                    project_id=project_id,
                    location=str(row.get("location") or row.get("zone") or "").strip(),
                )

        show_cluster_summary = bool(all_clusters) or not manual_cluster_names_requested
        if show_cluster_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "GKE Clusters",
                all_clusters,
                clusters_resource.COLUMNS,
                primary_resource="Clusters",
                primary_sort_key="location",
            )
        elif args.get:
            print("[*] No GKE clusters found for the supplied --cluster-names.")
        else:
            print("[*] Manual --cluster-names supplied without --get; skipping cluster summary.")

    if selected.get("node_pools", False):
        manual_node_pool_names_requested = bool(node_pool_names)
        manual_cluster_parents_requested = bool(cluster_names)
        node_pool_rows: list[dict] = []

        if manual_node_pool_names_requested and args.get:
            for name in node_pool_names:
                row = node_pools_resource.get(resource_id=name, action_dict=api_actions)
                if isinstance(row, dict) and row:
                    node_pool_rows.append(row)
        elif not manual_node_pool_names_requested:
            cluster_targets = list(cluster_names)
            if not cluster_targets:
                if all_clusters:
                    cluster_targets = [str(row.get("name", "")).strip() for row in all_clusters if isinstance(row, dict) and row.get("name")]
                elif not selected.get("clusters", False):
                    cached_clusters = get_cached_rows(
                        session,
                        clusters_resource.TABLE_NAME,
                        project_id=project_id,
                        columns=["name"],
                    ) or []
                    cluster_targets = [str(row.get("name", "")).strip() for row in cached_clusters if row.get("name")]

            if not cluster_targets:
                print("[*] No cluster parent data available for node pool enumeration. Run this module with --clusters or supply --cluster-names.")
            else:
                for cluster_name in cluster_targets:
                    listed = node_pools_resource.list(cluster_name=cluster_name, action_dict=scope_actions)
                    if listed in ("Not Enabled", None) or not listed:
                        continue
                    if args.get:
                        listed = [node_pools_resource.get(resource_id=row.get("name", ""), action_dict=api_actions) or row for row in listed]
                    node_pools_resource.save(listed, project_id=project_id, cluster_name=cluster_name)
                    node_pool_rows.extend(listed)

        if node_pool_rows and manual_node_pool_names_requested:
            for row in node_pool_rows:
                full_name = str(row.get("name") or "").strip()
                parsed_project = extract_path_segment(full_name, "projects")
                parsed_location = extract_path_segment(full_name, "locations")
                parsed_cluster = extract_path_segment(full_name, "clusters")
                cluster_name = (
                    f"projects/{parsed_project}/locations/{parsed_location}/clusters/{parsed_cluster}"
                    if parsed_project and parsed_location and parsed_cluster
                    else full_name.partition("/nodePools/")[0]
                )
                node_pools_resource.save(
                    [row],
                    project_id=project_id,
                    cluster_name=cluster_name,
                )

        show_node_pool_summary = bool(node_pool_rows) or (
            not manual_node_pool_names_requested and (manual_cluster_parents_requested or bool(node_pool_rows))
        )
        if show_node_pool_summary:
            UtilityTools.summary_wrapup(
                project_id,
                "GKE Node Pools",
                node_pool_rows,
                node_pools_resource.COLUMNS,
                primary_resource="Node Pools",
                primary_sort_key="location",
            )
        elif manual_node_pool_names_requested and args.get:
            print("[*] No GKE node pools found for the supplied --node-pool-names.")
        elif manual_node_pool_names_requested:
            print("[*] Manual --node-pool-names supplied without --get; skipping node pool summary.")
        elif manual_cluster_parents_requested:
            print("[*] No GKE node pools found for the supplied --cluster-names.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="gke_actions_allowed")

    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="gke_actions_allowed")

    return 1
