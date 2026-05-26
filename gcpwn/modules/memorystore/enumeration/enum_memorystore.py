from __future__ import annotations

import argparse
from collections import defaultdict

from google.cloud.redis_v1.types import Instance

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_tail, extract_project_id_from_resource
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.memorystore.utilities.helpers import HashableRedisInstance, MemorystoreRedisResource


COMPONENTS = [
    ("instances", "Enumerate Memorystore Redis instances"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all regions")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

        instance_group = parser.add_mutually_exclusive_group(required=False)
        instance_group.add_argument("--redis-instance-names", type=str, help="Instances in format projects/<pid>/locations/<location>/instances/<name>")
        instance_group.add_argument("--redis-instance-names-file", type=str, help="File containing redis instance resource names")

    return parse_component_args(
        user_args,
        description="Enumerate Memorystore resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    if not selected.get("instances", False):
        return 1

    project_id = session.project_id
    redis_resource = MemorystoreRedisResource(session)
    action_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    all_redis_instances = {}

    redis_inputs = parse_csv_file_args(
        getattr(args, "redis_instance_names", None),
        getattr(args, "redis_instance_names_file", None),
    )
    if redis_inputs:
        for redis_name in redis_inputs:
            redis_project_id = extract_project_id_from_resource(redis_name, fallback_project=project_id)
            redis_hash = HashableRedisInstance(Instance(name=redis_name), validated=False)
            all_redis_instances.setdefault(redis_project_id, set()).add(redis_hash)
    else:
        regions = None
        if args.all_regions:
            regions = ["-"]
        elif args.regions_list:
            regions = parse_csv_file_args(args.regions_list, getattr(args, "regions_file", None))
        elif args.regions_file:
            regions = parse_csv_file_args(None, args.regions_file)
        elif session.workspace_config.preferred_regions:
            regions = session.workspace_config.preferred_regions

        if regions:
            listed_by_region = map_regions_with_disabled_short_circuit(
                regions,
                lambda region: redis_resource.list(
                    parent=f"projects/{project_id}/locations/{region}",
                    action_dict=action_dict,
                ),
                threads=getattr(args, "threads", 3),
            )
            for _region, listed in listed_by_region:
                if listed in ("Not Enabled", None):
                    all_redis_instances.setdefault(project_id, set())
                    continue
                redis_resource.save(listed)
                all_redis_instances.setdefault(project_id, set()).update(HashableRedisInstance(redis) for redis in listed)
        else:
            parent = f"projects/{project_id}/locations/-"
            listed = redis_resource.list(parent=parent, action_dict=action_dict)
            if listed not in ("Not Enabled", None):
                redis_resource.save(listed)
                all_redis_instances.setdefault(project_id, set()).update(HashableRedisInstance(redis) for redis in listed)
            else:
                all_redis_instances.setdefault(project_id, set())

    for target_project_id, redis_instances in all_redis_instances.items():
        for redis_instance in list(redis_instances):
            full_name = redis_instance.name
            if args.get:
                redis_get = redis_resource.get(resource_id=full_name, action_dict=action_dict)
                if redis_get:
                    redis_resource.save([redis_get])
                    if (args.redis_instance_names or args.redis_instance_names_file) and not redis_instance.validated:
                        redis_instances.discard(redis_instance)
                        redis_instances.add(HashableRedisInstance(redis_get, validated=True))

            if args.get:
                auth_string = redis_resource.get_auth_string(resource_id=full_name, action_dict=action_dict)
                if auth_string:
                    for current_instance in redis_instances:
                        if current_instance.name == full_name:
                            current_instance.auth_string = auth_string
                            break

        session.insert_actions(action_dict, target_project_id)

    for target_project_id, redis_instances in all_redis_instances.items():
        final_instances = list(redis_instances)
        if args.redis_instance_names or args.redis_instance_names_file:
            final_instances = [instance for instance in final_instances if instance.validated]
        for redis_instance in final_instances:
            redis_instance._redis_instance.name = extract_path_tail(redis_instance._redis_instance.name)
        UtilityTools.summary_wrapup(
            target_project_id,
            "Cloud Redis Instances",
            final_instances,
            ["name", "display_name", "state_output", "location_id", "host", "port", "auth_enabled", "auth_string"],
            primary_resource="instances",
            primary_sort_key="location_id",
            )

    return 1
