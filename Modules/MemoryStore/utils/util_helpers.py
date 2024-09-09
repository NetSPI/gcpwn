from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import textwrap
import argparse
import requests
import importlib

from google.cloud import redis_v1


from collections import defaultdict
from typing import List, Union, Dict, Optional, Tuple

from google.api_core.exceptions import (
    PermissionDenied,
    BadRequest,
    NotFound,
    Forbidden
)
from google.api_core.extended_operation import ExtendedOperation
from google.cloud import compute_v1
from google.cloud.compute_v1.types import Instance
from google.iam.v1 import iam_policy_pb2

from session import SessionUtility
from Modules.IAM.utils.util_helpers import instance_get_iam_policy, instance_set_iam_policy
from UtilityController import *

########### SAVE OPERATIONS FOR COMPUTE INSTANCES
def save_redis_instance(redis_instance, session):
    table_name = 'memorystore-redis'
    save_data = {}
    
    if redis_instance.name: 
        redis_project_id = redis_instance.name.split("/")[-1]
        save_data["project_id"] = redis_project_id
        
    if redis_instance.name: save_data["name"] = redis_instance.name
    if redis_instance.display_name: save_data["display_name"] = redis_instance.display_name
    if redis_instance.labels: save_data["labels"] = str(dict(redis_instance.labels))
    if redis_instance.location_id: save_data["location_id"] = redis_instance.location_id
    if redis_instance.alternative_location_id: save_data["alternative_location_id"] = redis_instance.alternative_location_id
    if redis_instance.redis_version: save_data["redis_version"] = redis_instance.redis_version
    if redis_instance.reserved_ip_range: save_data["reserved_ip_range"] = redis_instance.reserved_ip_range
    if redis_instance.secondary_ip_range: save_data["secondary_ip_range"] = redis_instance.secondary_ip_range
    if redis_instance.host: save_data["host"] = redis_instance.host
    if redis_instance.port: save_data["port"] = redis_instance.port
    if redis_instance.current_location_id: save_data["current_location_id"] = redis_instance.current_location_id
    if redis_instance.create_time: save_data["create_time"] = str(redis_instance.create_time)
    if redis_instance.state: save_data["state"] = str(redis_instance.state)
    if redis_instance.status_message: save_data["status_message"] = redis_instance.status_message
    if redis_instance.redis_configs: save_data["redis_configs"] = str(dict(redis_instance.redis_configs))
    if redis_instance.tier: save_data["tier"] = str(redis_instance.tier)
    if redis_instance.memory_size_gb: save_data["memory_size_gb"] = str(redis_instance.memory_size_gb)
    if redis_instance.authorized_network: save_data["authorized_network"] = str(redis_instance.authorized_network)
    if redis_instance.persistence_iam_identity: save_data["persistence_iam_identity"] = str(redis_instance.persistence_iam_identity)
    if redis_instance.connect_mode: save_data["connect_mode"] = str(redis_instance.connect_mode)
    if redis_instance.auth_enabled: save_data["auth_enabled"] = str(redis_instance.auth_enabled)
    if redis_instance.server_ca_certs: save_data["server_ca_certs"] = str(redis_instance.server_ca_certs)
    if redis_instance.transit_encryption_mode: save_data["transit_encryption_mode"] = str(redis_instance.transit_encryption_mode)

    maintenance_policy = {}
    if redis_instance.maintenance_policy:
        if redis_instance.maintenance_policy.create_time: maintenance_policy["create_time"] = str(redis_instance.maintenance_policy.create_time)
        if redis_instance.maintenance_policy.update_time: maintenance_policy["update_time"] = str(redis_instance.maintenance_policy.update_time)
        if redis_instance.maintenance_policy.description: maintenance_policy["description"] = str(redis_instance.maintenance_policy.description)
        if redis_instance.maintenance_policy.weekly_maintenance_window: maintenance_policy["weekly_maintenance_window"] = str(dict(redis_instance.maintenance_policy.weekly_maintenance_window))
    save_data["maintenance_policy"] = maintenance_policy

    maintenance_schedule = {}
    if redis_instance.maintenance_schedule:
        if redis_instance.maintenance_schedule.start_time: maintenance_schedule["start_time"] = str(redis_instance.maintenance_schedule.start_time)
        if redis_instance.maintenance_schedule.end_time: maintenance_schedule["end_time"] = str(redis_instance.maintenance_schedule.end_time)
        if redis_instance.maintenance_schedule.can_reschedule: maintenance_schedule["can_reschedule"] = str(redis_instance.maintenance_schedule.can_reschedule)
        if redis_instance.maintenance_schedule.schedule_deadline_time: maintenance_schedule["schedule_deadline_time"] = str(redis_instance.maintenance_schedule.schedule_deadline_time)
    save_data["maintenance_schedule"] = maintenance_schedule

    if redis_instance.replica_count: save_data["replica_count"] = str(redis_instance.replica_count)
    if redis_instance.nodes: save_data["nodes"] = str(redis_instance.nodes)
    if redis_instance.read_endpoint: save_data["read_endpoint"] = str(redis_instance.read_endpoint)
    if redis_instance.read_endpoint_port: save_data["read_endpoint_port"] = str(redis_instance.read_endpoint_port)
    if redis_instance.read_replicas_mode: save_data["read_replicas_mode"] = str(redis_instance.read_replicas_mode)
    if redis_instance.customer_managed_key: save_data["customer_managed_key"] = str(redis_instance.customer_managed_key)


    persistence_config = {}
    if redis_instance.persistence_config:
        
        if redis_instance.persistence_config.persistence_mode: persistence_config["persistence_mode"] = str(redis_instance.persistence_config.persistence_mode)
        if redis_instance.persistence_config.rdb_snapshot_period: persistence_config["rdb_snapshot_period"] = str(redis_instance.persistence_config.rdb_snapshot_period)
        if redis_instance.persistence_config.rdb_next_snapshot_time: persistence_config["rdb_next_snapshot_time"] = str(redis_instance.persistence_config.rdb_next_snapshot_time)
        if redis_instance.persistence_config.rdb_snapshot_start_time: persistence_config["rdb_snapshot_start_time"] = str(redis_instance.persistence_config.rdb_snapshot_start_time)
    save_data["persistence_config"] = persistence_config

    if redis_instance.suspension_reasons: save_data["suspension_reasons"] = str(dict(redis_instance.suspension_reasons))
    if redis_instance.maintenance_version: save_data["maintenance_version"] = str(redis_instance.maintenance_version)
    if redis_instance.available_maintenance_versions: save_data["available_maintenance_versions"] = str(redis_instance.available_maintenance_versions)

    # Primary keys means add if doesn't exist, else ignore
    session.insert_data(table_name, save_data, only_if_new_columns = ["project_id"])


def list_redis_instances(redis_client, parent, debug=False):
    
    if debug: print(f"[DEBUG] Listing Redis instances for: {parent}...")
    
    project_id = parent.split("/")[1]

    redis_instance_list = []

    try:

        request = redis_v1.ListInstancesRequest(
            parent=parent,
        )

        redis_instance_list = list(redis_client.list_instances(request=request))
        
    except Forbidden as e:

        if "does not have redis.instances.list" in str(e):
            UtilityTools.print_403_api_denied("redis.instances.list", project_id = project_id)

        elif f"Google Cloud Memorystore for Redis API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            UtilityTools.print_403_api_disabled("Memorystore Redis", project_id)
            return "Not Enabled"
        print(str(e))
        return None

    except NotFound as e:

        if "was not found" in str(e):
            UtilityTools.print_404_resource(project_id)
        return None

    except Exception as e:
        project_id = parent.split("/")[1]
        UtilityTools.print_500(project_id, "redis.instances.list", e)
        return None

    return redis_instance_list

def get_redis_instance(redis_instances_client, name, debug=False):

    if debug: print(f"[DEBUG] Getting {name}...")

    project_id = name.split("/")[1]

    redis_instance_metdata = None

    try:

        # Initialize request argument(s)
        request = redis_v1.GetInstanceRequest(
            name=name,
        )

        # Make the request
        redis_instance_metdata = redis_instances_client.get_instance(request=request)

    except Forbidden as e:
        
        if "does not have redis.instances.get" in str(e):
            UtilityTools.print_403_api_denied("redis.instances.get", resource_name = instance_name)

        elif f"Google Cloud Memorystore for Redis API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            UtilityTools.print_403_api_disabled("Memorystore Redis", project_id)

    except NotFound as e:

        if "was not found" in str(e):
            UtilityTools.print_404_resource(instance_name)

    except Exception as e:

        UtilityTools.print_500(instance_name, "redis.instances.get", e)

    if debug:
        print(f"[DEBUG] Succcessfully completed get_redis_instance ...")

    # Handle the response
    return redis_instance_metdata  

def get_redis_instance_auth_string(redis_instances_client, name, debug=False):

    if debug: print(f"[DEBUG] Getting auth string for {name}...")

    project_id = name.split("/")[1]

    redis_instance_metdata = None

    try:

        # Initialize request argument(s)
        request = redis_v1.GetInstanceAuthStringRequest(
            name=name,
        )

        # Make the request
        redis_instance_metdata = redis_instances_client.get_instance_auth_string(request=request)

    except Forbidden as e:
        
        if "does not have redis.instances.getAuthString" in str(e):
            UtilityTools.print_403_api_denied("redis.instances.getAuthString", resource_name = instance_name)

        elif f"Google Cloud Memorystore for Redis API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            UtilityTools.print_403_api_disabled("Memorystore Redis", project_id)

    except NotFound as e:

        if "was not found" in str(e):
            UtilityTools.print_404_resource(instance_name)

    except Exception as e:

        UtilityTools.print_500(instance_name, "redis.instances.getAuthString", e)

    if debug:
        print(f"[DEBUG] Succcessfully completed get_redis_instance_auth_string ...")

    # Handle the response
    return redis_instance_metdata  