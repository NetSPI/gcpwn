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

# Taken from code snippet at https://cloud.google.com/compute/docs/instances/stop-start-instance
def wait_for_extended_operation(
    operation: ExtendedOperation, verbose_name: str = "operation", timeout: int = 480
) -> Any:
    """
    Waits for the extended (long-running) operation to complete.

    If the operation is successful, it will return its result.
    If the operation ends with an error, an exception will be raised.
    If there were any warnings during the execution of the operation
    they will be printed to sys.stderr.

    Args:
        operation: a long-running operation you want to wait on.
        verbose_name: (optional) a more verbose name of the operation,
            used only during error and warning reporting.
        timeout: how long (in seconds) to wait for operation to finish.
            If None, wait indefinitely.

    Returns:
        Whatever the operation.result() returns.

    Raises:
        This method will raise the exception received from `operation.exception()`
        or RuntimeError if there is no exception set, but there is an `error_code`
        set for the `operation`.

        In case of an operation taking longer than `timeout` seconds to complete,
        a `concurrent.futures.TimeoutError` will be raised.
    """
    result = operation.result(timeout=timeout)

    if operation.error_code:
        print(
            f"Error during {verbose_name}: [Code: {operation.error_code}]: {operation.error_message}",
            file=sys.stderr,
            flush=True,
        )
        print(f"Operation ID: {operation.name}", file=sys.stderr, flush=True)
        raise operation.exception() or RuntimeError(operation.error_message)

    if operation.warnings:
        print(f"Warnings during {verbose_name}:\n", file=sys.stderr, flush=True)
        for warning in operation.warnings:
            print(f" - {warning.code}: {warning.message}", file=sys.stderr, flush=True)

    return result

def stop_instance(instance_client, project_id: str, zone: str, instance_name: str):

    stop_status = None

    try:

        print(f"Shutting down {instance_name}...")
        

        request = compute_v1.StopInstanceRequest(
            instance=instance_name,
            project=project_id,
            zone=zone
        )

        operation = instance_client.stop(request=request)
        stop_status = wait_for_extended_operation(operation, f"{instance_name} stopping")
    
    except Forbidden as e:
        if "does not have compute.instances.stop" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.stop permissions{UtilityTools.RESET}")

    except Exception as e:
        print(f"Could not stop {instance_name} for following reasons:")
        print(str(e))

    return stop_status

def start_instance(instance_client, project_id: str, zone: str, instance_name: str):


    start_status = None

    try:

        operation = instance_client.start(
            project=project_id, zone=zone, instance=instance_name
        )

        start_status = wait_for_extended_operation(operation, "instance start")

    except Forbidden as e:
        if "does not have compute.instances.start" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.start permissions{UtilityTools.RESET}")

    except Exception as e:
        print(f"Could not stop {instance_name} for following reasons:")
        print(str(e))

    return start_status

########### Compute Instance Zones

def get_all_instance_zones(
        session: SessionUtility, 
        project_id: str, 
        all_zones: Optional[bool] = False, 
        zones_list: Optional[str] = None, 
        zones_file: Optional[str] = None
    ):

    if all_zones:

        zones = [line.strip() for line in open('Modules/CloudCompute/utils/zones.txt')]
        
    elif zones_list:
        zones = zones_list.split(",")
       
    elif zones_file:

        zones = [line.strip() for line in open(zones_file)]        
    
    elif session.config_zones_list:

        zones = session.config_zones_list
    return zones


########### SAVE OPERATIONS FOR COMPUTE INSTANCES

def save_compute_project_to_resource(compute_project, session):
    table_name = 'abstract-tree-hierarchy'
    save_data = {}
    
    if compute_project.name: 
        project_id = compute_project.name.split("/")[-1]
        save_data["project_id"] = project_id
        
    save_data["name"] = "Unknown"

    # Primary keys means add if doesn't exist, else ignore
    session.insert_data(table_name, save_data, only_if_new_columns = ["project_id"])

def save_compute_project(compute_project, session):
    table_name = 'cloudcompute-projects'
    save_data = {}

    if compute_project.cloud_armor_tier: save_data["cloud_armor_tier"] = str(compute_project.cloud_armor_tier)
    if compute_project.cloud_armor_tier: save_data["cloud_armor_tier"] = str(compute_project.cloud_armor_tier)
    if compute_project.creation_timestamp: save_data["creation_timestamp"] = str(compute_project.creation_timestamp)
    if compute_project.default_network_tier: save_data["default_network_tier"] = str(compute_project.default_network_tier)
    if compute_project.default_service_account: save_data["default_service_account"] = str(compute_project.default_service_account)
    if compute_project.description: save_data["description"] = str(compute_project.description)
    if compute_project.enabled_features: save_data["enabled_features"] = str(compute_project.enabled_features)
    if compute_project.id: save_data["id"] = str(compute_project.id)
    if compute_project.kind: save_data["kind"] = str(compute_project.kind)
    if compute_project.name: save_data["project_id"] = str(compute_project.name)
    if compute_project.quotas: save_data["quotas"] = str(compute_project.quotas)
    if compute_project.self_link: save_data["self_link"] = str(compute_project.self_link)
    if compute_project.vm_dns_setting: save_data["vm_dns_setting"] = str(compute_project.vm_dns_setting)
    if compute_project.xpn_project_status: save_data["xpn_project_status"] = str(compute_project.xpn_project_status)

    usage_export_location = {}
    if compute_project.usage_export_location:
        if compute_project.usage_export_location.bucket_name: usage_export_location["bucket_name"] = compute_project.usage_export_location.bucket_name
        if compute_project.usage_export_location.report_name_prefix: usage_export_location["report_name_prefix"] = compute_project.usage_export_location.report_name_prefix
    save_data["usage_export_location"] = str(usage_export_location)

    common_instance_metadata = {}
    save_data["metadata_enable_os_login"] = "None"
    if compute_project.common_instance_metadata: 
        if compute_project.common_instance_metadata.fingerprint: common_instance_metadata["fingerprint"] = compute_project.common_instance_metadata.fingerprint
        if compute_project.common_instance_metadata.items: 
            common_instance_metadata["items"] = compute_project.common_instance_metadata.items
            save_data["metadata_enable_os_login"] = "False"
            for item in compute_project.common_instance_metadata.items:
                if "enable-oslogin" in item.key:
                    if item.value == "TRUE":
                        save_data["metadata_enable_os_login"] = "True"
                        
        if compute_project.common_instance_metadata.kind: common_instance_metadata["kind"] = compute_project.common_instance_metadata.kind
    save_data["common_instance_metadata"] = common_instance_metadata

    session.insert_data(table_name, save_data)

def save_instance(instance, session, project_id):
    table_name = 'cloudcompute-instances'
    save_data = {}
    save_data["project_id"] = project_id

    advanced_machine_features = {}
    if instance.advanced_machine_features:
        if instance.advanced_machine_features.advanced_machine_features: advanced_machine_features["enable_nested_virtualization"] = instance.advanced_machine_features.advanced_machine_features
        if instance.advanced_machine_features.enable_uefi_networking: advanced_machine_features["enable_uefi_networking"] = instance.advanced_machine_features.enable_uefi_networking
        if instance.advanced_machine_features.threads_per_core: advanced_machine_features["threads_per_core"] = instance.advanced_machine_features.threads_per_core	
        if instance.advanced_machine_features.visible_core_count: advanced_machine_features["visible_core_count"] = instance.advanced_machine_features.visible_core_count
    
    save_data["advanced_machine_features"] = advanced_machine_features

    if instance.can_ip_forward: save_data["can_ip_forward"] = str(instance.can_ip_forward)

    confidential_instance_config = {}
    if instance.confidential_instance_config: 
        if instance.confidential_instance_config.enable_confidential_compute: confidential_instance_config["enable_confidential_compute"] = instance.confidential_instance_config.enable_confidential_compute
    save_data["confidential_instance_config"] = confidential_instance_config
    
    if instance.cpu_platform: save_data["cpu_platform"] = str(instance.cpu_platform)
    if instance.creation_timestamp: save_data["creation_timestamp"] = str(instance.creation_timestamp)
    if instance.deletion_protection: save_data["deletion_protection"] = str(instance.deletion_protection)
    if instance.description: save_data["description"] = str(instance.description)

    # TODO BREAK OUT LATER
    if instance.disks: save_data["disks"] = str(instance.disks)
    if instance.guest_accelerators: save_data["guest_accelerators"] = str(instance.guest_accelerators)
    if instance.network_interfaces: save_data["network_interfaces"] = str(instance.network_interfaces)
    if instance.scheduling: save_data["scheduling"] = str(instance.scheduling)

    display_device = {}
    if instance.display_device: 
        if instance.display_device.enable_display: display_device["enable_display"] = instance.display_device.enable_display
    save_data["display_device"] = display_device

    if instance.fingerprint: save_data["fingerprint"] = str(instance.fingerprint)
    if instance.hostname: save_data["hostname"] = str(instance.hostname)
    if instance.id: save_data["id"] = str(instance.id)

    instance_encryption_key = {}
    if instance.instance_encryption_key: 
        if instance.instance_encryption_key.kms_key_name: instance_encryption_key["kms_key_name"] = instance.instance_encryption_key.kms_key_name
        if instance.instance_encryption_key.kms_key_service_account: instance_encryption_key["kms_key_service_account"] = instance.instance_encryption_key.kms_key_service_account
        if instance.instance_encryption_key.raw_key: instance_encryption_key["raw_key"] = instance.instance_encryption_key.raw_key
        if instance.instance_encryption_key.rsa_encrypted_key: instance_encryption_key["rsa_encrypted_key"] = instance.instance_encryption_key.rsa_encrypted_key
        if instance.instance_encryption_key.sha256: instance_encryption_key["sha256"] = instance.instance_encryption_key.sha256
    save_data["instance_encryption_key"] = instance_encryption_key

    if instance.key_revocation_action_type: save_data["key_revocation_action_type"] = str(instance.key_revocation_action_type)
    if instance.kind: save_data["kind"] = str(instance.kind)
    if instance.label_fingerprint: save_data["label_fingerprint"] = str(instance.label_fingerprint)
    if instance.labels: save_data["labels"] = str(instance.labels)
    if instance.last_start_timestamp: save_data["last_start_timestamp"] = str(instance.last_start_timestamp)
    if instance.last_stop_timestamp: save_data["last_stop_timestamp"] = str(instance.last_stop_timestamp)
    if instance.last_suspended_timestamp: save_data["last_suspended_timestamp"] = str(instance.last_suspended_timestamp)
    if instance.machine_type: save_data["machine_type"] = str(instance.machine_type)

    metadata = {}
    save_data["metadata_enable_os_login"] = "None"
    if instance.metadata: 
        if instance.metadata.fingerprint: metadata["fingerprint"] = instance.metadata.fingerprint
        if instance.metadata.items: 
            metadata["items"] = instance.metadata.items
            save_data["metadata_enable_os_login"] = "False"
            for item in instance.metadata.items:
                if "enable-oslogin" in item.key:
                    if item.value == "TRUE":
                        save_data["metadata_enable_os_login"] = "True"
                        
        if instance.metadata.kind: metadata["kind"] = instance.metadata.kind
    save_data["metadata"] = metadata

    if instance.min_cpu_platform: save_data["min_cpu_platform"] = str(instance.min_cpu_platform)
    if instance.name: save_data["name"] = str(instance.name)

    network_performance_config = {}
    if instance.network_performance_config: 
        if instance.network_performance_config.total_egress_bandwidth_tier: network_performance_config["total_egress_bandwidth_tier"] = instance.network_performance_config.total_egress_bandwidth_tier
    save_data["network_performance_config"] = network_performance_config

    params = {}
    if instance.params: 
        if instance.params.resource_manager_tags: params["resource_manager_tags"] = instance.params.resource_manager_tags
    save_data["params"] = params   

    if instance.private_ipv6_google_access: save_data["private_ipv6_google_access"] = str(instance.private_ipv6_google_access)

    reservation_affinity = {}
    if instance.reservation_affinity: 
        if instance.reservation_affinity.consume_reservation_type: reservation_affinity["consume_reservation_type"] = instance.reservation_affinity.consume_reservation_type
        if instance.reservation_affinity.key: reservation_affinity["key"] = instance.reservation_affinity.key
        if instance.reservation_affinity.values: reservation_affinity["values"] = instance.reservation_affinity.values
    save_data["reservation_affinity"] = reservation_affinity 

    if instance.resource_policies: save_data["resource_policies"] = str(instance.resource_policies)
    
    resource_status = {}
    if instance.resource_status: 
        if instance.resource_status.physical_host: resource_status["physical_host"] = instance.resource_status.physical_host
        if instance.resource_status.upcoming_maintenance: 
            resource_status["upcoming_maintenance"] = {}
            if instance.resource_status.upcoming_maintenance.can_reschedule: resource_status["upcoming_maintenance"]["can_reschedule"] = instance.resource_status.upcoming_maintenance.can_reschedule
            if instance.resource_status.upcoming_maintenance.latest_window_start_time: resource_status["upcoming_maintenance"]["latest_window_start_time"] = instance.resource_status.upcoming_maintenance.latest_window_start_time
            if instance.resource_status.upcoming_maintenance.type_: resource_status["upcoming_maintenance"]["type_"] = instance.resource_status.upcoming_maintenance.type_
            if instance.resource_status.upcoming_maintenance.window_end_time: resource_status["upcoming_maintenance"]["window_end_time"] = instance.resource_status.upcoming_maintenance.window_end_time
            if instance.resource_status.upcoming_maintenance.window_end_time: resource_status["upcoming_maintenance"]["window_end_time"] = instance.resource_status.upcoming_maintenance.window_end_time
    save_data["resource_status"] = resource_status 

    if instance.satisfies_pzs: save_data["satisfies_pzi"] = str(instance.satisfies_pzi)
    if instance.satisfies_pzs: save_data["satisfies_pzs"] = str(instance.satisfies_pzs)
    if instance.self_link: save_data["self_link"] = str(instance.self_link)
    if instance.service_accounts: save_data["service_accounts"] = str(instance.service_accounts)

    shielded_instance_config = {}
    if instance.shielded_instance_config: 
        if instance.shielded_instance_config.enable_integrity_monitoring: shielded_instance_config["enable_integrity_monitoring"] = str(instance.shielded_instance_config.enable_integrity_monitoring)
        if instance.shielded_instance_config.enable_secure_boot: shielded_instance_config["enable_secure_boot"] = str(instance.shielded_instance_config.enable_secure_boot)
        if instance.shielded_instance_config.enable_vtpm: shielded_instance_config["enable_vtpm"] = str(instance.shielded_instance_config.enable_vtpm)
    save_data["shielded_instance_config"] = shielded_instance_config 

    shielded_instance_integrity_policy = {}
    if instance.shielded_instance_config: 
        if instance.shielded_instance_integrity_policy.update_auto_learn_policy: shielded_instance_integrity_policy["update_auto_learn_policy"] = str(instance.shielded_instance_integrity_policy.update_auto_learn_policy)
    save_data["shielded_instance_integrity_policy"] = shielded_instance_integrity_policy 

    if instance.source_machine_image: save_data["source_machine_image"] = str(instance.source_machine_image)
    if instance.source_machine_image_encryption_key: save_data["source_machine_image_encryption_key"] = str(instance.source_machine_image_encryption_key)


    source_machine_image_encryption_key = {}
    if instance.source_machine_image_encryption_key: 
        if instance.source_machine_image_encryption_key.kms_key_name: source_machine_image_encryption_key["kms_key_name"] = instance.source_machine_image_encryption_key.kms_key_name
        if instance.source_machine_image_encryption_key.kms_key_service_account: source_machine_image_encryption_key["kms_key_service_account"] = instance.source_machine_image_encryption_key.kms_key_service_account
        if instance.source_machine_image_encryption_key.raw_key: source_machine_image_encryption_key["raw_key"] = instance.source_machine_image_encryption_key.raw_key
        if instance.source_machine_image_encryption_key.rsa_encrypted_key: source_machine_image_encryption_key["rsa_encrypted_key"] = instance.source_machine_image_encryption_key.rsa_encrypted_key
        if instance.source_machine_image_encryption_key.sha256: source_machine_image_encryption_key["sha256"] = instance.source_machine_image_encryption_key.sha256
    save_data["source_machine_image_encryption_key"] = source_machine_image_encryption_key


    if instance.start_restricted: save_data["start_restricted"] = str(instance.start_restricted)
    if instance.status: save_data["status"] = str(instance.status)
    if instance.status_message: save_data["status_message"] = str(instance.status_message)
   
    tags = {}
    if instance.tags: 
        if instance.tags.fingerprint: tags["fingerprint"] = str(instance.tags.fingerprint)
        if instance.tags.items: tags["items"] = str(instance.tags.items)
    save_data["tags"] = tags

    if instance.zone: save_data["zone"] = str(instance.zone)

    session.insert_data(table_name, save_data)

########### Create/Update Instances

# Arguments for created instance mainly taken from: https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/compute.instances.create.py
def create_instance(
        instance_client, 
        instance_name, 
        project_id, 
        instance_zone, 
        startup_script_data = None, 
        sa_email = None, 
        debug=False
    ):

    try:

        print(f" [*] Creating instance {instance_name} in zone {instance_zone}")

        access = compute_v1.AccessConfig()
        access.type_ = compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name
        access.name = "External NAT"

        # 7 bucks a month
        body = {
            'name': instance_name,
            'machine_type': f'zones/{instance_zone}/machineTypes/e2-micro',
            'network_interfaces': [
                {
                    'access_configs':[access],
                    'network': f'global/networks/default'
                }
            ],
            'disks': [
                {
                    'auto_delete': True,
                    'boot': True,
                    'initialize_params':{
                        'source_image':f'projects/debian-cloud/global/images/family/debian-12'
                    }
                }
            ]
        }

        # TODO allow scope submission
        if sa_email:

            body['service_accounts'] = []

            added_creds = {
                "email":sa_email,
                "scopes":["https://www.googleapis.com/auth/cloud-platform"]
            }

            body['service_accounts'].append(added_creds)

           
        if startup_script_data:

            body['metadata'] = {
                'items':[
                    {
                        'key': 'startup-script',
                        'value': f'{startup_script_data}'
                    }
                ]
            }

        request = compute_v1.InsertInstanceRequest(
            project=project_id,
            zone=instance_zone,
            instance_resource=body
        )


        print(f"Creating the {instance_name} instance in {instance_zone}...")

        try:
            # Make the request
            operation = instance_client.insert(request=request)
            response = wait_for_extended_operation(operation, "instance creation")

            print(f"Instance {instance_name} created.")

        except Exception as e:
            print(str(e))

        return 1

    except Exception as e:
        print("[X] Something failed while trying to create the instance. See the error code below:")
        print(str(e))
        return -1


def set_instance_metadata(instance_client, instance_name, project_id, zone_id, metadata_object, debug = False):
    
    if debug:
        print(f"[DEBUG] Updating metadata for {instance_name} ...")
   
    instance_metadata = None

    try:
        request = compute_v1.SetMetadataInstanceRequest(
            project=project_id,
            instance=instance_name,
            zone=zone_id,
            metadata_resource = metadata_object
        )


        # Make the request
        instance_metadata = instance_client.set_metadata(request=request)

    except Forbidden as e:
        if "does not have compute.instances.setCommonInstanceMetadata" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.setCommonInstanceMetadata permissions{UtilityTools.RESET}")

    except Exception as e:
        print(f"The compute.instances.setCommonInstanceMetadata operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed instances update instance metadata ..")

    return instance_metadata


def set_instance_project_metadata(instance_projects_client, project_id, metadata_object, debug = False):
    
    if debug:
        print(f"[DEBUG] Updating metadata for {project_id} ...")
   
    project_metadata = None

    try:
        request = compute_v1.SetCommonInstanceMetadataProjectRequest(
            project=project_id,
            metadata_resource = metadata_object
        )


        # Make the request
        project_metadata = instance_projects_client.set_common_instance_metadata(request=request)

    except Forbidden as e:
        if "does not have compute.projects.setCommonInstanceMetadata" in str(e):
            print(f"[X] 403: The user does not have compute.projects.setCommonInstanceMetadata permissions")

    except Exception as e:
        print(f"The compute.projects.setCommonInstanceMetadata operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed instances update project metadata ..")

    return project_metadata

def add_metadata(
        client, 
        action_dict,
        project_id, 
        added_metadata, 
        instance_name = None, 
        instance_zone= None, 
        type_of_resource = None, 
        overwrite_previous_key_values = False, 
        debug=False
    ):
    
    if type_of_resource == "instance":
        
        # Per google: You must always provide an up-to-date fingerprint hash in order to update or change metadata, otherwise the request will fail with error 412 conditionNotMet 
        current_instance = get_instance(client, instance_name, project_id, instance_zone, debug=debug)

        if current_instance:
            
            current_metadata = current_instance.metadata
            kind = current_metadata.kind
            fingerprint = current_metadata.fingerprint
 
            if not overwrite_previous_key_values:

                action_dict.setdefault(project_id, {}).setdefault("compute.instances.get", {}).setdefault("instances", set()).add(instance_name)


                starting_list  = list(current_metadata.items)
            
                # Append to existing values if key exists
                for new_entry in added_metadata:
                    key_exists = False
                    for item in starting_list:
                        if item.key == new_entry["key"]:
                            item.value = item.value + "\n"+new_entry["value"]
                            key_exists = True
                            break
                    if not key_exists:
                        starting_list.append(new_entry)
                
                final_metadata_list = starting_list

            else:

                final_metadata_list = added_metadata
                
        else:
            print("[X] Could not retrieve the fingerprint for the compute instance metadata. Thus no updates could be done. Exititng...")
            return None

        metadata_object = {
            "kind": "compute#metadata",
            "items":final_metadata_list
        }

        if fingerprint:
            metadata_object["fingerprint"] = fingerprint

        if debug:
            print(f"Setting Metadata to: {metadata_object}")

        output = set_instance_metadata(client, instance_name, project_id, instance_zone, metadata_object, debug=debug)
        
        if output:
            action_dict.setdefault(project_id, {}).setdefault("compute.instances.setMetadata", {}).setdefault("instances", set()).add(instance_name)            

        return output

    elif type_of_resource == "project":
        
        current_project = get_compute_project(client, project_id, debug=debug)
        
        if current_project:

            current_metadata = current_project.common_instance_metadata
            fingerprint = current_metadata.fingerprint
            kind = current_metadata.kind

            if not overwrite_previous_key_values:
                
                action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add("compute.projects.get")

                starting_list  = list(current_metadata.items)
                
                # Append to existing values if key exists
                for new_entry in added_metadata:
                    key_exists = False
                    for item in starting_list:
                        if item.key == new_entry["key"]:
                            item.value = item.value + "\n"+new_entry["value"]
                            key_exists = True
                            break
                    if not key_exists:
                        starting_list.append(new_entry)
                
                final_metadata_list = starting_list
        
            elif overwrite_previous_key_values:

                final_metadata_list = added_metadata

        else:
            print("[X] Could not retrieve the fingerprint for the compute project metadata. Thus no updates could be done. Exititng...")
            return None            

        metadata_object = {
        "kind": "compute#metadata",
        "items":final_metadata_list
        }

        if fingerprint:
            metadata_object["fingerprint"] = fingerprint

        output = set_instance_project_metadata(client, project_id, metadata_object, debug=debug)
        if output:
            action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add("compute.projects.setCommonInstanceMetadata")            
        return output 

def add_instance_iam_member(instance_client, instance_name, project_id, zone, member, action_dict, brute = False, role = None, debug=False):
    
    additional_bind = {"role": role, "members": [member]}
   
    print(f"[*] Adding {member} to {instance_name}")
    policy = instance_get_iam_policy(instance_client, instance_name, project_id, zone, debug=debug)
    policy_dict = {}

    if policy:
        # Just assume v1 till I can get a better method
        action_dict.setdefault(project_id, {}).setdefault("compute.instances.getIamPolicy", {}).setdefault("instances", set()).add(instance_name)
        policy_dict["bindings"] = list(policy.bindings)
        policy_dict["bindings"].append(additional_bind)
        policy_dict["etag"] = policy.etag
        policy_dict["version"] = policy.version
        policy = policy_dict
   
        bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {instance_name} \n{bindings}")

    else:
        # Could not retrieve policy to append, rewrite entire policy?
        if brute:
            print(f"[-] Could not call get_iam_policy for {instance_name}.")
            policy_dict["bindings"] = []
            policy_dict["bindings"].append(additional_bind)

            policy_dict["version"] = 1
            print(f"[*] New policy below being added to {instance_name} \n{additional_bind}")
            policy = policy_dict
        else:

            print(f"[X] Exiting the module as we cannot append binding to existing bindings. Supply --brute to OVERWRITE (as opposed to append) IAM policy of the bucket to just your member and role")
            return -1

    status = instance_set_iam_policy(instance_client, instance_name, project_id, zone, policy, debug=debug)
    if status:
        action_dict.setdefault(project_id, {}).setdefault("compute.instances.setIamPolicy", {}).setdefault("instances", set()).add(instance_name)
    
    return status


def instance_get_serial(instance_client, instance_name, project_id, zone_id, workspace_name, output = None,  debug = False):

    if debug:
        print(f"[DEBUG] Getting Screenshot for {instance_name} ...")
  
    instance_serial = None
    try:

        request = compute_v1.GetSerialPortOutputInstanceRequest(
            instance=instance_name,
            project=project_id,
            zone=zone_id,
        )

        # Make the request
        instance_serial = instance_client.get_serial_port_output(request=request)

        instance_image_name = f"{project_id}/{instance_name}_{time.time()}.txt"

        if output != None:
            destination_filename = f"{output}/{instance_image_name}"
        else:
            destination_filename = UtilityTools.get_save_filepath(workspace_name, instance_image_name, "Compute Serial")

        if instance_serial:
            with open(destination_filename, 'w') as f:
                f.write(instance_serial.contents)
            
    except Forbidden as e:
        if "does not have compute.instances.getSerialPortOutput" in str(e):
            print(f"{UtilityTools.RED}[X] 403: Serial Download failed for {instance_name}. The user does not have compute.instances.getSerialPortOutput permissions{UtilityTools.RESET}")

    except NotFound as e:

        if "was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The resource does not appear to exist in {project_id}.{UtilityTools.RESET}")

    except Exception as e:
        
        if "is not ready" in str(e) and "The resource" in str(e):
            print(f"{UtilityTools.RED}[X] 400: Serial Download failed for {instance_name}. The VM was \"not ready\" and might be turned off.{UtilityTools.RESET} ")
        else:
            print(f"The compute.instances.getSerialPortOutput operation failed for unexpected reasons. See below:")
            print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed instances getSerialOutput ..")

    return instance_serial


def instance_get_screenshot(instance_client, instance_name, project_id, zone_id, output = None, debug = False):

    if debug:
        print(f"[DEBUG] Getting Screenshot for {instance_name} ...")

    
    instance_screenshot_b64 = None

    try:

        request = compute_v1.GetScreenshotInstanceRequest(
            project=project_id,
            instance=instance_name,
            zone=zone_id,
        )

        # Make the request
        instance_screenshot_b64 = instance_client.get_screenshot(request=request)


        if output != None:
            destination_filename = f"{output}/{instance_image_name}"
        else:
            destination_filename = UtilityTools.get_save_filepath(workspace_name, instance_image_name, "Compute Screenshots")


        if instance_screenshot_b64:
            image_data = base64.b64decode(instance_screenshot_b64.contents)
            with open(destination_filename, 'wb') as f:
                f.write(image_data)

    except Forbidden as e:
        if "does not have compute.instances.getScreenshot" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.getScreenshot permissions{UtilityTools.RESET}")
    
    except NotFound as e:

        if "was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The resource does not appear to exist in {project_id}.{UtilityTools.RESET}")

    except Exception as e:
        
        if "Display device needs to be enabled for the instance" in str(e):
            print(f"{UtilityTools.RED}[X] 400: Screenshot failed for {instance_name}. Display device needs to be enabled for instance {instance_name}.{UtilityTools.RESET} ")
        
        elif "is not ready" in str(e) and "The resource" in str(e):
            print(f"{UtilityTools.RED}[X] 400: Screenshot failed for {instance_name}. The VM was \"not ready\" and might be turned off.{UtilityTools.RESET} ")
        
        else:
            print(f"The compute.instances.getScreenshot operation failed for unexpected reasons. See below:")
            print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed instances getScreenshot ..")

    return instance_screenshot_b64

# Returns all instancesa across all zones while list_instances specificies zone.
def list_aggregated_instances(instances_client, project_id, debug=False):

    if debug:
        print(f"[DEBUG] Listing instances for project {project_id} ...")

    all_instances = []

    try:

        request = compute_v1.AggregatedListInstancesRequest(
            project=project_id
        )

        agg_list = instances_client.aggregated_list(request=request)

        all_instances = defaultdict(list)

        for zone, response in agg_list:
            if response.instances:
                all_instances[zone].extend(response.instances)

    except Forbidden as e:
      
        if "does not have compute.instances.list" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.list permissions on project {project_id}{UtilityTools.RESET}")
        
        elif f"Compute Engine API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The Compute API does not appear to be enabled for project {project_id}{UtilityTools.RESET}")

        
        return None

    except NotFound as e:

        if "was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The resource does not appear to exist in {project_id}.{UtilityTools.RESET}")
            
        return None
    except Exception as e:
        print(f"The compute.instances.list aggregated operation failed for unexpected reasons for {project_id}. See below:")
        print(str(e))
        return None

    return all_instances

def get_compute_project(compute_project_client, project_id, debug=False):

    if debug:
        print(f"[DEBUG] Getting compute project {project_id} ...")
    
    compute_project = None

    try:

        request = compute_v1.GetProjectRequest(
            project=project_id
        )

        compute_project = compute_project_client.get(request=request)

    except Forbidden as e:
        if "does not have compute.projects.get" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.projects.get permissions on project {project_id}{UtilityTools.RESET}")

        elif f"Compute Engine API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The Compute API does not appear to be enabled for project {project_id}{UtilityTools.RESET}")

    except NotFound as e:
        if f"{project_id}' was not found" in str(e):
            print(f"{UtilityTools.RED}[X] The supplied project-id was not found (404). Double check the project ID name{UtilityTools.RESET}")

    except Exception as e:
        print(f"The compute.projects.get operation failed for unexpected reasons for {project_id}. See below:")
        print(str(e))

    return compute_project

def list_instances(instances_client, project_id, zone, debug=False):
    
    if debug:
        print(f"[DEBUG] Listing instances for project {project_id} zone {zone} ...")
    
    instance_list = []

    try:

        request = compute_v1.ListInstancesRequest(
            project=project_id,
            zone=zone
        )

        instance_list = list(instances_client.list(request=request)) 
        
    except Forbidden as e:
        if "does not have compute.instances.list" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.list permissions on project {project_id}{UtilityTools.RESET}")
        

        elif f"Compute Engine API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The Compute API does not appear to be enabled for project {project_id}{UtilityTools.RESET}")
            return "Not Enabled"

        return None

    except NotFound as e:

        if "was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The resource does not appear to exist in {project_id}.{UtilityTools.RESET}")
        return None

    except Exception as e:
        print(f"The compute.instances.list operation failed for unexpected reasons for {project_id}. See below:")
        print(str(e))
        return None

    return instance_list

def get_instance(instances_client, instance_name, project_id, zone, debug=False):
    

    if debug:
        print(f"[DEBUG] Getting instances for project {project_id} zone {zone} ...")

    instance_metdata = None

    try:

        # Initialize request argument(s)
        request = compute_v1.GetInstanceRequest(
            instance=instance_name,
            project=project_id,
            zone=zone,
        )


        # Make the request
        instance_metdata = instances_client.get(request=request)

    except NotFound as e:

        if "was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The resource does not appear to exist in {project_id}.{UtilityTools.RESET}")

    except Forbidden as e:
        if "does not have compute.instances.get" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have compute.instances.get permissions on project {project_id}{UtilityTools.RESET}")

        elif f"Compute Engine API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The Compute API does not appear to be enabled for project {project_id}{UtilityTools.RESET}")


    except Exception as e:
        print(f"The compute.instances.get operation failed for unexpected reasons for {project_id}. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Succcessfully completed get_instance ...")

    # Handle the response
    return instance_metdata  
  
def check_instance_permissions(instance_client, project_id, instance_name, zone, debug = False):
    
    authenticated_permissions = []
   
    try:
        permission_list ={
            "permissions": [
                'compute.instances.addAccessConfig',
                'compute.instances.addMaintenancePolicies',
                'compute.instances.addResourcePolicies',
                'compute.instances.attachDisk',
                #'compute.instances.create',
                'compute.instances.createTagBinding',
                'compute.instances.delete',
                'compute.instances.deleteAccessConfig',
                'compute.instances.deleteTagBinding',
                'compute.instances.detachDisk',
                'compute.instances.get',
                'compute.instances.getEffectiveFirewalls',
                'compute.instances.getGuestAttributes',
                'compute.instances.getIamPolicy',
                'compute.instances.getScreenshot',
                'compute.instances.getSerialPortOutput',
                'compute.instances.getShieldedInstanceIdentity',
                'compute.instances.getShieldedVmIdentity',
                #'compute.instances.list',
                'compute.instances.listEffectiveTags',
                'compute.instances.listReferrers',
                'compute.instances.listTagBindings',
                'compute.instances.osAdminLogin',
                'compute.instances.osLogin',
                # 'compute.instances.pscInterfaceCreate',
                'compute.instances.removeMaintenancePolicies',
                'compute.instances.removeResourcePolicies',
                'compute.instances.reset',
                'compute.instances.resume',
                'compute.instances.sendDiagnosticInterrupt',
                'compute.instances.setDeletionProtection',
                'compute.instances.setDiskAutoDelete',
                'compute.instances.setIamPolicy',
                'compute.instances.setLabels',
                'compute.instances.setMachineResources',
                'compute.instances.setMachineType',
                'compute.instances.setMetadata',
                'compute.instances.setMinCpuPlatform',
                'compute.instances.setName',
                'compute.instances.setScheduling',
                'compute.instances.setSecurityPolicy',
                'compute.instances.setServiceAccount',
                'compute.instances.setShieldedInstanceIntegrityPolicy',
                'compute.instances.setShieldedVmIntegrityPolicy',
                'compute.instances.setTags',
                'compute.instances.simulateMaintenanceEvent',
                'compute.instances.start',
                'compute.instances.startWithEncryptionKey',
                'compute.instances.stop',
                'compute.instances.suspend',
                'compute.instances.update',
                'compute.instances.updateAccessConfig',
                'compute.instances.updateDisplayDevice',
                'compute.instances.updateNetworkInterface',
                'compute.instances.updateSecurity',
                'compute.instances.updateShieldedInstanceConfig',
                'compute.instances.updateShieldedVmConfig',
                'compute.instances.use',
                'compute.instances.useReadOnly'
            ]
        }

        request = compute_v1.TestIamPermissionsInstanceRequest()
        request.project = project_id
        request.resource = instance_name
        request.zone = zone
        request.test_permissions_request_resource = permission_list
            
        authenticated_permissions = instance_client.test_iam_permissions(request=request)
        authenticated_permissions = authenticated_permissions.permissions
     
    
    except Forbidden as e:

        if f"Compute Engine API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The Compute API does not appear to be enabled for project {project_id}{UtilityTools.RESET}")

    except NotFound as e:

        if "was not found" in str(e):
            print(f"{UtilityTools.RED}[X] 404: The resource does not appear to exist in {project_id}.{UtilityTools.RESET}")

    except Exception as e:
        print(f"The testIAMPermissions operation failed for unexpected reasons for {instance_name}. See below:")
        print(str(e))

    return authenticated_permissions

def check_instance_format(input_string):
    pattern = r'^projects/[^/]+/zones/[^/]+/instances/[^/]+$'
    if re.match(pattern, input_string):
        return 1
    else:
        print("[X] Input string does not follow the correct format. It should be in the format: projects/{project_name}/zones/{zone_name}/instances/{instance_name}")
        return None

def check_sa_format(input_string: str):
    pattern = r'^projects/[^/]+/serviceAccounts/[^/]+$'
    if re.match(pattern, input_string):
        return 1
    else:
        print("[X] Input string does not follow the correct format. It should be in the format: projects/{project_id}/serviceAccounts/{serviceAccount}")
        return None

def update_instance(
        instance_client, 
        instance_name, 
        project_id, 
        instance_zone, 
        action_dict,
        startup_script_data = None, 
        sa_email = None, 
        debug=False
    ):

    try:

        # Will return None if the instance is already shut down
        result = stop_instance(instance_client, project_id, instance_zone, instance_name)

        if result:
                action_dict.setdefault(project_id, {}).setdefault("compute.instances.stop", {}).setdefault("instances", set()).add(instance_name)            

        try:

            output = get_instance(instance_client, instance_name, project_id, instance_zone, debug=False)
            if output:
                action_dict.setdefault(project_id, {}).setdefault("compute.instances.get", {}).setdefault("instances", set()).add(instance_name)            

                fingerprint = output.fingerprint

            else:
                print("[X] Cannot fetch instance and determine fingerprint for update. Exiting...")
                return None

            # TODO See if can mask this in anyway, does not seem to be the case.
            access = compute_v1.AccessConfig()
            access.type_ = compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name
            access.name = "External NAT"

            body = {
                'name': instance_name,
                'fingerprint':f'{fingerprint}',
                'machine_type': f'zones/{instance_zone}/machineTypes/e2-micro',
                'disks': [
                    {
                        'auto_delete': True,
                        'boot': True,
                        'initialize_params':{
                            'source_image':f'projects/debian-cloud/global/images/family/debian-12'
                        }
                    }
                ],
                'network_interfaces': [
                    {
                        'access_configs':[access],
                        'network': f'global/networks/default'
                    }
                ]
            }

            if startup_script_data:

                body['metadata'] = {
                    'items':[
                        {
                            'key': 'startup-script',
                            'value': f'{startup_script_data}'
                        }
                    ]
                }

            # Update Service Account to try to get new creds
            if sa_email:

                body['service_accounts'] = []

                added_creds = {
                    "email":sa_email,
                    "scopes":["https://www.googleapis.com/auth/cloud-platform"]
                }

                body['service_accounts'].append(added_creds)

            # This will FAIL if you don't pass in a fingerprint for some reason
            # https://cloud.google.com/compute/docs/instances/update-instance-properties
            request = compute_v1.UpdateInstanceRequest(
                instance = instance_name,
                instance_resource=body,
                project=project_id,
                zone=instance_zone
            )
      
            # Make the request
            print(f"Updating instance {instance_name}...")
            operation = instance_client.update_unary(request=request)
            response = wait_for_extended_operation(operation, "instance update")
            if response:
                action_dict.setdefault(project_id, {}).setdefault("compute.instances.update", {}).setdefault("instances", set()).add(instance_name)            

        except Exception as e:
            print(str(e))

        # START VM  
        response = start_instance(instance_client, project_id, instance_zone, instance_name)   
        if response:
            action_dict.setdefault(project_id, {}).setdefault("compute.instances.start", {}).setdefault("instances", set()).add(instance_name)            
        
 
        return 1

    except Exception as e:
        import traceback
        print("[X] Something failed while trying to update the instance. See the error code below:")
        print(traceback.format_exc())
        return -1