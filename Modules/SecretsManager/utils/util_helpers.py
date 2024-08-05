from google.cloud import secretmanager_v1
import argparse
from UtilityController import *
import pandas as pd
import os
from Modules.IAM.utils.util_helpers import secret_get_iam_policy, secret_set_iam_policy


from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import InvalidArgument

from google.iam.v1 import iam_policy_pb2 

# Utilities
from UtilityController import *

def save_secret(secret, session, secret_project_id):

    table_name = 'secretsmanager-secrets'

    project_name = secret.name.split("/")[1]

    save_data = {"project_id":secret_project_id, "project_name":f"projects/{project_name}"}   

    if secret.name: save_data["name"] = secret.name
    
    replication = {}
    if secret.replication:
        if secret.replication.automatic: 
            replication["automatic"] = {}
            if secret.replication.automatic.customer_managed_encryption:
                replication["automatic"]["customer_managed_encryption"] = secret.replication.automatic.customer_managed_encryption

        if secret.replication.user_managed: 
            replication["user_managed"] = {}
            if secret.replication.user_managed.replicas:
                replication["user_managed"]["replicas"] = []
                for replica in secret.replication.user_managed.replicas:
                    replica_starting = {"location": None, "customer_managed_encryption": {"kms_key_name": None}}
                    if replica.location:
                        replica_starting["location"] = replica.location
                    if replica.customer_managed_encryption and replica.customer_managed_encryption.kms_key_name:
                        replica_starting["customer_managed_encryption"]["kms_key_name"] = replica.customer_managed_encryption.kms_key_name

                    if replica_starting["location"] or replica_starting["customer_managed_encryption"]["kms_key_name"]:
                        replication["user_managed"]["replicas"].append(replica_starting)
                
    save_data["replication"] = replication

    if secret.create_time: save_data["create_time"] = secret.create_time
    if secret.labels: save_data["labels"] = dict(secret.labels)
    if secret.topics: save_data["topics"] = dict(secret.topics)
    if secret.expire_time: save_data["expire_time"] = str(secret.expire_time)
    if secret.ttl: save_data["ttl"] = str(secret.ttl)
    if secret.etag: save_data["etag"] = str(secret.etag)

    rotation = {}
    if secret.rotation:
        if secret.rotation.next_rotation_time: rotation["next_rotation_time"] = str(secret.rotation.next_rotation_time)
        if secret.rotation.rotation_period: rotation["rotation_period"] = str(secret.rotation.rotation_period)

    save_data["rotation"] = rotation
    if secret.version_aliases: save_data["version_aliases"] = dict(secret.version_aliases)
    if secret.annotations: save_data["annotations"] = dict(secret.annotations)
    if secret.version_destroy_ttl: save_data["version_destroy_ttl"] = str(secret.version_destroy_ttl)

    if secret.customer_managed_encryption: 
        if secret.customer_managed_encryption.kms_key_name: 
            save_data["customer_managed_encryption"] = {"kms_key_name": secret.customer_managed_encryption.kms_key_name}

    session.insert_data(table_name, save_data)

def save_secret_version(secret, session, secret_project_id):

    table_name = 'secretsmanager-secretversions'

    project_name = secret.name.split("/")[1]
    version_num = secret.name.split("/")[-1]

    save_data = {"project_id":secret_project_id, "project_name":f"projects/{project_name}", "version_num": version_num}   

    if secret.name: save_data["name"] = secret.name
    if secret.create_time: save_data["create_time"] = secret.create_time
    if secret.destroy_time: save_data["destroy_time"] = secret.destroy_time
    if secret.state: save_data["state"] = str(secret.state)
    if secret.etag: save_data["etag"] = str(secret.etag)
    if secret.client_specified_payload_checksum: save_data["client_specified_payload_checksum"] = str(secret.client_specified_payload_checksum)
    if secret.scheduled_destroy_time	: save_data["scheduled_destroy_time	"] = str(secret.scheduled_destroy_time	)


    replication_status = {}
    if secret.replication_status:
        if secret.replication_status.automatic: 
            replication_status["automatic"] = {}
            if secret.replication_status.automatic.customer_managed_encryption:
                replication_status["automatic"]["customer_managed_encryption"] = secret.replication_status.automatic.customer_managed_encryption

        if secret.replication_status.user_managed: 
            replication_status["user_managed"] = {}
            if secret.replication_status.user_managed.replicas:
                replication_status["user_managed"]["replicas"] = []
                for replica in secret.replication_status.user_managed.replicas:
                    replica_starting = {"location": None, "customer_managed_encryption": {"kms_key_name": None}}
                    if replica.location:
                        replica_starting["location"] = replica.location
                    if replica.customer_managed_encryption and replica.customer_managed_encryption.kms_key_name:
                        replica_starting["customer_managed_encryption"]["kms_key_name"] = replica.customer_managed_encryption.kms_key_name

                    if replica_starting["location"] or replica_starting["customer_managed_encryption"]["kms_key_name"]:
                        replication_status["user_managed"]["replicas"].append(replica_starting)
                
    save_data["replication_status"] = replication_status

    if secret.customer_managed_encryption: 
        if secret.customer_managed_encryption.kms_key_name: 
            save_data["customer_managed_encryption"] = {"kms_key_name": secret.customer_managed_encryption.kms_key_name}

    session.insert_data(table_name, save_data)



def add_secret_iam_member(secret_client, secret_name, secret_project_id, member, action_dict, brute = False, role = None, debug=False):
    
    additional_bind = {"role": role, "members": [member]}
    policy_dict = {}

    if brute:
        print(f"[*] Overwiting {secret_name} to just be {member}")

        policy_dict["bindings"] = []
        policy_dict["bindings"].append(additional_bind)
        policy_dict["version"] = 1
        policy = policy_dict

    else:

        print(f"[*] Fetching current policy for {secret_name}...")
        policy = secret_get_iam_policy(secret_client, secret_name, debug=debug)
    
        if policy:

            if policy == 404:

                print(f"{UtilityTools.RED}[X] Exiting the module as {secret_name} does not exist. Double check the name.{UtilityTools.RESET}")
                return -1

            else:

                action_dict.setdefault(secret_project_id, {}).setdefault("secretmanager.secrets.getIamPolicy", {}).setdefault("secrets", set()).add(secret_name.split("/")[-1])
                
                policy_dict["bindings"] = list(policy.bindings)
                policy_dict["bindings"].append(additional_bind)
                policy_dict["etag"] = policy.etag
                policy_dict["version"] = policy.version
                policy = policy_dict
        
        else:
            print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --overwrite to OVERWRITE entire bucket IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
            return -1

    if policy != None:
        policy_bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {secret_name} \n{policy_bindings}")

    else:
        print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
        return -1


    status = secret_set_iam_policy(secret_client, secret_name, policy, debug=debug)
    
    if status:
        if status == 404:
            print(f"{UtilityTools.RED}[X] Exiting the module as {secret_name} does not exist. Double check the name.{UtilityTools.RESET}")
            return -1

        else:
            action_dict.setdefault(secret_project_id, {}).setdefault("secretmanager.secrets.setIamPolicy", {}).setdefault("secrets", set()).add(secret_name.split("/")[-1])

    return status

def get_all_secret_locations(
        session, 
        all_locations = False, 
        locations_list = None, 
        locations_file = None
    ):

    if all_locations:

        locations = [line.strip() for line in open('Modules/SecretsManager/utils/locations.txt')]
        
    elif locations_list:
        locations = locations_list.split(",")
       
    elif locations_file:

        locations = [line.strip() for line in open(locations_file)]        
    
    # TODO tie to session config
    elif session.config_zones_list:

        pass

    return locations


def list_secrets(
        secret_client, 
        parent, 
        debug = False
    ):

    if debug: print(f"[DEBUG] Listing secrets for project {parent} ...")
    
    secrets_list = []

    try:
        request = secretmanager_v1.ListSecretsRequest(
            parent=parent,
        )

        secrets_list = list(secret_client.list_secrets(request=request))
    except Forbidden as e:

        if "Permission 'secretmanager.secrets.list' denied for resource" in str(e):
            
            UtilityTools.print_403_api_denied("secretmanager.secrets.list", resource_name = parent)
        
            return None
            
        elif "Secret Manager API has not been used in project" in str(e) and "before or it is disabled" in str(e):
            
            UtilityTools.print_403_api_disabled("Secrets Manager", parent)

            return "Not Enabled"

        return None

    except NotFound as e:

        if f"was not found" in str(e):
            UtilityTools.print_404_resource(parent)

    except Exception as e:
        
        UtilityTools.print_500(parent, "secretmanager.secrets.list", e)
        return None

    if debug: print(f"[DEBUG] Successfully called list_secrets for {parent} ...")
    
    return secrets_list


def get_secret(
        secret_client, 
        secret_name, 
        debug = False
    ):

    if debug: print(f"[DEBUG] Getting secret for project {secret_name} ...")
    
    secret_meta = None

    try:

        request = secretmanager_v1.GetSecretRequest(
            name=secret_name,
        )

        secret_meta = secret_client.get_secret(request=request)



    except Forbidden as e:
        
        if "does not have secretmanager.secrets.get access" in str(e):

            UtilityTools.print_403_api_denied("secretmanager.secrets.get", resource_name = secret_name)
                    
        elif "Secret Manager API has not been used in project" in str(e) and "before or it is disabled" in str(e):

            UtilityTools.print_403_api_disabled("Secrets Manager", secret_name)

            return "Not Enabled"

        return None

    except NotFound as e:
        if "404 Secret" in str(e):
            UtilityTools.print_404_resource(secret_name)

        return 404

    except Exception as e:

        UtilityTools.print_500(secret_name, "secretmanager.secrets.get", e)

        return None

    if debug: print(f"[DEBUG] Successfully called list_secrets for {secret_name} ...")
    
    return secret_meta


def list_secret_versions(
        secret_client, 
        parent, 
        debug = False
    ):

    if debug: print(f"[DEBUG] Listing secret versions for project {parent} ...")
    
    secrets_list_versions = []

    try:

        request = secretmanager_v1.ListSecretVersionsRequest(
            parent=parent,
        )
        secrets_list_versions = list(secret_client.list_secret_versions(request=request))

    except Forbidden as e:
        
        if "does not have secretmanager.versions.list access" in str(e):
            
            UtilityTools.print_403_api_denied("secretmanager.versions.list access", resource_name = parent)
                    
        elif "Secret Manager API has not been used in project" in str(e) and "before or it is disabled" in str(e):

            UtilityTools.print_403_api_disabled("Secrets Manager", parent)

            return "Not Enabled"

        return None

    except NotFound as e:
        if "404 Secret" in str(e):
            UtilityTools.print_404_resource(parent)

        return 404

    except Exception as e:
        UtilityTools.print_500(secret_name, "secretmanager.versions.list", e)
        
        return None

    if debug: print(f"[DEBUG] Successfully called list_secret_versions for {parent} ...")
    
    return secrets_list_versions

def get_secret_version(
        secret_client, 
        secret_name_version, 
        debug = False
    ):

    if debug:
        print(f"[DEBUG] Getting secret version {secret_name_version} ...")
    
    secret_meta_version = None

    try:

        request = secretmanager_v1.GetSecretVersionRequest(
            name=secret_name_version,
        )

        secret_meta_version = secret_client.get_secret_version(request=request)


    except Forbidden as e:
        
        if "does not have secretmanager.versions.get access" in str(e):
            
            UtilityTools.print_403_api_denied("secretmanager.versions.get access", resource_name = secret_name_version)
        
            return None
            
        elif "Secret Manager API has not been used in project" in str(e) and "before or it is disabled" in str(e):
                        
            UtilityTools.print_403_api_disabled("Secrets Manager", secret_name_version)

            return "Not Enabled"

        return None

    except NotFound as e:
        if "404 Secret" in str(e):
            UtilityTools.print_404_resource(secret_name_version)

        return 404

    except Exception as e:

        UtilityTools.print_500(secret_name_version, "secretmanager.versions.get", e)
        return None

    if debug: print(f"[DEBUG] Successfully called get_secret_version for {secret_name_version} ...")
    
    return secret_meta_version


def access_secret_value(
        secret_client, 
        secret_name_version, 
        debug = False
    ):

    if debug: print(f"[DEBUG] Getting secret version value for {secret_name_version} ...")
    
    secret_meta_version_value = None

    try:

        request = secretmanager_v1.AccessSecretVersionRequest(
            name=secret_name_version,
        )

        secret_meta_version_value = secret_client.access_secret_version(request=request)
            

    except Forbidden as e:
        
        if "does not have secretmanager.versions.access access" in str(e):

            UtilityTools.print_403_api_denied("secretmanager.versions.access", resource_name = secret_name_version)
                    
        elif "Secret Manager API has not been used in project" in str(e) and "before or it is disabled" in str(e):
            
            UtilityTools.print_403_api_disabled("Secrets Manager", secret_name_version)

            return "Not Enabled"

        return None

    except Exception as e:

        UtilityTools.print_500(secret_name_version, "secretmanager.versions.access", e)

        return None

    if debug: print(f"[DEBUG] Successfully called get_secret_version for {secret_name_version} ...")
    
    return secret_meta_version_value

def check_secret_permissions(secret_client, secret_name, debug = False):
    
    authenticated_permissions = []

    try:
        
        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=secret_name,
            permissions=[
                    'secretmanager.secrets.delete',
                    'secretmanager.secrets.get',
                    'secretmanager.secrets.getIamPolicy',
                    'secretmanager.secrets.setIamPolicy',
                    'secretmanager.secrets.update'
            ] 
                
        )
        
        authenticated_permissions = secret_client.test_iam_permissions(
            request=request
        )

        # Get list of allowed permissions
        authenticated_permissions = list(authenticated_permissions.permissions)

    except NotFound as e:
        if "404 Secret" in str(e):
            print(f"{UtilityTools.RED}[X] 404 The secret is not found for {parent}{UtilityTools.RESET}")
        return 404

    except Forbidden as e:
        print(f"[-] 403 The user does not have testIamPermissions permissions on {secret_name} ")
    
    except Exception as e:
        print("An unknown exception occurred when trying to call list_functions as follows:\n" + str(e))

    return authenticated_permissions


def check_secret_version_permissions(secret_client, secret_name_version, debug = False):
    
    authenticated_permissions = []

    try:
        
        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=secret_name_version,
            permissions=[
                    'secretmanager.versions.access',
                    'secretmanager.versions.destroy',
                    'secretmanager.versions.disable',
                    'secretmanager.versions.enable',
                    'secretmanager.versions.get'
            ] 
                
        )
        
        authenticated_permissions = secret_client.test_iam_permissions(
            request=request
        )

        # Get list of allowed permissions
        authenticated_permissions = list(authenticated_permissions.permissions)

    except Forbidden as e:
        print(f"[-] 403 The user does not have testIamPermissions permissions on {secret_name_version} ")
    
    except Exception as e:
        print("An unknown exception occurred when trying to call list_functions as follows:\n" + str(e))

    return authenticated_permissions