import argparse, json, importlib
from google.cloud import iam_admin_v1, iam_credentials_v1, compute_v1, functions_v2, storage, resourcemanager_v3, secretmanager_v1
from google.iam.v1 import iam_policy_pb2 
from UtilityController import *
import os

from google.oauth2 import service_account  # type: ignore
import googleapiclient.discovery  # type: ignore
from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.protobuf.json_format import MessageToDict

########## Parse Bindings
def parse_iam_bindings_by_members(bindings, session, type_of_resource, name, project_id, policy_type = None):
    try:        

        display_name_data = None
        all_permissions = {}

        if type_of_resource in ["project", "org", "folder"]:
            display_name_data = session.get_display_name(name)
        for binding in bindings:
            if policy_type == "google.api_core.iam.Policy":
                all_members = binding["members"]
                role = binding["role"]
            else:
                all_members = binding.members
                role = binding.role

            for member in all_members:

                if member in all_permissions.keys():
                    if role not in all_permissions[member]["roles"]:
                        all_permissions[member]["roles"] = all_permissions[member]["roles"] + [role]
                else:
                    all_permissions[member] = {
                        "type":type_of_resource,
                        "roles": [role],
                        "name": name,
                        "project_id":project_id
                    }   

                    if display_name_data:
                        all_permissions[member]["display_name"] = display_name_data[0]["display_name"],
                  
        save_iam_bindings(session, all_permissions, display_name_data = display_name_data)
        
    except Exception as e:
        print("Saving the IAM binding failed for the following reason")
        print(str(e))


########## SAVE ROLES

def save_service_account_key(service_account,session):
    table_name = 'iam-sa-keys'

    save_data = {}
    
    if service_account.name: save_data["name"] = service_account.name
    if service_account.private_key_type: save_data["private_key_type"] = service_account.private_key_type
    if service_account.key_algorithm: save_data["key_algorithm"] = service_account.key_algorithm
    if service_account.private_key_data: save_data["private_key_data"] = service_account.private_key_data
    if service_account.public_key_data: save_data["public_key_data"] = service_account.public_key_data
    if service_account.valid_after_time: save_data["valid_after_time"] = service_account.valid_after_time
    if service_account.valid_before_time: save_data["valid_before_time"] = service_account.valid_before_time
    if service_account.key_origin: save_data["key_origin"] = service_account.key_origin
    if service_account.key_type: save_data["key_type"] = service_account.key_type
    if service_account.disabled: 
        save_data["disabled"] = service_account.disabled
    # assume enabled if not set
    else:
        save_data["disabled"] = False

    session.insert_data(table_name, save_data)

def save_service_account(service_account,session, credname = None):
    table_name = 'iam-principals'

    save_data = {}
    
    if credname: save_data["credname"] = credname

    if service_account.name: save_data["name"] = service_account.name
    if service_account.project_id: save_data["project_id"] = service_account.project_id
    if service_account.unique_id: save_data["unique_id"] = service_account.unique_id
    if service_account.email: save_data["email"] = service_account.email
    if service_account.display_name: save_data["display_name"] = service_account.display_name
    if service_account.etag: save_data["etag"] = service_account.etag
    if service_account.description: save_data["description"] = service_account.description
    if service_account.oauth2_client_id: save_data["oauth2_client_id"] = service_account.oauth2_client_id
    if service_account.disabled: save_data["disabled"] = service_account.disabled

    save_data["type"]="service_account"

    session.insert_data(table_name, save_data)

def save_iam_role(role,session, scope = None):
    table_name = 'iam-roles'

    save_data = {}
    if scope: save_data["scope_of_custom_role"] = scope
    if role.name: save_data["name"] = role.name
    if role.title: save_data["title"] = role.title
    if role.description: save_data["description"] = role.description
    if role.included_permissions: save_data["included_permissions"] = role.included_permissions
    if role.stage: save_data["stage"] = role.stage
    if role.etag: save_data["etag"] = role.etag
    if role.deleted: save_data["deleted"] = role.deleted
    session.insert_data(table_name, save_data)

def save_iam_bindings(session, all_permissions, display_name_data = None):
    
    table_name = "iam-bindings"
    for key in all_permissions.keys():
        save_data = {}
        save_data["type"] = all_permissions[key]["type"]
        save_data["roles"] = all_permissions[key]["roles"]
        if display_name_data: save_data["display_name"] = all_permissions[key]["display_name"][0]
        save_data["name"] = all_permissions[key]["name"]
        save_data["project_id"] = all_permissions[key]["project_id"]
        save_data["member"] = key
        session.insert_data(table_name, save_data)


def iam_disable_service_account_key(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM access token for {sa_name} ..")

    status = None

    try:
        request = iam_admin_v1.DisableServiceAccountKeyRequest(
            name=sa_name,
        )

        # For some reason this does not throw an error and just returns none if fails :/ 
        status = iam_client.disable_service_account_key(request=request)

    except Forbidden as e:
        if "does not have iam.serviceAccountKeys.disable" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccountKeys.disable permissions")

    except Exception as e:
        print(f"The iam.serviceAccountKeys.disable operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed IAM disable_service_account_key ..")

    return status

def iam_enable_service_account_key(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM access token for {sa_name} ..")

    status = None

    try:
        request = iam_admin_v1.EnableServiceAccountKeyRequest(
            name=sa_name,
        )

        # For some reason this does not throw an error and just returns none if fails :/ 
        status = iam_client.enable_service_account_key(request=request)

    except Forbidden as e:
        if "does not have iam.serviceAccountKeys.enable" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccountKeys.enable permissions")

    except Exception as e:
        print(f"The iam.serviceAccountKeys.enable operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed IAM enable_service_account_key ..")

    return status

# private_key_data only provided in this APi call so store and use for later
def iam_generate_service_account_key(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM access token for {sa_name} ..")

    name_account_key = None

    try:
        request = iam_admin_v1.CreateServiceAccountKeyRequest(
            name=sa_name,
        )

        # For some reason this does not throw an error and just returns none if fails :/ 
        name_account_key = iam_client.create_service_account_key(request=request)

    except Forbidden as e:
        if "does not have iam.serviceAccountKeys.create" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccountKeys.create permissions")

    except Exception as e:
        print(f"The iam.serviceAccountKeys.create operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed IAM generate_service_account_key ..")

    return name_account_key

def iam_generate_access_token(iam_client, sa_name, delegation = None, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM access token for {sa_name} ..")

    name_access_token = None

    try:
        request = iam_credentials_v1.GenerateAccessTokenRequest(
            name=sa_name,
            scope=[
                "https://www.googleapis.com/auth/cloud-platform"
            ]
        )
        if delegation:
            request.delegates = delegation

        name_access_token = iam_client.generate_access_token(request=request)
    
    # API Seems bugged and does not return Forbidden on access error
    except Forbidden as e:
        if "does not have iam.serviceAccounts.getAccessToken" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccounts.getAccessToken permissions")
        else:
            print(str(e))
    except Exception as e:
        print(f"The iam.serviceAccounts.getAccessToken operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed IAM generate_access_token ..")
    
    if not name_access_token:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Was unable to get access token for {sa_name}, most likely permission denied{UtilityTools.RESET}")

    return name_access_token

def get_custom_role(iam_client, role_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting {role_name} ..")

    role = None

    try:
        request = iam_admin_v1.GetRoleRequest(
            name=role_name
        )
        role = iam_client.get_role(request=request)

    except Forbidden as e:
        if "does not have iam.roles.get" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have iam.roles.get permissions{UtilityTools.RESET}")

    except NotFound as e:
        if f"404 The role named {role_name} was not found." in str(e):
            print(f"{UtilityTools.RED}[X] 404: The role does not appear to exist in the specified project{UtilityTools.RESET}")

    except Exception as e:
        print(f"The iam.roles.get operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print(f"[DEBUG] Successfully completed organization getIamPolicy ..")
    
    return role


def iam_list_roles(iam_client, parent, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM bindings for {parent} ..")

    iam_roles = None

    try:
        request = iam_admin_v1.ListRolesRequest(
            parent=parent,
            view=1,
            page_size=900
        )
        iam_roles = list(iam_client.list_roles(request=request))

    except Forbidden as e:
        if "does not have iam.roles.list" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have iam.roles.list permissions{UtilityTools.RESET}")

    except Exception as e:
        print(f"The iam.roles.list operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print(f"[DEBUG] Successfully completed organization getIamPolicy ..")
    
    return iam_roles

def organization_set_iam_policy(organization_client, organization_name, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {organization_name} ...")
   
    organization_iam_policy = None

    try:


        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=organization_name,
            policy=policy
        )
        organization_iam_policy = organization_client.set_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Organization {organization_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have resourcemanager.organizations.setIamPolicy" in str(e):
            print(f"[X] 403: The user does not have resourcemanager.organizations.setIamPolicy permissions")

    except Exception as e:
        print(f"The resourcemanager.organizations.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed organizations getIamPolicy ..")

    return organization_iam_policy

def folder_set_iam_policy(folder_client, folder_name, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {folder_name} ...")
   
    folder_iam_policy = None

    try:


        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=folder_name,
            policy=policy
        )


        folder_iam_policy = folder_client.set_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Folder {folder_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have resourcemanager.folders.setIamPolicy" in str(e):
            print(f"[X] 403: The user does not have resourcemanager.folders.setIamPolicy permissions")

    except Exception as e:
        print(f"The resourcemanager.folders.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed folder getIamPolicy ..")

    return folder_iam_policy


def project_set_iam_policy(project_client, project_name, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {project_name} ...")
   
    project_iam_policy = None

    try:


        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=project_name,
            policy=policy
        )


        project_iam_policy = project_client.set_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Project {project_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have resourcemanager.projects.setIamPolicy" in str(e):
            print(f"[X] 403: The user does not have resourcemanager.projects.setIamPolicy permissions")

    except Exception as e:
        print(f"The resourcemanager.projects.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed projects getIamPolicy ..")

    return project_iam_policy

def project_get_iam_policy(project_client, project_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {project_name} ...")
    

    project_iam_policy = None

    try:

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=project_name
        )


        project_iam_policy = project_client.get_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Project {project_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have resourcemanager.projects.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have resourcemanager.projects.getIamPolicy permissions")

    except Exception as e:
        print(f"The resourcemanager.projects.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return project_iam_policy


def folder_get_iam_policy(folder_client, folder_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {folder_name} ...")
   
    folder_iam_policy = None

    try:

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=folder_name
        )

        folder_iam_policy = folder_client.get_iam_policy(request=request)
    
    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Folder {folder_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have resourcemanager.folders.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have resourcemanager.folders.getIamPolicy permissions")

    except Exception as e:
        print(f"The resourcemanager.folders.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return folder_iam_policy


def organization_get_iam_policy(organization_client, organization_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {organization_name} ...")
   
    organization_iam_policy = None

    try:

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=organization_name
        )

        organization_iam_policy = organization_client.get_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Organization {organization_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have resourcemanager.organizations.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have resourcemanager.organizations.getIamPolicy permissions")
        elif "denied on resource" in str(e) and "(or it may not exist)" in str(e):
            print(f"[X] 403: The user does not have permissions on this organization (or it may not exist)")


    except Exception as e:
        print(f"The resourcemanager.organizations.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return organization_iam_policy


def instance_set_iam_policy(instance_client, instance_name, project_id, zone_id, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {instance_name} ...")
   
    instances_iam_policy = None

    try:

        zone_set_policy_request_resource = {
            "policy": policy
        }
        request = compute_v1.SetIamPolicyInstanceRequest(
            project = project_id,
            resource=instance_name,
            zone=zone_id,
            zone_set_policy_request_resource=zone_set_policy_request_resource
        )
        
        instances_iam_policy = instance_client.set_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Instance {instance_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have compute.instances.setIamPolicy" in str(e):
            print(f"[X] 403: The user does not have cloudfunctions.functions.getIamPolicy permissions")

    except Exception as e:
        print(f"The compute.instances.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed instances getIamPolicy ..")

    return instances_iam_policy

def instance_get_iam_policy(instance_client, instance_name, project_id, zone_id, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {instance_name} ...")
   
    instances_iam_policy = None
    try:
        request = compute_v1.GetIamPolicyInstanceRequest(
            project=project_id,
            resource=instance_name,
            zone=zone_id,
        )

        # Make the request
        instances_iam_policy = instance_client.get_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Instance {instance_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have compute.instances.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have compute.instances.getIamPolicy permissions")

    except Exception as e:
        print(f"The compute.instances.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed instances getIamPolicy ..")

    return instances_iam_policy



def bucket_set_iam_policy(storage_client, bucket_name, policy, debug = False):

    status = None

    try:
        
        bucket_object  = storage_client.bucket(bucket_name)
        status = bucket_object.set_iam_policy(policy)
    
    except NotFound as e:
        
        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Bucket {bucket_name} does not exist.")
        
        return 404

    except Forbidden as e:
        print("[X] User is not allowed to call storage.buckets.setIamPolicy on existing bucket.")
    

    except Exception as e:
        print("[X] The buckets set IAM policy has failed for uknonw reasons shown below:")
        print(str(e))
    
    return status

def bucket_get_iam_policy(storage_client, bucket_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {bucket_name} ...")
   
    bucket_iam_policy = None

    try:

        bucket_object  = storage_client.bucket(bucket_name)
        bucket_iam_policy = bucket_object.get_iam_policy()

    except NotFound as e:

        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Bucket {bucket_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have storage.buckets.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have storage.buckets.getIamPolicy permissions")


    except Exception as e:
        print(f"The storage.buckets.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed buckets getIamPolicy ..")

    return bucket_iam_policy





def secret_set_iam_policy(secret_client, secret_name, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {secret_name} ...")
   
    secret_iam_policy = None

    try:

        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=secret_name,
            policy=policy
        )
        secret_iam_policy = secret_client.set_iam_policy(request=request)

    except NotFound as e:
      

        return 404

    except Forbidden as e:
        if "does not have secretmanager.secrets.setIamPolicy" in str(e):
            print(f"[X] 403: The user does not have cloudfunctions.functions.setIamPolicy permissions")

    except Exception as e:
        print(f"The secretmanager.secrets.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return secret_iam_policy

def secret_get_iam_policy(secret_client, secret_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {secret_name} ...")
   
    secret_iam_policy = None

    try:

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=secret_name
        )
        secret_iam_policy = secret_client.get_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Bucket {bucket_name} does not exist.")

        return 404
    except Forbidden as e:
        if "does not have secretmanager.secrets.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have secretmanager.secrets.getIamPolicy permissions")

    except Exception as e:
        print(f"The secretmanager.secrets.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return secret_iam_policy







def cloudfunction_set_iam_policy(function_client, function_name, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {function_name} ...")
   
    functions_iam_policy = None

    try:

        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=function_name,
            policy=policy
        )
        functions_iam_policy = function_client.set_iam_policy(request=request)

    except NotFound as e:
        if "404" in str(e) and "was not found" in str(e):
            print(f"[X] 404: Function {function_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have cloudfunctions.functions.setIamPolicy" in str(e):
            print(f"[X] 403: The user does not have cloudfunctions.functions.getIamPolicy permissions")

    except Exception as e:
        print(f"The cloudfunctions.functions.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return functions_iam_policy

def cloudfunction_get_iam_policy(function_client, function_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {function_name} ...")
   
    functions_iam_policy = None

    try:

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=function_name
        )
        functions_iam_policy = function_client.get_iam_policy(request=request)
    except NotFound as e:
        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Bucket {bucket_name} does not exist.")

        return 404
    except Forbidden as e:
        if "does not have cloudfunctions.functions.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have cloudfunctions.functions.getIamPolicy permissions")

    except Exception as e:
        print(f"The cloudfunctions.functions.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print(f"[DEBUG] Successfully completed functions getIamPolicy ..")

    return functions_iam_policy


def compute_instance_get_iam_policy(instance_client, project_id, instance_name, zone_id, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {instance_name} ...")
   
    instances_iam_policy = None

    try:
        request = compute_v1.GetIamPolicyInstanceRequest(
            project=project_id,
            resource=instance_name,
            zone=zone_id,
        )

        # Make the request
        instances_iam_policy = instance_client.get_iam_policy(request=request)


    except Forbidden as e:
        if "does not have compute.instances.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have compute.instances.getIamPolicy permissions")

    except Exception as e:
        print(f"The compute.instances.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed instances getIamPolicy ..")

    return instances_iam_policy




def list_service_accounts(iam_client, project_id, debug = None):
    """Lists all service accounts for the current project."""

    if debug:
        print(f"[DEBUG] Getting IAM service accounts for {project_id} ...")

    service_account_list = []

    try:

        request = iam_admin_v1.ListServiceAccountsRequest(
            name=f"projects/{project_id}",
        )
        service_account_list = list(iam_client.list_service_accounts(request=request))

    except Forbidden as e:
        if "does not have iam.serviceAccounts.list" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccounts.list permissions")

        elif "Identity and Access Management (IAM) API has not been used in project" in str(e):
            print(f"[X] 403: Identity and Access Management (IAM) API has not been used or enabled")

        return None

    except Exception as e:
        print(f"The iam.serviceAccounts.list operation failed for unexpected reasons. See below:")
        print(str(e))
        return None
        
    if debug:
        print(f"[DEBUG] Successfully completed list_service_accounts ..")

    return service_account_list

def get_service_account(iam_client, email, debug = None):
    """Lists all service accounts for the current project."""

    if debug:
        print(f"[DEBUG] Getting IAM service account for {email} ...")

    service_account = None

    try:

        request = iam_admin_v1.GetServiceAccountRequest(
            name=f"projects/-/serviceAccounts/{email}",
        )

        service_account = iam_client.get_service_account(request=request)

    except Forbidden as e:

        if "does not have iam.serviceAccounts.get" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccounts.get permissions")

        elif "Identity and Access Management (IAM) API has not been used in project" in str(e):
            print(f"[X] 403: Identity and Access Management (IAM) API has not been used or enabled")

    except Exception as e:
        print(f"The iam.serviceAccounts.get operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed get_service_account ..")

    return service_account

def check_sa_permissions(iam_client, name, debug=False):

    if debug:
        print(f"[DEBUG] Testing IAM permissions for {name} ...")


    base_permissions = [
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.delete",
        "iam.serviceAccounts.disable",
        "iam.serviceAccounts.enable",
        "iam.serviceAccounts.get",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getIamPolicy",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.setIamPolicy",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
        "iam.serviceAccounts.undelete",
        "iam.serviceAccounts.update"
    ]

    allowed_permissions = None

    try:

        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=name,
            permissions=base_permissions,
        )
        allowed_permissions = iam_client.test_iam_permissions(request=request)
        allowed_permissions = list(allowed_permissions.permissions)

    except Exception as e:
        print(f"The sa testiampermissions operation failed for unexpected reasons. See below:")
        print(str(e))  

    return allowed_permissions

def list_service_account_keys(iam_client, name, debug = None):

    if debug:
        print(f"[DEBUG] Getting IAM service accounts for {name} ...")

    service_account_key_list = None

    try:

        request = iam_admin_v1.ListServiceAccountKeysRequest(
            name=name,
        )
        service_account_key_list = list(iam_client.list_service_account_keys(request=request).keys)

    except Forbidden as e:
        if "does not have iam.serviceAccounts.list" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccounts.list permissions")

    except Exception as e:
        print(f"The iam.serviceAccounts.list operation failed for unexpected reasons. See below:")
        print(str(e))  

    return service_account_key_list

def get_service_account_key(iam_client, key_name, debug = None):

    if debug:
        print(f"[DEBUG] Getting IAM service account key {key_name} ...")

    service_account_key = None

    try:

        request = iam_admin_v1.GetServiceAccountKeyRequest(
            name=key_name,
        )
        service_account_key = iam_client.get_service_account_key(request=request)

    except Forbidden as e:
        if "does not have iam.serviceAccounts.get" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccounts.get permissions")

    except Exception as e:
        print(f"The iam.serviceAccounts.get operation failed for unexpected reasons. See below:")
        print(str(e))  

    return service_account_key

def sa_get_iam_policy(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM bindings for {sa_name} ...")
   
    sa_iam_policy = None

    try:
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=sa_name,
        )
        sa_iam_policy = iam_client.get_iam_policy(request=request)


    except Forbidden as e:
        if "does not have iam.serviceAccounts.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have iam.serviceAccounts.getIamPolicy permissions")

    except Exception as e:
        print(f"The iam.serviceAccounts.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed service accounts getIamPolicy ..")

    return sa_iam_policy
