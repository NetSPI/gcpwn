import importlib, requests, importlib, argparse
from Modules.IAM.utils.util_helpers import organization_set_iam_policy,organization_get_iam_policy
from Modules.IAM.utils.util_helpers import folder_get_iam_policy, folder_set_iam_policy
from Modules.IAM.utils.util_helpers import project_get_iam_policy, project_set_iam_policy

from UtilityController import *

from google.cloud import storage
from google.cloud import functions_v2
from google.cloud import resourcemanager_v3
from google.cloud import compute_v1

from google.api_core.iam import Policy
from google.iam.v1 import iam_policy_pb2

from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import BadRequest

def add_project_iam_member(project_client, project_name, member, action_dict, brute = False, role = None, debug=False):
    
    policy_dict = {}
    additional_bind = {"role": role, "members": [member]}

    if brute:
        print(f"[*] Overwiting {project_name} to just be {member}")
        policy_dict["bindings"] = []
        policy_dict["bindings"].append(additional_bind)
        policy_dict["version"] = 1
        policy = policy_dict


    else:

        print(f"[*] Fetching current policy for {project_name}...")
        policy = project_get_iam_policy(project_client, project_name, debug=debug)

        if policy:

            if policy == 404:

                print(f"{UtilityTools.RED}[X] Exiting the module as {project_name} does not exist. Double check the name. {UtilityTools.RESET}")
                return -1

            else:

                action_dict.setdefault("project_permissions", {}).setdefault(project_name, set()).add("resourcemanager.projects.getIamPolicy")
                policy_dict["bindings"] = list(policy.bindings)
                policy_dict["bindings"].append(additional_bind)
                policy_dict["etag"] = policy.etag
                policy_dict["version"] = policy.version
                policy = policy_dict

        else:
            print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire folder IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
            return -1

    if policy != None:
        policy_bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {project_name} \n{policy_bindings}")

    else:
        print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
        return -1


    status = project_set_iam_policy(project_client, project_name, policy, debug=debug)
    if status:
        
        if status == 404:
            print(f"{UtilityTools.RED}[X] Exiting the module as {project_name} does not exist. Double check the name. {UtilityTools.RESET}")
            return -1

        else:
            action_dict.setdefault("folder_permissions", {}).setdefault(project_name, set()).add("resourcemanager.folders.setIamPolicy")
    
    return status

def add_folder_iam_member(folder_client, folder_name, member, action_dict, brute = False, role = None, debug=False):
    
    policy_dict = {}
    additional_bind = {"role": role, "members": [member]}
   
    if brute:
        print(f"[*] Overwiting {folder_name} to just be {member}")
        policy_dict["bindings"] = []
        policy_dict["bindings"].append(additional_bind)

        policy_dict["version"] = 1
        policy = policy_dict


    else:

        print(f"[*] Fetching current policy for {folder_name}...")
        policy = folder_get_iam_policy(folder_client, folder_name, debug=debug)

        if policy:

            if policy == 404:

                print(f"{UtilityTools.RED}[X] Exiting the module as {folder_name} does not exist. Double check the name. {UtilityTools.RESET}")
                return -1

            else:

                # Just assume v1 till I can get a better method
                action_dict.setdefault("folder_permissions", {}).setdefault(folder_name, set()).add("resourcemanager.folders.getIamPolicy")
                policy_dict["bindings"] = list(policy.bindings)
                policy_dict["bindings"].append(additional_bind)
                policy_dict["etag"] = policy.etag
                policy_dict["version"] = policy.version
                policy = policy_dict
        
        else:
            print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire folder IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
            return -1

    if policy != None:
        policy_bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {folder_name} \n{policy}")

    else:
        print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
        return -1

    status = folder_set_iam_policy(folder_client, folder_name, policy, debug=debug)
    if status:
        
        if status == 404:
            print(f"{UtilityTools.RED}[X] Exiting the module as {folder_name} does not exist. Double check the name. {UtilityTools.RESET}")
            return -1

        else:
            action_dict.setdefault("folder_permissions", {}).setdefault(folder_name, set()).add("resourcemanager.folders.setIamPolicy")
    
    return status


def add_organization_iam_member(organization_client, organization_name, member, action_dict, brute = False, role = None, debug=False):
    
    policy_dict = {}
    additional_bind = {"role": role, "members": [member]}
   
    if brute:
        print(f"[-] Could not call get_iam_policy for {organization_name}.")
        policy_dict["bindings"] = []
        policy_dict["bindings"].append(additional_bind)

        policy_dict["version"] = 1
        policy = policy_dict

    else:

        print(f"[*] Fetching current policy for {organization_name}...")
        policy = organization_get_iam_policy(organization_client, organization_name, debug=debug)

        if policy:

            if policy == 404:

                print(f"{UtilityTools.RED}[X] Exiting the module as {organization_name} does not exist. Double check the name. {UtilityTools.RESET}")
                return -1

            else:

                # Just assume v1 till I can get a better method
                action_dict.setdefault("organization_permissions", {}).setdefault(organization_name, set()).add("resourcemanager.organizations.getIamPolicy")
                policy_dict["bindings"] = list(policy.bindings)
                policy_dict["bindings"].append(additional_bind)
                policy_dict["etag"] = policy.etag
                policy_dict["version"] = policy.version
                policy = policy_dict
        
        else:
            print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire organization IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
            return -1

    if policy != None:
        policy_bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {organization_name} \n{policy}")

    else:
        print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
        return -1

    status = organization_set_iam_policy(organization_client, organization_name, policy, debug=debug)

    if status:
        
        if status == 404:
            print(f"{UtilityTools.RED}[X] Exiting the module as {organization_name} does not exist. Double check the name. {UtilityTools.RESET}")
            return -1

        else:
            action_dict.setdefault("organization_permissions", {}).setdefault(organization_name, set()).add("resourcemanager.organizations.setIamPolicy")
    
    return status


def check_project_permissions(authenticated_project_client, project_name, permissions, authenticated = True, debug = False):
    
    authenticated_permissions = []

    if authenticated_project_client and authenticated:

        try:

            request = iam_policy_pb2.TestIamPermissionsRequest(
                resource=project_name,
                permissions=permissions
            )
         
            authenticated_permissions = authenticated_project_client.test_iam_permissions(request=request)
            authenticated_permissions = authenticated_permissions.permissions


        except NotFound as e:
            print(f"[-] 404  {bucket_name} does not appear to exist ")
            authenticated_permissions_list = []

        except Forbidden as e:
            print(f"[-] 403 Bucket Exists, but the user does not have storage.testIamPermissions permissions on bucket {project_name} ")
            authenticated_permissions_list = []
        except Exception as e:
            print(f"[-] 403 TestIAMPermissions failed for {project_name} for the following reason:\n"+str(e))
            authenticated_permissions_list = []  

    return authenticated_permissions   

def check_folder_permissions(authenticated_folder_client, folder_name, permissions, authenticated = True, all_permissions = False, debug = False):

    authenticated_permissions = []
    if authenticated_folder_client and authenticated:
        try:
            # If client exists, use it to make an authenticated check
            
            request = iam_policy_pb2.TestIamPermissionsRequest(
                resource=folder_name,
                permissions=permissions
            )

            # Make the request
            authenticated_permissions = authenticated_folder_client.test_iam_permissions(request=request)
            authenticated_permissions = authenticated_permissions.permissions


        except NotFound as e:
            print(f"[-] 404  {bucket_name} does not appear to exist ")
            authenticated_permissions = []

        except Forbidden as e:
            print(f"[-] 403 Bucket Exists, but the user does not have storage.testIamPermissions permissions on bucket {folder_name} ")
            authenticated_permissions = []
        except Exception as e:
            print(f"[-] 403 TestIAMPermissions failed for {folder_name} for the following reason:\n"+str(e))
            authenticated_permissions = []  

    return authenticated_permissions          

def check_organization_permissions(authenticated_org_client, org_name, permissions, authenticated = True, unauthenticated = False, debug = False):
    authenticated_permissions = []

    if authenticated_org_client and authenticated:
        try:
            # If client exists, use it to make an authenticated check

            request = iam_policy_pb2.TestIamPermissionsRequest(
                resource=org_name,
                permissions=permissions
            )
            # Make the request
            authenticated_permissions = authenticated_org_client.test_iam_permissions(request=request)
            authenticated_permissions = authenticated_permissions.permissions

        except NotFound as e:
            print(f"[-] 404  {bucket_name} does not appear to exist ")
            authenticated_permissions = []

        except Forbidden as e:
            print(f"[-] 403 Bucket Exists, but the user does not have storage.testIamPermissions permissions on bucket {org_name} ")
            authenticated_permissions = []
        except Exception as e:
            print(f"[-] 403 TestIAMPermissions failed for {org_name} for the following reason:\n"+str(e))
            authenticated_permissions = []            

    return authenticated_permissions


def list_projects(project_client, parent_id, debug=False):
    
    if debug:
        print(f"[DEBUG] Listing projects in domain")

    projects_list = None

    try:

        request = resourcemanager_v3.ListProjectsRequest(
            parent=parent_id,
        )


        projects_list = list(project_client.list_projects(request=request))
    
    except Forbidden as e:
        if "does not have resourcemanager.projects.list" in str(e):
            print(f"[-] The user does not have 'resourcemanager.projects.list' to list projects")
    
    except Exception as e:
        print(str(e))
        print("[DEBUG] UNKNOWN EXCEPTION WHEN GETTING BLOB DETAILS")

    if debug:
        print(f"[DEBUG] Successful completed list_projects...")     
    
    return projects_list

def list_folders(folder_client, parent_id, debug=False):
    
    if debug:
        print(f"[DEBUG] Listing folders in domain")

    folders_list = None
    
    try: 

        request = resourcemanager_v3.ListFoldersRequest(
            parent=parent_id,
        )


        folders_list = list(folder_client.list_folders(request=request))

    except Forbidden as e:
        if "does not have resourcemanager.folders.list" in str(e):
            print(f"[-] The user does not have 'resourcemanager.folders.list' to list folders")

    except Exception as e:
        print(str(e))
        print("[DEBUG] UNKNOWN EXCEPTION WHEN GETTING BLOB DETAILS")

    if debug:
        print(f"[DEBUG] Successful completed list_folders...") 
    
    return folders_list


###### Get/List Orgs/Folders/Projects
def search_organizations(resource_client, debug=False):

    if debug:
        print(f"[DEBUG] Listing organizations in domain")
    
    organizations_list = None

    try:

        request = resourcemanager_v3.SearchOrganizationsRequest()
        organizations_list = list(resource_client.search_organizations(request=request))
       
    except Forbidden as e:
        if "does not have resourcemanager.organizations.get" in str(e):
            UtilityTools.print_403_api_denied("resourcemanager.organizations.get")
        
        elif f"Cloud Resource Manager API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
             UtilityTools.print_403_api_disabled("Resource Manager", "Current Organization")
             return "Not Enabled"
        print(str(e))
        return None

    except NotFound as e:
        if "was not found" in str(e):
            UtilityTools.print_404_resource("CURRENT ORGANIZATION")
            
        return None

    except Exception as e:
        UtilityTools.print_500("Current Organization", "resourcemanager.organizations.get", e)
        return None    


    if debug:
        print(f"[DEBUG] Successful completed list_organizations...")

    return organizations_list

# To do another way to gather projects if this fails.
def search_projects(project_client, debug=False):
    
    if debug:
        print(f"[DEBUG] Searching projects in domain")    
    
    projects_list = None
   
    try:

        request = resourcemanager_v3.SearchProjectsRequest()
        projects_list = list(project_client.search_projects(request=request))


    except Forbidden as e:
        if "does not have resourcemanager.projects.get" in str(e):
            UtilityTools.print_403_api_denied("resourcemanager.projects.get")
        
        elif f"Cloud Resource Manager API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
             UtilityTools.print_403_api_disabled("Resource Manager", "Current Project")
             return "Not Enabled"

        return None

    except NotFound as e:
        if "was not found" in str(e) and f"{project_id}" in str(e):
            UtilityTools.print_404_resource(project_id)
            
        return None

    except Exception as e:
        UtilityTools.print_500("Current Project", "resourcemanager.projects.get", e)
        return None    
    
    if debug:
        print(f"[DEBUG] Successfully completed search_projects...") 

    return projects_list

def search_folders(folder_client, debug=False):

    if debug:
        print(f"[DEBUG] Searching folders in domain")    

    folders_list = None

    try:

        request = resourcemanager_v3.SearchFoldersRequest()
        folders_list = list(folder_client.search_folders(request=request))


    except Forbidden as e:
        if "does not have resourcemanager.folders.get" in str(e):
            UtilityTools.print_403_api_denied("resourcemanager.folders.get")
        
        elif f"Cloud Resource Manager API has not been used in project" in str(e) and "before or it is disabled. Enable it by visiting" in str(e):
             UtilityTools.print_403_api_disabled("Resource Manager", "Current Project")
             return "Not Enabled"

        return None

    except NotFound as e:
        if "was not found" in str(e):
            UtilityTools.print_404_resource("CURRENT FOLDER")
            
        return None

    except Exception as e:
        UtilityTools.print_500("Current Folder", "resourcemanager.folders.get", e)
        return None    

    if debug:
        print(f"[DEBUG] Successfully completed search_folders...") 

    return folders_list