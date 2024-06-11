import pandas as pd
import ast
import json
import argparse
import traceback
import importlib
from UtilityController import *
from collections import Counter, defaultdict

from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from DataController import DataController
import datetime



def load_in_yaml_rules():
    
    yaml_rules = load_permission_mapping()
    main_permission_counts = Counter()
    single_role_dict = {}
    multi_role_dict = defaultdict(list)    # Check each main_permission against other rules' IDs
    for rule in yaml_rules:
        main_permission = rule["main_permission"]
        if main_permission != "None":
            main_permission_counts[main_permission] = 0

    # Check each main_permission against other rules' IDs
    for rule in yaml_rules:
        main_permission = rule["main_permission"]
        if main_permission != "None":
            for other_rule in yaml_rules:
                if rule != other_rule and main_permission in other_rule["id"]:
                    main_permission_counts[main_permission] += 1

    # Separate the rules based on main_permission counts
    for rule in yaml_rules:
        main_permission = rule["main_permission"]
        if main_permission != "None":
            if main_permission_counts[main_permission] == 0:
                single_role_dict[main_permission] = rule
            else:
                related_rules = [other_rule for other_rule in yaml_rules if main_permission in other_rule["id"]]
                multi_role_dict[main_permission].extend(related_rules)

    return single_role_dict, multi_role_dict

#### Current Permissions Incoming Format
# {
#     "credname": "username",
#     "organization_actions_allowed": {
#         "organizations/#": [
#             "resourcemanager.hierarchyNodes.deleteTagBinding",
#             "orgpolicy.constraints.list",
#         ]
#     },
#     "project_actions_allowed": {
#         "project_id_1": [
#             "compute.instances.setMetadata",
#             "iam.roles.get"
#         ],
#         "project_id_2": [
#             "compute.instances.setMetadata",
#             "resourcemanager.hierarchyNodes.deleteTagBinding",
#         ]
#     },
#     "folder_actions_allowed": {
#         "folders/#": [
#             "resourcemanager.projects.setIamPolicy",
#         ],
#         "folders/#": [
#             "resourcemanager.projects.setIamPolicy",
#             "resourcemanager.hierarchyNodes.deleteTagBinding",
#         ]
#     },
#     "storage_actions_allowed": {
#         "project_id": {
#             "storage.buckets.get": {
#                 "buckets": [
#                     "bucket_1",
#                     "bucket_2",
#                 ]
#             },
#             "storage.buckets.delete": {
#                 "buckets": [
#                     "bucket_1",
#                     "bucket_2",
#                 ]
#             },
#         },
# ...

            
def generate_summary_of_permission_vulns(
    current_permissions,
    session,
    check_permission_vulns=False,
    snapshot = False,
    first_run=False,
    output_file=None,
    csv=False,
    txt=False,
    stdout=False
):  

    credname = current_permissions.pop("credname")
    resources = DataController.read_resource_file()
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    output = output_file if output_file else "Vuln_Permission_Summary" if check_permission_vulns else f"Snapshots/Permission_Summary_{credname}_{timestamp}" if snapshot else "Permission_Summary" 
    
    txt_output = UtilityTools.get_save_filepath(session.workspace_directory_name,f"{output}.txt", "Reports") if txt else None
    csv_output = UtilityTools.get_save_filepath(session.workspace_directory_name,f"{output}.csv", "Reports") if csv else None

    csv_rows = []
    formatted_string = ""

    if stdout or txt:
        formatted_string = f"[******] Permission Summary for {credname} [******]\n"
    
    if current_permissions:

        if check_permission_vulns:

            perm_output = populate_permission_vulnerabilities(session, current_permissions)
            
            if perm_output:
                direct_issues = perm_output["direct"]
                for issue in direct_issues:
                    row = {
                        "issue_id": issue["issue_id"],
                        "credname": credname,
                        "issue_title": issue["issue_title"],
                        "issue_type": "PERMISSION_DIRECT",
                        "issue_permission": issue["permission"],
                        "permission_mappings": issue["permission_mappings"],
                        "asset_type": issue["resource_type"],
                        "asset_name": issue["resource_names"],
                        "asset_project_id": issue["project_id"]
                    }
                    csv_rows.append(row)
                    formatted_string += (
                        f"\nIssue ID: {issue['issue_id']}\n"
                        f"Issue Title: {issue['issue_title']}\n"
                        f"Issue Impacted Permission: {issue['permission']}\n"
                        f"Issue Resource Type: {issue['resource_type']}\n"
                        f"Issue Resource Name: {issue['resource_names']}\n"
                        f"Issue Project Id: {issue['project_id']}\n"
                        f"Issue Permission Mappings: {issue['permission_mappings']}\n"
                    )
        else:

            # Get list of permissions to bold Red
            yaml_stuff = load_permission_mapping()
            permissions_list = [data['permission'] for data in yaml_stuff if data.get('main_permission') != "None"]

            # If stdout/txt make formatted string
            if stdout or txt:
                for resource_key, gen_perms in current_permissions.items():
                    if resource_key in ['project_actions_allowed', 'folder_actions_allowed', 'organization_actions_allowed']:
                        base_permissions = {
                            'project_actions_allowed': "Project",
                            'folder_actions_allowed': "Folder",
                            'organization_actions_allowed': "Organization"
                        }.get(resource_key, "")
                        
                        section_content = ""

                        for asset_name, permission_list in gen_perms.items():
                            asset_content = f"  - {asset_name}\n"
                            for permission in sorted(permission_list):
                                asset_content += (
                                    f"{UtilityTools.RED}{UtilityTools.BOLD}    - {permission}{UtilityTools.RESET}\n"
                                    if permission in permissions_list or ".setIamPolicy" in permission
                                    else f"    - {permission}\n"
                                )
                            section_content += asset_content

                        if section_content:
                            formatted_string += f"- {base_permissions} Permissions\n{section_content}"
                    else:
                        # TODO Make title better
                        header = f"- {resource_key.replace('_', ' ').title()} Permissions\n"
                        section_content = ""

                        for project_id, permission_list in gen_perms.items():
                            project_asset_string = ""
                            for permission_name, asset_descriptions in permission_list.items():
                                permissions_asset_string = "".join(
                                    f"      - {asset_name} ({asset_type})\n"
                                    for asset_type, asset_list in asset_descriptions.items()
                                    for asset_name in asset_list if asset_list
                                )
                                if permissions_asset_string:
                                    project_asset_string += (
                                        f"{UtilityTools.RED}{UtilityTools.BOLD}    - {permission_name}{UtilityTools.RESET}\n{permissions_asset_string}"
                                        if permission_name in permissions_list or ".setIamPolicy" in permission_name
                                        else f"    - {permission_name}\n{permissions_asset_string}"
                                    )
                            if project_asset_string:
                                section_content += f"  - {project_id}\n{project_asset_string}"

                        if section_content:
                            formatted_string += header + section_content

            if csv:
                for resource_key, gen_perms in current_permissions.items():
                    if resource_key in ['project_actions_allowed', 'folder_actions_allowed', 'organization_actions_allowed']:
                        base_permissions = {
                            'project_actions_allowed': "Project",
                            'folder_actions_allowed': "Folder",
                            'organization_actions_allowed': "Organization"
                        }.get(resource_key, "")
                        for asset_name, permissions in gen_perms.items():
                            
                            project_id = asset_name if resource_key == 'project_actions_allowed' else "N/A"

                            for permission in permissions:
                                event = {
                                    "Credname": credname,
                                    "Permission": permission,
                                    "Asset Type": base_permissions,
                                    "Asset Name": asset_name,
                                    "Project_ID": project_id,
                                    "Flagged": "True" if permission in permissions_list or ".setIamPolicy" in permission else "False"
                                }
                                csv_rows.append(event)
                    else:
                        for project_id, permission_list in gen_perms.items():
                            for permission_name, asset_descriptions in permission_list.items():
                                for asset_type, asset_list in asset_descriptions.items():
                                    for asset_name in asset_list:
                                        event = {
                                            "Credname": credname,
                                            "Permission": permission_name,
                                            "Asset Type": asset_type,
                                            "Asset Name": asset_name,
                                            "Project_ID": project_id,
                                            "Flagged": "True" if permission_name in permissions_list or ".setIamPolicy" in permission_name else "False"
                                        }
                                        csv_rows.append(event)

    if stdout:
        print(formatted_string)

    if txt and txt_output:
        mode = "w" if first_run else "a"
        with open(txt_output, mode) as txt_file:
            txt_file.write(formatted_string)

    if csv and csv_output:
        df = pd.DataFrame(csv_rows)
        mode = "w" if first_run else "a"
        header = first_run  # Write header only if it's the first run
        df.to_csv(csv_output, mode=mode, header=header, index=False)


def populate_permission_vulnerabilities(session, all_credname_resources_dict):
   
    single_role_dict, multi_role_dict = load_in_yaml_rules()

    existing_vulns = {
        "direct": []
    }

    def extend_vulns(findings):
        if findings:
            existing_vulns["direct"].extend(findings)

    extend_vulns(permission_only_single_permission(session, single_role_dict, all_credname_resources_dict))
    extend_vulns(permission_only_multi_permission(session, multi_role_dict, all_credname_resources_dict))

    return existing_vulns


def permission_only_single_permission(session, single_role_dict, all_resources_dict):
    vuln_ids = []

    def process_permission(permission_name, asset_category, resource_name, project_id=None, all_affected_resources=None):
        for issue_id, rule in single_role_dict.items():
            if rule["permission"] == permission_name:
                if asset_category == "organization_actions_allowed":
                    asset_category = "organization"
                elif asset_category == "folder_actions_allowed":
                    asset_category = "folder"
                elif asset_category == "project_actions_allowed":
                    asset_category = "project"

                vuln_entry = {
                    "issue_id": issue_id,
                    "issue_title": rule["issue"],
                    "permission": permission_name,
                    "resource_type": asset_category,
                    "permission_mappings": "N/A",
                    "project_id": project_id if project_id else "N/A",
                    "resource_names": all_affected_resources if all_affected_resources else resource_name
                }
                vuln_ids.append(vuln_entry)

    for asset_category, all_asset_information in all_resources_dict.items():
        if asset_category in ["organization_actions_allowed", "folder_actions_allowed", "project_actions_allowed"]:
            for resource_name, permissions in all_asset_information.items():
                project_id = resource_name if asset_category == "project_actions_allowed" else None
                for permission_name in permissions:
                    process_permission(permission_name, asset_category, resource_name, project_id = project_id)
        else:
            for project_id, specific_resource_info in all_asset_information.items():
                for permission_name, asset_types in specific_resource_info.items():
                    for asset_type, all_affected_resources in asset_types.items():
                        process_permission(permission_name, asset_type, project_id, project_id = project_id, all_affected_resources = all_affected_resources)

    return vuln_ids

# TODO ADD CHECK TO TAKE SET OF RESOURCES TO NO TDO DIFF RESOURCES
def permission_only_multi_permission(session, multi_role_dict, all_resources_dict):
    vuln_ids = []

    for issue_id, rules in multi_role_dict.items():
        permissions_list = [rule["permission"] for rule in rules]

        # Go through each rule in the rule set tied to an issue and make sure we have those permissions
        for rule in rules:
            main_permission = rule["main_permission"]

            # If the main permission ID appears in EVERY other rule in this rule set then it must be the "main permission"
            if main_permission != "None" and all(main_permission in rule["id"] for rule in rules):
                issue_id = main_permission
                issue_title = rule["issue"]
                required_permission = rule["permission"]

                # Go through each asset, if perm is found at resource level check all permissions on that resource OR on the project level; TODO be more dynamic
                for asset_type, all_asset_information in all_resources_dict.items():
                    if asset_type in ["organization_actions_allowed", "folder_actions_allowed", "project_actions_allowed"]:
                        for resource_name, permissions in all_asset_information.items():
                            
                            # If main permission in permissions in org/project/folder
                            if required_permission in permissions:
                                impacted_roles_and_permissions = [{"permission": required_permission, "asset_names": [resource_name], "asset_type": asset_type}]
                                every_permission_present = True
                                
                                # Grab every other permission needed
                                permission_list_local = [perm for perm in permissions_list if perm != required_permission]
                                
                                for permission in permission_list_local:
                                    permissions_summary = check_if_permission_exists(
                                        all_resources_dict, permission, 
                                        org_name_to_check=resource_name if asset_type == "organization_actions_allowed" else None,
                                        folder_name_to_check=resource_name if asset_type == "folder_actions_allowed" else None,
                                        project_id_to_check=resource_name if asset_type == "project_actions_allowed" else None
                                    )

                                    if permissions_summary:
                                        impacted_roles_and_permissions.append(permissions_summary)
                                    else:
                                        every_permission_present = False
                                        break

                                if every_permission_present:
                                    vuln_entry = {
                                        "issue_id": issue_id,
                                        "issue_title": issue_title,
                                        "permission": required_permission,
                                        "permission_mappings": impacted_roles_and_permissions,
                                        "project_id": "N/A",
                                        "resource_names": "N/A",
                                        "resource_type": "N/A"
                                    }
                                    vuln_ids.append(vuln_entry)

                    else:
                        for project_id, specific_resource_info in all_asset_information.items():
                            for permission_name, asset_types in specific_resource_info.items():
                                if permission_name == required_permission:

                                    # Add all assets under the 1 permission here
                                    for asset_type, all_affected_resources in asset_types.items():
                                        impacted_roles_and_permissions = [{"permission": permission_name, "asset_names": all_affected_resources, "asset_type": asset_type}]
                                        every_permission_present = True
                                        permission_list_local = [perm for perm in permissions_list if perm != required_permission]

                                        for permission in permission_list_local:
                                            permissions_summary = check_if_permission_exists(
                                                all_resources_dict, permission, project_id_to_check=project_id
                                            )
                                            if permissions_summary:
                                                impacted_roles_and_permissions.append(permissions_summary)
                                            else:
                                                every_permission_present = False
                                                break

                                        if every_permission_present:
                                            updated_permissions = update_permission_groupings(impacted_roles_and_permissions)
                                            if updated_permissions:
                                           
                                                vuln_entry = {
                                                    "issue_id": issue_id,
                                                    "issue_title": issue_title,
                                                    "permission": permission_name,
                                                    "permission_mappings": updated_permissions,
                                                    "project_id": "N/A",
                                                    "resource_names": "N/A",
                                                    "resource_type": "N/A"
                                                }
                                                vuln_ids.append(vuln_entry)
    return vuln_ids

def check_if_permission_exists(all_resources_dict, permission, project_id_to_check=None, folder_name_to_check=None, org_name_to_check=None):
    for asset_type, all_asset_information in all_resources_dict.items():
        if asset_type in ["project_actions_allowed", "folder_actions_allowed", "organization_actions_allowed"]:
            for resource_name, permissions in all_asset_information.items():
                if (
                    (asset_type == "project_actions_allowed" and project_id_to_check == resource_name) or
                    (asset_type == "folder_actions_allowed" and folder_name_to_check == resource_name) or
                    (asset_type == "organization_actions_allowed" and org_name_to_check == resource_name)
                ) and permission in permissions:
                    return {
                        "permission": permission,
                        "asset_type": asset_type,
                        "asset_names": [resource_name]
                    }
        else:
            for project_id, specific_resource_info in all_asset_information.items():
                if project_id_to_check == project_id:
                    for permission_name, asset_types in specific_resource_info.items():
                        for asset_type, all_affected_resources in asset_types.items():
                            if permission == permission_name:
                                return {
                                    "permission": permission_name,
                                    "asset_type": asset_type,
                                    "asset_names": all_affected_resources
                                }
    return None

def update_permission_groupings(each_permission_details):

    # Organize permissions by asset type and find common assets
    permissions_by_type = defaultdict(list)
    common_assets = defaultdict(set)

    for permission_detail in each_permission_details:
        asset_type = permission_detail["asset_type"]
        permissions_by_type[asset_type].append(permission_detail)
        if asset_type in common_assets:
            common_assets[asset_type].intersection_update(permission_detail["asset_names"])
        else:
            common_assets[asset_type] = set(permission_detail["asset_names"])

    # Check if there are no shared resources for any asset type
    if all(not assets for assets in common_assets.values()):
        return None

    # Update permissions to include only common assets
    for asset_type, perms in permissions_by_type.items():
        common_assets_set = common_assets[asset_type]
        for perm in perms:
            perm["asset_names"] = list(common_assets_set)

    return each_permission_details

# {
#     "projects/#": {
#         "Direct Permissions": [
#             "roles/owner"
#         ],
#         "Inherited Permissions": [
#             {
#                 "ancestor": "folders/#",
#                 "roles": [
#                     "roles/resourcemanager.folderAdmin",
#                     "roles/resourcemanager.folderEditor"
#                 ]
#             },
#             {
#                 "ancestor": "organizations/#",
#                 "roles": [
#                     "roles/resourcemanager.organizationAdmin",
#                     "roles/resourcemanager.folderAdmin"
#                 ]
#             }
#         ],
#         "common_name": "Project2",
#         "parent_id": "project2_id",
#         "parent_name": "projects/#"
#     },
#     "folder": {
#         "folders/#": {
#             "Direct Permissions": [
#                 "roles/resourcemanager.folderAdmin",
#                 "roles/resourcemanager.folderEditor"
#             ],
#             "Inherited Permissions": [
#                 {
#                     "ancestor": "organizations/#",
#                     "roles": [
#                         "roles/resourcemanager.organizationAdmin",
#                         "roles/resourcemanager.folderAdmin"
#                     ]
#                 }
#             ],
#             "common_name": "Folder1",
#             "parent_id": "N/A",
#             "parent_name": "folders/#"
#         },
#         "folders/#": {
#             "Direct Permissions": [
#                 "roles/resourcemanager.folderAdmin",
#                 "roles/storage.admin_withcond_cd1ecfef6cae8bf38caf",
#                 "roles/resourcemanager.folderEditor"
#             ],
#             "Inherited Permissions": [
#                 {
#                     "ancestor": "folders/#",
#                     "roles": [
#                         "roles/resourcemanager.folderAdmin",
#                         "roles/resourcemanager.folderEditor"
#                     ]
#                 },
#                 {
#                     "ancestor": "organizations/#",
#                     "roles": [
#                         "roles/resourcemanager.organizationAdmin",
#                         "roles/resourcemanager.folderAdmin"
#                     ]
#                 }
#             ],
#             "common_name": "Folder2",
#             "parent_id": "N/A",
#             "parent_name": "folders/#"
#         }
#     },
#     "bucket": {
#         "bucket_name_1": {
#             "Direct Permissions": [
#                 "roles/storage.admin"
#             ],
#             "Inherited Permissions": [
#                 {
#                     "ancestor": "folders/#",
#                     "roles": [
#                         "roles/resourcemanager.folderAdmin",
#                         "roles/resourcemanager.folderEditor"
#                     ]
#                 },
#                 {
#                     "ancestor": "organizations/#",
#                     "roles": [
#                         "roles/resourcemanager.organizationAdmin",
#                         "roles/resourcemanager.folderAdmin"
#                     ]
#                 },
#                 {
#                     "ancestor": "projects/#",
#                     "roles": [
#                         "roles/owner"
#                     ]
#                 },
#                 {
#                     "ancestor": "projectOwner Points to projects/#",
#                     "roles": [
#                         "roles/storage.legacyObjectOwner",
#                         "roles/storage.legacyBucketOwner"
#                     ]
#                 }
#             ],
#             "common_name": "bucket_name",
#             "parent_id": "project2_id",
#             "parent_name": "projects/#"
#         }
#     },
#     "cloudfunction": {},
#     "computeinstance": {},
#     "saaccounts": {}
# }


def generate_summary_of_roles_or_vulns(
    session,
    member,
    roles_and_assets,
    issue_label=None,
    issue_type=None,
    snapshot = False,
    check_role_vulns=False,
    first_run=False,
    output_file=None,
    csv=False,
    txt=False,
    stdout=False
):
  
    def formatted_asset_name(asset_official_name, parent_id=None, asset_common_name=None, asset_project_id=None):
        formatted_string = f"  - \"{asset_official_name}\""
        if asset_type not in ["org", "folder", "project"]:
            formatted_string += f" (in {parent_id})"
        elif asset_common_name != "N/A":
            formatted_string += f" - {asset_common_name}"
        if asset_type == "project" and asset_project_id != "N/A":
            formatted_string += f" ({asset_project_id})"
        return formatted_string + "\n"

    def formatted_member_header():
        summary_type = "Vuln Summary" if check_role_vulns else "Summary"
        color = UtilityTools.RED if member in {"allUsers", "allAuthenticatedUsers"} else ""
        reset = UtilityTools.RESET if color else ""
        return f"{UtilityTools.BOLD}\n[******] {summary_type} for {member} [******]\n{UtilityTools.RESET}"

    def add_csv_row(issue=None):
        issue_direct_roles = "N/A"
        issue_inherited_roles = "N/A"
        if issue:
            if issue["issue_type"] == "IAM_DIRECT":
                issue_direct_roles = issue.get("role", "N/A")
            elif issue["issue_type"] == "IAM_INHERITED":
             
                issue_inherited_roles = issue.get("role", "N/A")

        row = {
            "issue_id": issue.get("issue_id", "0") if issue else "0",
            "member": member,
            "issue_title": issue.get("issue_title", issue_label) if issue else "N/A",
            "issue_type": issue.get("issue_type", issue_type) if issue else "N/A",
            "issue_permission": issue.get("permission", "N/A") if issue else "N/A",
            "issue_direct_roles": issue_direct_roles,
            "issue_inherited_roles": issue_inherited_roles,
            "issue_ancestor": issue.get("ancestor", issue_type) if issue else "N/A",
            "asset_type": asset_type,
            "asset_name": asset_official_name,
            "asset_common_name": asset_common_name,
            "asset_project_id": asset_project_id,
            "resource_owner": parent_id,
            "asset_all_direct_permissions": str(all_direct_roles),
            "asset_all_inherited_permissions": str(all_inherited_roles)
        }
        csv_rows.append(row)

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    output = output_file if output_file else "Vuln_Roles_Summary"  if check_role_vulns else f"Snapshots/Roles_Summary_{member}_{timestamp}" if snapshot else "Roles_Summary" 
    txt_output = UtilityTools.get_save_filepath(session.workspace_directory_name, f"{output}.txt", "Reports") if txt else None
    csv_output = UtilityTools.get_save_filepath(session.workspace_directory_name, f"{output}.csv", "Reports") if csv else None
    csv_rows = []

    if stdout or txt:
        formatted_string = formatted_member_header()

    asset_headers = {
        "org": "Organization Summary\n",
        "project": "Project Summary\n",
        "folder": "Folder Summary\n",
        "bucket": "Cloud Storage Summary\n",
        "cloudfunction": "Cloud Function Summary\n",
        "computeinstance": "Cloud Compute Summary\n",
        "saaccounts": "Service Accounts Summary\n",
    }

    for asset_type, all_assets in roles_and_assets.items():

        roles_exist = False
        asset_type_header = asset_headers.get(asset_type, "")

        for asset_official_name, asset_details in all_assets.items():

            parent_id = asset_details["parent_id"]
            asset_project_id = parent_id if asset_type == "project" else "N/A"
            asset_common_name = asset_details["common_name"] if asset_type in ["org", "project", "folder"] else "N/A"
            all_direct_roles, all_inherited_roles = asset_details["Direct Permissions"], asset_details["Inherited Permissions"]

            if check_role_vulns:

                if stdout or txt:
                    formatted_string += asset_type_header
                    formatted_string += formatted_asset_name(asset_official_name, parent_id, asset_common_name, asset_project_id)

                    if issue_type and issue_label:
                        formatted_string += (
                            f"    - 0:{issue_type}:{issue_label} \n"
                            f"      - Impacted Direct Role(s): {str(all_direct_roles) if all_direct_roles else 'N/A'} \n"
                            f"      - Impacted Inherited Role(s): {str(all_inherited_roles) if all_inherited_roles else 'N/A'} \n"
                        )
                    else:
                        
                        issues = populate_vulnerabilities(session, all_direct_roles, all_inherited_roles)
                        if issues:
                            for issue in issues["direct"] + issues["inherited"]:
                                issue_type = "IAM_INHERITED" if issue in issues["inherited"] else "IAM_DIRECT"
                                formatted_string += (
                                    f"    - {issue['issue_id']}:{issue_type}:{issue['permission']}:{issue['issue_title']} \n"
                                    f"      - Impacted {issue_type.replace('IAM_', '')} Role(s): {issue['role']} \n"
                                )

                if csv:
                    if issue_type and issue_label:
                        add_csv_row()
                    
                    else:
                        issues = populate_vulnerabilities(session, all_direct_roles, all_inherited_roles)
                        if issues:
                          

                            for issue in issues["direct"] + issues["inherited"]:
                                issue_type = "IAM_INHERITED" if issue in issues["inherited"] else "IAM_DIRECT"
                                issue["issue_type"] = issue_type
                                add_csv_row(issue)
            else:
                if stdout or txt:
                    if not roles_exist:
                        formatted_string += asset_type_header
                        roles_exist = True

                    formatted_string += formatted_asset_name(asset_official_name, parent_id, asset_common_name, asset_project_id)

                    for role in sorted(all_direct_roles):
                        formatted_string += f"    - {role}\n"

                        
                    filtered_inherited_roles = [
                        {'ancestor': item['ancestor'], 'roles': item['roles'] - all_direct_roles}
                        for item in all_inherited_roles
                        if item['roles'] - all_direct_roles
                    ]
                
                    for item in filtered_inherited_roles:
                        ancestor, inherited_roles = item["ancestor"], item["roles"]
                        if inherited_roles:
                            for role in sorted(inherited_roles):
                                if any(x in ancestor for x in ["projectEditor", "projectViewer", "projectOwner"]):
                                    ending = ancestor
                                else:
                                    ending = f" (Inherited From {ancestor})"
                                formatted_string = formatted_string +  f"    - {role} " + ending + "\n"
                           
                if csv:
                    row = {
                        "member": member,
                        "asset_type": asset_type,
                        "asset_name": asset_official_name,
                        "asset_common_name": asset_common_name,
                        "asset_project_id": asset_project_id,
                        "resource_owner": parent_id,
                        "asset_direct_permissions": str(all_direct_roles),
                        "asset_inherited_permissions": str(all_inherited_roles),
                    }
                    csv_rows.append(row)

    if stdout:
        print(formatted_string)

    if txt:
        mode = "w" if first_run else "a"
        with open(txt_output, mode) as txt_file:
            txt_file.write(formatted_string)

    if csv:
        df = pd.DataFrame(csv_rows)
        mode = "w" if first_run else "a"
        header = first_run
        df.to_csv(csv_output, mode=mode, header=header, index=False)



# Process IAM Binding: Save Member Summary
def save_member_summary(session, member, data_dict, crednames=None):
    table_name = "member-permissions-summary"
    save_data = {"member": member, "roles_and_assets": data_dict}

    if crednames:
        save_data["crednames"] = crednames

    session.insert_data(table_name, save_data)

def load_permission_mapping():
    with open("./utils/permission-mapping.yaml") as file:
        return yaml.safe_load(file)


def multi_role_check(session, testing_roles_list, multi_role_dict, existing_vulns, inherited = False):
    
    permission_name, issue_title, vuln_ids = None, None, []
    for issue_id, rules in multi_role_dict.items():
        
        ancestors, impacted_roles_and_permissions, fail, issue_applies = [], [], False, True


        for rule in rules:
            
            if issue_id == rule["main_permission"]: issue_title = rule["issue"]
            
            required_roles, required_permission, alternate_roles, alternate_permission = rule["roles"], rule["permission"], None, None

            if "alternate" in rule.keys() and rule["alternate"] != "None":
                
                alternate_rule = next((inner_rule for inner_rule in rules if inner_rule["permission"] == rule["alternate"]), None)
               
                if alternate_rule:
                    alternate_permission = alternate_rule["permission"]
                if alternate_rule:
                    alternate_roles = alternate_rule["roles"]
            
            if inherited:

                custom_roles = [d for d in testing_roles_list if any("projects/" in role or "organizations/" in role for role in d.get("roles", []))]

            else:

                custom_roles = [role for role in testing_roles_list if "projects/" in role or "organizations/" in role]
            
      

            # given "testing_roles_list" (roles for a given user), enumerate each role to see if ANY are in teh required_roles or 
            # required permisisons. If any match, break out fo current loop, move onto next rule, and keep going. If you have a fail even
            # after all those checks, break out of loop and don't add anything since one of the rules from rule set was not met
            fail = True  # Assume failure until proven otherwise
            for role_entry in testing_roles_list:

                if inherited:
                    roles_to_check = role_entry["roles"]
                    ancestor = role_entry["ancestor"]

                    # If at least ONE role appears in 
                    for role_entry in roles_to_check:
       
                        if role_entry in custom_roles:
                            
                            permissions_of_role = session.get_data("iam-roles", columns = ["included_permissions"], conditions = f" name = \"{role_entry}\"")
                            if permissions_of_role:

                                if required_permission in permissions_of_role:
                                    impacted_roles_and_permissions.append({"role":role_entry,"permission": required_permission, "ancestor": ancestor})
                                    ancestors.append(ancestor)
                                    fail = False
                                    break  # Exit the inner loop if we find a matching role

                                elif alternate_permission and alternate_permission in required_permission:
                                    impacted_roles_and_permissions.append({"role":role_entry,"permission": alternate_permission, "ancestor": ancestor})
                                    ancestors.append(ancestor)
                                    fail = False
                                    break  # Exit the inner loop if we find a matching role

                            # Could not retrieve custom role permissions, move onto  next role
                            else:
                                continue

                        elif role_entry in required_roles:
                            impacted_roles_and_permissions.append({"role":role_entry,"permission": required_permission, "ancestor": ancestor})
                            ancestors.append(ancestor)
                            fail = False
                            break  # Exit the inner loop if we find a matching role

                        elif alternate_roles and role_entry in alternate_roles:
                            impacted_roles_and_permissions.append({"role":role_entry,"permission": alternate_permission, "ancestor": ancestor})
                            ancestors.append(ancestor)
                            fail = False
                            break  # Exit the inner loop if we find a matching role

                else:

                    # If role we are checking atm is in "custom_roles", get its permissions and compare to main_permission
                    if role_entry in custom_roles:
                        permissions_of_role = session.get_data("iam-roles", columns = ["included_permissions"], conditions = f" name = \"{role_entry}\"")
                       
                        if permissions_of_role:

                            if required_permission in permissions_of_role:
                                impacted_roles_and_permissions.append({"role":role_entry,"permission": required_permission})
                                fail = False
                                break  # Exit the inner loop if we find a matching role

                            elif alternate_permission and alternate_permission in required_permission:
                                impacted_roles_and_permissions.append({"role":role_entry,"permission": alternate_permission})
                                fail = False
                                break  # Exit the inner loop if we find a matching role

                        else:
                            continue
                            # If we don't have permission def for role fail since we can't determine if it works

                    elif role_entry in required_roles:
                        impacted_roles_and_permissions.append({"role":role_entry,"permission": required_permission})
                        fail = False
                        break  # Exit the inner loop if we find a matching role

                    elif alternate_roles and role_entry in alternate_roles:
                        impacted_roles_and_permissions.append({"role":role_entry,"permission": alternate_permission})
                        fail = False
                        break  # Exit the inner loop if we find a matching role

            # If we went through ALL our roles and NONE of them amtched (fail state), than we need to just exit this rule check
            # with issue applies set to False so as to not savew aht we have done thus far
            if fail:
                
                issue_applies = False
                break
       
        if issue_applies == True:
            vuln_entry = {
                    "issue_id": issue_id,
                    "issue_title": issue_title, 
                    "role": impacted_roles_and_permissions,
                    "permission": "N/A"
                    
                }
            if inherited:
                vuln_entry["ancestor"] = ancestors
            else:
                vuln_entry["ancestor"] = "N/A"
    

            vuln_ids.append(vuln_entry)

 
    return vuln_ids


def single_role_check(session, role, single_role_dict, existing_vulns, ancestor=None, custom_role=False):
    vuln_ids = []

    permissions_of_role = None
    if custom_role:
        permissions_of_role = session.get_data("iam-roles", columns=["included_permissions"], conditions=f"name = \"{role}\"")

    for issue_id, rule in single_role_dict.items():
        permission = rule["permission"]
        issue_title = rule["issue"]

        if custom_role:
            if permissions_of_role and permission in permissions_of_role:
                vuln_entry = {
                    "issue_id": issue_id,
                    "issue_title": issue_title,
                    "role": role,
                    "permission": permission,
                    "ancestor": ancestor if ancestor else "N/A"
                }
                vuln_ids.append(vuln_entry)
        elif role in rule.get("roles", []):
            vuln_entry = {
                "issue_id": issue_id,
                "issue_title": issue_title,
                "role": role,
                "permission": permission,
                "ancestor": ancestor if ancestor else "N/A"
            }
            vuln_ids.append(vuln_entry)

    return vuln_ids

            
def populate_vulnerabilities(session, direct_roles, inherited_roles_dicts):

    
    single_role_dict, multi_role_dict = load_in_yaml_rules()
  
    
    existing_vulns = {
        "direct":[],
        "inherited":[]
    }

    # Check each role for individual checks (IDs 1-9) for direct & inherited
    for role in direct_roles:

        # Handle custom role
        if "projects/" in role or "organizations/" in role:
            custom_role = True
        else:
            custom_role = False

        # Take existing list and check next role and add if necessary
        individual_role_check = single_role_check(session, role, single_role_dict, existing_vulns, custom_role = custom_role)
        if individual_role_check:
            existing_vulns["direct"].extend(individual_role_check)

  
    # Take existing list and check next role and add if necessary
    if direct_roles:
        multi_role_check_results = multi_role_check(session, direct_roles, multi_role_dict, existing_vulns)
        if multi_role_check_results:
           
            existing_vulns["direct"].extend(multi_role_check_results)    

    for role_information in inherited_roles_dicts:
        ancestor = role_information["ancestor"]
        inherited_roles = role_information["roles"]
        
        for role in inherited_roles:
    
            # Handle custom role
            if "projects/" in role or "organizations/" in role:
                custom_role = True
            else:
                custom_role = False

            existing_inherited_vulns = single_role_check(session, role, single_role_dict, existing_vulns, ancestor = ancestor, custom_role = custom_role)
            if existing_inherited_vulns:
                existing_vulns["inherited"].extend(existing_inherited_vulns)
    if inherited_roles_dicts:
        # TODO MULTI ROLE CHECK NOT WORKING FOR INHERITED
        multi_role_check_results = multi_role_check(session, inherited_roles_dicts, multi_role_dict, existing_vulns, inherited = True)
        if multi_role_check_results:
            existing_vulns["inherited"].extend(multi_role_check_results)  
    


    return existing_vulns
    #return existing_direct_vulns, existing_inherited_vulns