from Modules.ResourceManager.utils.util_helpers import *

class HashableResource:

    r_type = None
    r_state = None

    # default validated to true unless otherwise noted
    def __init__(self, resource, resource_type = None, validated = True):
        self._resource = resource
        self.validated = validated
        self.r_type = resource_type
        if resource.state == 0:
            self.r_state = "STATE_UNSPECIFIED"
        elif resource.state and resource.state == 1:
            self.r_state = "ALIVE"
        elif resource.state and resource.state == 2:
            self.r_state = "DELETE_REQUESTED"

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._resource.name)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        if isinstance(other, HashableHMACKeyMetadata) and self._resource.name == other._resource.name:
            return True
        else:
            return False

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._resource, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableResource(name={self._resource.name})"



status_mapping = {
    0: "STATE_UNSPECIFIED",
    1: f"{UtilityTools.GREEN}ACTIVE{UtilityTools.RESET}",
    2: f"{UtilityTools.RED}DELETE_REQUESTED{UtilityTools.RESET}"
}
             
##### Build Abstract Tree
def build_tree(session, project_client, folder_client, parent_id, all_folder_info, all_project_info,
                only_projects = False, 
                only_folders = False, 
                only_organizations = False,  
                debug=False, object_list=None):
    if object_list is None:
        object_list = []

    # List projects under the parent
    projects = list_projects(project_client, parent_id, debug=debug)
    if projects:
        for project in projects:
            project_status = status_mapping.get(project.state, "UNKNOWN_STATE") if project.state is not None else "UNKNOWN_STATE"

            if not (only_folders and only_projects and only_organizations) or only_projects:
                save_metadata_gcp(session, project, "project")
            
            # Append the (object, type_of_object) tuple
            object_list.append((project, "project"))

    # List folders under the parent
    folders = list_folders(folder_client, parent_id, debug=debug)
    if folders:
        for folder in folders:
            folder_status = status_mapping.get(folder.state, "UNKNOWN_STATE") if folder.state is not None else "UNKNOWN_STATE"

            # If user specified no flags or if so if one of them is only_folders
            if not (only_folders and only_projects and only_organizations) or only_folders:
                save_metadata_gcp(session, folder, "folder")
            
            # Append the (object, type_of_object) tuple
            object_list.append((folder, "folder"))

            # Recursively build the tree for child folders and projects
            build_tree(session, project_client, folder_client, folder.name, all_folder_info, all_project_info, debug=debug, object_list=object_list)

    return object_list

def save_metadata_gcp(session, data_object, resource_type):

    table_name = 'abstract-tree-hierarchy'
    save_data = {}
    
    if data_object.name: save_data["name"] = data_object.name
    if data_object.name: save_data["display_name"] = data_object.display_name
    if data_object.state: save_data["state"] = data_object.state

    if resource_type == "organization":
        save_data["parent"] = "None"
        save_data["project_id"] = "N/A"
        save_data["type"]="org"
        if_column_matches = None

    elif resource_type == "project":
        save_data["parent"] = data_object.parent
        save_data["project_id"] = data_object.project_id
        save_data["type"] = "project"
        if_column_matches = ["project_id"]

    elif resource_type == "folder":
        save_data["parent"] = data_object.parent
        save_data["project_id"] = "N/A"
        save_data["type"] = "folder"
        if_column_matches = None
        
    # IAM table save list of users tied to role, if more users are added to the same role at later date we add them, to check permissions check if in list
    session.insert_data(table_name, save_data, if_column_matches  = if_column_matches)

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Resource Manager Resources (Orgs/Folders/Projects)", allow_abbrev=False)
    
    parser.add_argument("--organizations",action="store_true",required=False,help="List/Search Organizations")
    parser.add_argument("--folders",action="store_true",required=False,help="List/Search Folders")
    parser.add_argument("--projects",action="store_true",required=False,help="List/Search Projects")
    
    parser.add_argument("--iam",action="store_true",required=False,help="Call testiampermissions on each resource")
    parser.add_argument("--all-permissions",action="store_true",required=False,help="Check thousands of permissions via testiampermissions")

    parser.add_argument("--no-recursive",action="store_true",required=False,help="Don't call search on project/folders via recursion")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")

    args = parser.parse_args(user_args)

    project_id = session.project_id
    debug = args.debug

    all_resources = set([])

    all_org_info, all_folder_info, all_project_info = set([]),set([]),set([])

    action_dict = {}

    organization_client = resourcemanager_v3.OrganizationsClient(credentials=session.credentials)
    project_client = resourcemanager_v3.ProjectsClient(credentials=session.credentials)
    folder_client = resourcemanager_v3.FoldersClient(credentials=session.credentials)

    organization_list, projects_search, folders_search = None, None, None
    r_manager_disabled = False

    # If nothing default to enumerating everything
    if not args.organizations and not args.projects and not args.folders:
        args.organizations, args.projects, args.folders = True, True, True 

    if args.organizations:

        print("[*] Searching Organizations")

        permissions = None
        organization_list = search_organizations(organization_client, debug=debug)
        
        if organization_list:
            if len(organization_list) == 0:
                print(f"[*] No organizations were found.")
            else:
                for org in organization_list:

                    org_status = status_mapping.get(org.state, "UNKNOWN_STATE") if org.state is not None else "UNKNOWN_STATE"

                    all_org_info.add(HashableResource(org, resource_type = "Org"))
                    
                    if args.iam: 
                    
                        if args.all_permissions:
                            print(f"[*] Checking permissions in batches for {org.name}, note this might take a few minutes (~9000 permissions @ 500/~ 2 min = 36 min)")
                            file_name = "./Modules/ResourceManager/utils/all_organization_permissions.txt"
                        else:
                            file_name = "./Modules/ResourceManager/utils/general_organization_permissions.txt"

                        with open(file_name, 'r') as file:
                                lines = file.readlines()

                        permissions = [line.strip() for line in lines]  
                        perm_len = len(permissions)

                        if perm_len > 100:
                            permission_batches = [permissions[i:i+100] for i in range(0, perm_len, 100)]
                            perm_batch_len = len(permission_batches)
                            for i, batch in enumerate(permission_batches):

                                action_dict2 = {}
                                
                                permissions = check_organization_permissions(organization_client, org.name, batch, authenticated = True, debug = debug)
                       
                                if permissions:
                                    
                                    action_dict2.setdefault("organization_permissions", {}).setdefault(org.name, set()).update(permissions)

                                    session.insert_actions(action_dict2)

                                # Throttle to not hit quota
                                if (i + 1) % 5 == 0:
                                    print(f"Completed {(i + 1)}/{perm_batch_len}")
                                    import time
                                    time.sleep(65)  # Wait for 1 minute 10 seconds
                                
                                
                        else:
                            permissions = check_organization_permissions(organization_client, org.name, permissions, authenticated = True, debug = debug)
                            if permissions:
                                for permission in permissions:
                                    action_dict.setdefault("organization_permissions", {}).setdefault(org.name, set()).add(permission)  

                    save_metadata_gcp(session, org, "organization")

    if args.projects:

        print("[*] Searching All Projects")

        permissions = None
        projects_search = search_projects(project_client, debug=debug)
        if projects_search == "Not Enabled":
            r_manager_disabled = True

        if projects_search and projects_search != "Not Enabled":
            for project in projects_search:

                project_status = status_mapping.get(project.state, "UNKNOWN_STATE") if project.state is not None else "UNKNOWN_STATE"
                all_project_info.add(HashableResource(project, resource_type = "Project"))  
                
                if args.iam: 

                    if args.all_permissions:
                        print(f"[*] Checking permissions in batches for {project.name}, note this might take a few minutes (~9000 permissions @ 500/~ 2 min = 36 min)")
                        file_name = "./Modules/ResourceManager/utils/all_project_permissions.txt"
                    else:
                        file_name = "./Modules/ResourceManager/utils/general_project_permissions.txt"

                    with open(file_name, 'r') as file:
                            lines = file.readlines()
                    permissions = [line.strip() for line in lines]

                    perm_len = len(permissions)
                    if perm_len > 100:
                        # change back to 0
                        permission_batches = [permissions[i:i+100] for i in range(0, perm_len, 100)]
                        perm_batch_len = len(permission_batches)
                        for i, batch in enumerate(permission_batches):

                            action_dict2 = {}

                            permissions = check_project_permissions(project_client, project.name, batch, authenticated = True, debug = debug)
                            
                            if permissions:
                                
                                action_dict2.setdefault("project_permissions", {}).setdefault(project.project_id, set()).update(permissions)

                                session.insert_actions(action_dict2,project.project_id)

                            # Throttle to not hit quota
                            if (i + 1) % 5 == 0:
                                print(f"Completed {(i + 1)}/{perm_batch_len}")
                                import time
                                time.sleep(65)  # Wait for 1 minute 10 seconds
                                
                            
                    else:
                        permissions = check_project_permissions(project_client, project.name, permissions, authenticated = True, debug = debug)
                        if permissions:
                            for permission in permissions:
                                action_dict.setdefault("project_permissions", {}).setdefault(project.project_id, set()).add(permission)


                save_metadata_gcp(session, project, "project")

    if args.folders:
    
        print("[*] Searching All Folders")

        permissions = None
        folders_search = search_folders(folder_client, debug=debug)
        if folders_search:
            for folder in folders_search:

                folder_status = status_mapping.get(folder.state, "UNKNOWN_STATE") if folder.state is not None else "UNKNOWN_STATE"

                all_folder_info.add(HashableResource(folder, resource_type = "Folder"))  
                save_metadata_gcp(session, folder, "folder")
                if args.iam: 

                    if args.all_permissions:
                        print(f"[*] Checking permissions in batches for {folder.name}, note this might take a few minutes (~9000 permissions @ 500/~ 2 min = 36 min)")
                        file_name = "./Modules/ResourceManager/utils/all_folder_permissions.txt"
                    else:
                        file_name = "./Modules/ResourceManager/utils/general_folder_permissions.txt"

                    with open(file_name, 'r') as file:
                            lines = file.readlines()
                    permissions = [line.strip() for line in lines]

                    perm_len = len(permissions)
                    if perm_len > 100:
                        permission_batches = [permissions[i:i+100] for i in range(0, perm_len, 100)]
                        perm_batch_len = len(permission_batches)
                        for i, batch in enumerate(permission_batches):

                            action_dict2 = {}

                            permissions = check_folder_permissions(folder_client, folder.name, batch, authenticated = True, debug = debug)
                            
                            if permissions:
                                
                                action_dict2.setdefault("folder_permissions", {}).setdefault(folder.name, set()).update(permissions)

                                session.insert_actions(action_dict2)

                            # Throttle to not hit quota
                            if (i + 1) % 5 == 0:
                                print(f"Completed {(i + 1)}/{perm_batch_len}")
                                import time
                                time.sleep(65)  # Wait for 1 minute 10 seconds
                    else:
                        permissions = check_folder_permissions(folder_client, folder.name, permissions, authenticated = True, debug = debug)
                        if permissions:
                            for permission in permissions:
                                action_dict.setdefault("folder_permissions", {}).setdefault(folder.name, set()).add(permission)

                
    if not (organization_list or projects_search or folders_search):
        print(f"[-] No organizations, projects, or folders were identified. You might be restricted with regard to projects. If you know fo a project name add it manually via 'projects add <project_name> from the main menu")
   
    # TODO Integrate action_dict with recursive loop here 
    # Use List Projects and List Folders from either an org node or a folder node and build out the rest of the tree
    # For the use case wehre the search operations above might be blocked but list would not be
    if not args.no_recursive and not r_manager_disabled:

        print("[*] Getting remainting projects/folders via recursive folder/project list calls starting with org node if possible")
        print("[*] NOTE: This might take a while depending on the size of the domain")

        if organization_list and len(organization_list) >= 1:
            for org in organization_list:
                parent_id = org.name
                additional_objects = build_tree(session, project_client, folder_client, parent_id, all_folder_info, all_project_info, 
                only_projects = args.projects, 
                only_folders = args.folders, 
                only_organizations = args.organizations, 
                debug=debug)
        elif folders_search and len(folders_search) >= 1:
            for folder in folders_search:
                parent_id = folder.name
                additional_objects = build_tree(session, project_client, folder_client,parent_id, all_folder_info, all_project_info,
                only_projects = args.projects, 
                only_folders = args.folders, 
                only_organizations = args.organizations, 
                debug=debug)
    
    # Sync up any new projects that were found with workspace
    session.sync_projects()
    session.insert_actions(action_dict,project_id)
    for res in all_org_info:
        all_resources.add(HashableResource(res, resource_type="Org"))
    for res in all_project_info:
        all_resources.add(HashableResource(res, resource_type="Project"))
    for res in all_folder_info:
        all_resources.add(HashableResource(res, resource_type="Folder"))

    UtilityTools.summary_wrapup(
                project_id, 
                "Resource Orgs/Folders/Projects", 
                list(all_resources), 
                ["name","display_name","parent","r_type","project_id","r_state"],
                primary_resource = "Orgs/Folders/Projects",
                primary_sort_key = "r_type",
                output_format = output_format 
            )



