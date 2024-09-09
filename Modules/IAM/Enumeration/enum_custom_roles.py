from Modules.IAM.utils.util_helpers import *

# TODO: Add role listing at organization level (as opposed to project level)
  
class HashableCustomRole:

    role_stage = None

    # default validated to true unless otherwise noted
    def __init__(self, custom_role, validated = True):
        self._custom_role = custom_role
        self.validated = validated

        if custom_role.stage == 0:
            self.role_stage = "ALPHA"
        elif custom_role.stage and custom_role.stage == 1:
            self.role_stage = "BETA"
        elif custom_role.stage and custom_role.stage == 2:
            self.role_stage = "GA"
        elif custom_role.stage and custom_role.stage == 3:
            self.role_stage = "DEPRECATED"
        elif custom_role.stage and custom_role.stage == 4:
            self.role_stage = "DISABLED"
        elif custom_role.stage and custom_role.stage == 5:
            self.role_stage = "EAP"

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._custom_role.name)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        return isinstance(other, HashableCustomRole) and self._custom_role.name == other._custom_role.name

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._custom_role, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableCustomRole(id={self._custom_role.name})"

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
    
    exclusive_roles_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_roles_group.add_argument("--role-names", type=str,  help="Role names to process in the  form projects/[project_id]/roles/[role_name]")
    exclusive_roles_group.add_argument("--role-names-file", type=str, help="File name to get roles from in the format '--bucket-file /file/path/buckets.txt'")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)

    debug = args.debug

    # Initialize Variables
    debug, project_id = args.debug, session.project_id
    action_dict, all_custom_roles = {}, {}

    # Set up initial IAM client    
    iam_client = iam_admin_v1.IAMClient(credentials = session.credentials) 

    # Standard Start Message
    print(f"[*] Checking {project_id} for custom roles...")

    if args.role_names or args.role_names_file:

        if args.role_names:
            
            all_role_names = args.role_names.split(",")

        elif args.role_names_file:

            all_role_names = [line.strip() for line in open(args.role_names_file, "r").readlines()] 

        for role_name in all_role_names:

            _, role_project_id, _, _ = function.split("/")


            role_hash = HashableCustomRole(iam_admin_v1.Role(name=role_name))
            role_hash.validated = False
            
            all_custom_roles.setdefault(role_project_id, set()).add( e)            

    else:

        if debug:
            print(f"[DEBUG] Getting all IAM roles in {project_id}")

        every_role = iam_list_roles(iam_client, f"projects/{project_id}", debug=debug)

        if every_role == "Not Enabled" or every_role == None:
            all_custom_roles.setdefault(project_id, set())

        else:

            # Set action_dict whether functions are found or API worked but still empty list
            action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('iam.roles.list')

            # Handle case where every_function is empty
            if not every_role:
                all_custom_roles.setdefault(project_id, set())

            else:

                for role in every_role:

                    if "projects/" in role.name:
                        all_custom_roles.setdefault(project_id, set()).add(HashableCustomRole(role)) 
                        save_iam_role(role, session, scope="project")
                
                # If there are no custom roles
                if not all_custom_roles:
                    all_custom_roles.setdefault(project_id, set())


    for role_project_id, role_list in all_custom_roles.items():

        if debug: 

            if len(role_list) != 0:
                print(f"[DEBUG] {len(role_list)} custom roles were found")
            
            else:
                print(f"[DEBUG]  No custom roles were found")

        for role in role_list:
            
            validated = role.validated
            role_name = role.name

            if not args.minimal_calls:
                
                print(f"[**] GET role {role_name}...")
                role_get = get_custom_role(iam_client, role_name, debug=debug)

                if role_get:
                    if (args.role_names or args.role_names_file) and validated == False: 
                        validated = True
                        all_custom_roles[role_project_id].discard(role)
                        all_custom_roles[role_project_id].add(HashableCustomRole(role_gets))

                    action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('iam.roles.get')
                    save_iam_role(role_get, session, scope="project")

        session.insert_actions(action_dict, role_project_id)
    
    if all_custom_roles:

        for project_id, role_only_info in all_custom_roles.items():

            if args.role_names or args.role_names_file:
                role_only_info = [role for role in role_only_info if role.validated]

            # Clean up name
            list(map(lambda custom_role: setattr(
                custom_role._custom_role, 
                'name', 
                custom_role._custom_role.name.split("/")[-1]), 
                role_only_info
            ))

            UtilityTools.summary_wrapup(
                project_id, 
                "IAM Custom Roles", 
                list(role_only_info), 
                ["name","title","role_stage","included_permissions"],
                primary_resource = "Custom Roles",
                output_format = output_format,
                primary_sort_key = "name"
                )
    
