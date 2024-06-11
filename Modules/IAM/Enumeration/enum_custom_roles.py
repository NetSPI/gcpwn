from Modules.IAM.utils.util_helpers import *

# TODO: Add role listing at organization level (as opposed to project level)
  
def run_module(user_args, session, first_run = False, last_run = False):
    
    project_id = session.project_id

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
    
    exclusive_roles_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_roles_group.add_argument("--roles", type=str,  help="Role names to process in the  form projects/[project_id]/roles/[role_name]")
    exclusive_roles_group.add_argument("--roles-file", type=str, help="File name to get roles from in the format '--bucket-file /file/path/buckets.txt'")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)

    debug = args.debug

    # Set to hold printout data
    all_custom_roles = set([])

    # Dictionary to hold permissions
    action_dict = {}

    # Client with user credentials
    iam_client = iam_admin_v1.IAMClient(credentials = session.credentials)

    print(f"[*] Checking {project_id} for roles...")

    roles_list, roles_name = None, None

    filtered_roles_list = []    

    if not (args.roles or args.roles_file):

        roles_list = iam_list_roles(iam_client, f"projects/{project_id}", debug=debug)
        if roles_list:
            for role in roles_list:

                if "projects/" in role.name:
                    all_custom_roles.add(f"{role.title} ({role.name})")

                    filtered_roles_list.append(role)
                    save_iam_role(role, session, scope="project")

                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('iam.roles.list')

    else:

        if args.roles:

            for role in args.roles.split(","):
                project_id, role_name = args.roles.split("/")[1], args.roles.split("/")[3]
                filtered_roles_list.append(iam_admin_v1.Role(name=f"projects/{project_id}/roles/{role_name}"))

        elif args.roles_file:

            for line in open(args.roles_file, "r").readlines():

                single_role = line.strip()
                project_id, role_name = single_role.split("/")[1], single_role.split("/")[3]
                filtered_roles_list.append(iam_admin_v1.Role(name=f"projects/{project_id}/roles/{role_name}"))

    if filtered_roles_list:

        for role in filtered_roles_list:
            
            role_name = role.name


            if not args.minimal_calls:
                
                print(f"[**] GET on role {role_name}...")

                custom_role = get_custom_role(iam_client, role_name, debug=debug)
                
                if custom_role:
                    save_iam_role(custom_role, session, scope="project")
                    all_custom_roles.add(f"{role.title} ({role.name})")
                    action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('iam.roles.get')


    UtilityTools.summary_wrapup(resource_name = "Custom Role(s)", resource_list = all_custom_roles)
    session.insert_actions(action_dict, project_id)
