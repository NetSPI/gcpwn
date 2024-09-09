from Modules.IAM.utils.util_helpers import *
from Modules.Everything.utils.util_helpers import *

def add_convenience_roles(data_dict, convience_member_summary):
    for bucket_name, project_permissions in convience_member_summary.items():
        if bucket_name in data_dict["bucket"]:
            for project_name, permissions in project_permissions.items():
                if project_name in data_dict["project"]:
                    direct_permissions = data_dict["project"][project_name]["Direct Permissions"]
                    for role_type in ["viewer", "editor", "owner"]:
                        if permissions[role_type] and f"roles/{role_type}" in direct_permissions:
                            inherited = {
                                "ancestor": f"project{role_type.capitalize()} Points to {project_name}",
                                "roles": permissions[role_type]
                            }
                            data_dict["bucket"][bucket_name]["Inherited Permissions"].append(inherited)


def add_inherited_roles(session, data_dict):
    # Handle Project/Folder/Org Inheritance
    for asset_type in ["project", "folder", "org"]:
        for asset_name, asset_data in data_dict[asset_type].items():
            for ancestor_type, ancestor_name in session.find_ancestors(asset_name):
                if ancestor_name in data_dict[ancestor_type]:
                    inherited = {
                        "ancestor": ancestor_name,
                        "roles": data_dict[ancestor_type][ancestor_name]["Direct Permissions"]
                    }
                    asset_data["Inherited Permissions"].append(inherited)

    # Handle Resource-level Inheritance
    for asset_type, assets in data_dict.items():
        if asset_type not in ["project", "folder", "org"]:
            for asset_name, asset_data in assets.items():
                parent = asset_data['parent_name']
                if parent in data_dict['project']:
                    asset_data["Inherited Permissions"] = list(data_dict['project'][parent]["Inherited Permissions"])
                    asset_data["Inherited Permissions"].append({
                        "ancestor": parent,
                        "roles": data_dict['project'][parent]["Direct Permissions"]
                    })
                else:
                    for ancestor_type, ancestor_name in session.find_ancestors(parent):
                        if ancestor_name in data_dict[ancestor_type]:
                            asset_data["Inherited Permissions"].append({
                                "ancestor": ancestor_name,
                                "roles": data_dict[ancestor_type][ancestor_name]["Direct Permissions"]
                            })


def add_direct_roles(session, data_dict, member_data):
    with open('./utils/resource_perm_mappings.txt') as f:
        resource_types = [line.split(',')[0].strip() for line in f if ',' in line]

    for resource in resource_types:
        data_dict[resource] = {}

    for data in member_data:
        data_type, full_resource_name = data["type"], data["name"]
        project_id = data["project_id"]
        roles = ast.literal_eval(data["roles"])
        display_name = data.get("display_name", "")
        project_name = session.get_project_name(project_id)
        project_name = project_name[0]["name"] if project_name else "Unknown"

        if full_resource_name in data_dict[data_type]:
            data_dict[data_type][full_resource_name]["Direct Permissions"].update(roles)
        else:
            name_to_store = display_name if data_type in ["org", "project", "folder"] else full_resource_name
            data_dict[data_type][full_resource_name] = {
                "Direct Permissions": set(roles),
                "Inherited Permissions": [],
                "common_name": name_to_store,
                "parent_id": project_id,
                "parent_name": project_name
            }


def process_direct_and_inherited_iam(session, data_dict, member_data):
    try:
        add_direct_roles(session, data_dict, member_data)
        add_inherited_roles(session, data_dict)
    except Exception as e:
        print(traceback.format_exc())
        return None


def consolidate_convience_roles(session, convience_members, bindings):
    all_convience_summary = {}

    member_data_dict = {}
    for binding in bindings:
        member_data_dict.setdefault(binding['member'], []).append(binding)

    for member in convience_members:
        for data in member_data_dict.get(member, []):
            full_resource_name = data["name"]
            project_id = member.split(":")[1]
            project_name = session.get_project_name(project_id)
            project_name = project_name[0]["name"] if project_name else "Unknown"
            roles = ast.literal_eval(data["roles"])
            role_type = "owner" if member.startswith("projectOwner:") else "editor" if member.startswith("projectEditor:") else "viewer"

            if full_resource_name not in all_convience_summary:
                all_convience_summary[full_resource_name] = {}

            if project_name not in all_convience_summary[full_resource_name]:
                all_convience_summary[full_resource_name][project_name] = {"viewer": set(), "editor": set(), "owner": set()}

            all_convience_summary[full_resource_name][project_name][role_type].update(roles)

    return all_convience_summary


def run_module(user_args, session, first_run=False, last_run=False, output_format = ["table"]):
    parser = argparse.ArgumentParser(description="Consolidate all IAM Bindings into 1 Member Rows", allow_abbrev=False)
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Get verbose data returned")
    parser.add_argument("--txt", action="store_true", help="Output in TXT format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--silent", action="store_true", help="No stdout")
    parser.add_argument("--output", required=False, help="Output directory to store IAM snapshot report")
    args = parser.parse_args(user_args)

    debug = args.debug
    bindings = session.get_bindings()

    if bindings:
        all_unique_members = set(binding['member'] for binding in bindings)
        all_convience_members = sorted(member for member in all_unique_members if member.startswith(('projectViewer:', 'projectEditor:', 'projectOwner:')))
        all_valid_members = sorted(all_unique_members - set(all_convience_members))

        convience_member_summary = consolidate_convience_roles(session, all_convience_members, bindings)

        if all_valid_members and debug:
            print("[*] Proceeding with the following valid members:")
            for member in all_valid_members:
                print(f" - {member}")

        for index, member in enumerate(all_valid_members):
            if debug:
                print(f"[**] Processing IAM roles for {member}. Depending on size of org/resources this might take awhile...")

            member_data = sorted(
                (binding for binding in bindings if binding['member'] == member),
                key=lambda x: (x['member'] not in ["allUsers", "allAuthenticatedUsers"], x['member'])
            )

            data_dict = {}
            process_direct_and_inherited_iam(session, data_dict, member_data)
            add_convenience_roles(data_dict, convience_member_summary)

            if data_dict == (None, None):
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Processing failed. Exiting...{UtilityColor.RESET}")
                return -1

            crednames = None
            if data_dict and member not in ["allUsers", "allAuthenticatedUsers"]:
                if debug:
                    print(f"[*] Checking if {member} is tied to any existing crednames")

                email = member.split(":")[1]
                crednames = session.get_session_data("session", columns=["credname"], conditions=f"email = \"{email}\"")

                if crednames and debug:
                    crednames = [item['credname'] for item in crednames]
                    print(f"[*] The following crednames are tied to {email}:")
                    for credname in crednames:
                        print(f"  - {credname}")

            save_member_summary(session, member, data_dict, crednames=crednames)
            stdout = not args.silent
            first_run = (index == 0)

            generate_summary_of_roles_or_vulns(
                session,
                member,
                data_dict,
                first_run=first_run,
                output_file=args.output,
                csv=args.csv,
                txt=args.txt,
                stdout=stdout
            )
    else:
        print("[X] No IAM bindings were found. Consider running \"modules run enum_policy_bindings\" to get IAM bindings.")
