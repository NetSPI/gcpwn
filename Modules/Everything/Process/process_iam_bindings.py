from Modules.IAM.utils.util_helpers import *
from Modules.Everything.utils.util_helpers import *

def dprint(msg, debug):
    if debug:
        print(f"[DEBUG] {msg}")

# Adds inherited "convenience" IAM roles (viewer/editor/owner) from projects to bucket-level resources. Note the INPUT
# below is for a single user. 
#
# INPUT:
# data_dict = {
#   "bucket": {
#     "bkt-123": {"Inherited Permissions": [...], ...}
#   },
#   "project": {
#     "projects/abc123": {
#       "Direct Permissions": {"roles/viewer", "roles/editor"},
#       ...
#     }
#   }
# }
# convience_member_summary = {
#   "bkt-123": {
#     "projects/abc123": {
#       "viewer": {"roles/viewer"},
#       "editor": {"roles/editor"},
#       "owner": set()
#     }
#   }
# }
#
# OUTPUT: Mutates data_dict["bucket"]["bkt-123"]["Inherited Permissions"] with inherited entries

def add_convenience_roles(data_dict, convience_summary):
    for bucket, perms_by_project in convience_summary.items():
        if bucket not in data_dict.get("bucket", {}):
            continue
        for proj, roles in perms_by_project.items():
            proj_data = data_dict.get("project", {}).get(proj)
            if not proj_data or "Direct Permissions" not in proj_data:
                continue
            direct_roles = proj_data["Direct Permissions"]
            for role in ["viewer", "editor", "owner"]:
                if roles[role] and f"roles/{role}" in direct_roles:
                    data_dict["bucket"][bucket]["Inherited Permissions"].append({
                        "ancestor": f"project{role.capitalize()} Points to {proj}",
                        "roles": roles[role]
                    })

# Add IAM permissions inherited from ancestor org/folder/project
# Input:
#   session = GCP session object with ancestor lookup
#   data_dict = structure like below BEFORE:
#     {
#       "project": {"projects/123": {"Direct Permissions": set(...), "Inherited Permissions": []}},
#       "folder": {"folders/abc": {"Direct Permissions": set(...), "Inherited Permissions": []}},
#       "org": {"organizations/xyz": {"Direct Permissions": set(...), "Inherited Permissions": []}}
#     }
# Output: Mutates data_dict by appending to Inherited Permissions like:
#     {
#       "project": {
#         "projects/123": {
#           "Inherited Permissions": [
#             {"ancestor": "organizations/xyz", "roles": set(...)}
#           ]
#         }
#       }
#     }
def add_inherited_roles(session, data_dict):

    # Project/Folder/Org inheritance
    for level in ["project", "folder", "org"]:
        for asset, info in data_dict[level].items():
            for anc_type, anc_name in session.find_ancestors(asset):
                anc_roles = data_dict.get(anc_type, {}).get(anc_name, {}).get("Direct Permissions")
                if anc_roles:
                    info["Inherited Permissions"].append({
                        "ancestor": anc_name,
                        "roles": anc_roles
                    })

    # Resource-level inheritance
    for rtype, entries in data_dict.items():
        if rtype in ["project", "folder", "org"]:
            continue
        for name, info in entries.items():
            parent = info.get("parent_name")
            proj_data = data_dict.get("project", {}).get(parent)
            if proj_data:
                info["Inherited Permissions"] = proj_data["Inherited Permissions"][:]
                info["Inherited Permissions"].append({
                    "ancestor": parent,
                    "roles": proj_data["Direct Permissions"]
                })
            else:
                for anc_type, anc_name in session.find_ancestors(parent):
                    roles = data_dict.get(anc_type, {}).get(anc_name, {}).get("Direct Permissions")
                    if roles:
                        info["Inherited Permissions"].append({"ancestor": anc_name, "roles": roles})

  
# Add direct IAM roles for each resource
# Input:
#   member_data = list of dicts like:
#     {
#       "type": "org",
#       "name": "organizations/ORG_ID",
#       "project_id": "N/A",
#       "roles": "['roles/owner']",
#       "display_name": "Org Name"
#     },
#     {
#       "type": "folder",
#       "name": "folders/FOLDER_ID",
#       "project_id": "N/A",
#       "roles": "['roles/editor']",
#       "display_name": "Folder Name"
#     },
#     {
#       "type": "project",
#       "name": "projects/PROJECT_ID",
#       "project_id": "project-alias",
#       "roles": "['roles/owner']",
#       "display_name": "Project Name"
#     },
#     {
#       "type": "computeinstance",
#       "name": "projects/foo/zones/us-central1-a/instances/vm-1",
#       "project_id": "foo",
#       "roles": "['roles/compute.admin']"
#     },
#     {
#       "type": "computeinstance",
#       "name": "projects/foo/zones/us-central1-a/instances/vm-1",
#       "project_id": "foo",
#       "roles": "['roles/logging.logWriter']"
#     },
#     {
#       "type": "computeinstance",
#       "name": "projects/bar/zones/us-central1-a/instances/vm-2",
#       "project_id": "bar",
#       "roles": "['roles/compute.viewer']"
#     }
# Output:
#   data_dict updated to:
#     {
#       "org": {
#         "organizations/ORG_ID": {
#           "Direct Permissions": {"roles/owner"},
#           "Inherited Permissions": [],
#           "common_name": "Org Name",
#           "parent_id": "N/A",
#           "parent_name": "Unknown"
#         }
#       },
#       "folder": {
#         "folders/FOLDER_ID": {
#           "Direct Permissions": {"roles/editor"},
#           "Inherited Permissions": [],
#           "common_name": "Folder Name",
#           "parent_id": "N/A",
#           "parent_name": "Unknown"
#         }
#       },
#       "project": {
#         "projects/PROJECT_ID": {
#           "Direct Permissions": {"roles/owner"},
#           "Inherited Permissions": [],
#           "common_name": "Project Name",
#           "parent_id": "project-alias",
#           "parent_name": "Project Name"
#         }
#       },
#       "computeinstance": {
#         "projects/foo/zones/us-central1-a/instances/vm-1": {
#           "Direct Permissions": {"roles/compute.admin", "roles/logging.logWriter"},
#           "Inherited Permissions": [],
#           "common_name": "projects/foo/zones/us-central1-a/instances/vm-1",
#           "parent_id": "foo",
#           "parent_name": "Foo Project"
#         },
#         "projects/bar/zones/us-central1-a/instances/vm-2": {
#           "Direct Permissions": {"roles/compute.viewer"},
#           "Inherited Permissions": [],
#           "common_name": "projects/bar/zones/us-central1-a/instances/vm-2",
#           "parent_id": "bar",
#           "parent_name": "Bar Project"
#         }
#       }
#     }
def add_direct_roles(session, data_dict, member_data):


    with open('./utils/resource_perm_mappings.txt') as f:
        resource_types = [line.split(',')[0].strip() for line in f if ',' in line]

    for rtype in resource_types:
        data_dict.setdefault(rtype, {})

    for row in member_data:
        rtype, rname, pid = row["type"], row["name"], row["project_id"]
        roles = set(ast.literal_eval(row["roles"]))

        # If there is no display name default to resource name
        display = row.get("display_name", rname)

        # Get project name from project ID, else set as Unknown
        pname = session.get_project_name(pid)
        pname = pname[0]["name"] if pname else "Unknown"

        entry = data_dict[rtype].setdefault(rname, {
            "Direct Permissions": set(),
            "Inherited Permissions": [],
            "common_name": display if rtype in ["org", "project", "folder"] else rname,
            "parent_id": pid,
            "parent_name": pname
        })
        entry["Direct Permissions"].update(roles)


# Wrapper to apply direct and inherited role processing
# Returns None if an exception occurs

def process_direct_and_inherited_iam(session, data_dict, member_data):
    try:
        add_direct_roles(session, data_dict, member_data)
        add_inherited_roles(session, data_dict)
    except Exception:
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

# Goal: Take all individual IAM bindings and put them all in one big representative dictionary per user
def run_module(user_args, session, first_run=False, last_run=False, output_format = ["table"]):
    parser = argparse.ArgumentParser(description="Consolidate all IAM Bindings into 1 Member Rows", allow_abbrev=False)
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Get verbose data returned")
    parser.add_argument("--txt", action="store_true", help="Output in TXT format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--silent", action="store_true", help="No stdout")
    parser.add_argument("--output", required=False, help="Output directory to store IAM snapshot report")
    args = parser.parse_args(user_args)

    debug, bindings = args.debug, session.get_bindings()
    if not bindings:
        print("[X] No IAM bindings were found. Run 'modules run enum_policy_bindings' first.")
        return

    members = {b['member'] for b in bindings}
    conv_members = sorted(m for m in members if m.startswith(('projectViewer:', 'projectEditor:', 'projectOwner:')))
    valid_members = sorted(members - set(conv_members))

    conv_summary = consolidate_convience_roles(session, conv_members, bindings)

    if valid_members and debug:
        print("[*] Proceeding with the following valid members:\n  - " + "\n  - ".join(valid_members))
        print(f"[**] Processing IAM roles for {member}. Depending on size of org/resources this might take awhile...")

    for index, member in enumerate(valid_members):
        
        data_dict = {}
        
        # put allUsers and allAuthenticatedUsers at the top
        member_rows = sorted(
            (binding for binding in bindings if binding['member'] == member),
            key=lambda x: (x['member'] not in ["allUsers", "allAuthenticatedUsers"], x['member'])
        )

        process_direct_and_inherited_iam(session, data_dict, member_rows)
        
        add_convenience_roles(data_dict, conv_summary)

        if not data_dict:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Processing failed. Exiting...{UtilityColor.RESET}")
            return -1

        crednames = None
        if member not in ["allUsers", "allAuthenticatedUsers"]:
            
            print(f"[*] Checking if {member} is tied to any existing crednames")

            email = member.split(":")[1]
            crednames = session.get_session_data("session", columns=["credname"], conditions=f"email = \"{email}\"")

            if crednames and debug:
                crednames = [item['credname'] for item in crednames]
                print(f"[*] The following crednames are tied to {email}:")
                for credname in crednames:
                    print(f"  - {credname}")

        save_member_summary(session, member, data_dict, crednames=crednames)

        generate_summary_of_roles_or_vulns(
            session,
            member,
            data_dict,
            first_run=(index == 0),
            output_file=args.output,
            csv=args.csv,
            txt=args.txt,
            stdout=not args.silent
        )
