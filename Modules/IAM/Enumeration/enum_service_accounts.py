#import googleapiclient.discovery  # type: ignore
from Modules.IAM.utils.util_helpers import *
from collections import defaultdict

def dprint(msg, debug):
    if debug:
        print(f"[DEBUG] {msg}")

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
        
    exclusive_sa_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_sa_group.add_argument("--sa-account-names", type=str,  help="SA names to proceed with in the format 'projects/<project_id>/serviceAccounts/<email>'")
    exclusive_sa_group.add_argument("--sa-account-names-file", type=str, help="File name to get sa names from")
    
    parser.add_argument("--iam", action="store_true", help="Authenticated Service Account TestIAMPermission Checks")

    parser.add_argument("--minimal-calls",action="store_true",required=False,help="Get verbose data returned")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)
    debug, project_id = args.debug, session.project_id

    resource_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {}
    }
    sa_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    all_sas = defaultdict(dict)

    # Set up initial IAM client    
    iam_client = iam_admin_v1.IAMClient(credentials = session.credentials)

    # Standard Start Message
    print(f"[*] Checking {project_id} for service accounts...")

    if args.sa_account_names or args.sa_account_names_file:

        names = UtilityTools.gather_non_automated_input(4, args.sa_account_names, args.sa_account_names_file)
        
        for name in names:
            pid = name.split("/")[1]
            all_sas[pid][HashableServiceAccount(iam_admin_v1.ServiceAccount(name=name), validated=False)] = set()

    else:

        results = list_service_accounts(iam_client, project_id, debug=debug)
        if results and results not in ["Not Enabled", None]:
            resource_actions["project_permissions"][project_id].add("iam.serviceAccounts.list")
            for sa in results:
                all_sas[project_id][HashableServiceAccount(sa)] = set()
                save_service_account(sa, session)

    for pid, sa_dict in all_sas.items():

        dprint(f"{len(sa_dict)} instances were found", debug)
            
        for sa in list(sa_dict):
            
            name, validated = sa.name, sa.validated
            email = name.split("/")[-1]
            current_sa = sa

            if not args.minimal_calls:

                print(f"[***] GET Service Account - {email}")
                service_account_get = get_service_account(iam_client, email, debug=debug)
                
                if service_account_get:
                    
                    sa_actions[pid]["iam.serviceAccounts.get"]["service account"].add(email)
                    save_service_account(service_account_get, session)
                    if not validated and (args.sa_account_names or args.sa_account_names_file):
                        del sa_dict[current_sa]
                        current_sa = HashableServiceAccount(service_account_get, validated=True)
                        sa_dict[current_sa] = set()

            # SA TestIAMPermissions
            if args.iam:
                print(f"[***] TEST SA Permissions")

                perms = check_sa_permissions(iam_client, name, debug=debug)
                # Add results from testIAMPermissions
                if perms:

                    for p in perms:
                        sa_actions[pid][p]["service account"].add(email)
                    if not validated and (args.sa_account_names or args.sa_account_names_file):
                        sa.validated = True

            # List Service Account Keys
            service_account_keys = list_service_account_keys(iam_client, name, debug=debug)
            if service_account_keys and service_account_keys not in ["Not Enabled", None]:
                sa_actions[pid]["iam.serviceAccountKeys.list"]["service account"].add(email)

                for key in service_account_keys:
                    save_service_account_key(key, session)
                    key_id = key.name.split("/")[-1]
                    sa_dict[current_sa].add(f"{key_id} (DISABLED: {key.disabled})")

                    if not args.minimal_calls:
                        key_data = get_service_account_key(iam_client, key.name, debug=debug)
                        if key_data:
                            save_service_account_key(key_data, session)
                            sa_actions[pid]["iam.serviceAccountKeys.get"]["service account"].add(email)
        
        session.insert_actions(resource_actions, pid, column_name="service_account_actions_allowed")
        session.insert_actions(sa_actions, pid, column_name="service_account_actions_allowed")

    for pid, sa_map in all_sas.items():
        if args.sa_account_names or args.sa_account_names_file:
            sa_map = {k: v for k, v in sa_map.items() if k.validated}

        for sa in sa_map:
            sa._sa_account.name = sa._sa_account.name.split("/")[-1]

        UtilityTools.summary_wrapup(
            pid,
            "Service Account Principals/Keys",
            {k: sorted(list(v)) for k, v in sa_map.items()},
            ["email"],
            primary_resource="Service Accounts",
            secondary_title_name="SA Keys",
            output_format=output_format
        )