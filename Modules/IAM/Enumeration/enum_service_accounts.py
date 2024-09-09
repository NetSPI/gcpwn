#import googleapiclient.discovery  # type: ignore
from Modules.IAM.utils.util_helpers import *

class HashableServiceAccount:

    # default validated to true unless otherwise noted
    def __init__(self, sa_account, validated = True):
        self._sa_account = sa_account
        self.validated = validated

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._sa_account.unique_id)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        if isinstance(other, HashableServiceAccount) and self._sa_account.unique_id == other._sa_account.unique_id:
            return True
        else:
            return False

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._sa_account, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableServiceAccount(id={self._sa_account.unique_id})"

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
        
    exclusive_sa_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_sa_group.add_argument("--sa-account-names", type=str,  help="SA names to proceed with in the format 'projects/<project_id>/serviceaccount/<email>'")
    exclusive_sa_group.add_argument("--sa-account-names-file", type=str, help="File name to get sa names from")
    
    parser.add_argument("--iam", action="store_true", help="Authenticated Service Account TestIAMPermission Checks")

    parser.add_argument("--minimal-calls",action="store_true",required=False,help="Get verbose data returned")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)

    # Initialize Variables
    debug, project_id = args.debug, session.project_id
    action_dict, all_sas = {}, {}

    # Set up initial IAM client    
    iam_client = iam_admin_v1.IAMClient(credentials = session.credentials)

    # Standard Start Message
    print(f"[*] Checking {project_id} for service accounts...")

    
    if args.sa_account_names or args.sa_account_names_file:

        if args.sa_account_names:

            sa_list_names = args.sa_account_names.split(",")

        elif args.sa_account_names_file:

            sa_list_names = [line.strip() for line in open(args.sa_account_names_file, "r").readlines()] 

        for sa_name in sa_list_names:

            _, sa_project_id, _, _ = function.split("/")

            sa_hash = HashableServiceAccount(iam_admin_v1.ServiceAccount(sa_name))
            sa_hash.validated = False
            all_sas.setdefault(sa_project_id, {}).add(sa_hash)

    else:

        every_sa = list_service_accounts(iam_client, project_id, debug=debug)

        if every_sa == "Not Enabled" or every_sa == None:
            all_sas.setdefault(project_id, {})

        else:

            # Set action_dict whether functions are found or API worked but still empty list
            action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('iam.serviceAccounts.list')

            # Handle case where every_function is empty
            if not every_sa:
                all_sas.setdefault(project_id, {})

            else:

                all_sas.setdefault(project_id, {}).update({HashableServiceAccount(sa): {} for sa in every_sa})
                for sa in every_sa:
                    save_service_account(sa, session)

    for sa_project_id, sa_list in all_sas.items():

        if debug: 

            if len(sa_list) != 0:
                print(f"[DEBUG] {len(sa_list)} instances were found")
            
            else:
                print(f"[DEBUG]  No instances were found")

        for sa in sa_list:
            
            validated = sa.validated
            name = sa.name
            email = name.split("/")[-1]

            if not args.minimal_calls:

                print(f"[***] GET Service Account")
                service_account_get = get_service_account(iam_client, email, debug=debug)
                
                if service_account_get:

                    if args.sa_account_names or args.sa_account_names_file and validated == False: 
                        validated = True
                        temp = all_sas[sa_project_id].pop(sa)
                        all_sas[sa_project_id][service_account_get] = temp

                    action_dict.setdefault(project_id, {}).setdefault("iam.serviceAccounts.get", {}).setdefault("service account", set()).add(email)
                    save_service_account(service_account_get, session)

            # SA TestIAMPermissions
            if args.iam:
                print(f"[***] TEST SA Permissions")

                permissions = check_sa_permissions(iam_client, name, debug=debug)
                # Add results from testIAMPermissions
                if permissions:

                    if args.sa_account_names or args.sa_account_names_file and validated == False: 
                        validated = True
                        all_sas[sa_project_id][sa].validated = True

                    for permission in permissions:
                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("service account", set()).add(email)

            # List Service Account Keys
            key_names = []
            service_account_keys = list_service_account_keys(iam_client, name, debug=debug)
            if service_account_keys == "Not Enabled" or service_account_keys == None:
                all_sas[sa_project_id][sa] = set([])

            else:

                # Set action_dict whether functions are found or API worked but still empty list
                action_dict.setdefault(project_id, {}).setdefault("iam.serviceAccountKeys.list", {}).setdefault("service account", set()).add(email)

                if args.sa_account_names or args.sa_account_names_file and validated == False: 
                    validated = True
                    all_sas[sa_project_id][sa].validated = True
                all_sas[sa_project_id][sa] = set([])
                # Handle case where every_function is empty
                for key in service_account_keys:
                    save_service_account_key(key, session)
                    key_names.append(key.name)
                    simple_key_name = key.name.split("/")[-1]
                    all_sas[sa_project_id][sa].add(f"{simple_key_name} (DISABLED: {key.disabled})")
                
            for key_name in key_names:
            
                if not args.minimal_calls:
                    service_account_key = get_service_account_key(iam_client, key_name, debug=debug)

                    if service_account_key:
                        save_service_account_key(service_account_key, session)
                        action_dict.setdefault(project_id, {}).setdefault("iam.serviceAccountKeys.get", {}).setdefault("service account", set()).add(email)
        
        session.insert_actions(action_dict, sa_project_id, column_name = "service_account_actions_allowed")

    if all_sas:
            
        for project_id, sa_only_info in all_sas.items():

                if args.sa_account_names or args.sa_account_names_file:
                    sa_only_info = [sa for sa in sa_only_info if sa.validated]

                sa_only_info_lists = {k: sorted(list(v)) for k, v in sa_only_info.items()}

                # Clean up name
                list(map(lambda sa_account: setattr(
                    sa_account._sa_account, 
                    'name', 
                    sa_account._sa_account.name.split("/")[-1]), 
                    sa_only_info
                ))

                UtilityTools.summary_wrapup(
                    project_id, 
                    "Service Account Principals/Keys", 
                    sa_only_info_lists, 
                    ["email"],
                    primary_resource = "Serivce Accounts",
                    secondary_title_name = "SA Keys",
                    output_format = output_format
                )