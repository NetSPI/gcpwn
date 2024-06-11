#import googleapiclient.discovery  # type: ignore
from Modules.IAM.utils.util_helpers import *

def run_module(user_args, session, first_run = False, last_run = False):
    
    project_id = session.project_id

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
    
    parser.add_argument("--iam", action="store_true", help="SA names to proceed with in the format '--buckets bucket1,bucket2,bucket3'")

    exclusive_sa_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_sa_group.add_argument("--sa-accounts", type=str,  help="SA names to proceed with in the format '--buckets bucket1,bucket2,bucket3'")
    exclusive_sa_group.add_argument("--sa-accounts-file", type=str, help="File name to get sa names from in the format '--bucket-file /file/path/buckets.txt'")
    
    parser.add_argument("--minimal-calls",action="store_true",required=False,help="Get verbose data returned")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)

    action_dict = {}

    sa_printout_list = set([])

    debug = args.debug

    project_id = session.project_id

    iam_client = iam_admin_v1.IAMClient(credentials = session.credentials)


    print(f"[*] Checking {project_id} for service accounts...")

    sa_list, sa_name = None, None

    if not (args.sa_accounts or args.sa_accounts_file):

        sa_list = list_service_accounts(iam_client, project_id, debug=debug)
        if sa_list:
            for account in sa_list:
                sa_printout_list.add(account.name.split("/")[-1])
                save_service_account(account, session)
                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('iam.serviceAccounts.list')
    else:

        if args.sa_accounts:

            sa_list = [iam_admin_v1.ServiceAccount(f"projects/{project_id}/serviceAccounts/{email}") for email in args.sa_accounts.split(",")]

        elif args.sa_accounts_file:

            sa_list = [iam_admin_v1.ServiceAccount(f"projects/{project_id}/serviceAccounts/{email}") for email in open(args.sa_accounts_file, "r").readlines()]

    if sa_list:
        for sa in sa_list:
            
            name = sa.name
            email = name.split("/")[-1]

            if not args.minimal_calls:
                service_account = get_service_account(iam_client, email, debug=debug)
                if service_account:
                    sa_printout_list.add(email)
                
                    action_dict.setdefault(project_id, {}).setdefault("iam.serviceAccounts.get", {}).setdefault("service account", set()).add(email)

            if args.iam:
                if debug: print(f"[***] Permissions")

                permissions = check_sa_permissions(iam_client, name, debug=debug)
                # Add results from testIAMPermissions
                if permissions:
                    for permission in permissions:
                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("service account", set()).add(email)

            # List Service Account Keys
            service_account_keys = list_service_account_keys(iam_client, name, debug=debug)
            if service_account_keys:
                for key in service_account_keys:
                
                    key_name = key.name
                    save_service_account_key(key, session)

                    action_dict.setdefault(project_id, {}).setdefault("iam.serviceAccountKeys.list", {}).setdefault("service account", set()).add(email)

                    if not args.minimal_calls:
                        service_account_key = get_service_account_key(iam_client, key_name, debug=debug)

                        if service_account_key:
                            save_service_account_key(service_account_key, session)
                            action_dict.setdefault(project_id, {}).setdefault("iam.serviceAccountKeys.get", {}).setdefault("service account", set()).add(email)
    
    UtilityTools.summary_wrapup(resource_name = "Service Account(s)", resource_list = sorted(sa_printout_list), project_id = project_id)

    session.insert_actions(action_dict, project_id, column_name = "service_account_actions_allowed")
