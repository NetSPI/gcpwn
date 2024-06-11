from Modules.CloudStorage.utils.util_helpers import *
from google.cloud.storage.hmac_key import HMACKeyMetadata

# Entrypoint; Try-Catch Exists on Caller
def run_module(user_args, session, first_run = False, last_run = False):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate HMAC Keys Options", allow_abbrev=False)
    
    exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_access_key_group.add_argument("--access-keys", type=str, help="Access Keys to check in the format projects/[project_id]/hmacKeys/[accesskey]")
    exclusive_access_key_group.add_argument("--access-keys-file", type=str, help="File name to get access keys in format projects/[project_id]/hmacKeys/[accesskey] per line")

    # Debug/non-module specific
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    debug = args.debug

    # Set up static variables
    project_id = session.project_id

    action_dict, hmac_list_project = {}, {}
    # for summary
    resources_to_print = set([])

    print(f"[*] Checking {project_id} for HMAC keys...")

    if args.access_keys or args.access_keys_file:

        if args.access_keys:

            hmac_list_rudimentary = args.access_keys.split(",")

        elif args.access_keys_file:

            hmac_list_rudimentary = [line.strip() for line in open(args.access_keys_file)]

        for key in hmac_list_rudimentary:

            hmac_project_id, access_id = key.split("/")[1], key.split("/")[3]
            
            hmac_list_project.setdefault(hmac_project_id, []).append(access_id)

    else:

        storage_client = storage.Client(credentials = session.credentials, project = project_id)    
        hmac_list_output = list_hmac_keys(storage_client, debug = debug)
        if hmac_list_output:
            hmac_list_project.setdefault(project_id, []).extend(hmac_list_output)
        else:
            hmac_list_project = None

    if hmac_list_project:  

        for project_id, hmac_list in hmac_list_project.items():

            storage_client = storage.Client(credentials = session.credentials, project = project_id)    

            for hmac in hmac_list: 

                if type(hmac) == HMACKeyMetadata:
                    
                    string_to_store = f"{project_id} ({hmac.service_account_email if hmac.service_account_email else 'N/A'}) {hmac.access_id if hmac.access_id else 'N/A'} - {hmac.state if hmac.state else 'N/A'}"
                    resources_to_print.add(string_to_store)
                    save_hmac_key(hmac, session, dont_change = ["secret"])
                    action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('storage.hmacKeys.list')
                    access_id = hmac.access_id

                else:
                    string_to_store = f"{project_id} ({hmac}"
                    access_id = hmac
                                
                if not args.minimal_calls:
                    hmac_key_metadata = get_hmac_key(storage_client, access_id, debug = debug)
                    if hmac_key_metadata:
                        if args.access_keys or args.access_keys_file:
                            string_to_store = f"{project_id} ({hmac_key_metadata.service_account_email}) - {hmac_key_metadata.access_id} - {hmac_key_metadata.state}"
                            resources_to_print.add(string_to_store)
                        action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('storage.hmacKeys.get')
                        save_hmac_key(hmac_key_metadata, session, dont_change = ["secret"])

    session.insert_actions(action_dict,project_id, column_name = "storage_actions_allowed")

    UtilityTools.summary_wrapup(resource_name = "HMAC Key(s)", resource_list = sorted(resources_to_print), project_id = project_id)
