from Modules.CloudStorage.utils.util_helpers import *
from google.cloud.storage.hmac_key import HMACKeyMetadata

class HashableHMACKeyMetadata:

    # default validated to true unless otherwise noted
    def __init__(self, hmac_key, validated = True):
        self._hmac_key = hmac_key
        self.validated = validated

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._hmac_key.access_id)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        if isinstance(other, HashableHMACKeyMetadata) and self._hmac_key.access_id == other._hmac_key.access_id:
            return True
        else:
            return False

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._hmac_key, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableInstance(id={self._hmac_key.access_id})"

# Entrypoint; Try-Catch Exists on Caller
def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate HMAC Keys Options", allow_abbrev=False)
    
    exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_access_key_group.add_argument("--access-keys", type=str, help="Access Keys to check in the format projects/[project_id]/hmacKeys/[accesskey]")
    exclusive_access_key_group.add_argument("--access-keys-file", type=str, help="File name to get access keys in format projects/[project_id]/hmacKeys/[accesskey] per line")

    # Debug/non-module specific
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    # Initialize Variables
    debug, project_id = args.debug, session.project_id
    action_dict, all_hmacs = {}, {}
    
    # Set up initial HMAC client    
    storage_client = storage.Client(credentials = session.credentials, project = project_id)  

    # Standard Start Message
    print(f"[*] Checking {project_id} for HMAC keys...")

    if args.access_keys or args.access_keys_file:

        if args.access_keys:

            hmac_list_rudimentary = args.access_keys.split(",")

        elif args.access_keys_file:

            hmac_list_rudimentary = [line.strip() for line in open(args.access_keys_file, "r").readlines()] 

        for hmac_key_path in hmac_list_rudimentary:

            _, hmac_project_id, _, access_id = function.split("/")

            hmac_hash = HashableHMACKeyMetadata(HMACKeyMetadata(access_id = access_id,project_id = hmac_project_id ))
            hmac_hash.validated = False
            
            all_hmacs.setdefault(hmac_project_id, set()).add(hmac_hash)
    
    else:
        if debug:
            print(f"[DEBUG] Getting HMAC KEYS in {project_id}")

        every_hmac_key = list_hmac_keys(storage_client, debug = debug)
     
        if every_hmac_key == "Not Enabled" or every_hmac_key == None:
            all_hmacs.setdefault(project_id, set())

        else:

            # Set action_dict whether functions are found or API worked but still empty list
            action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('storage.hmacKeys.list')

            # Handle case where every_function is empty
            if not every_hmac_key:
                all_hmacs.setdefault(project_id, set())

            else:

                all_hmacs.setdefault(project_id, set()).update({HashableHMACKeyMetadata(hmac_key) for hmac_key in every_hmac_key})
                for hmac_key in every_hmac_key:
                    save_hmac_key(hmac_key, session, dont_change = ["secret"])

    for hmac_project_id, hmac_list in all_hmacs.items():

        storage_client = storage.Client(credentials = session.credentials, project = hmac_project_id)    

        if debug: 

            if len(hmac_list) != 0:
                print(f"[DEBUG] {len(hmac_list)} instances were found")
            else:
                print(f"[DEBUG]  No instances were found")

        for hmac in hmac_list: 

            validated = hmac.validated
            access_id = hmac.access_id

            print(f"[**] Reviewing {access_id}")                
                                                            
            if not args.minimal_calls:

                print(f"[***] GET HMAC Key")
                hmac_get = get_hmac_key(storage_client, access_id, debug = debug)

                if hmac_get:
                    
                    if (args.access_keys or args.access_keys_file) and validated == False: 
                        validated = True
                        all_hmacs[project_id].discard(hmac)
                        all_hmacs[project_id].add(HashableInstance(hmac_get))

                    action_dict.setdefault('project_permissions', {}).setdefault(hmac_project_id, set()).add('storage.hmacKeys.get')
                    save_hmac_key(hmac_get, session, dont_change = ["secret"])

        session.insert_actions(action_dict,hmac_project_id, column_name = "storage_actions_allowed")
        
    if all_hmacs:

        for project_id, hmac_only_info in all_hmacs.items():

            UtilityTools.summary_wrapup(
                    project_id, 
                    "Cloud Storage HMAC Keys", 
                    list(hmac_only_info), 
                    ["access_id","secret","state","service_account_email"],
                    primary_resource = "HMAC keys",
                    output_format = output_format,
                    primary_sort_key = "service_account_email"
                )
            