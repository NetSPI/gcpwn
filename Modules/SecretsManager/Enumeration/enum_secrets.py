from Modules.SecretsManager.utils.util_helpers import *

class HashableSecret:
    def __init__(self, secret, validated=True):
        self._secret = secret
        self.validated = validated

    def __hash__(self): return hash(self._secret.name)
    def __eq__(self, other): return isinstance(other, HashableSecret) and self._secret.name == other._secret.name
    def __getattr__(self, attr): return getattr(self._secret, attr)
    def __repr__(self): return f"HashableSecret({self._secret.name})"


def parse_range(range_str):
    """
    Parse a range string (e.g., "1-5,7,latest") and return a list of numbers
    or the string 'latest'.
    """
    numbers = []
    for part in range_str.split(','):
        if part == 'latest':
            numbers.append(part)
        elif '-' in part:
            start, end = part.split('-')
            numbers.extend(range(int(start), int(end) + 1))
        else:
            numbers.append(int(part))
    return numbers

# Entrypoint; Try-Catch Exists on Caller
def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Secrets", allow_abbrev=False)
    
    exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_access_key_group.add_argument("--secret-names", type=str, help="Secrets to check in the format projects/[project_number]/secrets/[secret_name]")
    exclusive_access_key_group.add_argument("--secret-names-file", type=str, help="File name to get secrets in format projects/[project_number]/secrets/[secret_name] per line")
    parser.add_argument("--version-range", type=parse_range,  help="Range of secret versions to try (ex. 1-100)")

    parser.add_argument("--iam",action="store_true",required=False,help="Call TestIAMPermissions on Compute Instances")
    parser.add_argument("--download",action="store_true",required=False,help="Download all secret VALUES to a local CSV")
 
    # Debug/non-module specific
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    debug, project_id = args.debug, session.project_id
    action_dict, secrets_track_resources = {}, {}
    
    secret_client = secretmanager_v1.SecretManagerServiceClient(credentials = session.credentials)   

    # Step 1: Gather User Input 
    if args.secret_names or args.secret_names_file:
        
        secrets_list_rudimentary = UtilityTools.gather_non_automated_input(4, \
            cmdline_in = args.secret_names, file_in = args.secret_names_file)

        if secrets_list_rudimentary != -1:
            secrets_track_resources.setdefault(project_id, {}).update({HashableSecret(Secret(name = secret_name), validated = False): {} for secret_name in secrets_list_rudimentary})

    else:

        parent = f"projects/{project_id}"

        every_secret = list_secrets(secret_client, parent, debug = debug)

        # Service is disabled or API failed
        if every_secret == "Not Enabled" or every_secret == None:
            secrets_track_resources.setdefault(project_id, {})

        else:

            # Set action_dict whether instances are found or API worked but still empty list
            action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('secretmanager.secrets.list')

            # API successful but empty list
            if not every_secret:
                secrets_track_resources.setdefault(project_id, {})

            else:
                secrets_track_resources.setdefault(project_id, {}).update({HashableSecret(secret): {} for secret in every_secret})
                for secret in every_secret:
                    save_secret(secret, session, project_id)

    # Step 2: Iterate through each resource running GET/IAM
    for secret_project_id, secret_list in secrets_track_resources.items():

        if debug: 

            if len(secret_list) != 0:
                num_of_secrets = len(secret_list)
                print(f"[DEBUG] {num_of_secrets} secrets were found")
            
            else:
                print(f"[DEBUG]  No instances were found")

        for secret in secret_list:

            validated = secret.validated
            secret_name = secret.name

            print(f"[**] [{secret_project_id}] Reviewing {secret_name}")

            if not args.minimal_calls:

                print(f"[***] GET Base Secret Entity")
                secret_get = get_secret(secret_client, secret_name, debug=debug)
                
                if secret_get:
                    if secret_get == 404:
                        continue

                    else:

                        # Add permission to dictionary and save GET response
                        action_dict.setdefault(secret_project_id, {}).setdefault('secretmanager.secrets.get', {}).setdefault('secrets', set()).add(secret_get.name.split("/")[-1])
                        save_secret(secret_get, session, secret_project_id)
                        
                        if (args.secret_names or args.secret_names_file) and validated == False:
                            for secret_iter in secrets_track_resources[secret_project_id].keys():

                                if secret_iter == HashableSecret(secret_get):
  
                                    secret_iter.validated = True
                                    break

            if args.iam:
                print(f"[***] TEST Secret Permissions")
                
                authenticated_permissions = check_secret_permissions(secret_client, secret_name, debug = debug)
                
                for permission in authenticated_permissions:
                    
                    if args.secret_names or args.secret_names_file and validated == False:
                       
                        for secret_iter in secrets_track_resources[secret_project_id].keys():
                            if secret_iter.name == secret_name:
                                secret_iter.validated = True
                                break

                    action_dict.setdefault(secret_project_id, {}).setdefault(permission, {}).setdefault('secrets', set()).add(secret.name.split("/")[-1])

            # Step 3: List secret versions within each secret and check each one
            if args.version_range:
                secret_versions_list = [f"{secret_name}/versions/{num}" for num in args.version_range]
            else:
                print(f"[***] LIST Secret Versions")
                secret_versions_list = list_secret_versions(secret_client, secret_name)

                # If we are going automated route, we need to wrap secret in object in order for it to be a key in our dictionary
                if secret_versions_list and not (args.secret_names or args.secret_names_file):
                    version_nums = [path.name.split('/')[-1] for path in secret_versions_list]
                    secrets_track_resources.setdefault(secret_project_id, {}).setdefault(secret, {})
                    for version in version_nums:
                        secrets_track_resources[secret_project_id][secret].setdefault(version, None)

            if secret_versions_list:

                for secret_version_value in secret_versions_list:
                    
                    if not args.version_range:
                        secret_version_full_name = str(secret_version_value.name)
                        save_secret_version(secret_version_value, session, secret_project_id)               

                    else:
                        secret_version_full_name = secret_version_value
                    
                    version_num = secret_version_full_name.split("/")[-1]

                    secret_version_condensed_name = secret_name + f" (Version: {version_num})"

                    if not args.minimal_calls:

                        print(f"[****] GET Secret Version {version_num}")
                        secret_get_version = get_secret_version(secret_client, secret_version_full_name, debug=debug)
                        
                        if secret_get_version:
                            if secret_get_version == 404:
                                continue
                            else:
                                # Add permission to dictionary and save GET response
                                action_dict.setdefault(secret_project_id, {}).setdefault('secretmanager.versions.get', {}).setdefault('secret version', set()).add(secret_version_condensed_name)
                                save_secret_version(secret_get_version, session, secret_project_id)
                                if args.version_range:
                                    secrets_track_resources[secret_project_id][secret][version_num] = None

                    if args.iam:
                        print(f"[****] TEST Secret Version Permissions")
                        
                        authenticated_permissions = check_secret_version_permissions(secret_client, secret_version_full_name, debug = debug)
                        
                        for permission in authenticated_permissions:
                            
                            if args.version_range:
                                secrets_track_resources[secret_project_id][secret][version_num] = None

                            
                            action_dict.setdefault(secret_project_id, {}).setdefault(permission, {}).setdefault('secret version', set()).add(secret_version_condensed_name)

                    print(f"[****] GETTING Secret Values For {version_num}")
                    secret_value = access_secret_value(secret_client, secret_version_full_name, debug = debug)

                    if secret_value:
                        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[****] SECRET VALUE RETRIEVED FOR {version_num}{UtilityTools.RESET}")
                        action_dict.setdefault(secret_project_id, {}).setdefault("secretmanager.versions.access", {}).setdefault('secret version', set()).add(secret_version_condensed_name)

                        if secret_value.payload.data:
                            
                            secret_value_data = secret_value.payload.data
                            
                            secrets_track_resources[secret_project_id][secret][version_num] = secret_value_data.decode('utf-8')
                            
                            entry = {
                                "primary_keys_to_match":{
                                    "name": secret_version_full_name
                                },
                                "data_to_insert":{
                                    "secret_value":secret_value_data
                                }
                            }
                            session.insert_data('secretsmanager-secretversions', entry, update_only = True )
                            if args.download:
                                destination_filename = UtilityTools.get_save_filepath(session.workspace_directory_name, "secrets_data_file.csv", "Secrets")
                                data = {
                                    "secret_project_id": [secret_project_id],
                                    "secret_name_version": [secret_version_condensed_name],
                                    "secret_value_data": [secret_value_data]
                                }                              
                                df = pd.DataFrame(data)
                                if not os.path.isfile(destination_filename):
                                    # File doesn't exist, so write (create) it
                                    df.to_csv(destination_filename, index=False)
                                else:
                                    # File exists, so append to it
                                    df.to_csv(destination_filename, mode='a', header=False, index=False)


        session.insert_actions(action_dict, secret_project_id, column_name = "secret_actions_allowed")

    # Format the final list and remove those manual entries not "validated"
    for project in list(secrets_track_resources.keys()):
        secrets = secrets_track_resources[project]
        
        keys_to_remove = []
        
        for secret, version_dict in secrets.items():
            if not hasattr(secret, "validated") or getattr(secret, "validated") is True:
                temp_list = [f'{version}: {value}' for version, value in version_dict.items()]
                secrets_track_resources[project][secret] = temp_list
            else:
                keys_to_remove.append(secret)

        for secret in keys_to_remove:
            del secrets_track_resources[project][secret]

    for secret_project_id, secret_only_info in secrets_track_resources.items():
    
        # Remove projects/[project_num] from names
        list(map(lambda secret: setattr(
            secret._secret, 
            'name', 
            secret._secret.name.split("/")[-1]), 
            secret_only_info
        ))

        UtilityTools.summary_wrapup(
            secret_project_id, 
            "Secrets Secrest/Versions", 
            secret_only_info, 
            ["name","expire_time"],
            primary_resource = "Secret Names",
            secondary_title_name = "versions: <secrets>",
            output_format = output_format
        ) 