from Modules.SecretsManager.utils.util_helpers import *

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
def run_module(user_args, session, first_run = False, last_run = False):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate HMAC Keys Options", allow_abbrev=False)
    
    exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_access_key_group.add_argument("--secrets", type=str, help="Secrets to check in the format projects/[project_id]/secrets/[secret_name]")
    exclusive_access_key_group.add_argument("--secrets-file", type=str, help="File name to get secrets in format projects/[project_id]/secrets/[secret_name] per line")
    parser.add_argument("--version-range", type=parse_range,  help="Range of secret versions to try (ex. 1-100)")

    parser.add_argument("--iam",action="store_true",required=False,help="Call TestIAMPermissions on Compute Instances")
    parser.add_argument("--download",action="store_true",required=False,help="Download all secret VALUES to a local CSV")
    parser.add_argument("--txt", type=str, required=False, help="Output file for final summary")

    # Debug/non-module specific
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    debug = args.debug

    action_dict, secrets_list = {}, {}
    

    final_output_secrets = {}

    secret_client = secretmanager_v1.SecretManagerServiceClient(credentials = session.credentials)   

    if not (args.secrets or args.secrets_file):
        

        secret_project_id = session.project_id

        parent = f"projects/{secret_project_id}"

        secrets_list_output = list_secrets(secret_client, parent, debug = debug)
        if secrets_list_output:
            secrets_list.setdefault(secret_project_id, []).extend(secrets_list_output)
            action_dict.setdefault('project_permissions', {}).setdefault(secret_project_id, set()).add('secretmanager.secrets.list')
            for secret in secrets_list_output:
                final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret.name.split("/")[-1], {})

        else:
            secrets_list = None

    else:

        if args.secrets:

            secrets_list_rudimentary = args.secrets.split(",")

        elif args.secrets_file:

            secrets_file = args.secrets_file

            try:

                secrets_list_rudimentary = [line.strip() for line in open(secrets_file)]
                
            except FileNotFoundError:
                print(f"{UtilityTools.RED}[X] File {secrets_file} does not appear to exist. Exiting...{UtilityTools.RESET}")
                return -1

        # Check if input is valid
        status, incorrect_input = UtilityTools.validate_input_format(secrets_list_rudimentary, 4)
        if status != 0: 
            print(f"{UtilityTools.RED}[X] Value \"{incorrect_input}\" is incorrect. Must be 'projects/[project_id]/secrets/[secret_name] Please try again...{UtilityTools.RESET}")
            return -1

        for key in secrets_list_rudimentary:

            secret_project_id = key.split("/")[1]
            secrets_list.setdefault(secret_project_id, []).append(key)

    if secrets_list:  

        for secret_project_id, secrets in secrets_list.items():

            for secret in secrets:

                if not args.secrets and not args.secrets_file:
                    save_secret(secret, session, secret_project_id)

                    secret_name = secret.name

                else:

                    secret_name = secret

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
                            
                            if args.secrets or args.secrets_file:
                                final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret_name.split("/")[-1], {})


                if args.iam:
                    print(f"[***] TEST Secret Permissions")
                    
                    authenticated_permissions = check_secret_permissions(secret_client, secret_name, debug = debug)
                    
                    for permission in authenticated_permissions:
                        
                        if args.secrets or args.secrets_file:
                            final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret_name.split("/")[-1], {})
                        
                        action_dict.setdefault(secret_project_id, {}).setdefault(permission, {}).setdefault('secrets', set()).add(secret.name.split("/")[-1])

                print(f"[***] LIST Secret Versions")

                secret_versions_list = []
                if args.version_range:
                    all_version_numbers = args.version_range
                    for number in all_version_numbers:
                        secret_versions_list.append(f"{secret_name}/versions/{number}")
                
                else:
                    secret_versions_list = list_secret_versions(secret_client, secret_name)

                    if secret_versions_list:
                        if not args.secrets and not args.secrets_file:
                            version_nums = [path.name.split('/')[-1] for path in secret_versions_list]
                            for version in version_nums:
                                final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret_name.split("/")[-1], {}).setdefault(version, None)


                if secret_versions_list:

                    for secret_version in secret_versions_list:
                        
                        if not args.version_range:
                            save_secret_version(secret_version, session, secret_project_id)
                            secret_version_name = secret_version.name
                        
                        else:
                            secret_version_name = secret_version
                        
                        version_num = secret_version_name.split('/')[5]


                        secret_version_condensed_name = secret_version_name.split("/")[3] + f" (Version: {version_num})"

                        #print(f"[**] [{secret_project_id}] Reviewing {secret_version_name}")

                        if not args.minimal_calls:

                            print(f"[****] GET Secret Version {version_num}")
                            secret_get_version = get_secret_version(secret_client, secret_version_name, debug=debug)
                            
                            if secret_get_version:
                                if secret_get_version == 404:
                                    continue
                                else:
                                    # Add permission to dictionary and save GET response
                                    action_dict.setdefault(secret_project_id, {}).setdefault('secretmanager.versions.get', {}).setdefault('secret version', set()).add(secret_version_condensed_name)
                                    save_secret_version(secret_get_version, session, secret_project_id)
                                    if args.version_range:
                                        final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret_name.split("/")[-1], {}).setdefault(version_num, None)

                        if args.iam:
                            print(f"[****] TEST Secret Version Permissions")
                            
                            authenticated_permissions = check_secret_version_permissions(secret_client, secret_version_name, debug = debug)
                            
                            for permission in authenticated_permissions:
                                
                                if args.version_range:
                                    final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret_name.split("/")[-1], {}).setdefault(version_num, None)

                                
                                action_dict.setdefault(secret_project_id, {}).setdefault(permission, {}).setdefault('secret version', set()).add(secret_version_condensed_name)

                        # TODO maybe make this optional in future?
                        print(f"[****] GETTING Secret Values For {version_num}")
                        secret_value = access_secret_value(secret_client, secret_version_name, debug = debug)

                        if secret_value:
                            print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[****] SECRET VALUE RETRIEVED FOR {version_num}{UtilityTools.RESET}")
                            action_dict.setdefault(secret_project_id, {}).setdefault("secretmanager.versions.access", {}).setdefault('secret version', set()).add(secret_version_condensed_name)

                            if secret_value.payload.data:
                                
                                # secret_project_id
                                # secret_version_condensed_name
                                secret_value_data = secret_value.payload.data
                                
                                final_output_secrets.setdefault(secret_project_id, {}).setdefault(secret_name.split("/")[-1], {})[version_num] = secret_value_data[:120].decode('utf-8')
                                
                                entry = {
                                    "primary_keys_to_match":{
                                        "name": secret_version_name
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
    for secret_project_id, secret_only_info in final_output_secrets.items():

        # Summary portion
        total_versions = len(secret_only_info.keys())
        
        all_secret_key_info = {
            key: [
                f"{k}: {v if v is not None else '<value_not_found>'}" for k, v in sorted(value.items(), key=lambda item: (item[0] == 'latest', item[0] if item[0] != 'latest' else ''))
            ]
            for key, value in secret_only_info.items()
        }

        UtilityTools.summary_wrapup(
            title="Secret(s)",
            nested_resource_dict = all_secret_key_info, 
            project_id = secret_project_id,        
            output_file_path = args.txt
        )    