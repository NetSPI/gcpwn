from Modules.CloudStorage.utils.util_helpers import *
import sys

def validate_args(args):
    if (args.blob_names or args.blob_names_file) and not args.bucket_names:
        print("When specifying 'blob' or 'blob-file', 'bucket' argument is required")
        return -1
    return 1

def run_module(user_args, session, first_run = False, last_run = False,output_format = ["table"], dependency = False):

    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate Buckets Options", allow_abbrev=False)
    
    exclusive_bucket_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_bucket_group.add_argument("--bucket-names", type=str,  help="Bucket names to proceed with in the format '--buckets bucket1,bucket2,bucket3'")
    exclusive_bucket_group.add_argument("--bucket-names-file", type=str, help="File name to get bucket names from in the format '--bucket-file /file/path/buckets.txt'")
    
    exclusive_blob_group = parser.add_mutually_exclusive_group(required = False)
    exclusive_blob_group.add_argument("--blob-names",type=str, help = "Bucket names to proceed with in the format '--blobs /blob1/name.txt,/blob2/name2.txt'")
    exclusive_blob_group.add_argument("--blob-names-file", type=str, help="Specify file path with list of blobs")

    # Exfiltrate data options
    parser.add_argument("--download",required=False,action="store_true", help="Attempt to download all blobs enumerated")
    parser.add_argument("--output", type=str, required=False, help="Output folder for downloading files")
    parser.add_argument("--file-size", type=int, required=False, help="File size filter for downloads in bytes")
    parser.add_argument("--good-regex", type=str, required=False, help="Good regex to match for downloading files")
    parser.add_argument("--time-limit",type=str,required=False,help="Set time limit per bucket in seconds, at which point program will move onto next bucket")

    parser.add_argument("--external-curl",required=False, action="store_true", help="Good regex to match for downloading files")
    
    parser.add_argument("--iam",required=False, action="store_true", help="Do IAM checks now on buckets. This is also done in the generic IAM modules.")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("--access-id", type=str,  help="Access ID for HMAC key to use in Request")
    parser.add_argument("--hmac-secret", type=str,  help="HMAC Secret to use when making API call")
    
    parser.add_argument("--list-hmac-secrets",required=False, action="store_true", help="Good regex to match for downloading files")
    parser.add_argument("--validate-buckets", required=False,action="store_true", help="Specify file path with list of blobs")


    # Debug/non-module specific
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    # List HMAC secrets if applicable
    if args.list_hmac_secrets:
        hmac_secrets = get_all_hmac_secrets(session)
        if hmac_secrets:
            print("[*] The following HMAC keys have secrets that can be used:")
            for secret in hmac_secrets:
                access_id, secret, sa_email = secret["access_id"], secret["secret"], secret["service_account_email"]
                print(f"   - {secret} \n      - {access_id} @ {sa_email}")
        return 1

    # Ensure if a blob argument is supplied a bucket argument is also supplied
    if validate_args(args) == -1:
        return -1

    # Set OUTPUT directory if different than default
    if args.output:
        OUTPUT_DIRECTORY = args.output 
    else:
        OUTPUT_DIRECTORY = UtilityTools.get_save_filepath(session.workspace_directory_name,"","Storage")

    # Initialize Variables

    debug, project_id = args.debug, session.project_id
    action_dict = {}
    all_buckets = {}
    bucket_validated = True

    # Set up initial storage client    
    storage_client = storage.Client(credentials = session.credentials, project = project_id)    

    # Standard Start Message
    print(f"[*] Checking {project_id} for buckets...")

    # Manual List + Automated List
    if args.bucket_names or args.bucket_names_file:

        bucket_validated = False

        # STDIN
        if args.bucket_names:
            bucket_list = [storage_client.bucket(bucket_name) for bucket_name in args.bucket_names.split(",")]

        # File
        elif args.bucket_names_file:
            bucket_list = [storage_client.bucket(bucket_name.strip()) for bucket_name in open(args.bucket_names_file, "r").readlines()]
        
        for bucket in bucket_list:
            all_buckets[bucket] = []

    else:

        # XML API HMAC Signature
        if args.access_id and args.hmac_secret:
            
            bucket_list = hmac_list_buckets(storage_client, args.access_id, args.hmac_secret, project_id, debug=debug)
        
        # Standard Auth Creds
        else:

            bucket_list = list_buckets(storage_client, debug = debug)

        if bucket_list == "Not Enabled" or bucket_list == None:
            pass

        else:

            if not (args.access_id and args.hmac_secret):
                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('storage.buckets.list')

            if not bucket_list:
                pass

            else:

                for bucket in bucket_list:

                    all_buckets[bucket] = set([])

                    if args.access_id and args.hmac_secret:
                        save_bucket_xml(bucket, session)
                    else:
                        save_bucket(bucket, session)

    if debug: 

        if len(all_buckets.keys()) != 0:
            print(f"[DEBUG] {len(all_buckets.keys())} buckets were found")
        else:
            print(f"[DEBUG]  No buckets were found")

    ### Enumerate through each bucket and check external curl, IAM, and bucket metadata where applicable
    for bucket in all_buckets.keys():

        bucket_name = bucket.name 

        print(f"[**] Reviewing {bucket.name}")

        # If not minimum calls or HMAC, GET bucket
        if not(args.access_id and args.hmac_secret) and not args.minimal_calls:

            print(f"[***] GET Bucket Object")
            bucket_get = get_bucket(storage_client, bucket_name, debug = debug)

            if bucket_get:
                
                action_dict.setdefault(project_id, {}).setdefault("storage.buckets.get", {}).setdefault("buckets", set()).add(bucket_name)
                
                if (args.bucket_names or args.bucket_names_file) and bucket_validated == False:
                    bucket_validated = True
                    save_bucket(bucket, session)

        # Check External Curl
        if args.external_curl:
        
            print(f"[***] TEST External Curl")
             
            # Set bucket name
            bucket_url = "https://storage.googleapis.com/"+bucket_name
            
            return_data = requests.get(bucket_url)

            if "Anonymous caller does not have storage.objects.list access to the Google Cloud Storage bucket" not in return_data.text:
                # TODO handle case were this does not exist

                entry = {
                    "primary_keys_to_match":{
                        "project_id": project_id,
                        "name": bucket_name
                    },
                    "data_to_insert":{
                        "external_curl":"True"
                    }
                }

                session.insert_data('cloudstorage-buckets', entry, update_only = True )
            
            if debug:
                print(f"[DEBUG] Response for {bucket_url} was {return_data.text}")

        # Bucket Unauth & Auth TestIAMPermissions
        if args.iam:
            
            print(f"[***] TEST Bucket Permissions")

            authenticated_permissions, unauthenticated_permissions = check_bucket_permissions(storage_client, bucket_name, authenticated = True, unauthenticated = True, debug=debug)

            # Add results from testIAMPermissions
            for permission in authenticated_permissions:
                action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("buckets", set()).add(bucket_name)

            # Add to IAM bindings table under unauth
            if unauthenticated_permissions and len(unauthenticated_permissions) > 0:
                unauthenticated_info = {
                    "name":bucket_name,
                    "type":"bucket",
                    "permissions":str(unauthenticated_permissions)
                }
                session.add_unauthenticated_permissions(unauthenticated_info, project_id = project_id)

        print(f"[***] LIST Bucket Blobs")

        if args.blob_names or args.blob_names_file:

            blobs_validated = False

            if args.blob_names:
                blob_list = [blob_name for blob_name in args.blob_names.split(",")]

            elif args.blob_names_file:
                blob_list = [blob_name in open(args.blob_names_file, "r").readlines()]

            blob_list = [bucket.blob(blob) for blob in blob_list]
        
        else: 
        
            if args.access_id and args.hmac_secret:
                blob_list = hmac_list_blobs(storage_client, args.access_id , args.hmac_secret, bucket_name, project_id, debug=False)
            else:
                blob_list = list_blobs(storage_client, bucket_name, debug = debug)  

            if blob_list == "Not Enabled" or blob_list == None:
                all_buckets[bucket] = set([])

                # break as no use trying to continue with blob enumeration
                break

            else:

                # Set permission at bucket level; not blobs yet
                action_dict.setdefault(project_id, {}).setdefault("storage.objects.list", {}).setdefault("buckets", set()).add(bucket_name)

                # Handle case where every_function is empty
                if not blob_list:
                    all_buckets[bucket] = set([])

                else:

                    for blob in blob_list:

                        if len(all_buckets[bucket]) <= 10 and blob.name[-1] != "/":
                            all_buckets[bucket].add(blob.name)

                        if (args.access_id and args.hmac_secret): save_blob_xml(blob, session)
                        else:save_blob(blob, session)

        # If blobs empty say no blobs, if blobs are there debug 
        if blob_list and len(blob_list) == 0:
            print(f"[**] No blobs fround for {bucket_name}...")

            # if no blobs move onto next bucket
            continue

        if blob_list:

            if not(args.access_id and args.hmac_secret)  and not args.minimal_calls:
                print(f"[***] GET Bucket Blobs")
                # TODO looks like this got missed? Addt his later
            
            if args.download:
                print(f"[***] DOWNLOAD Bucket Blobs")

            # time limit is per bucket
            if args.time_limit:
                start_time = time.time()
                
            max_len = len(blob_list)

            try:
                for index, blob in enumerate(blob_list):
                    
                    # If blob is user supplied string, cast to blob object for later use
                    blob_name = blob.name

                    if not(args.access_id and args.hmac_secret)  and not args.minimal_calls:
                        
                        blob_get = get_blob(bucket,blob_name, debug = debug)
                        if blob_get:
                            save_blob(blob_get, session)
                            action_dict.setdefault(project_id, {}).setdefault("storage.objects.get", {}).setdefault("buckets", set()).add(bucket_name)

                    if args.download:
                        
                        if args.access_id and args.hmac_secret and blob_name[-1] != "/":
                            hmac_download_blob(storage_client,args.access_id, args.hmac_secret, bucket_name, blob_name,project_id, debug=debug, output_folder = OUTPUT_DIRECTORY)
                        else:
                            download_blob(storage_client, bucket,blob, project_id, debug = debug, output_folder = OUTPUT_DIRECTORY, user_regex_pattern = args.good_regex, blob_size_limit = args.file_size)
                        
                        if args.time_limit:
                            time_limit = args.time_limit
                            elapsed_time = time.time() - start_time
                            if elapsed_time > int(time_limit):
                                print(f"[-] Time limit of {time_limit} reached for download for bucket {bucket_name}")
                                break

                    # Print the counter
                    print(f"[***] Processed {index + 1} of {max_len} blobs. Enter Ctrl+C to exit blob counts for this bucket...", end='\r')
                    sys.stdout.flush()  # Ensure the print is updated in plac
                print("\n")
            except KeyboardInterrupt:
                print("[*] Ended blob enumeration. Moving onto next bucket...")

    session.insert_actions(action_dict,project_id, column_name = "storage_actions_allowed")

    all_buckets_lists = {k: sorted(list(v)) for k, v in all_buckets.items()}

    if not dependency:

        UtilityTools.summary_wrapup(
            project_id, 
            "Cloud Storage Buckets/Blobs", 
            all_buckets_lists, 
            ["id","location"],
            primary_resource = "Buckets",
            secondary_title_name = "blobs",
            output_format = output_format 
        )

