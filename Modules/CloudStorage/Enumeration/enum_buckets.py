from Modules.CloudStorage.utils.util_helpers import *
import sys

def validate_args(args):
    if (args.blobs or args.blob_file) and not args.buckets:
        print("When specifying 'blob' or 'blob-file', 'bucket' argument is required")
        return -1
    return 1

def run_module(user_args, session, first_run = False, last_run = False):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Buckets Options", allow_abbrev=False)
    
    exclusive_bucket_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_bucket_group.add_argument("--buckets", type=str,  help="Bucket names to proceed with in the format '--buckets bucket1,bucket2,bucket3'")
    exclusive_bucket_group.add_argument("--bucket-file", type=str, help="File name to get bucket names from in the format '--bucket-file /file/path/buckets.txt'")
    
    exclusive_blob_group = parser.add_mutually_exclusive_group(required = False)
    exclusive_blob_group.add_argument("--blobs",type=str, help = "Bucket names to proceed with in the format '--blobs /blob1/name.txt,/blob2/name2.txt'")
    exclusive_blob_group.add_argument("--blob-file", type=str, help="Specify file path with list of blobs")

    # Exfiltrate data options
    parser.add_argument("--download",required=False,action="store_true", help="Attempt to download all blobs enumerated")
    parser.add_argument("--output", type=str, required=False, help="Output folder for downloading files")
    parser.add_argument("--file-size", type=int, required=False, help="File size filter for downloads in bytes")
    parser.add_argument("--good-regex", type=str, required=False, help="Good regex to match for downloading files")
    parser.add_argument("--time-limit",type=str,required=False,help="Set time limit per bucket in seconds, at which point program will move onto next bucket")

    # Check if buckets are externally facing
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

    if args.output:
        OUTPUT_DIRECTORY = args.output 
    else:
        OUTPUT_DIRECTORY = UtilityTools.get_save_filepath(session.workspace_directory_name,"","Storage")

    # Ensure if a blob argument is supplied a bucket argument is also supplied
    if validate_args(args) == -1:
        return -1

    debug = args.debug

    if args.list_hmac_secrets:
        hmac_secrets = get_all_hmac_secrets(session)
        if hmac_secrets:
            print("[*] The following HMAC keys have secrets that can be used:")
            for secret in hmac_secrets:
                access_id, secret, sa_email = secret["access_id"], secret["secret"], secret["service_account_email"]
                print(f"   - {secret} \n      - {access_id} @ {sa_email}")
        return 1


    action_dict = {}
    all_buckets = {}
        
    # Default Project ID
    project_id = session.project_id

    # Default Variable Names
    bucket_list, bucket_name, blobs = None, None, None
  
    # Set up scope for call to specified project
    storage_client = storage.Client(credentials = session.credentials, project = project_id)    
    
    print(f"[*] Checking {project_id} for buckets/blobs via LIST buckets...")

    ### List all buckets either via API call or manually if supplied
    if not (args.buckets or args.bucket_file):

        # XML API HMAC Signature
        if args.access_id and args.hmac_secret:
            bucket_list = hmac_list_buckets(storage_client, args.access_id, args.hmac_secret, project_id, debug=debug)
        
        else:
            bucket_list = list_buckets(storage_client, debug = debug)

        # Successful API call (aka no permission error)
        if bucket_list:

            if not (args.access_id and args.hmac_secret):
                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('storage.buckets.list')
            
            for bucket in bucket_list:
                all_buckets[bucket.name] = []
                if args.access_id and args.hmac_secret: save_bucket_xml(bucket, session)
                else:  save_bucket(bucket, session)
            
    else:

        if args.buckets:

            bucket_list = [storage_client.bucket(bucket_name) for bucket_name in args.buckets.split(",")]

        elif args.bucket_file:

            bucket_list = [storage_client.bucket(bucket_name.strip()) for bucket_name in open(args.bucket_file, "r").readlines()]

        
        # Added functionality if user chooses to filter out bad buckets or do like a pre-fetch check
        if args.validate_buckets:
            # Maybe in the future add a flag that opts out of saving otherwise seems good 
            removed_indices = []
            all_good = False
            for i, bucket in enumerate(bucket_list):
                if check_existence(bucket.name, debug = debug):
                    save_bucket(bucket, session)
                else:
                    if not all_good:
                        response = input(f"{bucket.name} does not appear to exist. Proceed with it included? (y/n/a): ").lower()
                    if response == 'n':
                        removed_indices.append(i)
                    elif response == 'a' and not all_good:
                        all_good = True
                    else:
                        pass

            removed_items = [bucket_list.pop(idx) for idx in sorted(removed_indices, reverse=True)]

        else:
            
            for bucket in bucket_list:
                save_bucket(bucket, session)
        
        for bucket in bucket_list:
            all_buckets[bucket.name] = []

    # Break this into two separate branches, dont print error again if it failed in exception
    if bucket_list == None:
        return -1

    ### Enumerate through each bucket and check external curl, IAM, and bucket metadata where applicable
    for bucket in bucket_list:

        bucket_name = bucket.name 

        print(f"[**] Reviewing {bucket.name}")

        # Check Get Bucket
        if not(args.access_id and args.hmac_secret) and not args.minimal_calls:
            print(f"[***] GET Bucket Object")
            bucket_meta = get_bucket(storage_client, bucket_name, debug = debug)
            if bucket_meta:
                
                action_dict.setdefault(project_id, {}).setdefault("storage.buckets.get", {}).setdefault("buckets", set()).add(bucket_name)
                save_bucket(bucket, session)

        # Check External Curl
        if args.external_curl:
        
            print(f"[***] TEST Curl Check")
             
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

        # Check Bucket IAM
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

        # If no command line specifications provided for blob, list them
        if not (args.blobs or args.blob_file): 
            
            if args.access_id and args.hmac_secret:
                blob_list = hmac_list_blobs(storage_client, args.access_id , args.hmac_secret, bucket_name, project_id, debug=False)
            else:
                blob_list = list_blobs(storage_client, bucket_name, debug = debug)  

            if blob_list:
                if not (args.access_id and args.hmac_secret):
                    action_dict.setdefault(project_id, {}).setdefault("storage.objects.list", {}).setdefault("buckets", set()).add(bucket_name)

                for blob in blob_list:
                    if (args.access_id and args.hmac_secret): save_blob_xml(blob, session)
                    else:save_blob(blob, session)
        
        # use user-supplied arguments instead of automated list returned
        else:
            
            if args.blobs:

                if "," in args.blobs:
                    blob_list = args.blobs.split(",")
                else:
                    blob_list = [args.blobs]

            elif args.blob_file:
                blob_file = open(args.blob_file, "r")
                for line in blob_file.readlines():
                    line = line.strip()
                    blob_list = blob_list + [line]

            blob_list = [bucket.blob(blob) for blob in blob_list]

            for blob in blob_list:
                save_blob(blob, session)

        if blob_list and debug:
            print(f"[DEBUG] Blob names identified/supplied for {project_id}:{bucket_name} are:")
            for blob in blob_list:
                print("     " + blob.name)

        # If blobs empty say no blobs, if blobs are there debug 
        if blob_list and len(blob_list) == 0:
            print(f"[**] No blobs fround for {bucket_name}...")

        if blob_list:

            if not(args.access_id and args.hmac_secret)  and not args.minimal_calls:
                print(f"[***] GET Bucket Blobs")
            
            if args.download:
                print(f"[***] DOWNLOAD Bucket Blobs")

            # time limit is per bucket
            if args.time_limit:
                start_time = time.time()
                
            if blob_list:
                max_len = len(blob_list)

            for index, blob in enumerate(blob_list):
                
                # If blob is user supplied string, cast to blob object for later use
                blob_name = blob.name

                if bucket_name in all_buckets.keys() and len(all_buckets[bucket_name]) <= 10:
                    all_buckets[bucket_name].append(blob_name)

                if not(args.access_id and args.hmac_secret)  and not args.minimal_calls:
                    blob_meta = get_blob(bucket,blob_name, debug = debug)
                    if blob_meta:
                        save_blob(blob_meta, session)
                        action_dict.setdefault(project_id, {}).setdefault("storage.objects.get", {}).setdefault("buckets", set()).add(bucket_name) if bucket_name not in action_dict.get(project_id, {}).get("storage.objects.get", {}).get("buckets", set()) else None

                    
                if args.download:
                    
                    if args.access_id and args.hmac_secret and blob_name[-1] != "/":
                        hmac_download_blob(storage_client,args.access_id, args.hmac_secret, bucket_name, blob_name,project_id, debug=debug, output_folder = OUTPUT_DIRECTORY)
                    else:
                        download_blob(storage_client, bucket,blob, project_id, debug = debug,output_folder = OUTPUT_DIRECTORY, user_regex_pattern = args.good_regex, blob_size_limit = args.file_size)
                    
                    if args.time_limit:
                        time_limit = args.time_limit
                        elapsed_time = time.time() - start_time
                        if elapsed_time > int(time_limit):
                            print(f"[-] Time limit of {time_limit} reached for download for bucket {bucket_name}")
                            break
                # Print the counter
                print(f"[***] Processed {index + 1} of {max_len} blobs", end='\r')
                sys.stdout.flush()  # Ensure the print is updated in plac

    UtilityTools.summary_wrapup(resource_top = "Buckets (with up to 10 blobs shown each)",resource_dictionary = all_buckets,project_id = project_id)
    session.insert_actions(action_dict,project_id, column_name = "storage_actions_allowed")