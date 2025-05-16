import argparse
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import threading
from Modules.CloudStorage.utils.util_helpers import *

def validate_args(args):
    if (args.blob_names or args.blob_names_file) and not args.bucket_names:
        print("When specifying 'blob' or 'blob-file', 'bucket' argument is required")
        return -1
    return 1

def dprint(msg, debug):
    if debug:
        print(f"[DEBUG] {msg}")

# Returns List_Of_Buckets, False if buckets provided manually
def get_bucket_list(args, session, storage_client, project_id, resource_actions, debug):
    mode, validated = (
        ("manual", False) if args.bucket_names or args.bucket_names_file else
        ("hmac", True) if args.access_id and args.hmac_secret else
        ("default", True)
    )

    all_buckets = {}
    if mode == "manual":
        bucket_list = UtilityTools.gather_non_automated_input(
            1,
            cmdline_in=args.bucket_names,
            file_in=args.bucket_names_file,
            validate_input=False,
            transform=lambda name: storage_client.bucket(name)
        )
        for bucket in bucket_list: all_buckets[bucket] = set()
        return all_buckets, validated

    if mode == "hmac":
        bucket_list = hmac_list_buckets(storage_client, args.access_id, args.hmac_secret, project_id, debug)
    else:
        bucket_list = list_buckets(storage_client, debug)
        if bucket_list and bucket_list not in ["Not Enabled", None]:
            resource_actions["project_permissions"][project_id].add("storage.buckets.list")


    if bucket_list in ["Not Enabled", None]:
        return {}, validated

    for bucket in bucket_list:
        all_buckets[bucket] = set()
        if mode == "hmac":
            save_bucket_xml(bucket, session)
        else:
            save_bucket(bucket, session)

    return all_buckets, validated

def get_blob_list(storage_client, bucket, args, project_id, debug):
    if args.blob_names or args.blob_names_file:
        return [bucket.blob(b) for b in UtilityTools.gather_non_automated_input(
            1, cmdline_in=args.blob_names, file_in=args.blob_names_file, validate_input=False)]
    if args.access_id and args.hmac_secret:
        return hmac_list_blobs(storage_client, args.access_id, args.hmac_secret, bucket.name, project_id, debug)
    return list_blobs(storage_client, bucket.name, debug)



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
    
    parser.add_argument("--iam",required=False, action="store_true", help="Do IAM checks now on buckets. This is also done in the generic IAM modules.")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("--access-id", type=str,  help="Access ID for HMAC key to use in Request")
    parser.add_argument("--hmac-secret", type=str,  help="HMAC Secret to use when making API call")
    
    parser.add_argument("--threads", type=int, default=1, help="Number of threads for blob download (default: 5)")

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
                print(f"   - {secret['secret']} \n      - {secret['access_id']} @ {secret['service_account_email']}")
        return 1

    # Ensure if a blob argument is supplied a bucket argument is also supplied
    if validate_args(args) == -1:
        return -1

    # Initialize Variables
    debug, project_id = args.debug, session.project_id


    resource_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {}
    }
    bucket_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    all_buckets = {}
    all_validated_buckets = {}

    
    # Set up initial storage client    
    storage_client = storage.Client(credentials = session.credentials, project = project_id)    

    # Standard Start Message
    print(f"[*] Checking {project_id} for buckets...")

    all_buckets, bucket_validated = get_bucket_list(args, session, storage_client, project_id, resource_actions, debug)
    
    dprint(f"{len(all_buckets)} buckets were found" if all_buckets else "No buckets found", debug)
    
    ### Enumerate through each bucket and check external curl, IAM, and bucket metadata where applicable
    for bucket in list(all_buckets.keys()):  # [CLEANED] Simplified by iterating over frozen keys only
        print(f"[**] Reviewing {bucket.name}")

        if not args.minimal_calls and not (args.access_id and args.hmac_secret):
            dprint("GET Bucket Object", debug)
            bucket_get = get_bucket(storage_client, bucket.name, debug)
            if bucket_get:
                if not bucket_validated:
                    # pop the previous item (remove the key and get the value) and assign value to new key
                    all_buckets[bucket_get] = all_buckets.pop(bucket)  
                    bucket_validated = True
                bucket = bucket_get  # [FIXED] Always switch to enriched object
                
                bucket_actions[project_id]["storage.buckets.get"]["buckets"].add(bucket.name)
                save_bucket(bucket, session)

        # Bucket Unauth & Auth TestIAMPermissions
        if args.iam:
            dprint("TEST Bucket Permissions", debug)
            auth_perms, unauth_perms = check_bucket_permissions(storage_client, bucket.name, authenticated=True, unauthenticated=True, debug=debug)
            for p in auth_perms:
                bucket_actions[project_id][p]["buckets"].add(bucket.name)
            if unauth_perms:
                session.add_unauthenticated_permissions({"name": bucket.name, "type": "bucket", "permissions": str(unauth_perms)}, project_id=project_id)

        print(f"[***] LIST Bucket Blobs")

        blob_list = get_blob_list(storage_client, bucket, args, project_id, debug)

        if blob_list in ("Not Enabled", None):
            continue

        bucket_actions[project_id]["storage.objects.list"]["buckets"].add(bucket.name)
        all_buckets[bucket] = set(blob.name for blob in blob_list if blob.name[-1] != "/")

        if len(blob_list) == 0:
            print("[***] No blobs identified. Moving on...")

        for blob in blob_list:
            if args.access_id and args.hmac_secret:
                save_blob_xml(blob, session)
            else:
                save_blob(blob, session)

        if args.download:
            non_folder_blobs = [b for b in blob_list if b.name[-1] != "/"]
            output_dir = args.output or UtilityTools.get_save_filepath(session.workspace_directory_name, "", "Storage")
            start_time = time.time()
            lock = Lock()
            counter = {"count": 0}

            def process_blob(blob):
                blob_name = blob.name
                if blob_name[-1] == "/":
                    return False  # skip folders

                # download logic
                if args.access_id and args.hmac_secret:
                    status = hmac_download_blob(storage_client, args.access_id, args.hmac_secret,
                                    bucket.name, blob_name, project_id, debug,
                                    output_folder=output_dir)
                else:
                    status = download_blob(storage_client, bucket, blob, project_id, debug,
                                output_folder=output_dir,
                                user_regex_pattern=args.good_regex,
                                blob_size_limit=args.file_size)

                # Only save in main thread
                if status:
                    bucket_validated = True
                if args.threads == 1:
                    save_blob(blob, session)
                    bucket_actions[project_id]["storage.objects.get"]["buckets"].add(bucket.name)

                with lock:
                    counter["count"] += 1
                    
                    print(f"\r[***] Processed {counter['count']} of {len(non_folder_blobs)} blobs...", end="")
                    sys.stdout.flush()

                return True

            try:
                if args.threads == 1:
                    for blob in blob_list:
                        if args.time_limit and (time.time() - start_time) > int(args.time_limit):
                            print(f"\n[-] Time limit of {args.time_limit} reached for bucket {bucket.name}")
                            break
                        process_blob(blob)
                else:
                    with ThreadPoolExecutor(max_workers=args.threads) as executor:
                        executor.map(process_blob, blob_list)
                print()  # newline after final progress
            except KeyboardInterrupt:
                print("\n[*] Interrupted blob processing. Moving to next bucket...")
        if bucket_validated:
            all_validated_buckets[bucket] = all_buckets[bucket]

        session.insert_actions(resource_actions, project_id, column_name="compute_actions_allowed")
        session.insert_actions(bucket_actions, project_id, column_name="compute_actions_allowed")  

    if not dependency:
        UtilityTools.summary_wrapup(
            project_id,
            "Cloud Storage Buckets/Blobs",
            {k: sorted(list(v)) for k, v in all_validated_buckets.items()},
            ["id", "location"],
            primary_resource="Buckets",
            secondary_title_name="blobs",
            output_format=output_format
        )