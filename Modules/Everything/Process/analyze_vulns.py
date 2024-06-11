# Output list of buckets as a JSON
from google.cloud import resourcemanager_v3
from google.cloud import storage
from google.iam.v1 import iam_policy_pb2  # type: ignore
from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
import ast
import argparse
import importlib
import yaml

from Modules.Everything.utils.util_helpers import *

# TODO: Currently working on integrating this with rest of checks
def cloud_storage_bucket_analysis(all_storage_bucket_data):
    
    # External Curl
    potentially_public_buckets = []
    for bucket in all_storage_bucket_data:
        project_id = bucket["project_id"]
        name = bucket["name"]
        external_curl = bucket["external_curl"]
        if external_curl == "True":
            potentially_public_buckets.append((name,project_id))

    if len(potentially_public_buckets) > 0:
        print("[X] The following Cloud Storage Buckets appear to be accessible externally:")
        for bucket in potentially_public_buckets:
            bucket_name = bucket[0]
            project_id = bucket[1]
            print(f"{bucket_name} ({project_id})")

def cloud_storage_blobs_analysis(all_storage_blob_data):
    
    pattern = ["password", "secret", "config", "confidential", ".env", ".pem"]

    interesting_blobs = {}

    for blob in all_storage_blob_data:
        blob_name = blob["name"]
        if blob_name[-1] == "/":
            break
        else:
            blob_final_name = blob_name.split("/")[-1]

        bucket_name = blob["bucket_name"]
        project_id = blob["project_id"]
        matched_patterns = []
        
        for value in pattern:
            if value in blob_final_name:
                matched_patterns.append(value)

        if matched_patterns:
            for matched_pattern in matched_patterns:
                if bucket_name in interesting_blobs:
                    existing_blobs = interesting_blobs[bucket_name]
                    if (blob_name, project_id) not in [(item[0], item[1]) for item in existing_blobs]:
                        interesting_blobs[bucket_name].append((blob_name, project_id, matched_patterns))
                else:
                    interesting_blobs[bucket_name] = [(blob_name, project_id, matched_patterns)]


    if len(interesting_blobs.keys()) > 0:
        print("The following Cloud Storage Blobs appear to have interesting names. Check permissions to see if you can fetch any:")
        for bucket_name, blob_list in interesting_blobs.items():
            print(f"[*] {bucket_name}")
            for blob in blob_list:
                blob_name = blob[0]
                project_id = blob[1]
                print(f" - {blob_name} ({project_id})")        

def cloud_storage_misc_analysis(session):
    
    # Check if external-curl is true for bucket indicating it is probably publicly accessible
    all_storage_bucket_data = session.get_data("cloudstorage-buckets")
    if all_storage_bucket_data:
        cloud_storage_bucket_analysis(all_storage_bucket_data)

    # Check if any blob names are interesting and should be brought ot user attention
    all_storage_blob_data = session.get_data("cloudstorage-bucketblobs")
    if all_storage_blob_data:
        cloud_storage_blobs_analysis(all_storage_blob_data)

    
def iam_role_analysis(
                session,
                first_run = False, 
                output_file = None, 
                check_vulns = False, 
                issue = None, 
                csv = False, 
                txt = False, 
                stdout = False
                ):

    print("[*] Performing IAM Analysis on Workspace Thus Far...")

    get_all_iam_metadata = session.get_data("member-permissions-summary")
    if get_all_iam_metadata:

        for member_binding in get_all_iam_metadata:
            member = member_binding["member"]
            member_data_dict = ast.literal_eval(member_binding["roles_and_assets"])
            print(member)
            generate_summary_of_roles_or_vulns(
                                                    session,
                                                    member,
                                                    member_data_dict, 
                                                    first_run = first_run,
                                                    check_role_vulns = True,
                                                    output_file = output_file,
                                                    stdout = stdout,
                                                    csv = csv,
                                                    txt = txt
                                            )

    else:
        print("[X] Either no IAM data has been enumerated thus far or the database operation failed. Moving on to next service...")

def iam_permissions_analysis(
                session,
                first_run = False, 
                output_file = None, 
                check_vulns = False, 
                issue = None, 
                csv = False, 
                txt = False, 
                stdout = False
                ):

        print("[*] Performing IAM Analysis on Workspace Thus Far...")

        get_all_iam_permission_metadata = session.get_actions()  
        if get_all_iam_permission_metadata:
            
            for members_permission_data in get_all_iam_permission_metadata:
                generate_summary_of_permission_vulns(
                                                        members_permission_data,
                                                        session,
                                                        check_permission_vulns = True,
                                                        first_run = first_run,
                                                        output_file = output_file,
                                                        stdout = stdout,
                                                        csv = csv,
                                                        txt = txt
                                                )


def add_guidance_for_role(role):

    instructions = []

    instructions_file = open("./utils/permission-mapping.yaml")
    yaml_data = instructions_file.read().strip()

    role_guidance_data = yaml.safe_load(yaml_data)

    for violation in role_guidance_data:
        permission = violation["permission"]
        guidance  = violation["permission"]
        if role in violation["roles"]:
            instruction = f"This role contains {permission}. Try {instructions}"
            instructions.append(instruction)
    return instructions


# Review all IAM bindings for allUsers or allAuthenticatedUsers
def anonymous_and_all_authenticated_users_catch(session,
                                        first_run = False, 
                                        output_file = None, 
                                        check_vulns = False, 
                                        issue = None, 
                                        csv = False, 
                                        txt = False, 
                                        stdout = False):
    
    # Get all bindings
    anonymous_binding = session.get_data("member-permissions-summary", conditions = "member = \"allUsers\"")
    
    if anonymous_binding:
        data_dict = ast.literal_eval(anonymous_binding[0]["roles_and_assets"])
        generate_summary_of_roles_or_vulns(
                                                session,
                                                "allUsers",
                                                data_dict, 
                                                issue_type = "ALL_USERS",
                                                issue_label = "Issue #1: Anonymous Access",
                                                first_run = True,
                                                check_role_vulns = True,
                                                output_file = output_file,
                                                stdout = stdout,
                                                csv = csv,
                                                txt = txt
                                            )
    
    else:
        print("[X] No Anonymous Permissions were identified")

    all_auth_binding = session.get_data("member-permissions-summary", conditions = "member = \"allAuthenticatedUsers\"")
    if all_auth_binding:
        generate_summary_of_roles_or_vulns(
                                                session,
                                                data_dict, 
                                                "allAuthenticatedUsers",
                                                issue_type = "ALL_AUTHENTICATED_USERS",
                                                issue_label = "Issue #1: All Authenticated User Access",
                                                first_run = first_run,
                                                check_role_vulns = True,
                                                output_file = output_file,
                                                stdout = stdout,
                                                csv = csv,
                                                txt = txt
                                            )       
    else:
        print("[X] No Arbitrary Authenticated User Permissions were identified")



# user_args - command line instructions passed in by the user, ingest into ArgParse
# project_id - Current project ID module is running on
# session - Contains current workspace ID, database handlers, and permissions if needed
# last_project - Flag letting you know if this is the last project the module is running on, only True if more than one project is provided and you are on last project
## user_args is passed from the previous module, pass this into the , blob_max_size = args.parser if you are doing the non-standalone callable version
def run_module(user_args, session, first_run = False, last_run = False):


    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Analyze Vulns from Process IAM Bindings", allow_abbrev=False)
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    
    parser.add_argument("--txt", action="store_true", help="Output in TXT format")
    parser.add_argument("--csv", action="store_true", help="Output in CSV format")
    parser.add_argument("--silent", action="store_true", help="Don't print STDOUT")
    
    parser.add_argument("--output",required=False,help="Output directory to store IAM snapshot report")
    
    args = parser.parse_args(user_args)

    debug = args.debug
 
    if args.silent:
        stdout = False
    else:
        stdout = True

    print("[*****************] Anonymous and/or All Authenticated User Permissions  [*****************]")

    anonymous_and_all_authenticated_users_catch(
                                            session, 
                                            output_file = args.output, 
                                            csv = args.csv, 
                                            txt = args.txt, 
                                            stdout = stdout
                                        )

    print("[*****************] IAM Analysis (Roles) [*****************]")
    
    #cloud_storage_misc_analysis(session)

    iam_role_analysis(
                session, 
                output_file = args.output, 
                csv = args.csv, 
                txt = args.txt, 
                stdout = stdout
                )

    print("[*****************] All User Permissions Thus Far  [*****************]")

    iam_permissions_analysis(
            session, 
            output_file = args.output, 
            csv = args.csv, 
            txt = args.txt, 
            stdout = stdout
            )
    

