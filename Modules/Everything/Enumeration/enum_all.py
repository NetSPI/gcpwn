import importlib
import argparse
import threading
from Modules.Everything.utils.util_helpers import *

def run_other_module(session, user_args, module_name):
    try:

        module = importlib.import_module(module_name)
        module.run_module(user_args, session)
        
    except Exception as e:
        print(str(e))

## user_args is passed from the previous module, pass this into the , blob_max_size = args.parser if you are doing the non-standalone callable version
def run_module(user_args, session, first_run = False, last_run = False):
 
    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate All Services", allow_abbrev=False)

    parser.add_argument("--download", action="store_true", help="Where to save the stdout output")
    parser.add_argument("--download-output", required=False, help="Where to save the stdout output")
    
    parser.add_argument("--regions-list", required=False, help="List of regions as region1,region2,region3")
    parser.add_argument("--zones-list", required=False, help="Lize of zones as zone1,zone2,zone3")
    
    parser.add_argument("--iam", action="store_true", help="Execute TestIamPermissions wherever applicable")
    parser.add_argument("--all-permissions", action="store_true", help="For projects/folders/orgs, try ~9000 permissions for testIAMPermissions")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    
    parser.add_argument("--resource-manager", action="store_true", help="Execute resource mananger modules")
    parser.add_argument("--cloud-compute", action="store_true", help="Execute cloud compute modules")
    parser.add_argument("--cloud-functions", action="store_true", help="Execute cloud functions modules")
    parser.add_argument("--cloud-storage", action="store_true", help="Execute cloud storage modules")
    parser.add_argument("--cloud-iam", action="store_true", help="Execute IAM modules")
    parser.add_argument("--cloud-secretsmanager", action="store_true", help="Execute secrets manager modules")


    args = parser.parse_args(user_args)

    every_flag_missing = not args.resource_manager and not args.cloud_compute and not args.cloud_functions and not args.cloud_storage and not args.cloud_iam

    debug = args.debug

    more = False

    print(f"[***********] Beginning enumeration for {session.project_id} [***********]")


    if first_run and (args.resource_manager or every_flag_missing):

        original_project_count = len(session.global_project_list)

        # Resource Manager
        print("[*] Beginning Enumeration of RESOURCE MANAGER Resources...")

        user_args = []

        if debug:
            user_args = ["-v"]

        if args.iam:
            user_args = user_args + ["--iam"]

            if args.all_permissions:
                user_args = user_args + ["--all-permissions"]

        run_other_module(session, user_args, "Modules.ResourceManager.Enumeration.enum_resources")

        final_project_count = len(session.global_project_list)

        if original_project_count != final_project_count:
            more = True
            print("[*] Additional resources were identified projects/folders/orgs were identified")
            
    
    if args.cloud_compute or every_flag_missing:
    
        print("[*] Beginning Enumeration of CLOUD COMPUTE Resources...")

        user_args = []

        if debug:
            user_args = ["-v"]

        if args.zones_list:
            user_args.extend(["--zones-list", args.zones_list])

        if args.download:

            user_args.extend(["--take-screenshot", "--download-serial"])

            if args.download_output:

                output_directory = args.download_output
                user_args.extend(["--output",output_directory])

        if args.iam:
            user_args = user_args + ["--iam"]

        run_other_module(session, user_args, "Modules.CloudCompute.Enumeration.enum_instances")

        user_args = []

        if debug:
            user_args = ["-v"]
        run_other_module(session, user_args, "Modules.CloudCompute.Enumeration.enum_compute_projects")


    if args.cloud_functions or every_flag_missing:
    
        print("[*] Beginning Enumeration of CLOUD FUNCTION Resources...")

        user_args = []

        if debug:
            user_args = ["-v"]
        
        if args.regions_list:
            user_args.extend(["--regions-list", args.regions_list])
        
        if args.download:

            user_args.extend(["--download"])

            if args.download_output:
                output_directory = args.download_output
                user_args.extend(["--output",output_directory])
        
        if args.iam:
            user_args = user_args + ["--iam"]
        
        run_other_module(session, user_args, "Modules.CloudFunctions.Enumeration.enum_functions")

    if args.cloud_storage or every_flag_missing:

        print("[*] Beginning Enumeration of CLOUD STORAGE Resources...")

        user_args = []

        module = importlib.import_module("Modules.CloudStorage.Enumeration.enum_hmac_keys")
        module.run_module(user_args, session)

        
        if args.download:
            user_args.extend(["--download"])

            if args.download_output:
                output_directory = args.download_output
                user_args.extend([ "--output",output_directory])

        if args.iam:
            user_args = user_args + ["--iam"]

        run_other_module(session, user_args, "Modules.CloudStorage.Enumeration.enum_buckets")

    if args.cloud_secretsmanager or every_flag_missing:
        print("[*] Beginning Enumeration of SECRETS MANAGER Resources...")
        if args.download:
            user_args.extend(["--download"])

        if args.iam:
            user_args = user_args + ["--iam"]

        run_other_module(session, user_args, "Modules.SecretsManager.Enumeration.enum_secrets")


    if args.cloud_iam or every_flag_missing:
        # IAM
        print("[*] Beginning Enumeration of IAM Resources...")

        user_args = []
        if args.iam:
            user_args = user_args + ["--iam"]
        run_other_module(session, user_args, "Modules.IAM.Enumeration.enum_service_accounts")

        user_args = []
        run_other_module(session, user_args, "Modules.IAM.Enumeration.enum_custom_roles",)

        if last_run and more != True:
            run_other_module(session, user_args, "Modules.IAM.Enumeration.enum_policy_bindings")

        print(f"[***********] Ending enumeration for {session.project_id} [***********]")

    if more:
        return 2
    
    return 1
