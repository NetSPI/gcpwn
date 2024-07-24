from Modules.CloudFunctions.utils.util_helpers import *

# TODO: Currently does not suppot multiple projects given at once
def run_module(user_args, session, first_run = False, last_run = False):    

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Functions Module", allow_abbrev=False)
    
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")

    exclusive_function_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_function_group.add_argument("--functions", type=str,  help="Functions in comma-separated format 'projects/*/locations/*/functions/*'")
    exclusive_function_group.add_argument("--functions-file", type=str, help="List of functions names in file")

    # Default is all_regions unless otherwise specified
    regions_group = parser.add_mutually_exclusive_group()
    regions_group.add_argument("--v1-regions", action="store_true", required=False,help="Atempt all V1 Regions")
    regions_group.add_argument("--v2-regions", action="store_true", required=False,help="Attempt all V2 Regions")
    regions_group.add_argument("--v1v2-regions", action="store_true", required=False,help="Attempt all V1 & V2 Regions")
    regions_group.add_argument("--regions-list",required=False,help="Regions in list format, ex. region1,region2,region3")
    regions_group.add_argument("--regions-file",required=False,help="File with 1 region per newline")

    parser.add_argument("--external-curl",required=False, action="store_true", help="Attempt to curl external URL")
    
    parser.add_argument("--iam",action="store_true",required=False,help="Run testIAMPermissions on function")
    
    parser.add_argument("--download",action="store_true",required=False,help="Attempt to download function source code")
    parser.add_argument("--txt", type=str, required=False, help="Output file for final summary")
    
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform minimal set of API calls (usually just List API calls)")

    parser.add_argument("--output",required=False,help="Get verbose data returned")

    args = parser.parse_args(user_args)

    debug, project_id = args.debug, session.project_id
        
    action_dict = {}


    # Set locations list
    regions = None
    if args.v1_regions or args.v1_regions or args.v1v2_regions: regions = get_all_function_regions(session, project_id, v1_regions = args.v1_regions, v2_regions = args.v2_regions, v1v2_regions = args.v1v2_regions)
    elif args.regions_list: regions = get_all_function_regions(session, project_id, regions_list = args.regions_list)
    elif args.regions_file: regions = get_all_function_regions(session, project_id, regions_file = args.regions_file)

    function_client = functions_v2.FunctionServiceClient(credentials=session.credentials)

    print(f"[*] Checking {project_id} for functions...")

    functions_list = []

    resources_to_print = set([])

    # List Functions
    if not (args.functions_file or args.functions):
            
        if regions:

            for region in regions:

                parent = f"projects/{project_id}/locations/{region}"
             
                functions_list_zone = list_functions(function_client, parent, debug=debug)
                
                if functions_list_zone == "Not Enabled":
                    break

                if functions_list_zone:
                    functions_list.extend(functions_list_zone)
                    for function in functions_list_zone:
                        action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add('cloudfunctions.functions.list')
                        function_name = function.name
                        function_location = function_name.split("/")[3]
                        function_simple_name = function_name.split("/")[5]
                        resources_to_print.add(f"[{function_location}] {function_simple_name}")
                        save_function(function, session)

        else:

            parent = f"projects/{project_id}/locations/-"
            functions_list = list_functions(function_client, parent, debug=debug)
            if functions_list == "Not Enabled":
                    functions_list = None

            if functions_list:
                for function in functions_list:
                    action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add('cloudfunctions.functions.list')
                    
                    function_name = function.name
                    function_location = function_name.split("/")[3]
                    function_simple_name = function_name.split("/")[5]
                    resources_to_print.add(f"[{function_location}] {function_simple_name}")
                    save_function(function, session)

    else:

        if args.functions:
            
            functions_list = [Function(name=function_name) for function_name in args.functions.split(",")]
        
        elif args.functions_file:

            functions_list = [Function(name=line.strip()) for line in open(args.functions_file, "r").readlines()] 

    
    if functions_list:
        # Get Function
        for function in functions_list:

            function_name = function.name
            function_project_id = function_name.split("/")[1]
            function_location = function_name.split("/")[3]
            function_simple_name = function_name.split("/")[5]
            function_stored_entry = f"[{function_location}] {function_simple_name}"

            print(f"[**] Reviewing {function_name}")

            if not args.minimal_calls:
                print(f"[***] GET Individual Function")
                function_metadata = get_function(function_client, function_name, debug=False)
                if function_metadata: 
                    if function.environment and function.environment == 2: 
                        action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.get", {}).setdefault("functions_v2", set()).add(function_stored_entry)
                    else:
                        action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.get", {}).setdefault("functions_v1", set()).add(function_stored_entry)

                    resources_to_print.add(function_stored_entry)
                    save_function(function_metadata, session)

            # https://cloud.google.com/functions/docs/calling/http#url
            if args.external_curl:
                
                entry = {
                            "primary_keys_to_match":{
                                "project_id": project_id,
                                "name": function_name
                            },
                            "data_to_insert":{
                                "external_curl":"True"
                            }
                        }

                print(f"[***] TEST Curl Check")
                
                if function.url:
                    
                    if check_anonymous_external(function_url = function.url):
                            session.insert_data('cloudfunctions-functions', entry, update_only = True )
                else:
                    
                    if check_anonymous_external(function_name):

                            session.insert_data('cloudfunctions-functions', entry, update_only = True )
            
            if args.iam:

                print(f"[***] TEST Function Permissions")

                function_client_rest = functions_v2.FunctionServiceClient(credentials=session.credentials)

                authenticated_permissions = check_function_permissions(function_client_rest, function.name)   

                for permission in authenticated_permissions:
                    if function.environment and function.environment == 2:
                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("functions_v2", set()).add(function_stored_entry)
                    else:
                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("functions_v1", set()).add(function_stored_entry)

            if args.download:
                
                print(f"[***] DOWNLOADING Function Source Code")

                # If source code detials are present
                if function.build_config and function.build_config.source:
                    
                    # Bucket Source Code Route

                    if function.build_config.source.storage_source:

                        if function.build_config.source.storage_source.bucket and function.build_config.source.storage_source.object_:
                            bucket_name = function.build_config.source.storage_source.bucket
                            blob_name = function.build_config.source.storage_source.object_
                            
                        else:
                            print("[X] Could not download the source code as a bucket and/or blob name were not specified")
                            return -1
                    
                        user_args = ["--buckets", bucket_name ,"--blobs", blob_name]

                        if args.output:
                            OUTPUT_DIRECTORY = args.output 
                        else:
                            OUTPUT_DIRECTORY = UtilityTools.get_save_filepath(session.workspace_name,"","Functions")

                        user_args = user_args + ["--download", "--output", OUTPUT_DIRECTORY]
                        module = importlib.import_module("Modules.CloudStorage.Enumeration.enum_buckets")
                        module.run_module(user_args, session)
                    
                    elif function.build_config.source.repo_source:
                        pass

                    elif "gitUri" in source_dict.keys():
                        pass
                
                else:
                    print(f"[*] There are no build config details for {function_name}. You might need to manually download the data via another module (enum_buckets or enum_repos).")
    

    UtilityTools.summary_wrapup(
        title="Function(s)",
        resource_list = sorted(resources_to_print),
        project_id = project_id,        
        output_file_path = args.txt
    )

    session.insert_actions(action_dict, project_id, column_name = "function_actions_allowed")