from Modules.CloudFunctions.utils.util_helpers import *


class HashableFunction:

    service_account_output = None
    region_val = None
    state_output = None
    env = None

    def __init__(self, function, validated = True):
        self._function = function
        self.validated = validated

        if function.state and function.state == 1:
            self.state_output = "ACTIVE"
        elif function.state and function.state == 2:
            self.state_output = "FAILED"
        elif function.state and function.state == 3:
            self.state_output = "DEPLOYING"
        elif function.state and function.state == 4:
            self.state_output = "DELETING"
        elif function.state and function.state == 5:
            self.state_output = "UNKNOWN"

        if function.environment and function.environment == 1:
            self.env = "GEN_1"
        elif function.environment and function.environment == 2:
            self.env = "GEN_2"
        elif function.environment:
            self.env = "ENVIRONMENT_UNSPECIFIED"

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._function.name)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        return isinstance(other, HashableFunction) and self._function.name == other._function.name

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._function, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableFunction({self._function.name})"

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):    

    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate Functions Module", allow_abbrev=False)
    
    exclusive_function_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_function_group.add_argument("--function-names", type=str,  help="Functions in comma-separated format 'projects/*/locations/*/functions/*'")
    exclusive_function_group.add_argument("--function-names-file", type=str, help="List of functions names in file")
    parser.add_argument("--version", required=False, choices=["1", "2"], help="Version of function: '1' or '2'")


    regions_group = parser.add_mutually_exclusive_group()
    regions_group.add_argument("--v1-regions", action="store_true", required=False,help="Atempt all V1 Regions")
    regions_group.add_argument("--v2-regions", action="store_true", required=False,help="Attempt all V2 Regions")
    regions_group.add_argument("--v1v2-regions", action="store_true", required=False,help="Attempt all V1 & V2 Regions")
    regions_group.add_argument("--regions-list",required=False,help="Regions in list format, ex. region1,region2,region3")
    regions_group.add_argument("--regions-file",required=False,help="File with 1 region per newline")

    parser.add_argument("--external-curl",required=False, action="store_true", help="Attempt to curl external URL")
    
    parser.add_argument("--iam",action="store_true",required=False,help="Run testIAMPermissions on function")
    
    parser.add_argument("--download",action="store_true",required=False,help="Attempt to download function source code")
    
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform minimal set of API calls (usually just List API calls)")

    parser.add_argument("--output",required=False,help="Get verbose data returned")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")

    args = parser.parse_args(user_args)

    # Initialize Variables
    debug, project_id = args.debug, session.project_id
    action_dict = {}
    all_functions = {}

    # Set up initial function client    
    function_client = functions_v2.FunctionServiceClient(credentials=session.credentials)

    # Get region if specified
    regions = None
    if args.v1_regions or args.v1_regions or args.v1v2_regions: regions = get_all_function_regions(session, project_id, v1_regions = args.v1_regions, v2_regions = args.v2_regions, v1v2_regions = args.v1v2_regions)
    elif args.regions_list: regions = get_all_function_regions(session, project_id, regions_list = args.regions_list)
    elif args.regions_file: regions = get_all_function_regions(session, project_id, regions_file = args.regions_file)

    # Set OUTPUT directory if different than default
    if args.output:
        OUTPUT_DIRECTORY = args.output 
    else:
        OUTPUT_DIRECTORY = UtilityTools.get_save_filepath(session.workspace_name,"","Functions")

    # Standard Start Message
    print(f"[*] Checking {project_id} for functions...")

    # Manual List + Automated List
    if args.function_names_file or args.function_names:

        # STDIN
        if args.function_names:
                
            function_temporary_list = [Function(name=function_name) for function_name in args.function_names.split(",")]
        
        # File
        elif args.function_names_file:

            function_temporary_list = [Function(name=line.strip()) for line in open(args.function_names_file, "r").readlines()] 

        # Create Function object based off name; will be updated with more complete object if it exists
        for function in function_temporary_list:

            _, function_project_id, _, region, _, function_name = function.split("/")

            if args.version:
                env = int(args.version)
            
            # Default to v2
            else:
                env = 2

            function_value = HashableFunction(Function(name=function_name, environment=env))
            function_value.validated = False
            
            all_functions.setdefault(function_project_id, set()).add(function_value)

    else:
            
        if regions:

            for region in regions:

                if debug:
                    print(f"[DEBUG] Getting functions for region {region} in {project_id}")

                parent = f"projects/{project_id}/locations/{region}"
             
                functions = list_functions(function_client, parent, debug=debug)
                
                if functions == "Not Enabled":
                    all_functions.setdefault(project_id, set([]))
                    break

                elif functions == None:
                    all_functions.setdefault(project_id, set([]))

                else:

                    action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add('cloudfunctions.functions.list')

                    if len(functions) == 0:
                        all_functions.setdefault(project_id, set([]))
                    
                    else: 
                        all_functions.setdefault(project_id, set([])).update({HashableFunction(function) for function in functions})
                        for function in functions:
                            save_function(function, session)
            
        else:

            if debug:
                print(f"[DEBUG] Getting functions for all regions in {project_id}")

            parent = f"projects/{project_id}/locations/-"

            every_function = list_functions(function_client, parent, debug=debug)

            if every_function == "Not Enabled" or every_function == None:
                all_functions.setdefault(project_id, set())

            else:

                # Set action_dict whether functions are found or API worked but still empty list
                action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add('cloudfunctions.functions.list')

                # Handle case where every_function is empty
                if not every_function:
                    all_functions.setdefault(project_id, set())

                else:

                    for function in every_function:
                        all_functions.setdefault(project_id, set()).add(HashableFunction(function))
                        save_function(function, session)

    # Identified resources via list or manual supply, now run subsequent calls on resources
    for project_id, functions in all_functions.items():

        if debug: 

            if len(functions) != 0:
                print(f"[DEBUG] {len(functions)} functions were found")
            else:
                print(f"[DEBUG]  No functions were found")

        for function in functions:

            validated = function.validated

            function_name = function.name
            _, function_project_id, _, function_location, _, function_simple_name = function.name.split("/")

            # Shortname to store for granular permissions
            permission_label = f"[{function_location}] {function_simple_name}"

            print(f"[**] Reviewing {function_simple_name}")

            # If not minimum calls, GET function
            if not args.minimal_calls:

                print(f"[***] GET Function")
                function_get = get_function(function_client, function_name, debug=False)

                if function_get: 

                    if (args.function_names or args.function_names_file) and validated == False:
                        validated = True 
                        all_functions[project_id].discard(function)
                        all_functions[project_id].add(HashableFunction(function_get))

                    # Default to v2
                    if function.environment and function.environment == 1: 
                        action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.get", {}).setdefault("functions_v1", set()).add(permission_label)
                    else:
                        action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.get", {}).setdefault("functions_v2", set()).add(permission_label)
                    
                    save_function(function_get, session)

            # https://cloud.google.com/functions/docs/calling/http#url
            if args.external_curl:

                print(f"[***] TEST External Curl")
                
                entry = {
                            "primary_keys_to_match":{
                                "project_id": project_id,
                                "name": function_name
                            },
                            "data_to_insert":{
                                "external_curl":"True"
                            }
                        }

                if function.url:

                    if debug:
                        print(f"[DEBUG] Checking {function.url} via GET request")

                    if check_anonymous_external(function_url = function.url):
                        session.insert_data('cloudfunctions-functions', entry, update_only = True )
                else:
                    
                    if debug:
                        print(f"[DEBUG] Checking {function.url} via GET request")

                    if check_anonymous_external(function_name):
                        session.insert_data('cloudfunctions-functions', entry, update_only = True )

            # Function TestIAMPermissions
            if args.iam:

                print(f"[***] TEST Function Permissions")

                authenticated_permissions = check_function_permissions(function_client, function.name)   
                
                if authenticated_permissions and len(authenticated_permissions) > 0 and (args.function_names or args.function_names_file) and validated == False:
                    validated = True
                    all_functions[project_id].discard(function)
                    all_functions[project_id].add(HashableFunction(function))

                for permission in authenticated_permissions:
                    if function.environment and function.environment == 1:
                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("functions_v1", set()).add(permission_label)
                    else:
                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault("functions_v2", set()).add(permission_label)

            # Download Source Code (Involves calling other modules)
            if args.download:
                
                print(f"[***] DOWNLOADING Function Source Code")

                # If source code details are present
                if function.build_config and function.build_config.source:
                    
                    # Bucket Source Code Route
                    if function.build_config.source.storage_source:

                        if function.build_config.source.storage_source.bucket and function.build_config.source.storage_source.object_:
                            bucket_name = function.build_config.source.storage_source.bucket
                            blob_name = function.build_config.source.storage_source.object_
                            
                        else:
                            print("[X] Could not download the source code as a bucket and/or blob name were not specified")
                            return -1
                    
                        user_args = ["--bucket-names", bucket_name ,"--blob-names", blob_name]

                        user_args = user_args + ["--download", "--output", OUTPUT_DIRECTORY]
                        module = importlib.import_module("Modules.CloudStorage.Enumeration.enum_buckets")
                        module.run_module(user_args, session, dependency = True)
                    
                    elif function.build_config.source.repo_source:
                        pass

                    elif "gitUri" in source_dict.keys():
                        pass
                
                else:
                    print(f"[*] There are no build config details for {function_name}. You might need to manually download the data via another module (enum_buckets or enum_repos).")
    
        session.insert_actions(action_dict, project_id, column_name = "function_actions_allowed")

    if all_functions:
        
        for project_id, function_only_info in all_functions.items():

            if args.function_names or args.function_names_file:
                function_only_info = [function for function in function_only_info if function.validated]

            list(map(lambda function: setattr(
                function, 
                'region_val', 
                function._function.name.split("/")[3]), 
                function_only_info
            ))
            
            # Clean up regions
            list(map(lambda function: setattr(
                function._function, 
                'name', 
                function._function.name.split("/")[-1]), 
                function_only_info
            ))

            UtilityTools.summary_wrapup(
                project_id, 
                "Cloud Functions", 
                list(function_only_info), 
                ["name","region_val","env","state_output","url"],
                primary_resource = "Functions",
                primary_sort_key = "region_val",
                output_format = output_format
            )