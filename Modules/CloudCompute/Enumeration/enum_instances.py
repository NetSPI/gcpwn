from Modules.CloudCompute.utils.util_helpers import *

def run_module(user_args, session, first_run = False, last_run = False):
    
    # Set up Argparser to handle flag arguments; allow_abbrev is weird and turned off
    parser = argparse.ArgumentParser(description="Enumerate Compute Instance Options", allow_abbrev=False)

    zones_group = parser.add_mutually_exclusive_group()
    zones_group.add_argument("--all-zones", action="store_true", required=False,help="Try every zone in txt files")
    zones_group.add_argument("--zones-list",required=False,help="Zones in list format of zone1,zone2,zone3")
    zones_group.add_argument("--zones-file",required=False,help="File with each zone on newline")

    exclusive_instance_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_instance_group.add_argument("--instance-names", type=str,  help="Instance names to check in the format projects/[project_id]/zones/[zone]/instances/[instance_name]")
    exclusive_instance_group.add_argument("--instance-names-file", type=str, help="File name to get instance names to check in format projects/[project_id]/zones/[zone]/instances/[instance_name] per line")

    parser.add_argument("--iam",action="store_true",required=False,help="Call TestIAMPermissions on Compute Instances")
    
    parser.add_argument("--take-screenshot",action="store_true",required=False,help="Take screenshot if possible")
    parser.add_argument("--download-serial",action="store_true",required=False,help="Download serial log if possible")
    parser.add_argument("--output",type=str,required=False,help="Output file to save screenshot/serial if you don't want to use default")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform minimal set of API calls (usually just List API calls)")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    
    args = parser.parse_args(user_args)

    debug, project_id = args.debug, session.project_id
    action_dict = {}
    # Get zone if specified
    zones = None
    if args.all_zones: zones = get_all_instance_zones(session, project_id, all_zones = True)
    elif args.zones_list: zones = get_all_instance_zones(session, project_id, zones_list = args.zones_list)
    elif args.zones_file: zones = get_all_instance_zones(session, project_id, zones_file = args.zones_file)

    # Set up scope for call to specified project
    instance_client = compute_v1.InstancesClient(credentials = session.credentials)    
    
    print(f"[*] Checking {project_id} for instances...")

    # All instances for saving, all_instances_output for output
    all_instances, all_instances_output = {}, {}
    
    # If user did not supply instances, try to list all instances and proceed
    if not args.instance_names and not args.instance_names_file:

        # Specific zones = only list instances in those zones
        if zones:
        
            for zone in zones:

                if debug:
                    print(f"[DEBUG] Working through zone {zone}", end="\r")

                instances = list_instances(instance_client, project_id, zone, debug = debug)
                
                # If compute is not enabled don't bother going through rest of zones, just break
                if instances == "Not Enabled": break
                
                # If instances were found same permissions and save to all_instances for later looping
                if instances: 

                    action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('compute.instances.list')
                    all_instances.setdefault(project_id, {})[zone] = instances

        # No specific zones = defualt API call to get instances in all zones
        else:

            if debug:
                print(f"[DEBUG] Getting instances for all zones in {project_id}", end="\r")
            
            # Returns all instances in all zones per API documentation
            every_instance = list_aggregated_instances(instance_client, project_id, debug = debug)

            if every_instance:

                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('compute.instances.list')

                for zone, instances in every_instance.items():
                    all_instances.setdefault(project_id, {})[zone] = instances

    # If user supplied instances, take input and parse to get project/zone/instance_name and build dictionary and proceed
    else: 
        
        # parse list if STDIN or File
        if args.instance_names:
            all_instances_list = args.instance_names.split(",")
    
        elif args.instance_names_file:

            all_instances_list = [line.strip() for line in open(args.instance_names_file)]
        
        # For each instance create Instance object and add it to dictionary like we would do for automated approach
        for instance in all_instances_list:

            # For now assume all same project
            instance_project = instance.split("/")[1]
            instance_zone   = "zones/"+instance.split("/")[3]
            instance_name = instance.split("/")[5]

            instance_value = Instance(name = instance_name, zone = instance_zone)
            
            all_instances.setdefault(instance_project, {}).setdefault(instance_zone, []).append(instance_value)

    # Go through each project_id (mutliple if user-supplied)
    for project_id, instance_information in all_instances.items():
        
        # Go through each zone and grab the list of instances
        for zone, instances in instance_information.items():
        
            if debug: 

                if len(all_instances) != 0:
                    num_of_instances = len(all_instances)
                    print(f"[DEBUG] {num_of_instances} instances were found for zone {zone}")
                
                else:
                    print(f"[DEBUG]  No instances were found for zone {zone}")
            
            # For each instance in list of instances, try getting/screenshot/serial/etc
            for instance in instances:
                
                # If we got to this point without being user-supplied, must have come from list and save
                if not args.instance_names and not args.instance_names_file:
                    save_instance(instance, session, project_id)
    
                zone = instance.zone.split("/")[-1] # zone format: zones/us-west4-b
                instance_name = instance.name

                print(f"[**] Reviewing {instance_name}")

                if not args.minimal_calls:
                    print(f"[***] GET Instance")
                    instance_get = get_instance(instance_client, instance_name, project_id, zone, debug=False)
                    
                    if instance_get:
                        
                        # If user supplied, save to output dictionary since we have "proven" it does exist through GET call
                        if args.instance_names or args.instance_names_file: 
                            all_instances_output.setdefault(project_id, {}).setdefault(zone, set()).add(instance_get.name)
                        
                        # Add permission to dictionary and save GET response
                        action_dict.setdefault(project_id, {}).setdefault('compute.instances.get', {}).setdefault('instances', set()).add(instance_get.name)
                        save_instance(instance_get, session, project_id)

                if args.iam:
                    print(f"[***] TEST Instance Permissions")
                    
                    authenticated_permissions = check_instance_permissions(instance_client, project_id, instance_name, zone, debug = debug)
                    
                    for permission in authenticated_permissions:
                        
                        if args.instance_names or args.instance_names_file: 
                            all_instances_output.setdefault(project_id, {}).setdefault(zone, set()).add(instance_get.name)

                        action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault('instances', set()).add(instance_name)

                if args.take_screenshot:
                    print(f"[***] SCREENSHOT Instance")
                    instance_screenshot_b64 = instance_get_screenshot(instance_client, instance_name, project_id, zone, output = args.output, debug=False)
                    
                    if instance_screenshot_b64:
                        
                        if args.instance_names or args.instance_names_file: 
                            all_instances_output.setdefault(project_id, {}).setdefault(zone, set()).add(instance_get.name)

                        print(f"{UtilityTools.GREEN}[***] Successfully took screenshot of {instance_name}{UtilityTools.RESET}")
                        action_dict.setdefault(project_id, {}).setdefault('compute.instances.getScreenshot', {}).setdefault('instances', set()).add(instance_name)
            
                if args.download_serial:
                    print(f"[***] DOWNLOAD SERIAL Instance")
                    instance_serial = instance_get_serial(instance_client, instance_name, project_id, zone, session.workspace_directory_name, output = args.output, debug=False)
                    
                    if instance_serial:

                        if args.instance_names or args.instance_names_file: 
                            all_instances_output.setdefault(project_id, {}).setdefault(zone, set()).add(instance_get.name)

                        print(f"{UtilityTools.GREEN}[***] Successfully downloaded serial of {instance_name}{UtilityTools.RESET}")
                        action_dict.setdefault(project_id, {}).setdefault('compute.instances.getSerialPortOutput', {}).setdefault('instances', set()).add(instance_name)

    
        # Add per project to session
        session.insert_actions(action_dict,project_id, column_name = "compute_actions_allowed")

    # TODO Make this more efficient at some point
    # Use all_instances if no user input
    if not args.instance_names and not args.instance_names_file:

        for project_id, instance_only_info in all_instances.items():

            # Summary portion
            total_instances = sum(len(arr) for arr in instance_only_info.values())
            
            all_instances_key_values = {key: [obj.name for obj in value] for key, value in instance_only_info.items()}

            UtilityTools.summary_wrapup(resource_top = "Instances",resource_count = total_instances, resource_dictionary = all_instances_key_values, project_id = project_id)

    # Use all_instances_output if user input
    else:

        for project_id, instance_only_info in all_instances_output.items():

            # Summary portion
            total_instances = sum(len(arr) for arr in instance_only_info.values())
            
            all_instances_key_values = {key: [obj for obj in value] for key, value in instance_only_info.items()}

            UtilityTools.summary_wrapup(resource_top = "Instances",resource_count = total_instances, resource_dictionary = all_instances_key_values, project_id = project_id)