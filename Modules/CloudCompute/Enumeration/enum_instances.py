from Modules.CloudCompute.utils.util_helpers import *

# TODO: Make metadata output cleaner/show more

class HashableInstance:

    network_interfaces_output = None
    metadata_output = None

    # default validated to true unless otherwise noted
    def __init__(self, instance, validated = True):
        self._instance = instance
        self.validated = validated

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash((self._instance.id, self._instance.name))

    def __eq__(self, other):

        # Compare based on the name or any other combination of unique attributes
        return isinstance(other, HashableInstance) and self._instance.id == other._instance.id and self._instance.name == other._instance.name

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._instance, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableInstance(id={self._instance.id}, name={self._instance.name})"

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate Compute Instance Options", allow_abbrev=False)
    
    zones_group = parser.add_mutually_exclusive_group()
    zones_group.add_argument("--all-zones", action="store_true", required=False,help="Try every zone in txt files in ./utils/zones.txt")
    zones_group.add_argument("--zones-list",required=False,help="Zones in list format of zone1,zone2,zone3")
    zones_group.add_argument("--zones-file",required=False,help="File name with each zone on newline")
    
    exclusive_instance_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_instance_group.add_argument("--instance-names", type=str,  help="Instance names to check in the format projects/[project_id]/zones/[zone]/instances/[instance_name]")
    exclusive_instance_group.add_argument("--instance-names-file", type=str, help="File name with each instance on newline in format projects/[project_id]/zones/[zone]/instances/[instance_name]")

    parser.add_argument("--iam",action="store_true",required=False,help="Call TestIAMPermissions on Compute Instances")
    
    parser.add_argument("--take-screenshot",action="store_true",required=False,help="Take screenshot if possible")
    parser.add_argument("--download-serial",action="store_true",required=False,help="Download serial log if possible")
    
    parser.add_argument("--output",type=str,required=False,help="Output file to save screenshot/serial if you don't want to use default")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform minimal set of API calls (usually just List API calls)")
    
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")

    args = parser.parse_args(user_args)

    # Initialize Variables
    debug, project_id = args.debug, session.project_id
    action_dict = {}
    all_instances = {}

    # Set up initial instance client    
    instance_client = compute_v1.InstancesClient(credentials = session.credentials)    

    # Get zone if specified
    zones = None
    if args.all_zones:
        zones = get_all_instance_zones(session, project_id, all_zones=True)
    elif args.zones_list:
        zones = get_all_instance_zones(session, project_id, zones_list=args.zones_list)
    elif args.zones_file:
        zones = get_all_instance_zones(session, project_id, zones_file=args.zones_file)

    # Standard Start Message
    print(f"[*] Checking {project_id} for instances...")

    # Attempt to manually parse supplied values, else get them via automated means

    # Manual List + Automated List
    if args.instance_names or args.instance_names_file:

        # STDIN
        if args.instance_names:
            all_instances_list = args.instance_names.split(",")

        # File
        elif args.instance_names_file:
            all_instances_list = [line.strip() for line in open(args.instance_names_file)]
        
        # Create Compute Instance object based off name; will be updated with more complete object if it exists
        for instance in all_instances_list:

            # For now assume all same project
            _, instance_project, _, zone, _, instance_name = instance.split("/")
            instance_value = HashableInstance(Instance(name = instance_name, zone = f"zones/{zone}"))
            instance_value.validated = False
            
            all_instances.setdefault(instance_project, set([])).add(instance_value)  

    else:

        # Specific zones 
        if zones:
        
            for zone in zones:

                if debug:
                    print(f"[DEBUG] Getting instances for zone {zone} in {project_id}")

                instances = list_instances(instance_client, project_id, zone, debug = debug)
                
                # If compute is not enabled don't bother going through rest of zones, just break
                if instances == "Not Enabled":
                    all_instances.setdefault(project_id, set([]))
                    break
                
                # If instances are none set default for all_instances but dont break as future zones might have data
                elif instances == None:
                    all_instances.setdefault(project_id, set([]))

                else:

                    action_dict['project_permissions'][project_id].add('compute.instances.list')

                    if len(instances) == 0:
                        all_instances.setdefault(project_id, set([]))
                    
                    else: 
                        all_instances.setdefault(project_id, set([])).update({HashableInstance(instance) for instance in instances})
                        for instance in instances:
                            save_instance(instance, session, project_id)

        # Default Ever Zone
        else:

            if debug:
                print(f"[DEBUG] Getting instances for all zones in {project_id}")
            
            # Returns all instances in all zones per API documentation
            every_instance = list_aggregated_instances(instance_client, project_id, debug = debug)
            
            # If API is not enabled or error, than just set empty dictionary and don't set permissions
            if every_instance == "Not Enabled" or every_instance == None:
                all_instances.setdefault(project_id, set())

            else:

                # Set action_dict whether instances are found or API worked but still empty list
                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('compute.instances.list')

                # Handle case where every_instance is empty
                if not every_instance:
                    all_instances.setdefault(project_id, set())

                else:
                    for zone, instances in every_instance.items():
                        all_instances.setdefault(project_id, set()).update(HashableInstance(instance) for instance in instances)
                        for instance in instances:
                            save_instance(instance, session, project_id)

    # Identified resources via list or manual supply, now run subsequent calls on resources
    for project_id, instances in all_instances.items():

        if debug: 

            if len(instances) != 0:
                print(f"[DEBUG] {len(all_instances)} instances were found")
            
            else:
                print(f"[DEBUG]  No instances were found")
        
        # For each instance in list of instances, try getting/screenshot/serial/etc
        for instance in instances:

            validated = instance.validated

            zone = instance.zone.split("/")[-1] # zone format: zones/us-west4-b
            instance_name = instance.name

            print(f"[**] Reviewing {instance_name}")

            # If not minimum calls, GET instance
            if not args.minimal_calls:

                print(f"[***] GET Instance")
                instance_get = get_instance(instance_client, instance_name, project_id, zone, debug=debug)
                
                if instance_get:
                    
                    # If user supplied, save to output dictionary since we have "proven" it does exist through GET call
                    if (args.instance_names or args.instance_names_file) and validated == False: 
                        validated = True
                        all_instances[project_id].discard(instance)
                        all_instances[project_id].add(HashableInstance(instance_get))
                    
                    # Add permission to dictionary and save GET response
                    action_dict.setdefault(project_id, {}).setdefault('compute.instances.get', {}).setdefault('instances', set()).add(instance_get.name)
                    save_instance(instance_get, session, project_id)

            # Compute TestIAMPermissions
            if args.iam:

                print(f"[***] TEST Instance Permissions")
                authenticated_permissions = check_instance_permissions(instance_client, project_id, instance_name, zone, debug = debug)
                
                if authenticated_permissions and len(authenticated_permissions) > 0 and (args.instance_names or args.instance_names_file) and validated == False:
                        validated = True
                        all_instances[project_id].discard(instance)
                        all_instances[project_id].add(HashableInstance(instance))
                     
                for permission in authenticated_permissions:
                    
                    action_dict.setdefault(project_id, {}).setdefault(permission, {}).setdefault('instances', set()).add(instance_name)
            
            # Take Screenshot
            if args.take_screenshot:

                print(f"[***] SCREENSHOT Instance")

                instance_screenshot_b64 = instance_get_screenshot(instance_client, instance_name, project_id, zone, output = args.output, debug=debug)
                
                if instance_screenshot_b64:
                    
                    if args.instance_names or args.instance_names_file and validated == False: 
                        validated = True
                        all_instances[project_id].discard(instance)
                        all_instances[project_id].add(HashableInstance(instance))

                    print(f"{UtilityTools.GREEN}[***] Successfully took screenshot of {instance_name}{UtilityTools.RESET}")
                    action_dict.setdefault(project_id, {}).setdefault('compute.instances.getScreenshot', {}).setdefault('instances', set()).add(instance_name)

            # Download Serial
            if args.download_serial:
                print(f"[***] DOWNLOAD SERIAL Instance")
                instance_serial = instance_get_serial(instance_client, instance_name, project_id, zone, session.workspace_directory_name, output = args.output, debug=False)
                
                if instance_serial:

                    if args.instance_names or args.instance_names_file and validated == False: 
                        validated = True
                        all_instances[project_id].discard(instance)
                        all_instances[project_id].add(HashableInstance(instance))

                    print(f"{UtilityTools.GREEN}[***] Successfully downloaded serial of {instance_name}{UtilityTools.RESET}")
                    action_dict.setdefault(project_id, {}).setdefault('compute.instances.getSerialPortOutput', {}).setdefault('instances', set()).add(instance_name)

        # Add per project to session
        session.insert_actions(action_dict,project_id, column_name = "compute_actions_allowed")

    if all_instances:
        
        for project_id, instance_only_info in all_instances.items():

            if args.instance_names or args.instance_names_file:
                instance_only_info = [instance for instance in instance_only_info if instance.validated]


            # Clean up zone
            list(map(lambda instance: setattr(
                instance._instance, 
                'zone', 
                instance._instance.zone.split("/")[-1]), 
                instance_only_info
            ))

          
            # Clean up metadata
            list(map(lambda instance: setattr(
                instance, 
                'metadata_output', 
                "\n".join([f"KEY: {item.key}\nVALUE: {item.value}" for item in instance._instance.metadata.items])
                if ("txt" not in output_format) else [f"KEY: {item.key}\nVALUE: {item.value}" for item in instance._instance.metadata.items]
            ), instance_only_info))


            for instance in instance_only_info:
                ips = get_instance_ip_address(instance)
                if ips:
                    ips = "\n".join(ips)

                # Set the new field with the formatted output as a single string
                setattr(instance, 'network_interfaces_output', ips)

            UtilityTools.summary_wrapup(
                project_id, 
                "EC2 Compute Instances", 
                list(instance_only_info), 
                ["id","name","zone","network_interfaces_output","metadata_output"],
                primary_resource = "Instances",
                primary_sort_key = "zone",
                output_format = output_format 
            )