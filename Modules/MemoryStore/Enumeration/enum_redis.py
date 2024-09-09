from Modules.MemoryStore.utils.util_helpers import *

class HashableRedisInstance:

    auth_string = None
    sate_output = None

    def __init__(self, redis_instance, validated = True):
        self._redis_instance = redis_instance
        self.validated = validated

        if redis_instance.state == 0:
            self.state_output = "STATE_UNSPECIFIED"
        elif redis_instance.state and redis_instance.state == 1:
            self.state_output = "CREATING"
        elif redis_instance.state and redis_instance.state == 2:
            self.state_output = "READY"
        elif redis_instance.state and redis_instance.state == 3:
            self.state_output = "UPDATING"
        elif redis_instance.state and redis_instance.state == 4:
            self.state_output = "DELETING"
        elif redis_instance.state and redis_instance.state == 5:
            self.state_output = "REPAIRING"
        elif redis_instance.state and redis_instance.state == 6:
            self.state_output = "MAINTENANCE"
        elif redis_instance.state and redis_instance.state == 7:
            self.state_output = "IMPORTING"
        elif redis_instance.state and redis_instance.state == 7:
            self.state_output = "FAILING_OVER"


    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._redis_instance.name)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        return isinstance(other, HashableRedisInstance) and self._redis_instance.name == other._redis_instance.name

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._redis_instance, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableREdisInstance({self._redis_instance.name})"


def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate Cloud Redis Options", allow_abbrev=False)

    regions_group = parser.add_mutually_exclusive_group()
    regions_group.add_argument("--all-regions", action="store_true", required=False,help="Try every zone in txt files in ./utils/zones.txt")
    regions_group.add_argument("--regions-list",required=False,help="Zones in list format of zone1,zone2,zone3")
    regions_group.add_argument("--regions-file",required=False,help="File name with each zone on newline")

    exclusive_instance_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_instance_group.add_argument("--redis-instance-names", type=str,  help="Instance names to check in the format projects/[project_id]/locations/[location]/instances/[instance_name]")
    exclusive_instance_group.add_argument("--redis-instance-names-file", type=str, help="File name with each instance on newline in format projects/[project_id]/locations/[location]/instances/[instance_name]")

    parser.add_argument("--minimal-calls", action="store_true",  help="Perform minimal set of API calls (usually just List API calls)")
    
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    
    args = parser.parse_args(user_args)

    # Initialize Variables
    debug, project_id = args.debug, session.project_id
    action_dict, all_redis_instances = defaultdict(lambda: defaultdict(lambda: defaultdict(set))), {}

    # Set up scope for call to specified project
    redis_client = redis_v1.CloudRedisClient(credentials = session.credentials)   

    # Get zone if specified
    regions = None
    if args.all_regions:
        regions = get_all_redis_regions(session, project_id, all_regions=True)
    elif args.regions_list:
        regions = get_all_redis_regions(session, project_id, regions_list=args.regions_list)
    elif args.regions_file:
        regions = get_all_redis_regions(session, project_id, regions_file=args.regions_file)

    # Standard Start Message
    print(f"[*] Checking {project_id} for Redis instances...")

    # If user did not supply instances, try to list all instances and proceed
    if args.redis_instance_names or  args.redis_instance_names_file:
        
        # STDIN
        if args.redis_instance_names:
            
            all_redis_names = args.redis_instance_names.split(",")
    
        # FILE
        elif args.redis_instance_names_file:

            all_redis_names = [line.strip() for line in open(args.redis_instance_names_file)]
        
        # For each instance create Instance object and add it to dictionary like we would do for automated approach
        for redis_name in all_redis_names:

            _, redis_project_id, _, redis_region, _, redis_simple_name = function.split("/")

            redis_hash = HashableRedisInstance(Instance(name=redis_name))
            redis_hash.validated = False
            
            # Set since its just a list
            all_redis_instances.setdefault(redis_project_id, set()).add(redis_hash)
    
    else:

        if regions:
        
            for region in regions:

                if debug:
                    print(f"[DEBUG] Getting Redis Instance for region {region} in {project_id}")

                location = f"projects/{project_id}/locations/{region}"

                redis_instances_list = list_redis_instances(redis_client, location, zone, debug = debug)
                

                if redis_instances_list == "Not Enabled":
                    all_redis_instances.setdefault(project_id, set([]))
                    break

                elif redis_instances_list == None:
                    all_redis_instances.setdefault(project_id, set([]))

                else:

                    action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add('redis.instances.list')

                    if len(all_redis_instances) == 0:
                        all_redis_instances.setdefault(project_id, set([]))
                    
                    else: 
                        all_redis_instances.setdefault(project_id, set()).update({HashableRedisInstance(redis) for redis in redis_instances_list})
                        for redis_instance in redis_instances_list:
                            save_function(redis_instance, session)
        else:

            if debug:
                print(f"[DEBUG] Getting Redis instances for all regions in {project_id}")
            
            location = f"projects/{project_id}/locations/-"

            # Returns all instances in all zones per API documentation
            redis_instances_list = list_redis_instances(redis_client, location, debug = debug)
            
            if redis_instances_list == "Not Enabled" or redis_instances_list == None:
                all_redis_instances.setdefault(project_id, set([]))

            else:

                action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add('redis.instances.list')

                if len(all_redis_instances) == 0:
                    all_redis_instances.setdefault(project_id, set([]))
                
                else: 
                    all_redis_instances.setdefault(project_id, set()).update({HashableRedisInstance(redis) for redis in redis_instances_list})
                    for redis_instance in redis_instances_list:
                        save_function(redis_instance, session)
        
    for project_id, redis_instances in all_redis_instances.items():

        if debug: 

            if len(redis_instances) != 0:
                print(f"[DEBUG] {len(redis_instances)} Redis instances were found")
            
            else:
                print(f"[DEBUG]  No Redis instances were found")

        # For each instance in list of instances, try getting/screenshot/serial/etc
        for redis_instance in redis_instances:
            
            validated = redis_instance.validated
            full_redis_name = redis_instance.name
            common_redis_name = full_redis_name.split("/")[-1]

            print(f"[**] Reviewing {common_redis_name}")

            if not args.minimal_calls:

                print(f"[***] GET Redis Instance")
                redis_instance_get = get_redis_instance(redis_client, full_redis_name, debug=debug)
                
                if redis_instance_get:
                    save_redis_instance(redis_instance_get, session)
                    action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('redis.instances.get')

                    if (args.redis_instance_names or args.redis_instance_names_file) and validated == False:
                        validated = True 
                        all_redis_instances[project_id].discard(redis_instance)
                        all_redis_instances[project_id].add(HashableFunction(redis_instance_get))

            redis_instance_get_auth_string = get_redis_instance_auth_string(redis_client, full_redis_name, debug=debug)
            if redis_instance_get_auth_string:
                # TODO Save Redis Auth String
                action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('redis.instances.getAuthString')
                for instance in all_redis_instances[project_id]:
                    if instance == redis_instance:
                        instance.auth_string = redis_instance_get_auth_string
                        break
        
        session.insert_actions(action_dict,project_id)
               
    for project_id, redis_instance_only_info in all_redis_instances.items():

        if args.redis_instance_names or args.redis_instance_names_file:
            redis_instance_only_info = [redis_instance for redis_instance in redis_instance_only_info if redis_instance.validated]
        
        # Clean up regions
        list(map(lambda redis_instance: setattr(
            redis_instance._redis_instance, 
            'name', 
            redis_instance._redis_instance.name.split("/")[-1]), 
            redis_instance_only_info
        ))

        UtilityTools.summary_wrapup(
            project_id, 
            "Cloud Redis Instances", 
            list(redis_instance_only_info), 
            ["name","display_name","state_output","location_id","host","port","auth_enabled","auth_string"],
            primary_resource = "instances",
            primary_sort_key = "location_id",
            output_format = output_format
        )