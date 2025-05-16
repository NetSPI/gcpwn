from Modules.CloudCompute.utils.util_helpers import *

def dprint(msg, debug):
    if debug:
        print(f"[DEBUG] {msg}")

def run_module(user_args, session, first_run=False, last_run=False, output_format=["table"]):
    parser = argparse.ArgumentParser(description="Enumerate Compute Instance Options", allow_abbrev=False)
    
    zgroup = parser.add_mutually_exclusive_group()
    zgroup.add_argument("--all-zones", action="store_true", required=False, help="Try every zone in txt files in ./utils/zones.txt")
    zgroup.add_argument("--zones-list", required=False, help="Zones in list format of zone1,zone2,zone3")
    zgroup.add_argument("--zones-file", required=False, help="File name with each zone on newline")

    exclusive_instance_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_instance_group.add_argument("--instance-names", type=str, help="Instance names to check in the format projects/[project_id]/zones/[zone]/instances/[instance_name]")
    exclusive_instance_group.add_argument("--instance-names-file", type=str, help="File name with each instance on newline in format projects/[project_id]/zones/[zone]/instances/[instance_name]")

    parser.add_argument("--iam", action="store_true", required=False, help="Call TestIAMPermissions on Compute Instances")
    parser.add_argument("--take-screenshot", action="store_true", required=False, help="Take screenshot if possible")
    parser.add_argument("--download-serial", action="store_true", required=False, help="Download serial log if possible")
    parser.add_argument("--output", type=str, required=False, help="Output file to save screenshot/serial if you don't want to use default")
    parser.add_argument("--minimal-calls", action="store_true", help="Perform minimal set of API calls (usually just List API calls)")
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Get verbose data returned")

    args = parser.parse_args(user_args)
    debug, project_id = args.debug, session.project_id

    resource_actions = {
        "project_permissions": defaultdict(set),
    }
    instance_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    all_instances = defaultdict(set)
    client = compute_v1.InstancesClient(credentials=session.credentials)

    zones = (get_all_instance_zones(session, project_id, all_zones=True) if args.all_zones else
             get_all_instance_zones(session, project_id, zones_list=args.zones_list) if args.zones_list else
             get_all_instance_zones(session, project_id, zones_file=args.zones_file) if args.zones_file else None)

    print(f"[*] Checking {project_id} for instances...")

    if args.instance_names or args.instance_names_file:
        items = UtilityTools.gather_non_automated_input(6, args.instance_names, args.instance_names_file)
        for line in items:
            _, pid, _, zone, _, name = line.split("/")
            all_instances[pid].add(HashableInstance(compute_v1.Instance(name=name, zone=f"zones/{zone}"), validated=False))
    else:
        if zones:
            for zone in zones:
                dprint(f"Getting instances for zone {zone} in {project_id}", debug)
                results = list_instances(client, project_id, zone, debug=debug)
                if results == "Not Enabled": break
                if results:
                    resource_actions["project_permissions"][project_id].add("compute.instances.list")
                    for inst in results:
                        all_instances[project_id].add(HashableInstance(inst))
                        save_instance(inst, session, project_id)
        else:
            dprint(f"Getting instances for all zones in {project_id}", debug)
            results = list_aggregated_instances(client, project_id, debug=debug)
            if results and results != "Not Enabled":
                resource_actions["project_permissions"][project_id].add("compute.instances.list")
                for zone, instances in results.items():
                    for inst in instances:
                        all_instances[project_id].add(HashableInstance(inst))
                        save_instance(inst, session, project_id)

    for pid, instances in all_instances.items():
        dprint(f"{len(instances)} instances found" if instances else "No instances found", debug)
        for instance in list(instances):
            validated = instance.validated
            zone = instance.zone.split("/")[-1]
            name = instance.name
            print(f"[**] Reviewing {name}")

            if not args.minimal_calls:
                print(f"[***] GET Instance")
                result = get_instance(client, name, pid, zone, debug=debug)
                if result:
                    if (args.instance_names or args.instance_names_file) and not validated:
                        instances.discard(instance)
                        instances.add(HashableInstance(result))
                    instance_actions[pid]['compute.instances.get']['instances'].add(result.name)
                    save_instance(result, session, pid)

            if args.iam:
                print(f"[***] TEST Instance Permissions")
                perms = check_instance_permissions(client, pid, name, zone, debug=debug)
                if perms:
                    if (args.instance_names or args.instance_names_file) and not validated:
                        instance.validated = True
                    for p in perms:
                        instance_actions[pid][p]['instances'].add(name)

            if args.take_screenshot:
                print(f"[***] SCREENSHOT Instance")
                if (shot := instance_get_screenshot(client, name, pid, zone, output=args.output, debug=debug)):
                    if (args.instance_names or args.instance_names_file) and not validated:
                        instance.validated = True
                    print(f"{UtilityTools.GREEN}[***] Successfully took screenshot of {name}{UtilityTools.RESET}")
                    instance_actions[pid]['compute.instances.getScreenshot']['instances'].add(name)

            if args.download_serial:
                print(f"[***] DOWNLOAD SERIAL Instance")
                if (serial := instance_get_serial(client, name, pid, zone, session.workspace_directory_name, output=args.output, debug=debug)):
                    if (args.instance_names or args.instance_names_file) and not validated:
                        instance.validated = True
                    print(f"{UtilityTools.GREEN}[***] Successfully downloaded serial of {name}{UtilityTools.RESET}")
                    instance_actions[pid]['compute.instances.getSerialPortOutput']['instances'].add(name)

        session.insert_actions(resource_actions, pid, column_name="compute_actions_allowed")
        session.insert_actions(instance_actions, pid, column_name="compute_actions_allowed")

    for pid, data in all_instances.items():
        if args.instance_names or args.instance_names_file:
            data = [i for i in data if i.validated]
        for i in data:
            i._instance.zone = i._instance.zone.split("/")[-1]
            meta = getattr(i._instance.metadata, 'items', [])
            i.metadata_output = "\n".join([f"KEY: {m.key}\nVALUE: {m.value}" for m in meta]) if "txt" not in output_format else [f"KEY: {m.key}\nVALUE: {m.value}" for m in meta]
            if ips := get_instance_ip_address(i):
                i.network_interfaces_output = "\n".join(ips)

        UtilityTools.summary_wrapup(
            pid,
            "EC2 Compute Instances",
            list(data),
            ["name", "zone", "network_interfaces_output", "metadata_output"],
            primary_resource="Instances",
            primary_sort_key="zone",
            output_format=output_format
        )
