from Modules.CloudCompute.utils.util_helpers import *

## user_args is passed from the previous module, pass this into the , blob_max_size = args.parser if you are doing the non-standalone callable version
def run_module(user_args, session, first_run = False, last_run = False):
    
    parser = argparse.ArgumentParser(description="Enumerate Compute Projects", allow_abbrev=False)
    parser.add_argument("-v","--debug",action="store_true", required=False, help="Get verbose data returned")
    args = parser.parse_args(user_args)

    debug, project_id = args.debug, session.project_id
    action_dict, project_name = {}, {}
    
    compute_project_client = compute_v1.ProjectsClient(credentials = session.credentials)    
    
    print(f"[*] Checking Cloud Compute Project {project_id}...")

    compute_project_get = get_compute_project(compute_project_client, project_id, debug=False)
    
    resource_count = 0

    if compute_project_get:

        metadata = []
        resource_count += 1
        for item in compute_project_get.common_instance_metadata.items:
            key, value = item.key, item.value
            metadata.append(f"KEY: {key} - VALUE: {value}")
        
        project_name[compute_project_get.name] = metadata[:10]

        action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add("compute.projects.get")
        
        # Save to two tables due to Resource Manager Project & Compute Project
        save_compute_project(compute_project_get, session)
        save_compute_project_to_resource(compute_project_get, session)
        
    if resource_count:
        print(f"{UtilityTools.BOLD}[*] Only first few metadata characters shown, run `data tables cloudcompute-projects --columns project_id,common_instance_metadata` to see all of metadata. Use --csv to export it to a csv.{UtilityTools.RESET}")
    
    UtilityTools.summary_wrapup(resource_top = "Compute Project(s) potentially with metadata", resource_count = resource_count, resource_dictionary = project_name)
    
    session.insert_actions(action_dict,project_id, column_name = "compute_actions_allowed")
