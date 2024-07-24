from Modules.CloudCompute.utils.util_helpers import *

# Project ID is specified via "project-ids" and will be in session.project_id
def run_module(user_args, session, first_run = False, last_run = False):
    
    parser = argparse.ArgumentParser(description="Enumerate Compute Projects", allow_abbrev=False)
    
    parser.add_argument("--txt", type=str, required=False, help="Save the stdout summary to a text file")

    parser.add_argument("-v","--debug",action="store_true", required=False, help="Get verbose data returned")
    
    args = parser.parse_args(user_args)

    debug = args.debug
    compute_project_id = session.project_id

    action_dict = defaultdict(lambda: defaultdict(set))
    project_metadata = defaultdict(list)
    
    compute_project_client = compute_v1.ProjectsClient(credentials = session.credentials)   
    
    print(f"[*] Checking Cloud Compute Project {compute_project_id}...")

    compute_project_get = get_compute_project(compute_project_client, compute_project_id, debug=False)

    if compute_project_get and compute_project_get != "Not Enabled":

        metadata_items = compute_project_get.common_instance_metadata.items
        project_metadata[compute_project_get.name] = [f"KEY: {item.key}\nVALUE: {item.value}" for item in metadata_items]

        action_dict["project_permissions"][compute_project_id].add("compute.projects.get")

        save_compute_project(compute_project_get, session)
        save_compute_project_to_resource(compute_project_get, session)

    UtilityTools.summary_wrapup(
        title="Compute Project(s) with potential metadata shown below.",
        nested_resource_dict=project_metadata,
        footer = "*Review any truncated data with 'data tables cloudcompute-projects --columns project_id,common_instance_metadata [--csv filename]'",        
        output_file_path = args.txt
    )

    session.insert_actions(action_dict, compute_project_id, column_name="compute_actions_allowed")
