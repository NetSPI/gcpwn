from Modules.CloudCompute.utils.util_helpers import *

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate Compute Projects", allow_abbrev=False)
    parser.add_argument("-v","--debug",action="store_true", required=False, help="Get verbose data returned")
    args = parser.parse_args(user_args)

    # Initialize Variables
    debug, compute_project_id = args.debug, session.project_id
    action_dict = defaultdict(lambda: defaultdict(set))
    projects_to_display = {}

    # Set up initial resource client    
    compute_project_client = compute_v1.ProjectsClient(credentials = session.credentials)   
    
    # Standard Start Message
    print(f"[*] Checking Cloud Compute Project {compute_project_id}...")

    # Get Project; No List 
    compute_project_get = get_compute_project(compute_project_client, compute_project_id, debug=debug)

    # If API is disabled set to empty array, else add data.
    if compute_project_get not in ["Not Enabled", None]:

        # Save data for eventual printout
        metadata_items = compute_project_get.common_instance_metadata.items
        metadata_summary = [f"KEY: {item.key} - VALUE: {item.value}" for item in metadata_items]
        projects_to_display[HashableComputeProject(compute_project_get)] = metadata_summary

        # Save GET Project ID Permissions
        action_dict["project_permissions"][compute_project_id].add("compute.projects.get")

        # Save Project to BOTH Compute Table and Resource Manager Table to sync projects
        save_compute_project(compute_project_get, session)
        save_compute_project_to_resource(compute_project_get, session)
    
    session.insert_actions(action_dict, compute_project_id, column_name="compute_actions_allowed")

    UtilityTools.summary_wrapup(
        compute_project_id, 
        "Compute Project", 
        projects_to_display, 
        ["id","name","description"],
        primary_resource = "Compute Projects",
        secondary_title_name = "metadata",
        output_format = output_format 
    )