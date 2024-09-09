from Modules.CloudCompute.utils.util_helpers import *

class HashableComputeProject:

    # default validated to true unless otherwise noted
    def __init__(self, compute_project, validated = True):
        self._compute_project = compute_project
        self.validated = validated

    def __hash__(self):
        # Hash based on the name or any other combination of unique attributes
        return hash(self._compute_project.id)

    def __eq__(self, other):
        # Compare based on the name or any other combination of unique attributes

        return isinstance(other, HashableComputeProject) and self._compute_project.id == other._compute_project.id

    def __getattr__(self, attr):
        # Delegate attribute access to the original secret object
        return getattr(self._compute_project, attr)

    def __repr__(self):
        # Make the string representation more informative by including both id and name
        return f"HashableComputeProject(id={self._compute_project.id})"

def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):
    
    # Set up Argparse
    parser = argparse.ArgumentParser(description="Enumerate Compute Projects", allow_abbrev=False)
    parser.add_argument("-v","--debug",action="store_true", required=False, help="Get verbose data returned")
    args = parser.parse_args(user_args)

    # Initialize Variables
    debug, compute_project_id = args.debug, session.project_id
    action_dict = defaultdict(lambda: defaultdict(set))
    project_list_to_print = {}

    # Set up initial resource client    
    compute_project_client = compute_v1.ProjectsClient(credentials = session.credentials)   
    
    # Standard Start Message
    print(f"[*] Checking Cloud Compute Project {compute_project_id}...")

    # Get Project; No List 
    compute_project_get = get_compute_project(compute_project_client, compute_project_id, debug=debug)

    # If API is disabled set to empty array, else add data.
    if compute_project_get:

        if compute_project_get == "Not Enabled":
            
            project_list_to_print = {}

        else:

            # Save data for eventual printout
            metadata_items = compute_project_get.common_instance_metadata.items
            project_list_to_print[HashableComputeProject(compute_project_get)] = [f"KEY: {item.key} - VALUE: {item.value}" for item in metadata_items]

            # Save GET Project ID Permissions
            action_dict["project_permissions"][compute_project_id].add("compute.projects.get")

            # Save Project to BOTH Compute Table and Resource Manager Table to sync projects
            save_compute_project(compute_project_get, session)
            save_compute_project_to_resource(compute_project_get, session)
    
    UtilityTools.summary_wrapup(
        compute_project_id, 
        "Compute Project", 
        project_list_to_print, 
        ["id","name","description"],
        primary_resource = "Compute Projects",
        secondary_title_name = "metadata",
        output_format = output_format 
    )

    session.insert_actions(action_dict, compute_project_id, column_name="compute_actions_allowed")
