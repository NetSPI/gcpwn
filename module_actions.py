import importlib, traceback
from UtilityController import UtilityTools

def interact_with_module(session, module_path,module_args, project_ids = None, zones_choices = None):

    try: 

        module_import_path = module_path.replace("/",".")
        module = importlib.import_module(module_import_path)

        one_project_only = False

        project_list = []
 
        module_indicators_of_no_project_prompt = [
            "enum_policy_bindings",
            "ResourceManager",
            "Exploit",
            "Process",
            "Unauthenticated"
        ]

        # Check if user supplied project IDs at cmdline
        if project_ids:
            project_list = project_ids

        # Next check if user has global setting set
        elif session.config_project_list:

            project_list = session.config_project_list

        # Depending on some items set proejct ID to just current project iD
        elif any(module_indicator in module_import_path for module_indicator in module_indicators_of_no_project_prompt):
               
            project_list = [session.project_id]

        elif not project_ids:

            project_list = [session.project_id]
            
            if len(session.global_project_list) > 1:

                all_projects_choice = session.choice_selector(
                        ["All Projects","Current/Single"],
                        f"Do you want to scan all projects or current single project? If not specify a project-id(s) with '--project-ids project1,project2,project3'"
                    )

                if all_projects_choice == "All Projects":
                    # A set of unique project IDs for all creds
                    project_list = session.global_project_list
                    one_project_only = False

                elif all_projects_choice == "Current/Single":
                    print("[*] Proceeding with just the current project ID")
                    one_project_only = True

                else:
                    print("[*] Exiting...")
                    return -1
                  
        else:

            project_list = None

        # Start looping through projects
        original_project_id = session.project_id
        current_project_length = len(project_list)

        if "Unauthenticated" not in module_path and session.credentials is None:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Cannot run module as credentials are 'None'. Please load in credentials or run an unauthenticated module.{UtilityTools.RESET}")
            return -1

        for index, project_id in enumerate(project_list):

            UtilityTools.log_action(session.workspace_directory_name , f"[START_MODULE] Entering {module_path.split('/')[-1]} module for {project_id}...")

            session.project_id = project_id
            first_run = (index == 0)
            last_run = (index == len(project_list) - 1)

            callback = module.run_module(module_args, session, first_run = first_run, last_run = last_run)
            # If callback in enum_all and user didnt specify project dis
            if callback == 2 and "enum_all" in module_import_path and not project_ids and not one_project_only:
                
                new_project_length = len(session.global_project_list)
             
                if new_project_length != current_project_length:
                    
                    # Find the difference between new and old project lists
                    diff_projects = list(set(session.global_project_list) - set(project_list))
                    
                    # Append the difference to project_list
                    project_list.extend(diff_projects)

                    current_project_length = new_project_length
            
            UtilityTools.log_action(session.workspace_directory_name, f"[END_MODULE] Exiting {module_path.split('/')[-1]} module for {project_id}...")
        
        # Reset session at end to default project
        session.project_id = original_project_id

    except KeyboardInterrupt:
        pass  # Handle Ctrl+C to exit gracefully

    except Exception as e:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] A generic occured while executing the module. See details below:{UtilityTools.RESET}")
        print(traceback.format_exc())



