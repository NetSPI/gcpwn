from datetime import datetime
import yaml, os


class UtilityTools:

    # Define ANSI escape codes for colors
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright versions
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Bold escape code
    BOLD = "\033[1m"

    @staticmethod
    def get_save_filepath(workspace_name, file_name, key_to_get):
   
        system_paths = {
            "Storage": f"GatheredData/{workspace_name}/Storage/{file_name}",
            "Compute Base": f"GatheredData/{workspace_name}/Compute/{file_name}",
            "Compute Serial": f"GatheredData/{workspace_name}/Compute/Serial/{file_name}",
            "Compute Screenshots": f"GatheredData/{workspace_name}/Compute/Screenshots/{file_name}",
            "Functions": f"GatheredData/{workspace_name}/Functions/{file_name}",
            "Reports": f"GatheredData/{workspace_name}/Reports/{file_name}",
            "Reports Snapshot": f"GatheredData/{workspace_name}/Reports/Snapshots/{file_name}",
            "Reports Graphs": f"GatheredData/{workspace_name}/Reports/Graphs/{file_name}",
            "System Log":  f"LoggingMechanism/{workspace_name}/{file_name}",

        }
        destination_filename = system_paths[key_to_get]
        directory = os.path.dirname(destination_filename)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        return destination_filename

    @staticmethod
    def color_text_output(text, color):
        return f"{UtilityTools.BOLD}{color}{text}{UtilityTools.RESET}"

    @staticmethod
    def load_in_all_yaml_stuff():
        with open("./utils/permission-mapping.yaml") as file:
            yaml_content = file.read()
        data = yaml.safe_load(yaml_content)
        return data

    @staticmethod
    def summary_wrapup(resource_name = None, project_id = None, resource_list = None, resource_top = None, resource_count = None, resource_second = None, resource_dictionary = None, module_summary_save = None):
        no_resources = False
        formatted_string = ""
    
        if resource_list != None:
            num_of_resources = len(resource_list)
            if num_of_resources == 0:
                no_resources = True
                formatted_string = f"[SUMMARY] GCPwn found or retrieved NO {resource_name}"
                if project_id: formatted_string = formatted_string + f" in {project_id}"
            else:
                formatted_string = f"[SUMMARY] GCPwn found {num_of_resources} {resource_name}"
                if project_id: formatted_string = formatted_string + f" in {project_id}"

                for resource_name in resource_list:
                    formatted_string = formatted_string + UtilityTools.color_text_output(f"\n   - {resource_name}", UtilityTools.GREEN)

        elif resource_dictionary != None:
            
            num_of_top_level_resources = len(resource_dictionary.keys())
            if num_of_top_level_resources == 0:
                no_resources = True
                formatted_string = f"[SUMMARY] GCPwn found or retrieved  NO {resource_top}"
                if project_id: formatted_string = formatted_string + f" in {project_id}"
   
            else:
                if resource_count:
                    formatted_string =  f"[SUMMARY] GCPwn found {resource_count} {resource_top}"
                    if project_id: formatted_string = formatted_string + f" in {project_id}"

                else:
                    formatted_string =  f"[SUMMARY] GCPwn found {num_of_top_level_resources} {resource_top}"
                    if project_id: formatted_string = formatted_string + f" in {project_id}"



                for index, resource_list in resource_dictionary.items():
                    formatted_string = formatted_string + f"\n   - {index}"
                    if len(resource_list) != 0:
                        for resource_name in resource_list[:10]:
                            formatted_string = formatted_string + f"\n     - {resource_name}"
            
        if no_resources:
            formatted_string = UtilityTools.color_text_output(formatted_string, UtilityTools.RED)
        else:
            formatted_string = UtilityTools.color_text_output(formatted_string, UtilityTools.GREEN)

        print(formatted_string)

        if module_summary_save:
            with open(module_summary_save, "w") as f:
                f.write(formatted_string)

    @staticmethod
    def log_action(workspace_name, action):
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_file = UtilityTools.get_save_filepath(workspace_name, "history_log.txt","System Log")
        
        # Check if the file exists, and create it if it doesn't
        if not os.path.isfile(log_file):
            open(log_file, 'w').close()  # This creates the file

        with open(log_file, "a") as file:
            file.write(f"[{timestamp}] {action}\n")
