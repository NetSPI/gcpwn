from datetime import datetime
import yaml, os, re


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
    ########### Formatting Check
    def validate_input_format(resource, sections):

        pattern = r'^' + r'/'.join([r'[^/]+' for _ in range(sections)]) + r'$'

        if type(resource) == list:        
            for key in resource:
                if not re.match(pattern, key):
                    return -1, key
        else:
            if not re.match(pattern, resource):
                return -1, resource       
        
        return 0, None 

    ########### Formatting Check
    def validate_user_format(member):

        pattern = r'^(user:|serviceaccount:)[^\[\]]+$'
        regex = re.compile(pattern, re.IGNORECASE)
        if not regex.match(member):
            return -1, member

        return 0, None 

    @staticmethod
    def get_save_filepath(workspace_name, file_name, key_to_get):
   
        system_paths = {
            "Storage": f"GatheredData/{workspace_name}/Storage/{file_name}",
            "Secrets": f"GatheredData/{workspace_name}/SecretManager/{file_name}",
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
    def color_text_output(text, color):
        return f"{color}{text}{UtilityTools.RESET}"
    @staticmethod
    def bold_text_output(text):
        return f"{UtilityTools.BOLD}{text}{UtilityTools.RESET}"
    
    # Example usage:
    # UtilityTools.summary_wrapup(
    #     resource_type="storage buckets",
    #     project_id="example-project",
    #     resource_list=["bucket1", "bucket2", "bucket3"]
    # )
    # UtilityTools.summary_wrapup(
    #     summary_title="Compute Projects",
    #     nested_resource_dict={"project1": {"instance1": ["metadata1", "metadata2"], "instance2": ["metadata1", "metadata2"]}, "project2": ["metadata1", "metadata2"]}
    # )

    @staticmethod
    def print_403_api_disabled(service_type, project_id):
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 403:{UtilityTools.RESET}{UtilityTools.RED} {service_type} API does not appear to be enabled for project {project_id}{UtilityTools.RESET}")

    @staticmethod
    def print_403_api_denied(permission_name, resource_name = None, project_id = None):
        if project_id:
            printout = "project " + project_id
        elif resource_name:
            printout = resource_name

        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 403:{UtilityTools.RESET}{UtilityTools.RED} User does not have {permission_name} permissions on {printout}{UtilityTools.RESET}")

    @staticmethod
    def print_404_resource(resource_name):
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 404:{UtilityTools.RESET}{UtilityTools.RED} {resource_name} was not found")

    @staticmethod
    def print_500(resource_name, permission, error):
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 500 (UNKNOWN):{UtilityTools.RESET}{UtilityTools.RED} {permission} failed for {resource_name}. See below:")
        print(str(error) + f"{UtilityTools.RESET}")

    @staticmethod
    def summary_wrapup(title=None, project_id=None, resource_list=None, total_resources=None, nested_resource_dict=None, footer=None, output_file_path=None):
        no_resources = False
        resources_found = False
        summary_output = ""

        if resource_list is not None:
            num_resources = len(resource_list)
            if num_resources == 0:
                no_resources = True
                summary_output = UtilityTools.bold_text_output(f"[SUMMARY] GCPwn found or retrieved NO {title}")
                if project_id:
                    summary_output += UtilityTools.bold_text_output(UtilityTools.color_text_output(f" in {project_id}", UtilityTools.RED))
            else:
                resources_found = True
                summary_output = UtilityTools.bold_text_output(f"[SUMMARY] GCPwn found {num_resources} {title}")
                if project_id:
                    summary_output += UtilityTools.color_text_output(UtilityTools.bold_text_output(f" in {project_id}"), UtilityTools.GREEN)
                for resource in resource_list:
                    summary_output += UtilityTools.color_text_output(UtilityTools.bold_text_output(f"\n   - {resource}"), UtilityTools.GREEN)

        elif nested_resource_dict is not None:
            def format_nested_dict(d, indent=0):
                lines = []
                for key, value in d.items():
                    lines.append(" " * indent + UtilityTools.color_text_output(UtilityTools.bold_text_output(f"- {key}"), UtilityTools.GREEN))
                    if isinstance(value, dict):
                        lines.extend(format_nested_dict(value, indent + 2))
                    else:
                        for item in value:
                            # Split the item by newline and add appropriate indentation
                            item_lines = item.split('\n')
                            for i, item_line in enumerate(item_lines):
                                if i == 0:
                                    lines.append(" " * (indent + 2) + UtilityTools.color_text_output(UtilityTools.bold_text_output(f"- {item_line}"), UtilityTools.GREEN))
                                else:
                                    lines.append(" " * (indent + 4) + UtilityTools.color_text_output(UtilityTools.bold_text_output(f"{item_line}"), UtilityTools.GREEN))
                return lines

            num_top_level_resources = len(nested_resource_dict)
            if num_top_level_resources == 0:
                no_resources = True
                summary_output = UtilityTools.bold_text_output(f"[SUMMARY] GCPwn found or retrieved NO {title}")
                if project_id:
                    summary_output += UtilityTools.bold_text_output(UtilityTools.color_text_output(f" in {project_id}", UtilityTools.RED))
            else:
                resources_found = True
                if total_resources:
                    summary_output = UtilityTools.bold_text_output(f"[SUMMARY] GCPwn found {total_resources} {title}")
                else:
                    summary_output = UtilityTools.bold_text_output(f"[SUMMARY] GCPwn found {num_top_level_resources} {title}")
                if project_id:
                    summary_output += UtilityTools.color_text_output(UtilityTools.bold_text_output(f" in {project_id}"), UtilityTools.GREEN)

                summary_output += "\n" + "\n".join(format_nested_dict(nested_resource_dict))

        if no_resources:
            summary_output = UtilityTools.color_text_output(summary_output, UtilityTools.RED)
        else:
            summary_output = UtilityTools.color_text_output(summary_output, UtilityTools.GREEN)

        if resources_found and footer:
            summary_output += f"\n{UtilityTools.color_text_output(UtilityTools.bold_text_output(footer), UtilityTools.GREEN)}"

        print(summary_output)

        if output_file_path:
            with open(output_file_path, "a") as f:  # Open file in append mode
                f.write(summary_output + "\n")  # Ensure new lines are added

    @staticmethod
    def log_action(workspace_name, action):
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_file = UtilityTools.get_save_filepath(workspace_name, "history_log.txt","System Log")
        
        # Check if the file exists, and create it if it doesn't
        if not os.path.isfile(log_file):
            open(log_file, 'w').close()  # This creates the file

        with open(log_file, "a") as file:
            file.write(f"[{timestamp}] {action}\n")
