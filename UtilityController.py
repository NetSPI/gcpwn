from datetime import datetime
import yaml, os, re
import pandas as pd
from tabulate import tabulate
import textwrap
import shutil

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

    # Todo try nested dictionary next :D and nothing
    # objects list
    # Option 1: [Bucket1, Bucket2, Bucket3]
    # Option 2: ["Bucket1": {blob1,blob2,blob3},"Bucket2":{blob1,blob2}]
    # Properties: ["name","time_created"]
    @staticmethod
    def summary_wrapup(project_id, service_account_name, objects_list, properties_list, primary_resource=None, secondary_title_name=None, max_width=None, output_format = ["table"], primary_sort_key=None):
        table = ("table" in output_format)
        txt = ("txt" in output_format)
        csv = ("csv" in output_format)
        # Dynamically get terminal width if max_width is not provided
        min_width = 10  # Set a minimum width for the table
        #TODO find a way to calculate this better
        if max_width is None:
            max_width = max(shutil.get_terminal_size().columns, min_width) - 30

        # Determine the number of resources found
        num_resources = len(objects_list) if objects_list else 0

        if num_resources == 0:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] GCPwn found 0 {primary_resource} in project {project_id}{UtilityTools.RESET}")
        else:
            print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] GCPwn found {num_resources} {primary_resource} in project {project_id}{UtilityTools.RESET}")

        if not objects_list:
            return

        title = f"{UtilityTools.BOLD}{UtilityTools.GREEN}{project_id.upper()} : {service_account_name.upper()}{UtilityTools.RESET}"

        table_data = []
        header = properties_list[:]  # Copy the properties list for the header
        
        def wrap_text(text, width):
            wrapper = textwrap.TextWrapper(width=width, break_long_words=True, break_on_hyphens=False)
            return "\n".join(wrapper.wrap(text))

        column_width = max(max_width // len(header),10)
        if isinstance(objects_list, dict):
            if secondary_title_name is None:
                raise ValueError("secondary_title_name must be provided if objects_list is a dictionary.")
           
            header.append(secondary_title_name)

            for obj, value in objects_list.items():
               
                row = {}
                for prop in properties_list:
                    value_str = str(getattr(obj, prop, "N/A"))
                    if value_str == "":
                        value_str = "[EMPTY]"
                    if len(value_str) > 300:
                        value_str = value_str[:300] + "[TRUNCATED]"
                    row[prop] = value_str if txt else wrap_text(value_str, column_width) if not csv else value_str
          
                if isinstance(value, dict):
                    # Format dictionary as a multi-line string for table output
                    dict_str = "\n".join(f"{k}: {v}" for k, v in value.items())
                    row[secondary_title_name] = dict_str
                else:
                    if not txt and not csv:
                        row[secondary_title_name] = "\n".join([wrap_text("* " +item, column_width) for item in value]) if isinstance(value, list) else wrap_text(value, column_width)
                    elif txt or csv:
                        row[secondary_title_name] = "\n".join([item for item in value]) if isinstance(value, list) else value
           
                table_data.append(row)

        elif isinstance(objects_list, list):
            for obj in objects_list:
                row = {}
                for prop in properties_list:
                    value_str = str(getattr(obj, prop, "N/A"))
                    if value_str == "":
                        value_str = "[EMPTY]"
                    if len(value_str) > 300:
                        value_str = value_str[:300] + "[TRUNCATED]"
                    row[prop] = wrap_text(value_str, column_width) if not (csv or txt) else value_str
                table_data.append(row)

        if primary_sort_key and primary_sort_key in properties_list:
            table_data.sort(key=lambda x: x.get(primary_sort_key, ""))
        
        output_data = []
        header_line = " - ".join(properties_list)
        output_data.append(header_line)

        if isinstance(objects_list, dict):
            for row in table_data:
                line = " - ".join(row[prop] for prop in properties_list)
                output_data.append(f"- {line}")
                if isinstance(row[secondary_title_name], str):
                    # Indent and prefix each blob with "*"
                    for blob in row[secondary_title_name].splitlines():
                        output_data.append(f"    * {blob}")
                else:
                    for item in row[secondary_title_name]:
                        # Indent each blob in the list
                        output_data.append(f"    * {item}")
        elif isinstance(objects_list, list):
            for row in table_data:
                line = ", ".join(row[prop] for prop in properties_list)
                output_data.append(f"- {line}")


        if txt:
            print("\n".join(output_data))
            

        if csv:
          
            df = pd.DataFrame(table_data, columns=header)
            print(df.to_csv(index=False))
        
        if table:

            header = [wrap_text(col, column_width) for col in header]
            title_wrapper = textwrap.TextWrapper(width=max_width, break_long_words=False, break_on_hyphens=False)
            wrapped_title = title_wrapper.fill(title)
            df = pd.DataFrame(table_data, columns=header)

            # Apply wrapping while keeping newlines in place
            for col in df.columns:
                df[col] = df[col].apply(lambda x: x.replace('\n', '\n') if isinstance(x, str) else x)

            table = tabulate(df, headers='keys', tablefmt='grid', showindex=False)

            table_width = len(table.splitlines()[0])

            title_visible_length = len(re.sub(r'\x1b\[[0-9;]*m', '', wrapped_title))

            bold_top_row = "┏" + "━" * (table_width - 2) + "┓"
            centered_title = "┃" + wrapped_title.center(table_width - 2 + (len(wrapped_title) - title_visible_length)) + "┃"

            table_lines = table.splitlines()
            table_lines[0] = "┣" + "━" * (table_width - 2) + "┫"

            final_output = bold_top_row + "\n" + centered_title + "\n" + "\n".join(table_lines)
        
            print(final_output)


    @staticmethod
    def log_action(workspace_name, action):
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_file = UtilityTools.get_save_filepath(workspace_name, "history_log.txt","System Log")
        
        # Check if the file exists, and create it if it doesn't
        if not os.path.isfile(log_file):
            open(log_file, 'w').close()  # This creates the file

        with open(log_file, "a") as file:
            file.write(f"[{timestamp}] {action}\n")
