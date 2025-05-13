from datetime import datetime
import yaml, os, re
import pandas as pd
from prettytable import PrettyTable
#from tabulate import tabulate
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
    def gather_non_automated_input(correct_individual_format, cmdline_in = False, file_in = False):

        if cmdline_in:

            list_rudimentary = cmdline_in.split(",")

        elif file_in:

            try:

                list_rudimentary = [line.strip() for line in open(file_in)]
                
            except FileNotFoundError:
                print(f"{UtilityTools.RED}[X] File {input_file} does not appear to exist. Exiting...{UtilityTools.RESET}")
                return -1

        # Check if input is valid
        status, incorrect_input = UtilityTools.validate_input_format(list_rudimentary, correct_individual_format)
        
        # If input is invalid, fial and return response
        if status != 0: 
            print(f"{UtilityTools.RED}[X] Value \"{incorrect_input}\" is incorrect. Please try again...{UtilityTools.RESET}")
            return -1

        # If everying is good, return list
        else:

            return list_rudimentary

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

    # TODO: Export SQLITE tables to CSV
    @staticmethod
    def export_csv():
        pass

    # Data Input:
    # 1. {
    #     Object: [
    #         Sub-Object 1
    #         Sub-Object 2
    #     ],
    #     Object2: [
    #         Sub_object 1
    #     ]
    # }
    # 2. [Object1, Object2, etc]
    # properties_list: ["name","time_created"]
    # secondary_title_name: name of list of items (ex. blobs)
    @staticmethod
    def summary_wrapup(project_id, service_account_name, objects_list, properties_list, primary_resource=None, secondary_title_name=None, max_width=None, output_format = ["table"], primary_sort_key=None):

        table, txt, csv = (fmt in output_format for fmt in ("table", "txt", "csv"))

        # Cache data so if multiple output formats don't redo computation        
        global all_rows
        all_rows = []

        def build_row(obj, properties_list):
            row =[
                (value_str[:300] + "[TRUNCATED]") if len(value_str := str(getattr(obj, prop, "N/A")) or "[EMPTY]") > 300 else value_str
                for prop in properties_list
            ]
            return row

        def build_all_rows(objects_list, properties_list, table_width, secondary_title_name):
            
            global all_rows
            data = []
            # If input is option 1
            if isinstance(objects_list, dict):
                column_headers = properties_list + [secondary_title_name]

                if len(all_rows) == 0:

                    for obj, value in objects_list.items():

                            row = build_row(obj, properties_list)
                            if len(value) > 0:
                                final_custom_value = "* " + "\n* ".join(value)
                            else:
                                final_custom_value = "[EMPTY]"
                            row.append(final_custom_value)
                            data.append(row)
                else:
                    data = all_rows           
                
            # If input is option 2
            elif isinstance(objects_list, list):
                column_headers = properties_list
                

                if len(all_rows) == 0:

                    for obj in objects_list:
                        row = build_row(obj, properties_list)
                        data.append(row)

                else:
                    data = all_rows  

            all_rows = data
            return all_rows, column_headers


        def print_text(objects_list, properties_list, table_width, secondary_title_name):

            data, column_headers = build_all_rows(objects_list, properties_list, table_width, secondary_title_name)

            for row in data:
                for index, header in enumerate(column_headers):
                    if header == secondary_title_name:
                        output = "\n" + row[index]
                    else:
                        output = row[index]
                    print(header+": "+output)
                print("\n")
                

        def print_table(objects_list, properties_list, table_width, secondary_title_name, min_col_width=10):
            
            table = None

            data, column_headers = build_all_rows(objects_list, properties_list, table_width, secondary_title_name)
            table = PrettyTable(column_headers)
            for row in data:
                table.add_row(row)

            table.align = "l"
            table.hrules = True
            
            # Step 1: Calculate column widths
            col_widths = {
            }
            for i, col in enumerate(column_headers):
                max_length_per_line = max(
                    max(len(line) for line in str(row[i]).split("\n")) if row[i] else 0
                    for row in data
                )
                col_widths[col] = max(min_col_width, len(col), max_length_per_line)

            # Step 2: Determine the total width occupied by the table
            border_space = len(column_headers) * 3 + 1  # PrettyTable border space
            min_total_width = sum(col_widths.values()) + border_space

            # Step 3: Adjust column sizes to fit within table width
            while sum(col_widths.values()) + border_space > table_width:
                largest_col = max(col_widths, key=col_widths.get)  # Find largest column
                if col_widths[largest_col] > min_col_width:
                    col_widths[largest_col] -= 1  # Reduce its width incrementally

            # Step 4: Apply calculated widths
            for col in column_headers:
                table.max_width[col] = col_widths[col]

            print(table)

        def print_csv(objects_list, properties_list, table_width, secondary_title_name):

            data, column_headers = build_all_rows(objects_list, properties_list, table_width, secondary_title_name)
            
            df = pd.DataFrame(data, columns=column_headers)
            
            print(df.to_csv(index=False))

        # If no resources are found, print no resources found message
        num_resources = len(objects_list)

        terminal_width = shutil.get_terminal_size((100, 20)).columns  
        breaker = "-" * (terminal_width - 10)
        print(f"{UtilityTools.BOLD}[*] {breaker} [*]{UtilityTools.RESET}")


        if num_resources  == 0:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] GCPwn found 0 {primary_resource} in project {project_id}{UtilityTools.RESET}")
            return
        else:
            print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] GCPwn found {num_resources} {primary_resource} in project {project_id}{UtilityTools.RESET}")

        # Get the terminal width dynamically (defaulting to 100 if undetectable)
        if table:

            print(f"{UtilityTools.BOLD}[*] TABLE OUTPUT ({project_id}){UtilityTools.RESET}")

            table_width = int(terminal_width * 0.9)  # Use 90% of terminal width
            print_table(objects_list, properties_list, table_width, secondary_title_name)

        if txt:
            print(f"{UtilityTools.BOLD}[*] TXT OUTPUT ({project_id}){UtilityTools.RESET}")
            print_text(objects_list, properties_list, table_width, secondary_title_name)

        if csv:
            print(f"{UtilityTools.BOLD}[*] {breaker} [*]{UtilityTools.RESET}")
            print(f"{UtilityTools.BOLD}[*] CSV OUTPUT ({project_id}){UtilityTools.RESET}")
            print_csv(objects_list, properties_list, table_width, secondary_title_name)

        print(f"{UtilityTools.BOLD}[*] {breaker} [*]{UtilityTools.RESET}")

    @staticmethod
    def log_action(workspace_name, action):
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_file = UtilityTools.get_save_filepath(workspace_name, "history_log.txt","System Log")
        
        # Check if the file exists, and create it if it doesn't
        if not os.path.isfile(log_file):
            open(log_file, 'w').close()  # This creates the file

        with open(log_file, "a") as file:
            file.write(f"[{timestamp}] {action}\n")