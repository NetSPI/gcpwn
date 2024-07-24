# Standard libraries
import json, os, argparse, re, shlex, yaml
import pandas as pd
from module_actions import interact_with_module
import traceback
import re

# Custom stuff
from session import SessionUtility
from UtilityController import *
from DataController import DataController

from Modules.Everything.utils.util_helpers import *
 
import time

# Exception handler
from google.api_core.exceptions import *

# Banner when you drop into workspace, Shoutout to Pacu where i grabbed this from and customized to match use case
def help_banner():

    banner = """
    GCPwn - https://github.com/NetSPI/gcpwn
    Written and researched by Scott Weston of NetSPI (https://www.netspi.com/). Heavy inspiration/code snippets from Rhino Security Labs - https://rhinosecuritylabs.com/

    Like Pacu for AWS, the goal of this tool is to be a more pentesty tool for red team individuals or those who are less concerned with configuration statistics.
    A wiki was created that explains all the modules/optins listed below found here: https://github.com/NetSPI/gcpwn/wiki.

    GCPwn command info:
        

        creds      [list]
        creds info [<credname>]                         Get all info about current user 
        creds tokeninfo [<credname]                     Send token to tokeninfo endponit to get more details
        creds set  [<credname>] --email <email>]        Set the user email 

        creds add/update   <credname> [--type adc ] |
                                      [--type adc-file --filepath-to-adc adc_filepath ]
                                      [--type oauth2 --token oauth2_token ] | 
                                      [--type service --service-file service_cred_filepath] |
                                      [--tokeninfo] [-assume]

        creds swap [<credname>] Change current creds to those of another in the workspace.
                                user to whatever email (user or service account) you want the tool to look for exploist for

        
        modules [list]                                              List all Modules
        modules search <keywrod>                                    Search for Module Name
        modules info   <module_name>                                Get Info about speciifc module
        modules run <module name> [--project-ids project-id1,project-id2]    Specify project ID at command line for module if desired
        modules run <module name> -h                           Get Module Specific arguments

        
        projects [list]                     List all projects known by GCPwn
        projects add <project_name>         Add to global project list
        projects set <project_name>         Set current project
        projects rm <project_name>          Remove project name


        config set [zones | locations | projects] project1,project2,project3  Set a project list to be used by all modules to avoid prompt
        config unset [zones | locations | projects]                           Set a zone list to be used by all modules to avoid prompts


        danger [<credname>]            Show dangerous permissions & attack paths for current user

        data tables                                                        List all service tables
        data <table_name> --columns                                       Get columns from tables.
        data <table_name> --columns column1,column2                       Get data from specific columns.
        data <table_name> --columns column1,column2 --csv [OUTPUT_FILE]   Save column data to CSV.
                 
        help                                Display this page of information       
        exit/quit                           Exit GCPwn

    Other command info:
        gcloud/bq/gsutil <command>            Run GCP CLI tool. It is recommended if you want to add a set of creds while in GCPwn
                                                to run the following command to st them at the command line
                                                
                                                gcloud auth login
                                                gcloud auth application-default login

Welcome to your workspace! Type 'help' or '?' to see available commands."""
    print(banner)

class CommandProcessor:
 
    def __init__(self, workspace_id, session):
        

        self.workspace_id = workspace_id
        self.session = session

        self.parser = argparse.ArgumentParser(description="Command processor")
        self.subparsers = self.parser.add_subparsers(dest='subcommand')

        self.setup_parsers()

        self.setup_folder_structure()

    def setup_folder_structure(self):

        workspace_directory_name = f"{self.session.workspace_id}"+"_"+ re.sub(r'\s+', '_', self.session.workspace_name.lower())
        self.session.workspace_directory_name = workspace_directory_name

        # Define the directories to check and create
        directories = [
            f"./GatheredData/",
            f"./GatheredData/{workspace_directory_name}",
            f"./GatheredData/{workspace_directory_name}/Storage",
            f"./GatheredData/{workspace_directory_name}/Compute",
            f"./GatheredData/{workspace_directory_name}/Compute/Serial",
            f"./GatheredData/{workspace_directory_name}/Compute/Screenshots",
            f"./GatheredData/{workspace_directory_name}/Functions",
            f"./GatheredData/{workspace_directory_name}/Reports",
            f"./GatheredData/{workspace_directory_name}/Reports/Snapshots",
            f"./GatheredData/{workspace_directory_name}/Reports/Graphs",
            f"./LoggingMechanism/",
            f"./LoggingMechanism/{workspace_directory_name}"
        ]

        # Check and create directories
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)


    def setup_parsers(self):
        # Define subcommands and their arguments
        commands = {
            'creds': {
                'subcommands': {
                    'list': {},
                    'info': {'args': [('--credname', {'required': False, 'help': 'Specify credname (none defaults to current)'}),
                                      ('--csv', {'required': False, 'action': 'store_true', 'help': 'Export info to CSV file'})]},
                    'tokeninfo': {'args': [('credname', {'nargs': '?', 'help': 'Specify credential name'})]},
                    'set': {'args': [('credname', {'nargs': '?', 'help': 'Specify credential name'}),
                                     ('--email', {'help': 'Specify email'}),
                                     ('--project-id', {'help': 'Specify project'})]},
                    'update': {'args': [('credname', {'nargs': '?', 'help': 'Specify credential name'}),
                                        ('--type', {'choices': ['adc', 'adc-file', 'oauth2', 'service'], 'required': True, 'help': 'Specify credential type'}),
                                        ('--tokeninfo', {'action': 'store_true', 'help': 'Display token information', 'required': False})]},
                    'add': {'args': [('credname', {'help': 'Specify credential name'}),
                                     ('--type', {'choices': ['adc', 'adc-file', 'oauth2', 'service'], 'required': True, 'help': 'Specify credential type'}),
                                     ('--service-file', {'help': 'Add token for oauth2', 'required': False}),                                     
                                     ('--token', {'help': 'Add token for oauth2', 'required': False}),                                     
                                     ('--assume', {'action': 'store_true', 'help': 'Assume credentials after adding', 'required': False}),
                                     ('--tokeninfo', {'action': 'store_true', 'help': 'Display token information', 'required': False})]},
                    'swap': {'args': [('credname', {'nargs': '?', 'help': 'Specify credential name'})]}
                }
            },
            'configs': {
                'subcommands': {

                    'set': {'args': [('type_of_entity', {'help': 'Specify zones/locations/projects/email to set for your session'}),
                                     ('objects', {'nargs': '*', 'help': 'Specify zones or projects list in format a,b,c'})]},
                    'unset': {'args': [('type_of_entity', {'help': 'Specify zones or projects'})]}
                }
            },
            'projects': {
                'subcommands': {
                    'list': {},
                    'set': {'args': [('project_id', {'help': 'Project ID to enter'})]},
                    'add': {'args': [('project_id', {'help': 'Project ID to enter'})]},
                    'rm': {'args': [('project_id', {'help': 'Project ID to enter'})]},
                    'search': {'args': [('search_term', {'help': 'Search term for modules'})]}
                }
            },
            'modules': {
                'subcommands': {
                    'list': {},
                    'search': {'args': [('search_term', {'help': 'Specify search term'})]},
                    'info': {'args': [('module_name', {'help': 'Module name'})]},
                    'run': {'args': [('module_name', {'help': 'Name of module to run'}),
                                     ('--project-ids', {'nargs': '*', 'dest': 'project_ids', 'help': 'Specify project type'}),
                                     ('module_args', {'nargs': argparse.REMAINDER, 'help': 'Arguments for the module'})]}
                }
            },
            'data': {
                'subcommands': {
                    'tables': {'args': [('table_name', {'nargs': '?', 'help': 'Specify table name'}),
                                        ('--csv', {'help': 'Export to CSV'}),
                                        ('--columns', {'help': 'Specify columns'}),
                                        ('--column-names', {'action': 'store_true', 'help': 'List column names'})]}
                }
            },
            'gcloud': {'args': [('gcloud_args', {'nargs': argparse.REMAINDER, 'help': 'Arguments for gcloud'})]},
            'bq': {'args': [('bq_args', {'nargs': argparse.REMAINDER, 'help': 'Arguments for bq'})]},
            'gsutil': {'args': [('gsutil_args', {'nargs': argparse.REMAINDER, 'help': 'Arguments for gsutil'})]},
            'exit': {},
            'quit': {}
        }

        for cmd, cmd_data in commands.items():
            self.create_subparser(self.subparsers, cmd, cmd_data)

    def create_subparser(self, parent, name, data):
        parser = parent.add_parser(name, help=data.get('help', ''))
        if 'subcommands' in data:
            subparsers = parser.add_subparsers(dest=f'{name}_subcommand')
            if isinstance(data['subcommands'], list):
                for subcmd in data['subcommands']:
                    subparsers.add_parser(subcmd)
            elif isinstance(data['subcommands'], dict):
                for subcmd, subcmd_data in data['subcommands'].items():
                    self.create_subparser(subparsers, subcmd, subcmd_data)
        if 'args' in data:
            for arg, arg_data in data['args']:
                parser.add_argument(arg, **arg_data)

    def process_command(self, command):

        if command.strip().lower() in ("help", "?"):
            help_banner()
            return 1
        try:
            args = self.parser.parse_args(shlex.split(command))
            if args.subcommand in ['gcloud', 'bq', 'gsutil']:
                os.system(command)
            elif args.subcommand in ['exit', 'quit']:
                return -1
            elif args.subcommand == 'creds':
                self.process_creds_command(args)
            elif args.subcommand == 'projects':
                self.process_projects_command(args)
            elif args.subcommand == 'data':
                self.process_data_command(args)
            elif args.subcommand == 'configs':
                self.process_config_command(args)
            elif args.subcommand == 'modules':
                self.process_modules_command(args)

        except argparse.ArgumentError as e:
            print(f"Error: {e}")
        except SystemExit:
            pass  # Prevent argparse from exiting the program on error

    # Creds Information/Logic
    def process_creds_command(self, args):

        if args.creds_subcommand in ['list', None]:
            available_creds = DataController.list_creds(self.workspace_id)
            list_all_creds_for_user(available_creds)

        elif args.creds_subcommand == 'set':
            credname = args.credname or self.session.credname
            email = args.email or self.session.email
            project_id = args.project_id or self.session.project_id
            try:
                self.session.update_creds(credname, email=email, project_id=project_id)
                self.session.email = email
                self.session.project_id = project_id
            except Exception as e:
                print("[X] There was an error changing either project ID or email. The change was not performed")
                print(str(e))
        elif args.creds_subcommand == 'tokeninfo':
            credname_to_check = args.credname or self.session.credname
            self.session.get_and_save_tokeninfo(credname_to_check)
        elif args.creds_subcommand == 'info':
            credname_to_check = args.credname or self.session.credname
            self.info_printout_save(credname_to_check, csv=args.csv)
        elif args.creds_subcommand == 'add':
            self.add_cred(args)
        elif args.creds_subcommand == 'update':
            self.update_cred(args)
        elif args.creds_subcommand == 'swap':
            self.swap_cred(args)

    def add_cred(self, args):
        credname = args.credname
        if args.type in ['adc', 'oauth2', 'adc-file']:
            token = getattr(args, "token", None)
            adc_filepath = getattr(args, "filepath_to_adc", None)
            if args.type == "oauth2" and not token:
                print("[X] Cannot proceed with adding Oauth2 credentials. Must supply token via --token")
                return
            if args.type == "adc-file" and not adc_filepath:
                print("[X] Cannot proceed with adding ADC-File credentials. Must supply filepath via --filepath-to-adc")
                return
            if adc_filepath and not os.path.exists(adc_filepath):
                print(f"[X] File {adc_filepath} does not exist...")
                return
            self.session.add_oauth2_account(credname, project_id=self.session.project_id, token=token, tokeninfo=args.tokeninfo, adc_filepath=adc_filepath, assume=args.assume)
        elif args.type == 'service':
            filepath = args.service_file
            if not os.path.exists(filepath):
                print(f"[X] File {filepath} does not exist...")
                return
            self.session.add_service_account(filepath, credname, assume=args.assume)

    def update_cred(self, args):
        credname = args.credname or self.session.credname
        old_cred_info = self.session.get_credinfo(credname=credname)
        email = old_cred_info.get("email")
        scopes = old_cred_info.get("scopes")

        if args.type in ['adc', 'oauth2', 'adc-file']:
            token = getattr(args, "token", None)
            adc_filepath = getattr(args, "filepath_to_adc", None)
            if args.type == "oauth2" and not token:
                print("[X] Cannot proceed with adding Oauth2 credentials. Must supply token via --token")
                return
            if args.type == "adc-file" and not adc_filepath:
                print("[X] Cannot proceed with adding ADC-File credentials. Must supply filepath via --filepath-to-adc")
                return
            if adc_filepath and not os.path.exists(adc_filepath):
                print(f"[X] File {adc_filepath} does not exist...")
                return
            self.session.add_oauth2_account(credname, project_id=self.session.project_id, token=token, tokeninfo=args.tokeninfo, scopes=scopes, email=email, adc_filepath=adc_filepath, assume=True, refresh_attempt=True)
        elif args.type == 'service':
            filepath = args.service_file
            if not os.path.exists(filepath):
                print(f"[X] File {filepath} does not exist...")
                return
            self.session.add_service_account(filepath, credname, assume=args.assume, refresh_attempt=True)

    def swap_cred(self, args):
        if args.credname:
            self.session.load_stored_creds(args.credname)
        else:
            available_creds = DataController.list_creds(self.workspace_id)
            list_all_creds_for_user(available_creds)
            answer = input("[*] Choose the username or index you want to assume: ")
            if any(answer == x[0] for x in available_creds):
                self.session.load_stored_creds(answer)
            elif is_integer_within_bounds(answer, len(available_creds)):
                credname = available_creds[int(answer) - 1][0]
                self.session.load_stored_creds(credname)

    ## Project Information/Logic
    def process_projects_command(self, args):

        if args.projects_subcommand in ['list', None]:
            self.list_projects()
        elif args.projects_subcommand == 'set':
            self.set_projects(args.project_id)
        elif args.projects_subcommand == 'add':
            self.add_projects(args.project_id)
        elif args.projects_subcommand == 'rm':
            self.remove_projects(args.project_id)

    def list_projects(self):

        if self.session.global_project_list:
            print("[*] Current projects known for all credentials: ")
            for project in self.session.global_project_list:
                print(f"  {project}")
            print()
        else:
            print("[X] No projects found globally. You can add some via 'projects add <project_name>")
    def add_projects(self, project_id):
        
        if project_id not in self.session.global_project_list:
            self.session.global_project_list.append(project_id)
            self.session.data_master.insert_project_ids(self.workspace_id, [project_id])
                
        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {project_id} already exists in the list as seen below:{UtilityTools.RESET}")
            for project_id_value in self.session.global_project_list:
                if project_id == project_id_value:
                    print(f" {UtilityTools.GREEN}{UtilityTools.BOLD}- {project_id_value}{UtilityTools.RESET}")
                else:
                    print(f" - {project_id_value}")

    def set_projects(self, project_id, set_as_default = False):
        
        if project_id not in self.session.global_project_list:
            print(f"[X] {project_id} is not in the list of project_ids. Adding...")
            self.add_projects(project_id)


        self.session.project_id = project_id

        # Set default project as well
        if set_as_default:
            self.session.change_default_project_id(project_id)

    def remove_projects(self, project_id):
        
        if project_id in self.session.global_project_list:
            self.session.global_project_list.remove(project_id)
            self.session.data_master.remove_project_ids(self.workspace_id, [project_id])
            if project_id == self.session.project_id:
                if len(self.session.global_project_list) > 0:
                    self.session.project_id = self.session.global_project_list[-1]
                else:
                    self.session.project_id = None
        else:
            print("[X] The project ID specified does not exist")

    ## Data Information/Logic
    def process_data_command(self, args):
        if args.data_subcommand == 'tables':
            self.handle_tables_command(args)

    def list_tables(self):
        print("[*] The following tables exist and can be queried: ")
        table_names = self.load_modules_from_yaml("./utils/database_info.yaml")
        table_name_list = [table["table_name"] for table in table_names["databases"][0]["tables"]]
        table_name_list.sort()
        for table_name in table_name_list:
            print(f"    - {table_name}")

    def process_table(self, args):
            table_name_list = [table["table_name"] for table in self.load_modules_from_yaml("./utils/database_info.yaml")["databases"][0]["tables"]]
            if args.table_name in table_name_list:
                column_names_yaml = self.load_modules_from_yaml("./utils/database_info.yaml")
                column_list = [column for table in column_names_yaml["databases"][0]["tables"] if table["table_name"] == args.table_name for column in table["columns"]]

                if args.column_names:
                    print(f"[*] The following columns exist in {args.table_name} and can be queried: ")
                    for column_name in sorted(column_list):
                        print(f"    - {column_name}")

                elif args.columns:
                    columns = args.columns.split(",")
                    if all(element in column_list for element in columns):
                        all_data = self.session.get_data(args.table_name, columns=columns)
                    else:
                        print("[X] A column name you supplied does not exist in the table's columns. Recheck --columns flag")
                else:
                    all_data = self.session.get_data(args.table_name)

                if not args.column_names and all_data:
                    df = pd.DataFrame(all_data)
                    if args.csv:
                        filepath = args.csv
                        try:
                            df.to_csv(filepath, index=False)
                        except OSError as e:
                            print("[X] Failed to save. Please ensure that the directory exists before saving the file.")
                    else:
                        import sys
                        df.to_csv(sys.stdout, index=False)
            else:
                print("[X] This table does not exist")

    def handle_tables_command(self, args):
        if args.table_name:
            table_names = self.load_modules_from_yaml("./utils/database_info.yaml")
            table_name_list = [table["table_name"] for table in table_names["databases"][0]["tables"]]
            if args.table_name in table_name_list:
                self.process_table(args)
            else:
                print("[X] This table does not exist")
        else:
            self.list_tables()

    ## Config Information/Logic
    def process_config_command(self, args):
        print(args.configs_subcommand)
        if args.configs_subcommand == None:
            self.print_config_snapshot()
        elif args.configs_subcommand == "set":
            if args.type_of_entity == "projects":
                self.session.config_project_list = args.objects[0].split(",")
            elif args.type_of_entity == "zones":
                self.session.config_zones_list = args.objects[0].split(",")
            elif args.type_of_entity == "locations":
                self.session.config_regions_list = args.objects[0].split(",")

        elif args.configs_subcommand == "unset":
            if args.type_of_entity == "projects":
                self.session.config_project_list = None
            elif args.type_of_entity == "zones":
                self.session.config_zones_list = None
            elif args.type_of_entity == "locations":
                self.session.config_regions_list = None

    def print_config_snapshot(self):
        print(f"Current Credname: {self.session.credname}")
        print(f"Current Email: {self.session.email}")
        print(f"Current Scopes: {self.session.scopes}")
        print(f"Fixed Zones Set: {self.session.config_zones_list}")
        print(f"Fixed Locations Set: {self.session.config_regions_list}")
        print(f"Fixed Projects Set: {self.session.config_project_list}")

    ## Module Information/Logic
    def process_modules_command(self, args):

        file_path = "./utils/module-mappings.yaml"
        modules_data = self.load_modules_from_yaml(file_path)

        if args.modules_subcommand in [None, 'list']:
            self.list_modules(modules_data)

        elif args.modules_subcommand == "info":
            self.get_module_info(modules_data, args.module_name)

        elif args.modules_subcommand == "search":
            self.list_modules(modules_data, search_term=args.search_term)

        elif args.modules_subcommand == "run":
            if "--project-ids" in args.module_args:
                project_id_index = args.module_args.index("--project-ids")
                # Only allow unique list of project ids, removes duplicates
                args.project_ids = set(args.module_args[project_id_index + 1].split(","))
                args.module_args.pop(project_id_index)
                args.module_args.pop(project_id_index)
            else:
                args.project_ids = None
           
            def find_module_path(modules_data, module_name):
                for service_name, service_data in modules_data.items():
                    for module_category, modules in self.group_modules_by_category(service_data).items():
                        for module in modules:
                            if module['module_name'] == module_name:
                                return module['location']
                return None


            module_path = find_module_path(modules_data, args.module_name)
            if module_path:
                interact_with_module(self.session, module_path, args.module_args, project_ids=args.project_ids)
            else:
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Module \"{args.module_name}\" not found.{UtilityTools.RED}{UtilityTools.RESET}")

    def list_modules(self, modules_data, search_term = None):
        
        self.print_modules(modules_data, search_term = search_term)  

    def get_module_info(self, modules_data,  module_name):
     
        self.print_module_info(modules_data, module_name)  
    
    def print_module_info(self, data, module_name, max_width=100):
        found = False
        import textwrap
        for service, modules in data.items():
            for module in modules:
                if module['module_name'] == module_name:
                    service_name = service.replace('_', ' ').title()
                    print(f"\n{UtilityTools.BOLD}Service Name:{UtilityTools.RESET} {UtilityTools.GREEN + UtilityTools.BOLD}{service_name}{UtilityTools.RESET}")
                    print(f"{UtilityTools.BOLD}Category:{UtilityTools.RESET} {UtilityTools.BLUE}{module['module_category']}{UtilityTools.RESET}")
                    print(f"{UtilityTools.BOLD}Module Name:{UtilityTools.RESET} {UtilityTools.YELLOW}{module['module_name']}{UtilityTools.RESET}")
                    print(f"{UtilityTools.BOLD}Author:{UtilityTools.RESET} {module['author']}")
                    print(f"{UtilityTools.BOLD}Version:{UtilityTools.RESET} {module['version']}")
                    print(f"{UtilityTools.BOLD}Location:{UtilityTools.RESET} {module['location']}")
                    print(f"{UtilityTools.BOLD}Description:{UtilityTools.RESET}\n{textwrap.fill(module['info_blurb'], max_width)}\n")
                    found = True
                    break
            if found:
                break

        if not found:
            print(f"{UtilityTools.RED}Module \"{module_name}\" not found.{UtilityTools.RESET}")

    def load_modules_from_yaml(self,file_path):
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
            return data

    def group_modules_by_category(self,modules_data):
        grouped_modules = {}
        for module in modules_data:
            module_category = module['module_category']
            if module_category not in grouped_modules:
                grouped_modules[module_category] = []
            grouped_modules[module_category].append(module)
        return grouped_modules

    
    def print_modules(self, data, search_term=None):
        header_color = UtilityTools.BOLD
        category_color = UtilityTools.BLUE + UtilityTools.BOLD
        module_color = UtilityTools.YELLOW

        found_match = False

        # Collect all the rows for the table
        rows = []
        for service, modules_data in data.items():
            service_name = service.replace('_', ' ').replace(' modules', '').title()
            for module_category, modules in self.group_modules_by_category(modules_data).items():
                matching_modules = sorted(
                    [module['module_name'] for module in modules if search_term is None or search_term.lower() in module['module_name'].lower()]
                )
                for module in matching_modules:
                    rows.append((service_name, module_category.capitalize(), module))
                    found_match = True

        if not found_match:
            print(f"{UtilityTools.RED}No matching modules found.{UtilityTools.RESET}")
            return

        # Determine the column widths
        col_widths = [max(len(row[i]) for row in rows) for i in range(3)]

        # Calculate the length for the horizontal lines
        separator_length = col_widths[0] + col_widths[1] + col_widths[2] + 6

        # Print the header
        header = ("Service", "Category", "Module")
        header_line = f"{header_color}{header[0]:<{col_widths[0]}} | {header[1]:<{col_widths[1]}} | {header[2]:<{col_widths[2]}}{UtilityTools.RESET}"
        print(header_line)
        print("-" * separator_length)

        # Print the rows with a horizontal line separating different services and categories
        current_service = None
        current_category = None
        for row in rows:
            service_name, module_category, module = row
            if service_name != current_service:
                if current_service is not None:
                    print("-" * separator_length)
                current_service = service_name
                current_category = None
                print(f"{UtilityTools.GREEN + UtilityTools.BOLD}{service_name:<{col_widths[0]}}{UtilityTools.RESET} | "
                    f"{category_color}{module_category:<{col_widths[1]}}{UtilityTools.RESET} | "
                    f"{module_color}{module:<{col_widths[2]}}{UtilityTools.RESET}")
                current_category = module_category
            elif module_category != current_category:
                current_category = module_category
                print(f"{' ' * (col_widths[0] + 1)}{'-' * (separator_length - col_widths[0] - 1)}")
                print(f"{' ' * col_widths[0]} | "
                    f"{category_color}{module_category:<{col_widths[1]}}{UtilityTools.RESET} | "
                    f"{module_color}{module:<{col_widths[2]}}{UtilityTools.RESET}")
            else:
                print(f"{' ' * col_widths[0]} | "
                    f"{' ' * col_widths[1]} | "
                    f"{module_color}{module:<{col_widths[2]}}{UtilityTools.RESET}")

    def info_printout_save(self, credname, csv = False):
        
        permissions_fetch = self.session.get_actions(credname = credname)
        role_member, roles_and_assets = None, None
        # If credname is found thanemail must also be known
        if self.session.email:
            email = self.session.email
            all_auth_binding = self.session.get_data("member-permissions-summary", conditions = f"member = \"user:{email}\" OR member = \"serviceAccount:{email}\"")
      
            if all_auth_binding:
                if all_auth_binding[0]["crednames"] and credname in all_auth_binding[0]["crednames"]:
                    role_member, roles_and_assets = all_auth_binding[0]["member"], ast.literal_eval(all_auth_binding[0]["roles_and_assets"])
                 

        if csv:
            
            final_directory  = UtilityTools.get_save_filepath(self.session.workspace_directory_name, f"", "Reports Snapshot")
            
            basic_info = [{
                "Email": str(self.session.email),
                "Scopes": str(self.session.scopes),
                "Projects": str(self.session.global_project_list)
            }]
            if self.session.access_token:
                basic_info[0]["Access Token"] = self.session.access_token

            df = pd.DataFrame(basic_info)
            df.to_csv(final_directory+f"/{credname}_{time.time()}.csv", mode="w", index=False)

            if role_member:
                generate_summary_of_roles_or_vulns(self.session, role_member, roles_and_assets, snapshot = True, first_run=True, csv = True)
            if permissions_fetch:
                generate_summary_of_permission_vulns(permissions_fetch[0], self.session, snapshot = True, first_run = True,  csv = True)

            return 1

        else:   

            formatted_default_project_string = self.session.default_project_id

            # Define Email Section
            formatted_email_string = self.session.email
            email_color = UtilityTools.GREEN if formatted_email_string else UtilityTools.RED

            # Define Scope Section
            if self.session.scopes and len(self.session.scopes) > 0:
                formatted_scope_string = ""
                for scope in self.session.scopes:
                    if scope == "https://www.googleapis.com/auth/cloud-platform":
                        formatted_scope_string += f"    - {scope} (See, edit, configure, and delete your Google Cloud data and see the email address for your Google Account.)\n"
                    else:
                        formatted_scope_string += f"    - {scope}\n"
                scope_color = UtilityTools.GREEN
            else:
                formatted_scope_string = "    - N/A"
                scope_color = UtilityTools.RED

            # Define Access Token Section
            formatted_access_token_string = self.session.access_token if self.session.access_token else "N/A"
            access_token_color = UtilityTools.GREEN if self.session.access_token else UtilityTools.RED

            # Define Project Section
            formatted_all_projects_string = ""
            for project in sorted(self.session.global_project_list):
                formatted_all_projects_string += f"    - {project}\n"
            project_color = UtilityTools.GREEN if formatted_all_projects_string.strip() else UtilityTools.RED

            # Define Default Project Section
            default_project_color = UtilityTools.GREEN if formatted_default_project_string else UtilityTools.RED

            whoami_info = (
                f"\n{UtilityTools.BOLD}Summary for {credname}:{UtilityTools.RESET}\n"
                f"{email_color}Email:{UtilityTools.RESET} {formatted_email_string}\n"
                f"{scope_color}Scopes:{UtilityTools.RESET}\n{formatted_scope_string}\n"
                f"{default_project_color}Default Project:{UtilityTools.RESET} {formatted_default_project_string}\n"
                f"{project_color}All Projects:{UtilityTools.RESET}\n{formatted_all_projects_string}\n"
                f"{access_token_color}Access Token:{UtilityTools.RESET} {formatted_access_token_string}\n"
            )

            print(whoami_info)
            if role_member:
                generate_summary_of_roles_or_vulns(self.session, role_member, roles_and_assets, snapshot = True, first_run=True, stdout=True)
            if permissions_fetch:
                generate_summary_of_permission_vulns(permissions_fetch[0], self.session, snapshot = True, first_run=True, stdout=True)
   
def list_all_creds_for_user(available_creds):
    
    if available_creds == None: 
        print("\n[-] No creds found")

    else:
        print("\n[*] Listing existing credentials...")
        for index,cred in enumerate(available_creds):
            name, type_of_cred, email = cred[0], cred[1], cred[2]
            
            if email != "None":
                print(f"  [{index+1}] {name} ({type_of_cred}) - {email}")
            else:
                print(f"  [{index+1}] {name} ({type_of_cred})")
        print("\n")

def is_integer_within_bounds(user_input, upper_bound):
    try:
        user_input_int = int(user_input)
        return 1 <= user_input_int <= upper_bound
    except ValueError:
        return False

def initial_instructions(workspace_id: int, workspace_name: str):

    # Session starts as None and Print Help Banner
    session = None

    # Argparse Helpers
    def tokeninfo_action(value: str) -> bool:
        return True if value.lower() == 'tokeninfo' else value

    # Initial Print Setup
    def first_time_message(available_creds):

        import textwrap

        # Print standard help menu
        help_banner()

        # Print out list of creds for specified user that were saved (note can be empty)
        list_all_creds_for_user(available_creds)

        # Prompt user for new credentials
        new_credentials_instructions = textwrap.dedent("""\
        Submit the name or index of an existing credential from above, or add NEW credentials via Application Default 
        Credentails (adc - google.auth.default()), a file pointing to adc credentials, a standalone OAuth2 Token, 
        or Service credentials. See wiki for details on each. To proceed with no credentials just hit ENTER and submit 
        an empty string. 
        [1] *adc      <credential_name> [tokeninfo]                    (ex. adc mydefaultcreds [tokeninfo]) 
        [2] *adc-file <credential_name> <filepath> [tokeninfo]         (ex. adc-file mydefaultcreds /tmp/name2.json)
        [3] *oauth2   <credential_name> <token_value> [tokeninfo]      (ex. oauth2 mydefaultcreds ya[TRUNCATED]i3jJK)  
        [4] service   <credential_name> <filepath_to_service_creds>    (ex. service mydefaultcreds /tmp/name2.json)

        *To get scope and/or email info for Oauth2 tokens (options 1-3) include a third argument of 
        "tokeninfo" to send the tokens to Google's official oauth2 endpoint to get back scope. 
        tokeninfo will set the credential name for oauth2, otherwise credential name will be used.
        Advised for best results. See https://cloud.google.com/docs/authentication/token-types#access-contents.
        Using tokeninfo will add scope/email to your references if not auto-picked up.

        Input: """)

        answer = input(new_credentials_instructions)

        arguments = re.split(r'\s+', answer.strip())

        return answer, arguments

    credname_help_message = "Arbitrary Credential Name (ex. WebbinrootCreds)"
    tokeninfo_help_message = "Send Tokens to Tokeninfo Endpoint"

    initial_startup_parser = argparse.ArgumentParser(description="Handle addition of credentials", exit_on_error=False)
    subparsers = initial_startup_parser.add_subparsers(dest="command", metavar="<command>", required=True)

    # Subparser for option 1
    parser_1 = subparsers.add_parser("adc", help="Set default credentials")
    parser_1.add_argument("credential_name", help=credname_help_message)
    parser_1.add_argument("tokeninfo", nargs='?', default=False, action="store", type=tokeninfo_action, help=tokeninfo_help_message)
    
    # Subparser for option 2
    parser_2 = subparsers.add_parser("adc-file", help="Set default credentials")
    parser_2.add_argument("credential_name", help=credname_help_message)
    parser_2.add_argument("filepath_to_adc", help="Filepath to ADC Information (ex. /tmp/adc_refreshtokens.json)")
    parser_2.add_argument("tokeninfo", nargs='?', default=False, action="store", type=tokeninfo_action, help=tokeninfo_help_message)
    
    # Subparser for option 3
    parser_3 = subparsers.add_parser("oauth2", help="Set OAuth2 token")
    parser_3.add_argument("credential_name", default=None, help=credname_help_message)
    parser_3.add_argument("token_value", help="OAuth2 token (ex. ya[TRUNCATED]i3jJK)")
    parser_3.add_argument("tokeninfo", nargs='?', default=False, action="store", type=tokeninfo_action, help=tokeninfo_help_message)

    # Subparser for option 4
    parser_4 = subparsers.add_parser("service", help="Set service credentials")
    parser_4.add_argument("credential_name", default=None, help=credname_help_message)
    parser_4.add_argument("filepath_to_service_creds", help="Filepath to service credentials (ex. /tmp/name2.json)")

    
    # Get list of existing crednames in format (credname, credtype, email)
    available_creds = DataController.list_creds(workspace_id)

    # List all creds and prompt user to make choice on how to proceed, accept number or name
    
    answer, arguments = first_time_message(available_creds)

    # Default None State
    if answer == "":
        return SessionUtility(workspace_id, workspace_name, None, None)

    # User types in credname to assume
    if any(answer == x[0] for x in available_creds):
        return SessionUtility(workspace_id, workspace_name, answer.strip(), None, resume=True)

    # User types in number of credname to assume   
    if is_integer_within_bounds(answer, len(available_creds)):
        
        credname = available_creds[int(answer)-1][0]
        return SessionUtility(workspace_id, workspace_name, credname, None, resume=True)

    # User adds new creds
    try:

        args = initial_startup_parser.parse_args(arguments)
    
    except argparse.ArgumentError:

        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Incorrect input. Make sure to either type the name of credentials that exist or start with default/oauth2/service. Entering GCPwn with no credentials or project set...{UtilityTools.RESET}")
        return SessionUtility(workspace_id, workspace_name, None, None)

    if args.command in {"adc", "oauth2", "adc-file"}:
        
        oauth_token = getattr(args, "token_value", None)
        adc_filepath = getattr(args, "filepath_to_adc", None)

        return SessionUtility(workspace_id, workspace_name, args.credential_name, args.command, oauth_token = oauth_token, adc_filepath=adc_filepath, tokeninfo=args.tokeninfo)
        
    elif args and args.command == "service":
        filepath = args.filepath_to_service_creds
        if not os.path.exists(filepath):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] File {filepath} does not exist. Proceeding with no credentials...{UtilityTools.RESET}")
            return SessionUtility(workspace_id, workspace_name, None, None)
        return SessionUtility(workspace_id, workspace_name, args.credential_name, args.command, filepath = filepath)
    

    return SessionUtility(workspace_id, workspace_name, None, None)

# Entrypoint for workspace
def workspace_instructions(workspace_id, workspace_name):
    
    # Get Session Object
    session = initial_instructions(workspace_id, workspace_name)

    # Create Command Line Processor
    command_processor = CommandProcessor(workspace_id, session)
    
    # Set up readline here (as opposed to before so as to not record setup inr eadline)
    import readline
    readline.set_history_length(25)

    while True:
        
        cli_prefix=f"{session.project_id}:{session.credname}"
        
        try:
            user_input = input(f'({cli_prefix})> ')

            # Thanks ChatGPT for nifty command
            readline.set_auto_history(False)

            keep_running = command_processor.process_command(user_input)
            if keep_running == -1:
                exit()

        except (ValueError, KeyboardInterrupt):
            break

        except Exception:

            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Program failed for unknown reasons. See below:{UtilityTools.RESET}")
            print(traceback.format_exc())

        finally:

            # Re-enable readline history tracking
            readline.set_auto_history(True)