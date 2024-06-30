import requests, json, ast, re
from datetime import datetime
import google.auth
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from DataController import DataController
from UtilityController import *
import google.auth.transport.requests
import traceback

from google.auth.exceptions import DefaultCredentialsError

class SessionUtility:

    # used by modules to access data if needed
    workspace_id, workspace_name, workspace_directory_name, data_master = None, None, None, None

    # Standard values for most items
    default_project_id, project_id = None, None 
    credname, credentials = None, None

    # Could be none forever unless tokeninfo called
    email, access_token, scopes = None,None, []
    global_project_list = []

    config_project_list, config_zones_list, config_regions_list = None, None, None

    def __init__(self, workspace_id, workspace_name, credname, auth_type, filepath=None, oauth_token=None, resume=None, adc_filepath = None, tokeninfo = False):
      
        # Contain connections to workspace and session tables. Also connection to database with all service info.
        self.data_master = DataController()
        self.data_master.create_service_databases()

        # Set Workspace ID for whole session object (integer stored as column in all tables)
        self.workspace_id = workspace_id
        self.workspace_name = workspace_name

        # Set global project list to all project IDs stored for session. 
        # Taken from SELECT global_project_list FROM workspaces WHERE id = ?
        # Can return empty list when there are no starting projects
        self.global_project_list = self.data_master.get_all_project_ids(self.workspace_id) 
   
        # No cred name and no auth type and not resuming just pass and fall into None workspace
        if not credname and not auth_type and resume == False:
            pass

        # ADC creds
        elif auth_type == "adc":
            
            self.add_oauth2_account(credname, tokeninfo = tokeninfo, assume = True)

        # ADC creds with file
        elif auth_type == "adc-file":

            self.add_oauth2_account(credname, adc_filepath = adc_filepath, tokeninfo = tokeninfo, assume = True)

        # Standalone Oauth2 token
        elif auth_type == "oauth2":

            self.add_oauth2_account(credname, token=oauth_token, tokeninfo = tokeninfo, assume = True)

        # Service account
        elif auth_type == "service":
            self.add_service_account(filepath, credname, assume=True)

        elif resume:

            # Get all current credentials for workspace
            current_workspace_crednames = DataController.list_creds(workspace_id)

            #compliments of ChatGPT :) checks every tuple to see if credname in there
            if any(credname in name for name in current_workspace_crednames):
                self.load_stored_creds(credname)
            else:
                print("[X] Could not resume credentials as they do not appear to exist for this workspace")


        # Having added the creds add the syncs
        # Format is {credential_name:{project:{project_name:[actions]},organization:{organization_name:[actions]}},credetnial_name, etc}
        # self.all_permissions = self.data_master.sync_session(workspace_id)
        # print(self.all_permissions )

    def get_all_actions(self):
        return self.data_master.get_all_actions(self.workspace_id)

    def get_actions(self, credname = None):
        
        permissions = self.data_master.get_actions(self.workspace_id, credname = credname)
        return permissions

    def get_display_name(self, name):
        table_name = "abstract-tree-hierarchy"
        workspace_id = self.workspace_id
        conditions =  f" workspace_id=\"{workspace_id}\" AND name = \"{name}\""
        data = self.data_master.get_columns(table_name, columns=["display_name"], conditions=conditions)
        return data

    ### Main Core Authentication Functions 
    def attempt_cred_refresh(self, auth_json):
        
        # Self.credentials.token = None handles first initialization case when trying to use creds
        if self.credentials and self.credentials.expired or self.credentials.valid == False or self.credentials.token == None:
            
            # expiry when set in refresh token JSON's does not correspond to expiry of final access token seems like       
            if self.credentials.expired:
                if "expiry" in auth_json.keys():
                    expiry_timestamp = auth_json["expiry"]

                # Convert the expiry timestamp string to a datetime object
                expiry_datetime = datetime.fromisoformat(expiry_timestamp.rstrip('Z'))

                # Get the current datetime
                current_datetime = datetime.utcnow()

                # Only print this out if token alos exists, else its just expected behavior
                if expiry_datetime < current_datetime and self.credentials.token:
                    print( f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Expired Credentials. Timestamp expiration for the access_token was {expiry_datetime}. Refresh is required{UtilityTools.RESET}")

            else:
                print( f"[X] Invalid credentials or no access token stored" )

            print("[*] Attempting to refresh the credentials using the stored refresh token. Note this is normal for brand new OAuth2 credentials added/updated.")

            auth_req = google.auth.transport.requests.Request()

            try:

                self.credentials.refresh(auth_req)
                print(f"{UtilityTools.GREEN}[*] Credentials sucessfully refreshed...{UtilityTools.RESET}")
                
                self.update_oauth2_account(self.credname, email=self.email, scopes = self.scopes, session_creds = self.credentials.to_json())
                print(f"{UtilityTools.GREEN}[*] Credentials sucessfully stored/updated...{UtilityTools.RESET}")

                return 1

            except Exception as e:
                if "Reauthentication is needed" in str(e) and "gcloud auth application-default login" in str(e):
                    message = (
                        f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Tried refreshing the credentials but ran into "
                        f"google.auth.exceptions.RefreshError error. The stored refresh token seems to no longer work "
                        f"(might be limited time-wise){UtilityTools.RESET}. To update your creds once in the tool:\n"
                        f"1. Run 'gcloud auth application-default login' to get a new set of credentials\n"
                        f"2. Run 'creds update <credname>' to update your current default credentials to the newest set"
                    )
                    
                elif "Max retries exceeded with url" in str(e):
                    message = (
                        f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Received network error when trying to refresh. Make sure"
                        f"you have a reliable internet connection or check your connectivity. "
                    )
                print(message)
        else:

            return 1

        return None

    # Change callers default project id
    def change_default_project_id(self, project_id):
        self.data_master.change_default_project_id(self.workspace_id, self.credname, project_id)

    # Expirty time of token: https://googleapis.dev/python/google-auth/latest/reference/google.auth.credentials.html#google.auth.credentials.Credentials
    def load_stored_creds(self, credname, tokeninfo_check = False):
        try:
            cred = self.data_master.fetch_cred(self.workspace_id, credname)
            if not cred:
                return None
            
            # Set current creds at command line
            self.default_project_id = cred["default_project"]

            self.project_id = cred["default_project"]
            
            if self.project_id  == "Unknown":
                print("[*] The project assosciated with these creds is unknown. To bind the creds to a project specify \"creds <credname> bind <projectname>\". Otherwise you might have limited functionality with non-global resources.")
            
            # Load in relevant data 
            self.credname = cred["credname"]
            scopes_str = cred.get("scopes", "[]")
            if scopes_str is None: scopes_str = "[]"
            self.scopes = ast.literal_eval(scopes_str)
            self.email = cred["email"]
            
            # Oauth2, downlaod creds and refresh if necessary
            if cred["credtype"] in ["adc","adc-file","oauth2"]:

                auth_json = json.loads(cred["session_creds"])           

                if cred["credtype"] in ["adc", "adc-file"]:
                    
                    print("[*] Loading in ADC credentials...")

                    self.credentials = Credentials.from_authorized_user_info(auth_json)
                    
                    status = self.attempt_cred_refresh(auth_json)
                    
                    if status:

                        self.access_token = self.credentials.token

                        if tokeninfo_check:

                            # get_and_save_tokeninfo updates already
                            scopes, email = self.get_and_save_tokeninfo(credname)

                            if scopes: 
                                self.scopes = scopes
                            if email: 
                                self.email = email

                        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Proceeding with up-to-date ADC credentials for {credname}...{UtilityTools.RESET}")

                    else:

                        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Proceeding with erroneous ADC credentials for {credname}...{UtilityTools.RESET}")


                # https://google-auth.readthedocs.io/en/master/reference/google.auth.credentials.html
                elif cred["credtype"] == "oauth2":

                    print("Loading in OAuth2 token. Note it might be expired based on how long its existed...")

                    token = auth_json["token"]
                    self.access_token = token
                    self.credentials = Credentials(token=token)

            # TODO Add P12 support?
            elif cred["credtype"] == "service":
                
                print("Loading in Service Credentials...")

                details_json = json.loads(cred["session_creds"])
                self.credentials = service_account.Credentials.from_service_account_info(details_json)
               
                if self.credentials.project_id:
                    self.project_id = self.credentials.project_id
                if self.credentials.service_account_email:
                    self.email = self.credentials.service_account_email
                if self.credentials.scopes:
                    self.scopes = self.credentials.scopes
                
                self.access_token = None

            if self.credentials is None:
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] There was an error loading your credentials. These credentials might not work/be passed onto the service{UtilityTools.RESET}")
                return -1
            else:
                print(f"[*] Loaded credentials {credname}")
                return 1


        except Exception as e:
            print(f"[X] Credentials {credname} could not be assumed.")
            import traceback
            print(traceback.format_exc())
   

    def add_oauth2_account(self, credname, token=None, project_id=None,adc_filepath = None, tokeninfo = False, scopes = None, email = None, assume = False, refresh_attempt = False):
        
        if not refresh_attempt and self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists. Try again with a new credname.{UtilityTools.RESET}")
            return None

        credentials, type_of_cred, tokeninfo_check = None, None, False

        if not project_id:
            project_id = "Unknown"
       
        try:

            if not token:

                if adc_filepath:

                    type_of_cred = "adc-file"
                    credentials, project_id =google.auth.load_credentials_from_file(adc_filepath)
                
                else:
                    # default credentials, HTTP traffic wise they return scopes but the google SDK does not seem to let me grab it :(
                    
                    type_of_cred = "adc"

                    try:
                        credentials, project_id =  google.auth.default()

                    except DefaultCredentialsError as e:

                        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] ADC not setup. See below for next steps:{UtilityTools.RESET}")
                        print("1. From the Tool:")
                        print("   a) GCPwn should forward you to a (None:None)> prefix")
                        print("   b) From the tool, run 'gcloud auth login' and sign in")
                        print("   c) From the tool, run 'gcloud auth application-default login' and sign in")
                        print("   d) Run 'creds add <credname> --type adc --assume' to add & assume ADC creds")
                        print("2. Outside the Tool:")
                        print("   a) Exit GCPwn via Ctrl+C")
                        print("   b) From command line, Run 'gcloud auth login' and sign in")
                        print("   c) From command line, Run 'gcloud auth application-default login' and sign in")
                        print("   d) Launch the tool again via 'python3 main.py'")
                        print("   e) At the screen to add creds, try 'adc <credname>' again and it should work")
                        return -1
 
            else:
                type_of_cred = "oauth2"
                credentials = Credentials(token=token)

            serialized_creds = credentials.to_json()
            json_creds = json.loads(serialized_creds)
            
            if tokeninfo:
                if type_of_cred == "oauth2":
                    scopes, email = self.call_tokeninfo(json_creds["token"])
                else:
                    tokeninfo_check = True
               
                                        
            if project_id:
                print("[*] Project ID of credentials is: " + project_id)
            else:
                print("[*] Project ID of credentials is Unknown. Set it via workspace with `projects set <project_id>`.")
            
            self.data_master.insert_creds(self.workspace_id, credname, type_of_cred, project_id, serialized_creds, email = email, scopes = str(scopes)) 
            if project_id:
                self.insert_data('abstract-tree-hierarchy', {"project_id":project_id,"name":"Unknown"}, only_if_new_columns = ["project_id"])

            if project_id and project_id != "Unknown" and project_id not in self.global_project_list:
                self.global_project_list.append(project_id)

            # Assume the creds we just inserted

            print("[*] Credentials successfuly added") 

            if assume:
                self.load_stored_creds(credname, tokeninfo_check = tokeninfo_check)
                
        except Exception as e:
            print("No default credentials were detected. If needed exit ths program and run 'gcloud auth login'")
            print(traceback.format_exc())

    # https://google-auth.readthedocs.io/en/master/reference/google.oauth2.service_account.html
    # Add service account. If successfull add to database
    def add_service_account(self, filename, credname, email = None, sa_info = None, assume = False, refresh_attempt = False):

        if not refresh_attempt and self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"[X] Apologies, {credname} already exists. Try again with a new credname.")
            return None

        if sa_info:
            serialized_creds = json.loads(sa_info)
        else:
            serialized_creds = json.load(open(filename))

        project_id = serialized_creds.get("project_id", "Unknown")
        
        if not email:
            email = serialized_creds.get("client_email")
        
        scopes = serialized_creds.get("scopes")

        if self.project_id == "Unknown":
            self.data_master.insert_row("abstract-tree-hierarchy", {"type":"project","parent":"None","project_id":self.project_id,"name":"NA"})
                
        self.data_master.insert_creds(self.workspace_id, credname, "service", project_id, json.dumps(serialized_creds), email = email, scopes = scopes) 
   
        print("[*] Credentials successfuly added") 

        if assume:
            
            self.load_stored_creds(credname)


    def get_session_data(self, table_name, columns="*", conditions=None):
        
        condition_string  = f"workspace_id=\"{self.workspace_id}\""
        if conditions:
            condition_string = f"{conditions} AND {condition_string}"

        return self.data_master.get_session_columns(table_name, columns=columns, conditions=condition_string)

    def update_creds(self, credname, serialized_creds = None, email=None, project_id=None):  

        self.data_master.update_creds(self.workspace_id, credname, serialized_creds = serialized_creds, email=email, project_id=project_id)  

    # TODO allow updating of arbitary creds in future
    def update_oauth2_account(self, credname, credtype=None, email=None, default_project=None,scopes=None, session_creds=None):
        
        try:
            save_data = {
                "credname": credname,
                "workspace_id": self.workspace_id
            }

            # Now change data if needed
            if credtype: 
                save_data["credtype"] = credtype
            
            if email: 
                save_data["email"] = email
                self.email = email
            else:
                save_data["email"] = self.email

            if scopes:
                save_data["scopes"] = str(scopes)
                self.scopes = scopes
            else:
                save_data["email"] = self.scopes

            if session_creds: 
                save_data["session_creds"] = session_creds

            if default_project: 
                save_data["default_project"] = default_project
                self.default_project_id = default_project
            else:
                save_data["default_project"] = self.default_project_id

            self.data_master.update_session_row(save_data)

        except Exception as e:
            print(str(e))
            print("Exception when trying to update oauth creds")

    def get_credinfo(self, credname = None, self_credname = False):
        if self:
            return self.data_master.fetch_cred(self.workspace_id, self.credname)
        else:
            return self.data_master.fetch_cred(self.workspace_id, credname)

    def get_and_save_tokeninfo(self, credname):
        cred = self.data_master.fetch_cred(self.workspace_id, credname)
        if cred["credtype"] != "service":
            access_token = json.loads(cred["session_creds"])["token"]
            scopes, email = self.call_tokeninfo(access_token)
            if scopes or email:
                self.update_oauth2_account(credname, scopes=scopes, email=email)
            return scopes, email
        else:
            print("[X] Can't perform tokeninfo operations with a service account token")
            return None, None

    def call_tokeninfo(self, token: str):
        
        print("[*] Checking credentials against https://oauth2.googleapis.com/tokeninfo endpoint...")
        token_url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"

        conn = requests.get(token_url)
        conn_json = conn.json()

        if conn.status_code == 200:
            print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Succeeded in querying tokeninfo. The response is shown below:{UtilityTools.RESET}")
            print(conn_json)

        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed in querying tokeninfo. The response is shown below:{UtilityTools.RESET}")
            print(conn_json)
            return None, None

        scopes = conn_json["scope"].split() if "scope" in conn_json else None
        email = conn_json["email"] if "email" in conn_json else None

        return scopes, email

    ### Logging Utility FUnctions

    def write_to_session_log(self, message, output_file = None):

        if not output_file:
            f = open("logfile.log", "a")
        import time
        timestamp = datetime.now().timestamp()
        f.write(f"{timestamp}: {message}")
        f.close()

    ### Project Utility FUnctions

    def sync_projects(self):

        update_projects = False

        projects = self.get_data("abstract-tree-hierarchy", columns = ["project_id"], conditions = f"workspace_id = {self.workspace_id} AND type=\"project\"")
        for project in projects:        
            if project["project_id"] not in self.global_project_list:  
                update_projects = True      
                self.global_project_list.append(project["project_id"])
        
        if update_projects:
            self.data_master.insert_project_ids(self.workspace_id, self.global_project_list)
    
    ### Database Bindings/Permissions//Ancestry Utility Functions

    # only_if_new ONLY adds entryif columns don't match what is passed in 
    # update_columns will update columns (as opposed to rewriting everyting)
    def insert_data(self, table_name, save_data, only_if_new_columns = None, update_only = False, dont_change = None, if_column_matches  = None):

        # Convert to string
        if not update_only:

            save_data = {key: str(value) for key, value in save_data.items()}


        if only_if_new_columns:

            save_data["workspace_id"] = self.workspace_id
            self.data_master.insert_if_not_exists(table_name, save_data, only_if_new_columns)

        elif update_only:
            
          
            save_data["primary_keys_to_match"]["workspace_id"] = self.workspace_id

            # dictionary has primary keys + changed values
            self.data_master.update_row(table_name, save_data)
    

        elif dont_change:
            
            save_data["workspace_id"] = self.workspace_id
       
            self.data_master.insert_row(table_name, save_data, dont_change = dont_change)
        
        elif if_column_matches:

            save_data["workspace_id"] = self.workspace_id
            self.data_master.insert_row(table_name, save_data, if_column_matches = if_column_matches)

        else:
            
            save_data["workspace_id"] = self.workspace_id

            self.data_master.insert_row(table_name, save_data)

    # Project ID None when more than one is specified
    def insert_actions(self, actions, project_id = None, column_name = None):
        self.data_master.insert_actions(self.workspace_id, self.credname, actions, project_id, column_name = column_name)

    def get_immediate_ancestor(self, asset_name):
        parent = self.data_master.get_immediate_parent_node(asset_name)
        return parent

    def find_ancestors(self, asset_name):
        workspace_id = self.workspace_id
        tree = self.data_master.find_ancestors(asset_name, workspace_id)
       
        return tree

    def get_bindings(self, asset_name = None, type_of_asset = None):
        workspace_id = self.workspace_id
        conditions = f" workspace_id=\"{workspace_id}\""
        if asset_name:
            conditions = conditions + f" AND asset_name = \"{asset_name}\""
        if type_of_asset:
            conditions = conditions + f" AND type = \"{type_of_asset}\""

        data = self.data_master.get_columns("iam-bindings",conditions=conditions)
        return data

    ### Database Data Utility Functions

    def get_data(self, table_name, columns="*", conditions=None):
        workspace_id = self.workspace_id
        if conditions:
            condition_string = conditions + f" AND workspace_id=\"{workspace_id}\""
        else:
            condition_string = f"workspace_id=\"{workspace_id}\""

        data = self.data_master.get_columns(table_name, columns=columns, conditions=condition_string)
        return data

 

    def add_unauthenticated_permissions(self, unauthenticated_info, project_id = None):
        table_name = "iam-unauth-permissions"
        unauthenticated_info["workspace_id"] = self.workspace_id
        if project_id:
            unauthenticated_info["project_id"] = project_id
        else:
            unauthenticated_info["project_id"] = self.project_id
        unauthenticated_info["member"] = "users:allUsers"

        self.data_master.insert_row(table_name, unauthenticated_info)

    ### Utility Prompt Functions

    def choice_prompt(self, prompt:str, regex = None):
        
        try:
            while True:
                user_input = input("> " + prompt).strip()
                if regex:
                    if re.match(regex, user_input):
                        return user_input
                    else:
                        print("Input doesn't match the required pattern. Please try again.")
                else:
                    return user_input
        except KeyboardInterrupt:
            return None
        except Exception as e:
            print("An error occurred:", e)
            print("Try again")

    def get_permission_data(self):
        self.data_master.get_permission_data(self.workspace_id)

    def choice_selector(self, rows_returned=None, custom_message="", fields=None, chunk_mappings=None, footer_title=None, footer_list=None, header=None):
        
        
        def print_entries(entries, start_index, fields):
            for index, entry in enumerate(entries):
                line = f">> [{start_index + index + 1}]"
                if fields:
                    line += " " + ", ".join(str(entry[field]) for field in fields)
                else:
                    line += f" {entry}"
                print(line)

        def calculate_chunk_offsets(chunk_mappings):
            offsets = [0]
            for chunk in chunk_mappings:
                total_length = len(chunk['data_values'])
                offsets.append(offsets[-1] + total_length)
            return offsets

        total_choices = 0
        chunk_offsets = []

        if header:
            print("\n" + header)

        if not chunk_mappings:
            print(f"{UtilityTools.BOLD}> " + custom_message + UtilityTools.RESET)
            if rows_returned:
                print_entries(rows_returned, 0, fields)
                total_choices = len(rows_returned)
        else:
            chunk_offsets = calculate_chunk_offsets(chunk_mappings)
            for i, chunk in enumerate(chunk_mappings):
                title = chunk.get("title", "")
                data_values = chunk.get("data_values", [])
                
                if not data_values:  # Skip chunks with empty data_values
                    continue
                
                print("\n> " + title)
                start_index = chunk_offsets[i]
                print_entries(data_values, start_index, fields)
                total_choices += len(data_values)

        if footer_title:
            print(f"{UtilityTools.BOLD}\n> " + footer_title + UtilityTools.RESET)
            if footer_list:
                for choice in footer_list:
                    print(">> " + choice)

        print(f"> [{total_choices + 1}] Exit\n")

        while True:
            try:
                option = int(input("> Choose an option: ").strip())
                if 1 <= option <= total_choices:
                    break
                elif option == total_choices + 1:
                    return None
                else:
                    print("Choose an index from the ones above.")
            except ValueError:
                print("Please enter a valid number.")
            except KeyboardInterrupt:
                return None

        if not chunk_mappings:
            return rows_returned[option - 1]
        else:
            chunk_offsets = calculate_chunk_offsets(chunk_mappings)
            for i, start_index in enumerate(chunk_offsets[:-1]):
                end_index = chunk_offsets[i + 1]
                if start_index < option <= end_index:
                    data_values = chunk_mappings[i]['data_values']
                    return data_values[option - start_index - 1]

   

    def get_project_name(self, project_id):
                
        return self.get_data("abstract-tree-hierarchy", columns = ["name"], conditions = f"workspace_id = {self.workspace_id} AND project_id=\"{project_id}\" AND name != \"Unknown\" AND name != \"Uknown\"")
   
    def choose_member(self, type_of_member = None, full_name = False):
      

      
        # TODO figure out why self.email is list sometimes
        if self.email != "None" and self.email != None:

            choice = self.choice_prompt(f"Do you want to use {self.email} set on the session? [y/n]")

            if choice.lower() == "y":
                return self.email
        
        # If email is not supplied and not set in config, list serivce accoutns ]

        choice = self.choice_selector(["Existing SA/User","New Member"],f"Do you want to use an enumerated SA/User or enter a new email?")
        if choice == "Existing SA/User":
            
            if type_of_member == "service_accounts":
                rows_returned = self.get_data("iam-principals", columns = ["name", "email","type"], conditions = "type = \"service_account\"")
            
            else:
                rows_returned = self.get_data("iam-principals", columns = ["name", "email","type"])

        
            if len(rows_returned) == 0:
                print("[X] No service accounts/users have been enumerated. Consdier running 'enum_iam_users_service' or rerun the module specifying the \"--member\" flag")
                return None
            
            for entity in rows_returned:
                type_of_entity = entity["type"]
                email_of_entity = entity["email"]
                name = entity["name"]

                if type_of_entity == "user":
                    entity["printout"] = f"({type_of_entity}) - {email_of_entity}"
                elif type_of_entity == "service_account":
                    project_id = name.split("/")[1]
                    entity["printout"] = f"({type_of_entity}) - {project_id} - {email_of_entity}"
            
            sorted_data = sorted(rows_returned, key=lambda x: x["printout"])

            service_account_dict = self.choice_selector(sorted_data,"Choose an existing role from below. Type New if you want to manually specify the name:", fields=["printout"])
            
            if service_account_dict:
                account_name = service_account_dict["name"]
                if full_name:
                    return account_name
                if account_name:
                    account_type = account_name.split("/")[2]
                else:
                    account_type = "user"

                if account_type == "serviceAccounts":
                    member = "serviceAccount:"+service_account_dict["email"]
                
                elif account_type == "user":
                    member = "user:"+service_account_dict["email"]
            else:
                return None

            return member

        elif choice == "New Member":
                choice = self.choice_prompt("Provide the member account email below in the format user:<email> or serviceAccount:<email>: ", regex = r'(\w+):([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
            
                return choice

        print("[X] No members found. Consider running rerunning the module specifying the \"--member\" flag")   
        return None

    def choose_role(self, suggested_roles, chosen_role = None, default_role = None):
        
        if chosen_role:
            return chosen_role

        suggested_roles.append("Different Role")
        
        role_choice = self.choice_selector(suggested_roles,f"A list of roles are supplied below. Choose one or enter your own:")
        
        if not role_choice:
            return None

        if role_choice == "Different Role":
            return self.choice_prompt("Provide the role name to attach in the format roles/role_name: ")

        if role_choice:
            
            if "(Default)" in role_choice:
            
                return role_choice.split()[0] 
                
            else:
                return role_choice
        
        else:

            return default_role

    def sync_users(self):

        # Get unique member list from iam-bindings
        bindings = self.get_bindings()
        all_unique_global_members = set(
            binding['member'].replace("user:","") for binding in bindings
            if binding['member'].startswith("user:")
        )
        
        get_current_members = self.get_data("iam-principals", ["email"], conditions = "type = \"user\"")
        all_unique_current_members = set(
            binding['email'] for binding in get_current_members            
        )

        difference_members = list(all_unique_global_members - all_unique_current_members)

        for member in difference_members:
            save_data = {
                "type": "user",
                "email":member.replace("user:","")
            }
            self.insert_data("iam-principals",save_data)