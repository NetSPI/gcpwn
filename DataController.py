from google.cloud import resourcemanager_v3

from WorkspaceConfig import WorkspaceConfig


import yaml, sqlite3, os, json
import traceback
import ast
from typing import List, Union, Dict, Optional

class DataController:
    
    workspace_database = "databases/workspaces.db"
    session_database = "databases/sessions.db"
    service_database = "databases/service_info.db"

    session_conn, session_cursor = None, None
    workspace_conn, workspace_cursor = None, None
    service_conn, service_cursor = None,None

    def __init__(self):
        
        self.session_conn = sqlite3.connect(self.session_database)
        self.session_conn.row_factory = sqlite3.Row
        self.session_cursor = self.session_conn.cursor()

        self.workspace_conn = sqlite3.connect(self.workspace_database)
        self.workspace_cursor = self.workspace_conn.cursor()

    ### Initial Setup: Create Databases + Insert/Fetch Workspace
    @staticmethod
    def read_resource_file():
        file_path = "./utils/resource_perm_mappings.txt"
        resources = {}
        with open(file_path, 'r') as file:
            for line in file:
                resource_name, column_name = line.strip().split(',')
                resources[resource_name] = column_name
        return resources

    def get_workspace_name(self, workspace_id):

        try:        
            query = f"SELECT name FROM workspaces WHERE id = \"{workspace_id}\""
            
            self.workspace_cursor.execute(query)
            self.workspace_conn.commit()
            
            
            session_cursor.execute('''CREATE TABLE IF NOT EXISTS session 
                (workspace_id INTEGER, credname TEXT,credtype TEXT, email TEXT, default_project TEXT, scopes TEXT,  session_creds TEXT, PRIMARY KEY (workspace_id,credname))''')
            session_conn.commit()

            resources = DataController.read_resource_file()
            columns = ", ".join([f"{column_name} TEXT" for column_name in resources.values()])

            session_cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS session_actions 
                (
                    workspace_id INTEGER, credname TEXT,
                    {columns},
                    PRIMARY KEY (workspace_id, credname)
                )
            ''')
            session_conn.commit()
            session_conn.close()

            return 1

        except Exception as e:
            print("[X] Failed in create_initial_workspace_session_database for following error")
            print(str(e))
            return None

    def get_workspace_config(self, workspace_id):
        try:        
            query = f"SELECT workspace_config FROM workspaces WHERE id = \"{workspace_id}\""
            
            self.workspace_cursor.execute(query)
            result = self.workspace_cursor.fetchone()
            
            if result is not None:
                return result[0]
            else:
                print(f"[X] No workspace configuration found for workspace_id {workspace_id}")
                return None

        except Exception as e:
            print("[X] Failed in get_workspace_configs for following error")
            print(str(e))
            return None

    def set_workspace_config(self, workspace_id, new_settings):
        try:        
            # Prepare the update query to overwrite the existing configuration
            update_query = f"""
            UPDATE workspaces
            SET workspace_config = ?
            WHERE id = ?
            """
            
            # Execute the update query with the new settings
            self.workspace_cursor.execute(update_query, (new_settings, workspace_id))
            self.workspace_conn.commit()
            
            print(f"[*] Successfully updated workspace configuration for workspace_id {workspace_id}")
            return True

        except Exception as e:
            print("[X] Failed in set_workspace_config for the following error")
            print(str(e))
            return False

    @staticmethod        
    def create_initial_workspace_session_database() -> Union[int, None]:

        try:        

            if not os.path.exists("./databases"):
                os.makedirs("./databases")

            workspace_conn = sqlite3.connect(DataController.workspace_database)
            workspace_cursor = workspace_conn.cursor()
            workspace_cursor.execute('''CREATE TABLE IF NOT EXISTS workspaces
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, global_project_list TEXT, data TEXT, workspace_config TEXT)''')
            workspace_conn.commit()
            workspace_conn.close()

            session_conn = sqlite3.connect(DataController.session_database)
            session_cursor = session_conn.cursor()
            # Made decision to remove all_projects. Makes more sense to have 1 workspace per 1 organization so keep project list global per workspace or else we need to regenerate it for each new session creds
            session_cursor.execute('''CREATE TABLE IF NOT EXISTS session 
                (workspace_id INTEGER, credname TEXT,credtype TEXT, email TEXT, default_project TEXT, scopes TEXT,  session_creds TEXT, PRIMARY KEY (workspace_id,credname))''')
            session_conn.commit()

            resources = DataController.read_resource_file()
            columns = ", ".join([f"{column_name} TEXT" for column_name in resources.values()])

            session_cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS session_actions 
                (
                    workspace_id INTEGER, credname TEXT,
                    {columns},
                    PRIMARY KEY (workspace_id, credname)
                )
            ''')
            session_conn.commit()
            session_conn.close()

            return 1

        except Exception as e:
            print("[X] Failed in create_initial_workspace_session_database for following error")
            print(str(e))
            return None


    # Create a generic table given metadata info in corresponding YAML setup file
    def create_table_generic(self, table_name, columns, primary_key_columns) -> Union[int, None]:
        
        try:
            
            columns_definition = ", ".join([f'"{col}" TEXT NULL' for col in columns])
            primary_keys_definition = ", ".join([f'"{key}"' for key in primary_key_columns])
            query = f"""
            CREATE TABLE IF NOT EXISTS "{table_name}" (
                {columns_definition},
                PRIMARY KEY ({primary_keys_definition})
            );
            """
            self.service_cursor.execute(query)
            self.service_conn.commit()

            return 1

        except Exception as e:
            print("[X] Failed in create_table_generic for following error")
            print(str(e))
            return None


    # Create individual service databases if they don't exist. If they do exit return connections
    def create_service_databases(self) -> Union[int, None]:

        try:

            yaml_file_path = "./utils/database_info.yaml"  # Fixed path
            with open(yaml_file_path, "r") as file:
                data = yaml.load(file, Loader=yaml.FullLoader)
        
            all_service_tables = []
            for database_info in data["databases"]:
                
                # Create database object, add workplace ID if too big maybe?
                database_name = "databases/"+database_info["database_name"]+".db"
                self.service_conn = sqlite3.connect(database_name)
                self.service_cursor = self.service_conn.cursor()
                
                for table in database_info["tables"]:
                    table_name = table["table_name"]

                    all_service_tables.append(table_name)
                    # Add workspace ID to all created tables here to columns & primary keys
                    columns = table["columns"] + ["workspace_id"]
                    primary_keys = table["primary_keys"] + ["workspace_id"]

                    self.create_table_generic(table_name, columns, primary_keys)

            return 1

        except Exception as e:
            print("[X] Failed in create_service_databases for following error")
            print(str(e))
            return None
    
    @staticmethod
    def insert_workspace(name: str) -> Union[int, None]:
        try:
            
            workspace_config = WorkspaceConfig()
            workspace_config_serialized = workspace_config.to_json_string()

            with sqlite3.connect(DataController.workspace_database) as workspace_conn:
                cursor = workspace_conn.cursor()
                cursor.execute("INSERT INTO workspaces (name, workspace_config) VALUES (?, ?)", (name,workspace_config_serialized))
                workspace_conn.commit()

            return 1

        except sqlite3.Error as e:
            print("[X] Failed to insert workspace due to database error")
            print(str(e))

        except Exception as e:
            print("[X] Failed to insert workspace due to an unexpected error")
            print(str(e))
            
        return None

    @staticmethod  
    def fetch_all_workspace_names() -> Union[List, None]:
        
        try:
            workspace_conn = sqlite3.connect(DataController.workspace_database)
            cursor = workspace_conn.cursor()
            
            cursor.execute("SELECT * FROM workspaces")
            workspaces_tuple = cursor.fetchall()
            workspace_conn.close()

            workspaces = [workspace[1] for workspace in workspaces_tuple]
            
            return workspaces
        
        except Exception as e:

            print("[X] Failed in fetch_all_workspaces for following error")
            print(str(e))
            return None 
 
    @staticmethod
    def get_workspaces() -> List:
        
        if os.path.exists("databases/workspaces.db"):

            workspace_conn = sqlite3.connect(DataController.workspace_database)
            workspace_cursor = workspace_conn.cursor()
            workspace_cursor.execute("SELECT id, name FROM workspaces")
            result_list =  workspace_cursor.fetchall()
            workspace_conn.close()
            return result_list

        else:
            return []

    @staticmethod
    def workspace_exists(id: int) -> Union[str, None]:
        try:
            with sqlite3.connect(DataController.workspace_database) as workspace_conn:
                workspace_cursor = workspace_conn.cursor()
                workspace_cursor.execute("SELECT name FROM workspaces WHERE id = ?", (id,))
                result = workspace_cursor.fetchone()
            return result[0] if result else None
        except sqlite3.Error as e:
            print("[X] Failed to check workspace existence due to database error")
            print(str(e))
        except Exception as e:
            print("[X] Failed to check workspace existence due to an unexpected error")
            print(str(e))
        return None


    ### Fetch/Insert/List Credentials
    def fetch_cred(self,workspace_id: int, credname: str) -> Union[Dict, None]:

        try:

            self.session_cursor.execute("SELECT * FROM session WHERE workspace_id=? AND credname=?",(workspace_id, credname))
            output = self.session_cursor.fetchone()

            if output:
                output = dict(output)
            else:
                output = None

            return output

        except Exception as e:

            print("[X] Failed in fetch_cred for following error")
            print(str(e))
            return None 

    
    def insert_creds(self, workspace_id:int, credname:str, credtype:str, default_project:str, session_creds:str, email = None, scopes = None) -> Union[None, int]:

        try: 
            if default_project:
                self.insert_project_ids(workspace_id, [default_project])

            columns = [workspace_id, credname, credtype, default_project, session_creds]
            placeholders = "?,?,?,?,?"  # Placeholder for required columns

            if email:
                columns.append(email)
                placeholders += ",?"  # Add placeholder for email if it exists

            if scopes:
                columns.append(scopes)
                placeholders += ",?"  # Add placeholder for scopes if it exists

            # Generate the column names string
            column_names = ",".join(["workspace_id", "credname", "credtype", "default_project", "session_creds"])
            if email:
                column_names += ",email"
            if scopes:
                column_names += ",scopes"

            # Generate the SQL query
            query = f"INSERT OR REPLACE INTO session ({column_names}) VALUES ({placeholders})"
            #print(query)
            #print(columns)
            # Execute the query with columns and placeholder values
            self.session_cursor.execute(query, tuple(columns))
            self.session_conn.commit()

        except Exception as e:

            print("[X] Failed in insert_creds for following error")
            print(str(e))
            return None 

    # Update a session's email or default_project value. Or if user wants to replace creds do that as well
    def update_creds(self,workspace_id: int,credname: str, serialized_creds = None, email = None, project_id = None) -> Union[None, int]:
    
        try:
            # Prepare SQL update statement
            update_query = "UPDATE session SET"

            update_values = []

            if serialized_creds:
                update_query += " session_creds = ?,"
                update_values.append(serialized_creds)            

            if email:
                update_query += " email = ?,"
                update_values.append(email)

            if project_id:
                update_query += " default_project = ?,"
                update_values.append(project_id)
           
            update_query = update_query.rstrip(',') + " WHERE credname = ? AND workspace_id = ?;"
            update_values.extend([credname, workspace_id])
          
            try:
                self.session_cursor.execute(update_query, update_values)
                self.session_conn.commit()
                print(f"[*] Credentials {credname} updated successfully.")
                return 1

            except sqlite3.Error as e:
                print(f"Error updating credentials: {e}")
                return None

        except Exception as e:

            print("[X] Failed in update_creds for following error")
            print(str(e))
            return None 

    @staticmethod
    def list_creds(workspace_id: int) -> Union[List, None]:
        
        try:
        
            session_conn = sqlite3.connect(DataController.session_database)
            session_cursor = session_conn.cursor()
            session_cursor.execute("SELECT credname, credtype, email FROM session where workspace_id=?",(workspace_id,))
            output = session_cursor.fetchall()
            return output

        except Exception as e:

            print("[X] Failed in list_creds for following error")
            print(str(e))
            return None 

    ### Project Management Insert/Remove/Get

    def sync_session(self,workspace_id):

        self.session_cursor.execute("SELECT * FROM session WHERE workspace_id=?",(workspace_id,))
        output = self.session_conn.commit()

    def change_default_project_id(self,workspace_id: int,credname:str, project_id: str) -> Union[int, None]:

        # Update workspace global project list based off ID. Should only ever grow the list
        self.session_cursor.execute("UPDATE session SET default_project = ? WHERE workspace_id = ? AND credname = ?", (project_id, workspace_id, credname))
        self.session_conn.commit()

        return 1

    def insert_project_ids(self, workspace_id: int, project_ids: List[str]) -> Union[int, None]:

        try:

            # Get global project IDs
            self.workspace_cursor.execute("SELECT global_project_list FROM workspaces WHERE id = ?", (workspace_id,))
            current_global_projects = self.workspace_cursor.fetchone()[0]
   
            # Take projects if they exist or none and conver to set
     
            if current_global_projects:
                current_global_projects = set(ast.literal_eval(current_global_projects))

            else:
                current_global_projects = set([])

            # Add 2 to many new project IDs to set ensuring they are unique
            current_global_projects.update(project_ids)

            # Convert set to list and then to string for storage in database
            current_global_projects_string = str(list(current_global_projects))


            # Update workspace global project list based off ID. Should only ever grow the list
            self.workspace_cursor.execute("UPDATE workspaces SET global_project_list = ? WHERE id = ?", (current_global_projects_string, workspace_id))
            self.workspace_conn.commit()

            return 1

        except Exception as e:
            print("[X] Failed in insert_project_ids for following error")
            print(str(e))
            return False

    def remove_global_projects(self,workspace_id, default_project,credname):

        self.workspace_cursor.execute("UPDATE workspaces SET global_project_list = (?) WHERE workspace_id = ? AND credname = ?",(str(default_project),workspace_id,credname))
        self.workspace_conn.commit()

    def remove_project_ids(self,workspace_id: int, project_ids: List[str]) -> Union[int, None]:

        try:

            # Fetch the current global_project_list for the given workspace_id
            self.workspace_cursor.execute("SELECT global_project_list FROM workspaces WHERE id = ?", (workspace_id,))
            current_global_projects = self.workspace_cursor.fetchone()[0]
                        
            # If there are existing projects, convert them to a set
            if current_global_projects:
                current_global_projects = set(ast.literal_eval(current_global_projects))
            else:
                print("[X] No projects appear to exist for the given workspace. Returning...")
                return None
            
            # Remove the  project IDs from the set
            for project in project_ids:
                current_global_projects.remove(project)
        
            # Update the global_project_list for the workspace
            self.workspace_cursor.execute("UPDATE workspaces SET global_project_list = ? WHERE id = ?", (str(current_global_projects), workspace_id))
            self.workspace_conn.commit()

            return 1

        except Exception as e:
            print("[X] Failed in remove_project_ids for following error")
            print(str(e))
            return None

    def get_all_project_ids(self,workspace_id: int) -> Union[List, None]:
        try:
        
            # Fetch the global_project_list for the given workspace_id
            self.workspace_cursor.execute("SELECT global_project_list FROM workspaces WHERE id = ?", (workspace_id,))
            
            global_projects_string = self.workspace_cursor.fetchone()[0]

            # If there are no projects, return an empty list
            if not global_projects_string:
                return []

            current_global_projects = list(set(ast.literal_eval(global_projects_string)))

            return current_global_projects

        except Exception as e:
            print(f"[X] Failed in get_all_project_ids for following error")
            print(str(e))
            return None


    def get_session_columns(self, table_name: str,  conditions: str, columns="*") -> List:
        
        try:

            # Build the SQL query to select the specified columns from the table
            if columns == "*":
                column_names = "*"
            else:
                column_names = ", ".join(columns)
            sql_query = f"SELECT {column_names} FROM \"{table_name}\""
           
            if conditions:  
                sql_query += " WHERE " + conditions
            
            # Execute the SQL query
            self.session_cursor.execute(sql_query)

            # Fetch all the rows
            rows = self.session_cursor.fetchall()

            # Extract column names
            column_names = [description[0] for description in self.session_cursor.description]

            # Prepare the result
            result = []
            for row in rows:
                result.append(dict(zip(column_names, row)))

            return result

        except sqlite3.Error as e:
            print("SQLite error:", e)
            return []


    def get_columns(self, table_name: str,  conditions: str, columns="*") -> List:
        
        try:

            # Build the SQL query to select the specified columns from the table
            if columns == "*":
                column_names = "*"
            else:
                column_names = ", ".join(columns)
            sql_query = f"SELECT {column_names} FROM \"{table_name}\""
           
            if conditions:  
                sql_query += " WHERE " + conditions

            # Execute the SQL query
            self.service_cursor.execute(sql_query)

            # Fetch all the rows
            rows = self.service_cursor.fetchall()

            # Extract column names
            column_names = [description[0] for description in self.service_cursor.description]

            # Prepare the result
            result = []
            for row in rows:
                result.append(dict(zip(column_names, row)))

            return result

        except sqlite3.Error as e:
            print("SQLite error:", e)
            return []

    def get_existing_row(self, table_name, data_dict, check_columns):
        try:
       
            where_conditions = ' AND '.join([f"{col} = ?" for col in check_columns])
            query = f"SELECT * FROM \"{table_name}\" WHERE {where_conditions};"
            values = [data_dict[key] for key in check_columns]
       
            self.service_cursor.execute(query, values)
            rows = self.service_cursor.fetchall()

            if rows:
                columns = [column[0] for column in self.service_cursor.description]
                existing_rows = [dict(zip(columns, row)) for row in rows]
                return existing_rows
            else:
                return None

        except Exception as e:
            print(f"[X] Failed in get_existing_row for the following error:")
            print(str(e))
            return None

    # If nothing exists insert partial data, if part of primary keys are defined but not all
    # rewritie row with new data. Useful for initial save and later update
    def insert_if_not_exists(self, table_name, data_dict, check_columns):
        # Get the primary keys for the table
        primary_keys = self.get_primary_keys(table_name)
 

        filtered_data = {key: data_dict[key] for key in check_columns if key in data_dict}
        existing_row_list = self.get_existing_row(table_name, filtered_data, check_columns)
        if existing_row_list:
            existing_row = existing_row_list[0]
        else:
            existing_row = None

        # If no existing row found, simply insert
        if not existing_row:

            columns = ', '.join(data_dict.keys())
            placeholders = ', '.join(['?'] * len(data_dict))
            query = f"INSERT INTO \"{table_name}\" ({columns}) VALUES ({placeholders})"

            self.service_cursor.execute(query, list(data_dict.values()))
            self.service_conn.commit()
            return


        # # Check if any differences exist between the values in the existing row and the incoming data for the given key
        # if any(existing_row.get(col) != data_dict.get(col) for col in data_dict.keys()):
            
        #     # Differences found, replace the existing row with the new values
        #     update_values = ', '.join([f"{col} = ?" for col in data_dict.keys()])
        #     where_conditions = ' AND '.join([f"{col} = ?" for col in primary_keys])
        #     query = f"UPDATE \"{table_name}\" SET {update_values} WHERE {where_conditions}"
        #     values = list(data_dict.values()) + [existing_row[key] for key in primary_keys]
        #     self.service_cursor.execute(query, values)
        #     self.service_conn.commit()

    def get_primary_keys(self, table_name):
        # Retrieve primary key information from the database schema
        query = f"PRAGMA table_info(\"{table_name}\")"
        self.service_cursor.execute(query)
        columns = self.service_cursor.fetchall()
        primary_keys = [col[1] for col in columns if col[5]]
        return primary_keys

    # Given a dictionary with key being column name and value being data, store 
    # Common use case is serialize object like Function and store in database
    # Return: 1 All Good, -1 No Data Entered, None Error
    
    # Full Query: INSERT OR REPLACE INTO "cloudstorage-hmac-keys" (access_id, etag, id, path, project_id, service_account_email, state, time_created, updated, workspace_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    def insert_row(self, table_name: str, save_data: Dict, dont_change: List[str] = [], if_column_matches: List[str] = []) -> Union[None, int]:
        try:
          
            if dont_change:
                self.service_cursor.execute(f"PRAGMA table_info('{table_name}')")
                table_info = self.service_cursor.fetchall()

                # Extract the primary key column names
                primary_key_columns = [row[1] for row in table_info if row[5] > 0]               
                # Check if the row exists using the primary key column(s)
                where_conditions = " AND ".join([f"{col} = ?" for col in primary_key_columns])
                exist_query = f"SELECT * FROM \"{table_name}\" WHERE {where_conditions}"
                existing_row = self.service_cursor.execute(exist_query, tuple(save_data[col] for col in primary_key_columns)).fetchone()

                if existing_row:
                    # If the row exists, update the values excluding columns in dont_change
                    columns_to_update = {col: save_data[col] for col in save_data.keys() if col not in dont_change}
                    set_clause = ", ".join([f"{col} = ?" for col in columns_to_update.keys()])
                    set_values = list(columns_to_update.values()) + [save_data[col] for col in primary_key_columns]
                    update_query = f"UPDATE \"{table_name}\" SET {set_clause} WHERE {where_conditions}"
                    #print(update_query)
                    self.service_cursor.execute(update_query, set_values)
                else:
                    
                    # If the row doesn't exist, insert it
                    columns = [col for col in save_data.keys() if col not in dont_change]
                    placeholders = ", ".join(["?" for _ in columns])
                    insert_query = f"INSERT INTO \"{table_name}\" ({', '.join(columns)}) VALUES ({placeholders})"
                    #print(insert_query)
                    self.service_cursor.execute(insert_query, [save_data[col] for col in columns])

            elif if_column_matches:

                where_conditions = " AND ".join([f"{col} = ?" for col in if_column_matches])
                exist_query = f"SELECT * FROM \"{table_name}\" WHERE {where_conditions}"
                existing_row = self.service_cursor.execute(exist_query, tuple(save_data[col] for col in if_column_matches)).fetchone()
                if existing_row:
                    # Delete the existing row
                    delete_query = f"DELETE FROM \"{table_name}\" WHERE {where_conditions}"
                    self.service_cursor.execute(delete_query, tuple(save_data[col] for col in if_column_matches))
                
                # Insert the new data
                columns = ", ".join(save_data.keys())
                placeholders = ", ".join(["?" for _ in save_data])
                insert_query = f"INSERT INTO \"{table_name}\" ({columns}) VALUES ({placeholders})"
                self.service_cursor.execute(insert_query, list(save_data.values()))

            else:
                # If dont_change is not set, perform the INSERT OR REPLACE statement
                columns = ", ".join(save_data.keys())
                placeholders = ", ".join(["?" for _ in save_data])
                query = f"INSERT OR REPLACE INTO \"{table_name}\" ({columns}) VALUES ({placeholders})"
              
                self.service_cursor.execute(query, list(save_data.values()))

            self.service_conn.commit()
            return 1
        except Exception as e:
            print(f"[X] Failed in insert_row for the following error:")
            print(str(e))
            return None

    # Update value in table
    def update_row(self, table_name: str, update_data: Dict):
        try:
            # Extract primary keys and data to insert from update_data
            primary_keys = update_data["primary_keys_to_match"]
            data_to_insert = update_data["data_to_insert"]

            # Construct the SET clause for the UPDATE statement
            set_values = [f"{column} = ?" for column in data_to_insert.keys()]
            set_clause = ", ".join(set_values)

            # Construct the WHERE clause using primary key columns
            where_conditions = " AND ".join([f"{key} = ?" for key in primary_keys])

            # Construct the SQL query
            query = f"UPDATE \"{table_name}\" SET {set_clause} WHERE {where_conditions};"
            # Concatenate values for SET and WHERE clauses
            values = list(data_to_insert.values()) + list(update_data["primary_keys_to_match"].values())
            # Execute the query
            self.service_cursor.execute(query, values)
            self.service_conn.commit()

        except Exception as e:
            print(f"[X] Failed to update row with the following error:")
            print(str(e))
            return None

    ### Recursive Query to Get ALL Parents given a node name
    def get_immediate_parent_node(self, node_id: str) -> str:
        table_name = "resourcemanager-metadata"

        query = f"""
            WITH RECURSIVE node_hierarchy AS (
                SELECT name, type, parent
                FROM \"abstract-tree-hierarchy\"
                WHERE name = ?
                UNION ALL
                SELECT rm.name, rm.type, rm.parent
                FROM \"abstract-tree-hierarchy\" rm
                JOIN node_hierarchy nh ON rm.name = nh.parent
                WHERE nh.parent IS NULL  -- Stop recursion once the immediate parent is found
            )
            SELECT name, type, parent
            FROM node_hierarchy
            ORDER BY name;
        """

        self.service_cursor.execute(query, (node_id,))
        hierarchy = self.service_cursor.fetchall()
 
        return hierarchy


    def update_session_row(self, save_data):
        # Assuming "credname" and "workspace_id" are the primary keys
        table_name = "session"
        primary_keys = ["credname", "workspace_id"]

        # Check if all primary keys exist in the save_data dictionary
        if not all(key in save_data for key in primary_keys):
            missing_keys = [key for key in primary_keys if key not in save_data]
            print(f"Primary key(s) {missing_keys} not found in the save_data dictionary.")
            return

        # Extract the update values excluding the primary keys
        update_values = {k: str(v) for k, v in save_data.items() if k not in primary_keys}

        # Construct the UPDATE query
        query = f"UPDATE \"{table_name}\" SET "
        set_values = [f"{column} = ?" for column in update_values.keys()]
        query += ", ".join(set_values)
        query += " WHERE " + " AND ".join([f"{key} = ?" for key in primary_keys]) + ";"


        # Extract the primary key values
        primary_key_values = [save_data[key] for key in primary_keys]

        # Extract the update values in the same order as the placeholders in the query
        values = list(update_values.values())
        
        # Extend the values list with the primary key values
        values.extend(primary_key_values)

      
        # Execute the UPDATE query
        self.session_cursor.execute(query, values)
        self.session_conn.commit()


    def find_ancestors(self, asset_name,  workspace_id):
 
        ancestors = []

        # Recursive Common Table Expression (CTE) to find ancestors
        self.service_cursor.execute('''
        WITH RECURSIVE Ancestors AS (
            SELECT name, parent, type, workspace_id
            FROM \"abstract-tree-hierarchy\"
            WHERE name = ? AND workspace_id = ?
        
            UNION ALL
        
            SELECT t.name, t.parent, t.type, t.workspace_id
            FROM \"abstract-tree-hierarchy\" t
            JOIN Ancestors a ON t.name = a.parent
            WHERE t.workspace_id = ?
        )
        SELECT type, name FROM Ancestors
        WHERE parent != 'N/A' AND name != ?
    ''', (asset_name, workspace_id, workspace_id, asset_name))
        
        # Fetch all rows from the result set
        rows = self.service_cursor.fetchall()

        # Extract parent names
        for row in rows:
            ancestors.append((row[0], row[1]))
       
        return ancestors

    def convert_sets_to_lists(self,data):
        if isinstance(data, dict):
            for key, value in data.items():
                data[key] = self.convert_sets_to_lists(value)
            return data
        elif isinstance(data, set):
            return list(data)
        else:
            return data

    def insert_actions(self, workspace_id, credname, permission_record, project_id=None, column_name=None):
        row_exists = True

        try:
            # Initialize permissions variables
            organization_permissions = permission_record.get('organization_permissions', {})
            folder_permissions = permission_record.get('folder_permissions', {})
            project_permissions = permission_record.get('project_permissions', {})
            resource_permissions = {k: v for k, v in permission_record.items() if k not in ['organization_permissions', 'folder_permissions', 'project_permissions']}

            # Build the query based on whether column_name is None
            if column_name:
                query = f"SELECT \"{column_name}\", \"organization_actions_allowed\", \"folder_actions_allowed\", \"project_actions_allowed\" FROM \"session_actions\" WHERE workspace_id = ? AND credname = ?"
            else:
                query = "SELECT \"organization_actions_allowed\", \"folder_actions_allowed\", \"project_actions_allowed\" FROM \"session_actions\" WHERE workspace_id = ? AND credname = ?"
            
            self.session_cursor.execute(query, (workspace_id, credname))
            existing_row = self.session_cursor.fetchone()

            # Initialize current permissions
            current_resource_permissions = {}
            current_organization_permissions = {}
            current_folder_permissions = {}
            current_project_permissions = {}
          
            if existing_row:
                if column_name and existing_row[0] is not None:
                    current_resource_permissions = json.loads(existing_row[0].strip()) if existing_row[0].strip() else {}
                if existing_row[-3] is not None:
                    current_organization_permissions = json.loads(existing_row[-3].strip()) if existing_row[-3].strip() else {}
                if existing_row[-2] is not None:
                    current_folder_permissions = json.loads(existing_row[-2].strip()) if existing_row[-2].strip() else {}
                if existing_row[-1] is not None:
                    current_project_permissions = json.loads(existing_row[-1].strip()) if existing_row[-1].strip() else {}



            # Update permissions
            def update_permissions(current_permissions, new_permissions):
                changed = False
                for name, permissions in new_permissions.items():
                    if name in current_permissions:
                        for permission in permissions:
                            if permission not in current_permissions[name]:
                                current_permissions[name].append(permission)
                                changed = True
                    else:
                        current_permissions[name] = list(permissions)
                        changed = True
                return changed

            org_changed = update_permissions(current_organization_permissions, organization_permissions)
            folder_changed = update_permissions(current_folder_permissions, folder_permissions)
            project_changed = update_permissions(current_project_permissions, project_permissions)

            resource_changed = False
            if column_name:
                for project_name, permissions in resource_permissions.items():
                    if project_name not in current_resource_permissions:
                        current_resource_permissions[project_name] = self.convert_sets_to_lists(permissions)
                        resource_changed = True
                    else:
                        for permission_name, permission_details in permissions.items():
                            if permission_name not in current_resource_permissions[project_name]:
                                current_resource_permissions[project_name][permission_name] = self.convert_sets_to_lists(permission_details)
                                resource_changed = True
                            else:
                                for asset_type, asset_names in permission_details.items():
                                    if asset_type not in current_resource_permissions[project_name][permission_name]:
                                        current_resource_permissions[project_name][permission_name][asset_type] = list(asset_names)
                                        resource_changed = True
                                    else:
                                        for name in asset_names:
                                            if name not in current_resource_permissions[project_name][permission_name][asset_type]:
                                                current_resource_permissions[project_name][permission_name][asset_type].append(name)
                                                resource_changed = True

            # If no new data was added, return True
            if not (resource_changed or project_changed or folder_changed or org_changed):
                return True

            # Create row if it doesn't exist
            if not existing_row:
                self.session_cursor.execute("INSERT OR REPLACE INTO session_actions (workspace_id, credname) VALUES (?, ?)", (workspace_id, credname))
                self.session_conn.commit()

            # Update the database with the new permissions
            def update_database(column, data):
                json_str = json.dumps(data)
                self.session_cursor.execute(f"UPDATE session_actions SET \"{column}\" = ? WHERE workspace_id = ? AND credname = ?", (json_str, workspace_id, credname))
                self.session_conn.commit()

            if resource_changed:
                update_database(column_name, current_resource_permissions)
            if project_changed:
                update_database("project_actions_allowed", current_project_permissions)
            if folder_changed:
                update_database("folder_actions_allowed", current_folder_permissions)
            if org_changed:
                update_database("organization_actions_allowed", current_organization_permissions)

            return True

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return False

    def get_actions(self, workspace_id, credname=None):
        try:
            resources = DataController.read_resource_file()
            action_columns = list(resources.values())
            all_columns = ",".join(action_columns)

            # Fetch data from the specified columns
            query = f'SELECT credname, {all_columns} FROM session_actions WHERE workspace_id="{workspace_id}"'
            if credname:
                query += f' AND credname="{credname}"'
            self.session_cursor.execute(query)

            # Initialize a list to store the extracted data for each credname
            permissions_list = []

            # Iterate over the fetched rows
            for row in self.session_cursor.fetchall():
                credname_row = row[0]
                permissions_dict = {"credname": credname_row}

                for resource_name, json_str in zip(resources.keys(), row[1:]):
                    # Parse JSON strings or initialize as empty dictionaries if no data
                    data = json.loads(json_str) if json_str else {}
                    permissions_dict[resources[resource_name]] = data

                permissions_list.append(permissions_dict)

            return permissions_list
        except Exception as e:
            print("Error:", e)
            return []