from typing import List, Tuple, Optional
from workspace_instructions import workspace_instructions
from DataController import DataController
from UtilityController import *
import sys

# Create new workspace given name
def create_workspace(workspace_name: str) -> Optional[int]:

    if workspace_name in DataController.fetch_all_workspace_names():
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] A workspace with the same name already exists.{UtilityTools.RESET}")
        return None
    
    DataController.insert_workspace(workspace_name)
    print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Workspace '{workspace_name}' created.{UtilityTools.RESET}")
    return 1

# List all workspaces
def list_workspaces(workspace_names: List[Tuple[int, str]]) -> None:

    print("[*] Found existing sessions:")
    print("  [0] New session")
    for idx, name in workspace_names:
        print(f"  [{idx}] {name}")
    print(f"  [{len(workspace_names)+1}] exit")

def create_workspace_flow(workspace_index: int) -> None:

    while True:
  
        workspace_name = input("> New workspace name: ").strip()

        if 0 < len(workspace_name) < 100:
            status = create_workspace(workspace_name)

            if status:
                break
        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] You need a workspace name of minimum 1 length or maximum 100 length. Please try again...{UtilityTools.RESET}")

    workspace_instructions(workspace_index, workspace_name)

def existing_workspaces_initiate(workspace_names: List[Tuple[int, str]]) -> None:

    list_workspaces(workspace_names)

    while True:
        try:
            option = int(input("Choose an option: ").strip())
            break  # Exit the loop if input is successfully converted to an integer
        
        except ValueError:
            print("Please enter a valid number.")
        
    # If user chooses to create new workspace start create new workspace flow. ID of workspace is
    # length plus 1. For example adding a second workspace means workspace 1 exists with ID 1, so the 
    # new workspace would be of ID 2
    if option == 0:

        create_workspace_flow(len(workspace_names)+1)

    elif option == len(workspace_names)+1:
        exit()

    else:
        workspace_name = DataController.workspace_exists(option)
        if workspace_name:
            workspace_instructions(option, workspace_name)
        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] No workspace was found with this option. Quitting...{UtilityTools.RESET}")
            exit()

def main()-> None:

    workspace_names = DataController.get_workspaces()
    
    # If the databases have not been created or no workspaces exist, give the default first time message
    if len(workspace_names) == 0:
        
        workspace_index = 1

        print("[*] No workspaces were detected. Please provide the name for your first workspace below.")

        DataController.create_initial_workspace_session_database()

        create_workspace_flow(workspace_index)
        
    # Workspaces exist, give option to choose an existing one
    else:
        
        existing_workspaces_initiate(workspace_names) 

if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
