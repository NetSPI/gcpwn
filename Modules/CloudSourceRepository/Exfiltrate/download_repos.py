# COMING SOON
# # https://source.cloud.google.com/onboarding/welcome - Cloud Source Repository
# import json, os
# from google.api_core.exceptions import PermissionDenied
# from google.api_core.exceptions import NotFound
# from google.api_core.exceptions import Forbidden
# import argparse
# from google.protobuf.json_format import MessageToDict
# import importlib

# from googleapiclient.discovery import build


# # There appears to be no python client for this
# # https://github.com/googleapis/google-api-python-client

# def repo_functions(repo_list):
#     for repo in repo_list:
#         print(f"[**] {repo}")


# def run_module(user_args, session,last_project=False, from_another_module=False):
#     # Set up static variables
#     print("IN DOWNLOAD")
#     workspace_id = session.workspace_id
#     project_id = session.project_id


#     # Set up Argparser to handle flag arguments
#     parser = argparse.ArgumentParser(description="Test Module")
#     parser.add_argument("--repo-name", required=True, help="Attempt to download all items enumerated")
#     args = parser.parse_args(user_args)

#     # Run user specified project if provided
#     #save_data = {"project_id":project_id,"workspace_id":workspace_id}

#     gcloud_command = f"gcloud source repos clone {args.repo_name} --project={project_id}"
#     directory_to_store = f"StoredContent/GoogleSourceRepository/{session.project_id}_{args.repo_name}/"

#     print(f"[*] Checking {project_id} for repositories...")

#     # Get repos, permission erorr will happen later on enumeration
#     repo_names = []
#     print("STARTING DOWNLOAD")
#     try:
#         os.makedirs(directory_to_store, exist_ok=True)
        
#         command_1 = f"cd {directory_to_store}"
#         command_2 = gcloud_command
#         overall_command = command_1 + " && " + command_2

#         # TODO change to subprocess later ot read error codes
#         os.system(overall_command)

#     except Exception as e:
#         if "does not have storage.buckets.list access to the Google Cloud project" in str(e):
#             print(f"[-] The user does not have storage.buckets.list permissions on project {project_id}")
#         print(str(e))
#     # Call any remaining linked modules if applicable

