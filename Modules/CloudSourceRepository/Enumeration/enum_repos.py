# Coming Soon
# # https://source.cloud.google.com/onboarding/welcome - Cloud Source Repository
# import json
# from google.api_core.exceptions import PermissionDenied
# from google.api_core.exceptions import NotFound
# from google.api_core.exceptions import Forbidden
# import argparse
# from google.protobuf.json_format import MessageToDict
# import importlib

# from googleapiclient.discovery import build


# # There appears to be no python client for this
# # https://github.com/googleapis/google-api-python-client

# def print_repos(repo_list):
#     for repo in repo_list:
#         print(f"[**] {repo}")


# def run_module(user_args, session,last_project=False, from_another_module=False):
#     # Set up static variables
#     workspace_id = session.workspace_id
#     project_id = session.project_id

#     table_name = 'cloudsourcerepositories-repositories'

#     # Set up Argparser to handle flag arguments
#     parser = argparse.ArgumentParser(description="Test Module")
#     parser.add_argument("--download", action="store_false", help="Attempt to download all items enumerated")
#     args = parser.parse_args(user_args)

#     # Run user specified project if provided
#     save_data = {"project_id":project_id,"workspace_id":workspace_id}

#     api_endpoint = f"https://sourcerepo.googleapis.com/v1/projects/{project_id}/repos"

#     print(f"[*] Checking {project_id} for repositories...")

#     # Get repos, permission erorr will happen later on enumeration
#     repo_names = []

#     try:
#         service = build('sourcerepo', 'v1', credentials=session.credentials)
#         repositories = service.projects().repos().list(name=f'projects/{project_id}').execute()

#         for repo in repositories.get('repos', []):
#             repo_names.append(repo["name"])
#             save_data["name"]=repo["name"]
#             save_data["url"]=repo["url"]
#             session.data_master.update_row(table_name, save_data)

#     except Exception as e:
#         if "does not have storage.buckets.list access to the Google Cloud project" in str(e):
#             print(f"[-] The user does not have storage.buckets.list permissions on project {project_id}")
#         print(str(e))
#     # Call any remaining linked modules if applicable

#     if len(repo_names) > 0:
#         print("[SUMMARY] The following functions were identified: ")
#         print_repos(repo_names)

#     try:
#         for repo_name in repo_names:
#             # Just need name not full path
#             repo_name = repo_name.split("/")[-1]
#             user_args = ["--repo-name",repo_name]
#             #target_api = "storage.client.get"
#             module = importlib.import_module("Modules.CloudSourceRepository.Exfiltrate.download_repos")
#             module.run_module(user_args,session, last_project=last_project, from_another_module=False)

#     except PermissionError as e:
#         print(e)
#     except PermissionDenied as e:
#         print(f"The user is not allowed to get the specific bucket: {bucket.name}")
#     except Forbidden as e:
#         print(f"The user is not allowed to call the {target_api}")

