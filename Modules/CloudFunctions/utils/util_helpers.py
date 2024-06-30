import argparse
import importlib
import re
import json
import requests
import textwrap
import ast

from Modules.IAM.utils.util_helpers import cloudfunction_get_iam_policy,cloudfunction_set_iam_policy

# Typing libraries
from typing import List, Union, Dict, Optional, Tuple
from session import SessionUtility
from google.cloud.storage.client import Client
from google.cloud.functions_v1 import CloudFunction
from google.cloud.functions_v2 import Function
from google.cloud.functions_v2 import FunctionServiceClient
from  google.iam.v1.policy_pb2 import Policy
from google.api_core.iam import Policy

# Main GCP Libraries
from google.cloud import functions_v1
from google.cloud import functions_v2
from google.iam.v1 import iam_policy_pb2 

# Error Codes
from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import InvalidArgument

# Utilities
from UtilityController import *

# Get v1 and/or v2, list of regions, file of regions, or default to session config. Only called if user wants to 
# specify region, otherwise GCP function will be used that just grabes it across all regions anyways
def get_all_function_regions(
        session: SessionUtility, 
        project_id: str, 
        v1_regions: Optional[bool] = False, 
        v2_regions: Optional[bool] = False, 
        v1v2_regions: Optional[bool] = False, 
        regions_list: Optional[List[str]] = None, 
        regions_file: Optional[str] = None
    ) -> List:

    if v1_regions:

        regions = [line.strip() for line in open('Modules/CloudFunctions/utils/regions_v1.txt')]

    elif v2_regions:

        regions = [line.strip() for line in open('Modules/CloudFunctions/utils/regions_v2.txt')]

    elif v1v2_regions:

        v1_regions = [line.strip() for line in open('Modules/CloudFunctions/utils/regions_v1.txt')]
        v2_regions = [line.strip() for line in open('Modules/CloudFunctions/utils/regions_v2.txt')]
        regions_set = set(v1_regions)
        regions_set.update(v2_regions)
        regions = list(regions_set)
        
    elif regions_list:
        
        regions = regions_list.split(",")
       
    elif regions_file:
        regions = [line.strip() for line in open(regions_file)]        
    
    elif session.config_regions_list:
        regions = session.config_regions_list

    return regions

# Utility for regex checking
def check_function_format(input_string: str):
    pattern = r'^projects/[^/]+/locations/[^/]+/functions/[^/]+$'
    if re.match(pattern, input_string):
        return 1
    else:
        print("[X] Input string does not follow the correct format. It should be in the format: projects/{project_name}/locations/{region_name}/functions/{function_name}")
        return None

def check_sa_format(input_string: str):
    pattern = r'^projects/[^/]+/serviceAccounts/[^/]+$'
    if re.match(pattern, input_string):
        return 1
    else:
        print("[X] Input string does not follow the correct format. It should be in the format: projects/{project_id}/serviceAccounts/{serviceAccount}")
        return None

def check_bucket_source_format(input_string: str):
    pattern = r'^gs://[^/]+/.+$'
    if re.match(pattern, input_string):
        return 1
    else:
        print("[X] Input string does not follow the correct format. It should be in the format: gs://<bucket_name>/<filepath>/<filename>")
        return None

########### Save Operations for Objects

# Function  V1 are listed in v2 call so can save them in v2 template
def save_function(function: Union[CloudFunction, Function], session: SessionUtility) -> None:

    table_name = 'cloudfunctions-functions'

    project_id = function.name.split("/")[1]

    save_data = {"project_id":project_id}   

    # Base google.cloud.functions_v2.types.Function: https://cloud.google.com/python/docs/reference/cloudfunctions/latest/google.cloud.functions_v2.types.Function
    if function.name: save_data["name"] = function.name
    if function.description: save_data["description"] = function.description
    if function.state: save_data["state"] = function.state
    if function.update_time: save_data["update_time"] = function.update_time
    if function.labels: save_data["labels"] = function.labels
    if function.state_messages: save_data["state_messages"] = function.state_messages
    if function.environment: save_data["environment"] = function.environment
    if function.url: save_data["url"] = function.url
    if function.kms_key_name: save_data["kms_key_name"] = function.kms_key_name
    
    # Build config cause serializing in GCP is ridiculous
    build_config = {}
    if function.build_config.build: build_config["build"] = function.build_config.build
    if function.build_config.runtime: build_config["runtime"] = function.build_config.runtime
    if function.build_config.entry_point: build_config["entry_point"] = function.build_config.entry_point
    if function.build_config.worker_pool: build_config["worker_pool"] = function.build_config.worker_pool
    if function.build_config.environment_variables: build_config["environment_variables"] = function.build_config.environment_variables
    if function.build_config.docker_repository: build_config["docker_repository"] = function.build_config.docker_repository
    
    if function.build_config.source: build_config["source"] = {}
    
    if function.build_config.source.storage_source: build_config["source"]["storage_source"] = {}
    if function.build_config.source.storage_source.bucket: build_config["source"]["storage_source"]["bucket"] = function.build_config.source.storage_source.bucket 
    if function.build_config.source.storage_source.object_: build_config["source"]["storage_source"]["object_"] = function.build_config.source.storage_source.object_
    if function.build_config.source.storage_source.generation: build_config["source"]["storage_source"]["generation"] = function.build_config.source.storage_source.generation
    
    if function.build_config.source.repo_source: build_config["source"]["repo_source"] = {}
    if function.build_config.source.repo_source.branch_name: build_config["source"]["repo_source"]["branch_name"] = function.build_config.source.repo_source.branch_name 
    if function.build_config.source.repo_source.tag_name: build_config["source"]["repo_source"]["tag_name"] = function.build_config.source.repo_source.tag_name
    if function.build_config.source.repo_source.commit_sha: build_config["source"]["repo_source"]["commit_sha"] = function.build_config.source.repo_source.commit_sha
    if function.build_config.source.repo_source.project_id: build_config["source"]["repo_source"]["project_id"] = function.build_config.source.repo_source.project_id
    if function.build_config.source.repo_source.repo_name: build_config["source"]["repo_source"]["repo_name"] = function.build_config.source.repo_source.repo_name
    if function.build_config.source.repo_source.dir_: build_config["source"]["repo_source"]["dir_"] = function.build_config.source.repo_source.dir_
    if function.build_config.source.repo_source.invert_regex: build_config["source"]["repo_source"]["invert_regex"] = function.build_config.source.repo_source.invert_regex

    if function.build_config.source: build_config["source_provenance"] = {}
    
    if function.build_config.source_provenance.resolved_storage_source: build_config["source_provenance"]["resolved_storage_source"] = {}
    if function.build_config.source_provenance.resolved_storage_source.bucket: build_config["source_provenance"]["resolved_storage_source"]["bucket"] = function.build_config.source_provenance.resolved_storage_source.bucket 
    if function.build_config.source_provenance.resolved_storage_source.object_: build_config["source_provenance"]["resolved_storage_source"]["object_"] = function.build_config.source_provenance.resolved_storage_source.object_
    if function.build_config.source_provenance.resolved_storage_source.generation: build_config["source_provenance"]["resolved_storage_source"]["generation"] = function.build_config.source_provenance.resolved_storage_source.generation
    
    if function.build_config.source_provenance.resolved_repo_source: build_config["source_provenance"]["resolved_repo_source"] = {}
    if function.build_config.source_provenance.resolved_repo_source.branch_name: build_config["source_provenance"]["resolved_repo_source"]["branch_name"] = function.build_config.source_provenance.resolved_repo_source.branch_name 
    if function.build_config.source_provenance.resolved_repo_source.tag_name: build_config["source_provenance"]["resolved_repo_source"]["tag_name"] = function.build_config.source_provenance.resolved_repo_source.tag_name
    if function.build_config.source_provenance.resolved_repo_source.commit_sha: build_config["source_provenance"]["resolved_repo_source"]["commit_sha"] = function.build_config.source_provenance.resolved_repo_source.commit_sha
    if function.build_config.source_provenance.resolved_repo_source.project_id: build_config["source_provenance"]["resolved_repo_source"]["project_id"] = function.build_config.source_provenance.resolved_repo_source.project_id
    if function.build_config.source_provenance.resolved_repo_source.repo_name: build_config["source_provenance"]["resolved_repo_source"]["repo_name"] = function.build_config.source_provenance.resolved_repo_source.repo_name
    if function.build_config.source_provenance.resolved_repo_source.dir_: build_config["source_provenance"]["resolved_repo_source"]["dir_"] = function.build_config.source_provenance.resolved_repo_source.dir_
    if function.build_config.source_provenance.resolved_repo_source.invert_regex: build_config["source_provenance"]["resolved_repo_source"]["invert_regex"] = function.build_config.source_provenance.resolved_repo_source.invert_regex

    if function.build_config.docker_registry: build_config["docker_registry"] = function.build_config.docker_registry

    save_data["build_config"] = json.dumps(build_config)

    # Base google.cloud.functions_v2.types.ServiceConfig: https://cloud.google.com/python/docs/reference/cloudfunctions/latest/google.cloud.functions_v2.types.ServiceConfig

    service_config = {}

    if function.service_config.service: service_config["service"] = function.service_config.service
    if function.service_config.timeout_seconds: service_config["timeout_seconds"] = function.service_config.timeout_seconds
    if function.service_config.available_memory: service_config["available_memory"] = function.service_config.available_memory
    if function.service_config.available_cpu: service_config["available_cpu"] = function.service_config.available_cpu
    if function.service_config.environment_variables: service_config["environment_variables"] = dict(function.service_config.environment_variables)
    if function.service_config.max_instance_count: service_config["max_instance_count"] = function.service_config.max_instance_count
    if function.service_config.min_instance_count: service_config["min_instance_count"] = function.service_config.min_instance_count
    if function.service_config.vpc_connector: service_config["vpc_connector"] = function.service_config.vpc_connector
    if function.service_config.vpc_connector_egress_settings: service_config["vpc_connector_egress_settings"] = function.service_config.vpc_connector_egress_settings
    if function.service_config.ingress_settings: service_config["ingress_settings"] = function.service_config.ingress_settings
    if function.service_config.service_account_email: service_config["service_account_email"] = function.service_config.service_account_email
    if function.service_config.all_traffic_on_latest_revision: service_config["all_traffic_on_latest_revision"] = function.service_config.all_traffic_on_latest_revision
    if function.service_config.secret_environment_variables: service_config["secret_environment_variables"] = function.service_config.secret_environment_variables
    if function.service_config.secret_volumes: service_config["secret_volumes"] = function.service_config.secret_volumes
    if function.service_config.revision: service_config["revision"] = function.service_config.revision
    if function.service_config.max_instance_request_concurrency: service_config["max_instance_request_concurrency"] = function.service_config.max_instance_request_concurrency
    if function.service_config.security_level: service_config["security_level"] = function.service_config.security_level
    
    save_data["service_config"] = json.dumps(service_config)

    # google.cloud.functions_v2.types.EventTrigger: google.cloud.functions_v2.types.EventTrigger
    event_trigger = {}

    if function.event_trigger.trigger: event_trigger["trigger"] = function.event_trigger.trigger
    if function.event_trigger.trigger_region: event_trigger["trigger_region"] = function.event_trigger.trigger_region
    if function.event_trigger.event_type: event_trigger["event_type"] = function.event_trigger.event_type
    if function.event_trigger.event_filters: event_trigger["event_filters"] = function.event_trigger.event_filters
    if function.event_trigger.pubsub_topic: event_trigger["pubsub_topic"] = function.event_trigger.pubsub_topic
    if function.event_trigger.service_account_email: event_trigger["service_account_email"] = function.event_trigger.service_account_email
    if function.event_trigger.retry_policy: event_trigger["retry_policy"] = function.event_trigger.retry_policy
    if function.event_trigger.channel: event_trigger["channel"] = function.event_trigger.channel

    save_data["event_trigger"] = json.dumps(event_trigger)

    session.insert_data(table_name, save_data)

# Set IAM Policy
def add_function_iam_member(
        function_client: FunctionServiceClient, 
        function_name: str, member: str, 
        action_dict: Dict, 
        env_version: Union[None, int], 
        brute: Optional[bool] = False, 
        role:Optional[str] = None, 
        debug:Optional[bool]=False
    ) -> Union[Policy, None]:
    
    project_id = function_name.split("/")[1]
    policy_dict = {}
    additional_bind = {"role": role, "members": [member]}
   
    if brute:

        print(f"[*] Overwiting {function_name} to just be {member}")

        policy_dict["bindings"] = []
        policy_dict["bindings"].append(additional_bind)
        policy_dict["version"] = 1
        policy = policy_dict

    else:

        print(f"[*] Fetching current policy for {function_name}...")
        policy = cloudfunction_get_iam_policy(function_client, function_name, debug=debug)
        if policy:

            if policy == 404:

                print(f"{UtilityTools.RED}[X] Exiting the module as {function_name} does not exist. Double check the name.{UtilityTools.RESET}")
                return -1

            else:

                if env_version == 1:
                    action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.getIamPolicy", {}).setdefault("functions_v1", set()).add(function_name)
                else:
                    action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.getIamPolicy", {}).setdefault("functions_v2", set()).add(function_name)

                policy_dict["bindings"] = list(policy.bindings)
                policy_dict["bindings"].append(additional_bind)
                policy_dict["etag"] = policy.etag
                policy_dict["version"] = policy.version
                policy = policy_dict
                
        else:
            print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire bucket IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
            return -1

    if policy != None:
        policy_bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {function_name} \n{policy_bindings}")

    else:
        print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
        return -1

    status = cloudfunction_set_iam_policy(function_client, function_name, policy, debug=debug)
    if status:
        if status == 404:
            print(f"{UtilityTools.RED}[X] Exiting the module as {function_name} does not exist. Double check the name. Note the gs:// prefix is not included{UtilityTools.RESET}")
            return -1

        else:
            if env_version == 1:
                action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.setIamPolicy", {}).setdefault("functions_v1", set()).add(function_name)

            else:
                action_dict.setdefault(project_id, {}).setdefault("cloudfunctions.functions.setIamPolicy", {}).setdefault("functions_v2", set()).add(function_name)

    return status

def create_function(
        function_client: FunctionServiceClient, 
        function_name: str, 
        bucket_source: str, 
        version: str, 
        entry_point: str,
        sa: Optional[str] = None, 
        debug: Optional[bool] = None
    ) -> Union[CloudFunction, Function, None]:

    update_status = None
    function_parts = function_name.split("/")
    parent, project, region, function_id = "/".join(function_parts[:4]), function_parts[1], function_parts[3], function_parts[5]

    if version == "1":
        
        try:

            function = {
                "source_archive_url": bucket_source,
                "name": function_name,
                "entry_point": entry_point,
                "runtime": "python312",
                "https_trigger": {}
            }
         
            if sa: 
                function["service_account_email"] = sa
            

            request = functions_v1.CreateFunctionRequest(
                location=parent,
                function=function
            )

            operation = function_client.create_function(request=request)

            print("[*] Waiting for V1 creation operation to complete, this might take some time...")

            response = operation.result()

            update_status =  response


        except Forbidden as e:
            if "does not have cloudfunctions.functions.create" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have cloudfunctions.functions.create permissions for the v1 function{UtilityTools.RESET}")
            
            elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
                print(f"{UtilityTools.RED}[X] 403 The Cloud Functions API is not enabled for this project{UtilityTools.RESET}")    

        except Exception as e:
            print(f"The V1 cloudfunctions.functions.create operation failed for unexpected reasons. See below:")
            print(str(e))

    elif version == "2":

        try:

            bucket_name = bucket_source.split("/")[2]
            object_path = "/".join(bucket_source.split("/")[3::])

            
            build_config = {
                "entry_point": entry_point,
                "runtime":"python312",
                "source": {
                    "storage_source": {
                        'bucket':bucket_name,
                        'object_':object_path
                    }
                }
            }
            
            function = {

                    "name": function_name,
                    "build_config": build_config,
                    "environment":"GEN_2",
            }
            
            if sa:
                function["service_config"] = {
                    "service_account_email": sa
                }

            request = functions_v2.CreateFunctionRequest(
                parent=parent,
                function=function,
                function_id=function_id
            )
            

            operation = function_client.create_function(request=request)

            print("[*] Waiting for V2 creation operation to complete, this might take some time...")

            response = operation.result()
            
            update_status = response


        except Forbidden as e:
            if "does not have cloudfunctions.functions.create" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have cloudfunctions.functions.create permissions for the v2 function{UtilityTools.RESET}")
            
            elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
                print(f"{UtilityTools.RED}[X] 403 The Cloud Functions API is not enabled for this project{UtilityTools.RESET}")    

        except Exception as e:
            print(f"The V2 cloudfunctions.functions.create operation failed for unexpected reasons. See below:")
            print(str(e))

    print(f"[*] Successfully created {function_name}")

    return update_status

# Note add generate_upload_url option
def update_function(
    function_client: FunctionServiceClient, 
    function_name: str, 
    bucket_source: str, 
    version: str,  
    entry_point: str,
    sa: Optional[str] = None, 
    debug: Optional[bool]=None
    )-> Union[Policy, None]:

    if debug:
        print(f"[*] Updating function {function_name}")

    update_status = None
        
    if version == "1":
        
        try:

            function = {
                "source_archive_url": bucket_source,
                "name":function_name,
                "entry_point": entry_point
                
            }
            if sa: 
                function["service_account_email"] = sa



            request = functions_v1.UpdateFunctionRequest(
                update_mask="entryPoint,sourceArchiveUrl,serviceAccountEmail",
                function=function
            )

            # Make the request
            operation = function_client.update_function(request=request)

            print("[*] Waiting for update operation on V1 to complete, this might take awhile...")

            response = operation.result()
            update_status = response


        except Forbidden as e:
            if "does not have cloudfunctions.functions.update" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have cloudfunctions.functions.update permissions for the v1 function{UtilityTools.RESET}")

            elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
                print(f"{UtilityTools.RED}[-] 403 The Cloud Functions API is not enabled for this project{UtilityTools.RESET}")    

        except Exception as e:
            print(f"The V1 cloudfunctions.functions.update operation failed for unexpected reasons. See below:")
            print(str(e))    

    elif version == "2":
        
        try:

            # object_zip format will be gs://bucket_name/path
            object_zip = "/".join(bucket_source.split("/")[3:])
            bucket = bucket_source.split("/")[2]

            source_config = {
                "storage_source": {
                    'bucket':bucket,
                    'object_':object_zip
                }
            }
            
            # What to set code as and version
            build_config = {
                "entry_point": entry_point,
                "runtime":"python312",
                "source": source_config
            }

            function = {
                "name": function_name,
                "build_config": build_config
            }

            if sa:
                service_config = {
                    "service_account_email": sa
                }
                function["service_config"] = service_config


            request = functions_v2.UpdateFunctionRequest(
                update_mask="buildConfig.entryPoint,buildConfig.runtime,buildConfig.source.storageSource,serviceConfig.serviceAccountEmail",
                function=function
            )

            # Make the request
            operation = function_client.update_function(request=request)
            print("[*] Waiting for update operation on V2 to complete, this might take awhile...")

            response = operation.result()
            update_status = response

        except Forbidden as e:
            if "does not have cloudfunctions.functions.update" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have cloudfunctions.functions.update permissions for the v2 function{UtilityTools.RESET}")

            elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
                print(f"{UtilityTools.RED}[X] 403 The Cloud Functions API is not enabled for this project{UtilityTools.RESET}")    

        except Exception as e:
            print(f"The V1 cloudfunctions.functions.update operation failed for unexpected reasons. See below:")
            print(str(e))   

    print("[*] Successfully uploaded the designated function")
    return update_status


def call_function(
        function_client_v1: FunctionServiceClient, 
        function_name: str, 
        version:str, 
        auth_json: Optional[Dict] = None, 
        debug: Optional[str] = False
    )-> Union[Policy, None]:

    if debug:
        print(f"[*] Calling {function_name}...")

    response_data = None

    if version == "1":

        try:

            # Data does not matter since we are passing it in
            request = functions_v1.CallFunctionRequest(
                name=function_name,
                data="test"
            )
            response = function_client_v1.call_function(request=request)
            # Handle the response
            response_data = response.result



        except Forbidden as e:
            if "does not have cloudfunctions.functions.invoke" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have cloudfunctions.functions.invoke permissions for the v1 function{UtilityTools.RESET}")

            elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
                print(f"{UtilityTools.RED}[X] 403 The Cloud Functions API is not enabled for this project{UtilityTools.RESET}")    
            print(str(e))
        except Exception as e:
            print(f"The V1 cloudfunctions.functions.invoke operation failed for unexpected reasons. See below:")
            print(str(e))        
        
    # Manual Build with REST APIs due to no API for V2 functions (Can't use V1 client)
    elif version == "2":   
        fail_string = "[X] Cannot invoke V2 functions from the python libraries at the moment due to the need for an identity token. If you have access to the google account via a web browser, navigate to the function and go to 'testing'. Run the CLI test command in cloud shell if possible to get the email/token back. Once these are returned add via normal command line via 'creds add --type Oauth2 --token <token>"
             
        try:
            grant_type = "refresh_token"
            if "token_uri" in auth_json.keys():
                token_uri = auth_json["token_uri"]
            if "client_id" in auth_json.keys():
                client_id = auth_json["client_id"]
            if "client_secret" in auth_json.keys():
                client_secret = auth_json["client_secret"]
            if "refresh_token" in auth_json.keys():
                refresh_token = auth_json["refresh_token"]

            if not (token_uri and client_id and client_secret and refresh_token):
                print(fail_string)
                return -1

            else:

                arguments = {
                    "grant_type":grant_type,
                    "client_id":client_id,
                    "client_secret":client_secret,
                    "refresh_token":refresh_token
                }

                headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                
                response = requests.post(token_uri, data=arguments, headers=headers)

                if response.status_code == 200:

                    response_json = json.loads(response.text)
                    if "id_token" in response_json.keys():
                        identity_token = response_json["id_token"]
                    else:
                        print(fail_string)
                        return -1
                
                    simple_name = function_name.split("/")[5]
                    region = function_name.split("/")[3]
                    project = function_name.split("/")[1]


                    url = f"https://{region}-{project}.cloudfunctions.net/{simple_name}"
                    
                    headers = {
                        'Authorization': f'bearer {identity_token}',
                        'Content-Type': 'application/json'
                    }

                    data = {
                        "name": "Hello World"
                    }



                    response = requests.post(url, headers=headers, data=json.dumps(data), timeout=70)
                    response_data = response.text


        except Exception as e:
            print(f"{UtilityTools.RED}The V2 cloudfunctions.functions.invoke operation failed for unexpected reasons. See below:{UtilityTools.RESET}")
            print(str(e))

    if debug:
        print(f"[DEBUG] Successfully completed functions cloudfunctions.functions.invoke ..")

    return response_data

# Mirroring check_bucket_existence from Rhino Security: https://github.com/RhinoSecurityLabs/GCPBucketBrute
def check_anonymous_external(
        function_name: Optional[str] = None, 
        function_url: Optional[str] = None, 
        printout: Optional[bool] = False,
        debug: Optional[bool] = False
    ):

    if debug:
        print(f"[DEBUG] Checking {function_url}")

    if not function_url:
        project = function_name.split("/")[1]
        location = function_name.split("/")[3]
        name = function_name.split("/")[5]

        function_url = f"https://{location}-{project}.cloudfunctions.net/{name}"

    response = requests.get(function_url)

    if response.status_code not in [400, 401, 404] and "Your client does not have permission to get" not in response.text:
        if printout:
            print(f"[*] Function {function_url} is available to anonymous users")
        return True
   
    if debug:
        print(f"[DEBUG] Function {function_url} returned {response.status_code}. Does not exist.")
    
    return False

def list_functions(
        function_client: FunctionServiceClient, 
        parent: str, 
        debug: Optional[bool] = False
    ):

    if debug:
        print(f"[DEBUG] Listing functions for project {parent} ...")
    
    function_list = []

    try:

        request = functions_v2.ListFunctionsRequest(
            parent=parent
        )

        function_list = list(function_client.list_functions(request=request))

    except Forbidden as e:
        
        if "does not have storage.buckets.get access" in str(e):
            
            print(f"{UtilityTools.RED}[X] 403: The user does not have storage.functions.list permissions on {parent}{UtilityTools.RESET}")
        
            return None
            
        elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
            
            print(f"{UtilityTools.RED}[X] 403 The Cloud Functions API is not enabled for {parent}{UtilityTools.RESET}")

            return "Not Enabled"

        return None

    except Exception as e:
        print("An unknown exception occurred when trying to call list_functions as follows:\n" + str(e))
        return None

    if debug:
        print(f"[DEBUG] Successfully called list_functions for {parent} ...")
    
    return function_list

def get_function(
        function_client: FunctionServiceClient, 
        function_name: str, 
        debug: Optional[bool] = False
    ):

    if debug:
        print(f"[DEBUG] Getting function {function_name} ...")
    
    function_meta = None

    try:
        # Initialize request argument(s)
        request = functions_v2.GetFunctionRequest(
            name=function_name
        )

        # Make the request
        function_meta = function_client.get_function(request=request)

    except InvalidArgument as e:
        if "400 Malformed name" in str(e):
            print(f"[X] Function name {function_name} is malformed. Make sure to do the format projects/*/locations/*/functions/*")

    except NotFound as e:
        if "404 Resource" in str(e):
            print(f"{UtilityTools.RED}[X] 404: Function {function_name} was not found{UtilityTools.RESET}")

    except Forbidden as e:
        if "does not have cloudfunctions.functions.get access to the Google Cloud project" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The user does not have cloudfunctions.functions.get permissions on function {function_name}{UtilityTools.RESET}")
        
        elif "Cloud Functions API has not been used in project" in str(e) and "before or it is disabled" in str(e):
            print(f"{UtilityTools.RED}[X] 403: The Cloud Functions API is not enabled for this project{UtilityTools.RESET}")    

    except Exception as e:
        print("[X] Something went wrong when trying to get the function. See details below:")
        print(str(e))

    if debug:
        print(f"[DEBUG] Successfully called list_functions for {function_name} ...")    

    # Handle the response
    
    return function_meta


########### TestIAMPermissions Checks

def check_function_permissions(function_client, function_name):
    
    authenticated_permissions = []

    try:
        
        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=function_name,
            permissions=[
                
                    'cloudfunctions.functions.call',
                    'cloudfunctions.functions.invoke',
                    'cloudfunctions.functions.delete',
                    'cloudfunctions.functions.get',
                    'cloudfunctions.functions.update',
                    'cloudfunctions.functions.sourceCodeGet',
                    'cloudfunctions.functions.sourceCodeSet',
                    'cloudfunctions.functions.getIamPolicy',
                    'cloudfunctions.functions.setIamPolicy'
            ] 
                
        )
        
        authenticated_permissions = function_client.test_iam_permissions(
            request=request
        )

        # Get list of allowed permissions
        authenticated_permissions = list(authenticated_permissions.permissions)

    except Forbidden as e:
        print(f"[-] 403 The user does not have testIamPermissions permissions on {function.name} ")
    
    except Exception as e:
        print("An unknown exception occurred when trying to call list_functions as follows:\n" + str(e))

    return authenticated_permissions