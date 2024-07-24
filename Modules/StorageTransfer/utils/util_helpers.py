
from google.cloud import storage_transfer_v1
import argparse
import json

from google.api_core.exceptions import PermissionDenied
from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import BadRequest

def save_agent_pool(agent, session):

    table_name = 'storagetransfer-agentpools'
    save_data = {}

    if agent.name: save_data["name"] = str(agent.name)
    if agent.display_name: save_data["display_name"] = str(agent.display_name)
    if agent.state: save_data["state"] = str(agent.state)
    
    bandwidth_limit = {}
    if agent.bandwidth_limit: 
        if agent.bandwidth_limit.limit_mbps: bandwidth_limit["limit_mbps"] = str(agent.bandwidth_limit.limit_mbps)
    
    save_data["bandwidth_limit"] = bandwidth_limit

    session.insert_data(table_name, save_data)

def save_transfer_job(transfer_job, session):

    table_name = 'storagetransfer-transferjobs'
    save_data = {}
    if transfer_job.name: save_data["name"] = transfer_job.name
    if transfer_job.description: save_data["description"] = transfer_job.description
    if transfer_job.project_id: save_data["project_id"] = transfer_job.project_id

    transfer_spec = {}
    if transfer_job.transfer_spec:

        gcs_data_sink = {}
        if transfer_job.transfer_spec.gcs_data_sink:
            if transfer_job.transfer_spec.gcs_data_sink.bucket_name: gcs_data_sink["bucket_name"] = transfer_job.transfer_spec.gcs_data_sink.bucket_name
            if transfer_job.transfer_spec.gcs_data_sink.path: gcs_data_sink["path"] = transfer_job.transfer_spec.gcs_data_sink.path
        transfer_spec["gcs_data_sink"] = gcs_data_sink


        posix_data_sink = {}
        if transfer_job.transfer_spec.posix_data_sink:
            if transfer_job.transfer_spec.posix_data_sink.root_directory: posix_data_sink["root_directory"] = transfer_job.transfer_spec.posix_data_sink.root_directory
        transfer_spec["posix_data_sink"] = posix_data_sink

        gcs_data_source = {}
        if transfer_job.transfer_spec.gcs_data_source:
            if transfer_job.transfer_spec.gcs_data_source.bucket_name: gcs_data_source["bucket_name"] = transfer_job.transfer_spec.gcs_data_source.bucket_name
            if transfer_job.transfer_spec.gcs_data_source.path: gcs_data_source["path"] = transfer_job.transfer_spec.gcs_data_source.path
        transfer_spec["gcs_data_source"] = gcs_data_source

        aws_s3_data_source = {}
        if transfer_job.transfer_spec.aws_s3_data_source:
            if transfer_job.transfer_spec.aws_s3_data_source.bucket_name: aws_s3_data_source["bucket_name"] = transfer_job.transfer_spec.aws_s3_data_source.bucket_name
            
            aws_access_key_id = {}
            if transfer_job.transfer_spec.aws_s3_data_source.aws_access_key: 
                if transfer_job.transfer_spec.aws_s3_data_source.aws_access_key.access_key_id: aws_access_key_id["aws_access_key"] = transfer_job.transfer_spec.aws_s3_data_source.aws_access_key.access_key_id
                if transfer_job.transfer_spec.aws_s3_data_source.aws_access_key.secret_access_key: aws_access_key_id["secret_access_key"] = transfer_job.transfer_spec.aws_s3_data_source.aws_access_key.secret_access_key
            aws_s3_data_source["aws_access_key_id"] = aws_access_key_id

            if transfer_job.transfer_spec.aws_s3_data_source.path: aws_s3_data_source["path"] = transfer_job.transfer_spec.aws_s3_data_source.path
            if transfer_job.transfer_spec.aws_s3_data_source.role_arn: aws_s3_data_source["role_arn"] = transfer_job.transfer_spec.aws_s3_data_source.role_arn
            if transfer_job.transfer_spec.aws_s3_data_source.credentials_secret: aws_s3_data_source["credentials_secret"] = transfer_job.transfer_spec.aws_s3_data_source.credentials_secret
        
        transfer_spec["aws_s3_data_source"] = aws_s3_data_source

        http_data_source = {}
        if transfer_job.transfer_spec.http_data_source:
            if transfer_job.transfer_spec.http_data_source.list_url: http_data_source["list_url"] = transfer_job.transfer_spec.http_data_source.list_url
        transfer_spec["http_data_source"] = http_data_source

        posix_data_source = {}
        if transfer_job.transfer_spec.posix_data_source:
            if transfer_job.transfer_spec.posix_data_source.root_directory: posix_data_source["root_directory"] = transfer_job.transfer_spec.posix_data_source.root_directory
        transfer_spec["posix_data_source"] = posix_data_source

        azure_blob_storage_data_source = {}
        if transfer_job.transfer_spec.azure_blob_storage_data_source:
            if transfer_job.transfer_spec.azure_blob_storage_data_source.storage_account: azure_blob_storage_data_source["storage_account"] = transfer_job.transfer_spec.azure_blob_storage_data_source.storage_account
            
            azure_credentials = {}
            if transfer_job.transfer_spec.azure_blob_storage_data_source.azure_credentials: 
                if transfer_job.transfer_spec.azure_blob_storage_data_source.azure_credentials.sas_token: azure_credentials["sas_token"] = transfer_job.transfer_spec.aws_s3_data_source.azure_credentials.sas_token
            azure_blob_storage_data_source["azure_credentials"] = azure_credentials

            if transfer_job.transfer_spec.azure_blob_storage_data_source.container: azure_blob_storage_data_source["container"] = transfer_job.transfer_spec.azure_blob_storage_data_source.container
            if transfer_job.transfer_spec.azure_blob_storage_data_source.path: azure_blob_storage_data_source["path"] = transfer_job.transfer_spec.azure_blob_storage_data_source.path
            if transfer_job.transfer_spec.azure_blob_storage_data_source.credentials_secret: azure_blob_storage_data_source["credentials_secret"] = transfer_job.transfer_spec.azure_blob_storage_data_source.credentials_secret

        transfer_spec["azure_blob_storage_data_source"] = azure_blob_storage_data_source

        aws_s3_compatible_data_source = {}   
        if transfer_job.transfer_spec.aws_s3_compatible_data_source:
            if transfer_job.transfer_spec.aws_s3_compatible_data_source.bucket_name: aws_s3_compatible_data_source["bucket_name"] = transfer_job.transfer_spec.aws_s3_compatible_data_source.bucket_name
            if transfer_job.transfer_spec.aws_s3_compatible_data_source.path: aws_s3_compatible_data_source["path"] = transfer_job.transfer_spec.aws_s3_compatible_data_source.path
            if transfer_job.transfer_spec.aws_s3_compatible_data_source.endpoint: aws_s3_compatible_data_source["endpoint"] = transfer_job.transfer_spec.aws_s3_compatible_data_source.endpoint
            if transfer_job.transfer_spec.aws_s3_compatible_data_source.region: aws_s3_compatible_data_source["region"] = transfer_job.transfer_spec.aws_s3_compatible_data_source.region


            s3_metadata = {}
            if transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata: 
                if transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.auth_method: s3_metadata["auth_method"] = str(transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.auth_method)
                if transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.request_model: s3_metadata["request_model"] = str(transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.request_model)
                if transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.protocol: s3_metadata["protocol"] = str(transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.protocol)
                if transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.list_api: s3_metadata["list_api"] = str(transfer_job.transfer_spec.aws_s3_compatible_data_source.s3_metadata.list_api)
            
            aws_s3_compatible_data_source["s3_metadata"] = s3_metadata
    
        transfer_spec["aws_s3_compatible_data_source"] = aws_s3_compatible_data_source

        gcs_intermediate_data_location = {}
        if transfer_job.transfer_spec.gcs_intermediate_data_location:
            if transfer_job.transfer_spec.gcs_intermediate_data_location.bucket_name: gcs_intermediate_data_location["bucket_name"] = transfer_job.transfer_spec.gcs_intermediate_data_location.bucket_name
            if transfer_job.transfer_spec.gcs_intermediate_data_location.path: gcs_intermediate_data_location["path"] = transfer_job.transfer_spec.gcs_intermediate_data_location.path
        
        transfer_spec["gcs_intermediate_data_location"] = gcs_intermediate_data_location

        object_conditions = {}
        if transfer_job.transfer_spec.object_conditions:
            if transfer_job.transfer_spec.object_conditions.min_time_elapsed_since_last_modification: object_conditions["min_time_elapsed_since_last_modification"] = str(transfer_job.transfer_spec.object_conditions.min_time_elapsed_since_last_modification)
            if transfer_job.transfer_spec.object_conditions.max_time_elapsed_since_last_modification: object_conditions["max_time_elapsed_since_last_modification"] = str(transfer_job.transfer_spec.object_conditions.max_time_elapsed_since_last_modification)
            if transfer_job.transfer_spec.object_conditions.include_prefixes: object_conditions["include_prefixes"] = dict(transfer_job.transfer_spec.object_conditions.include_prefixes)
            if transfer_job.transfer_spec.object_conditions.exclude_prefixes: object_conditions["exclude_prefixes"] = dict(transfer_job.transfer_spec.object_conditions.exclude_prefixes)
            if transfer_job.transfer_spec.object_conditions.last_modified_since: object_conditions["last_modified_since"] = str(transfer_job.transfer_spec.object_conditions.last_modified_since)
            if transfer_job.transfer_spec.object_conditions.last_modified_before: object_conditions["last_modified_before"] = str(transfer_job.transfer_spec.object_conditions.last_modified_before)

        transfer_spec["object_conditions"] = object_conditions

        transfer_options = {}
        if transfer_job.transfer_spec.transfer_options:
            if transfer_job.transfer_spec.transfer_options.overwrite_objects_already_existing_in_sink: transfer_options["overwrite_objects_already_existing_in_sink"] = str(transfer_job.transfer_spec.transfer_options.overwrite_objects_already_existing_in_sink)
            if transfer_job.transfer_spec.transfer_options.delete_objects_unique_in_sink: transfer_options["delete_objects_unique_in_sink"] = str(transfer_job.transfer_spec.transfer_options.delete_objects_unique_in_sink)
            if transfer_job.transfer_spec.transfer_options.delete_objects_from_source_after_transfer: transfer_options["delete_objects_from_source_after_transfer"] = str(transfer_job.transfer_spec.transfer_options.delete_objects_from_source_after_transfer)
            if transfer_job.transfer_spec.transfer_options.overwrite_when: transfer_options["overwrite_when"] = str(transfer_job.transfer_spec.transfer_options.overwrite_when)

            metadata_options = {}
            
            if transfer_job.transfer_spec.transfer_options.metadata_options: 
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
                if transfer_job.transfer_spec.transfer_options.metadata_options.symlink: metadata_options["symlink"] = str(transfer_job.transfer_spec.transfer_options.metadata_options.symlink)
            transfer_options["metadata_options"] = metadata_options
        
        transfer_spec["transfer_options"] = transfer_options

        transfer_manifest = {}
        if transfer_job.transfer_spec.transfer_manifest:
            if transfer_job.transfer_spec.transfer_manifest.location: transfer_manifest["location"] = transfer_job.transfer_spec.transfer_manifest.location        
        transfer_spec["transfer_manifest"] = transfer_manifest

        if transfer_job.transfer_spec.source_agent_pool_name: transfer_spec["source_agent_pool_name"] = transfer_job.transfer_spec.source_agent_pool_name
        if transfer_job.transfer_spec.sink_agent_pool_name: transfer_spec["sink_agent_pool_name"] = transfer_job.transfer_spec.sink_agent_pool_name


    save_data["transfer_spec"] = transfer_spec


    notification_config = {}
    if transfer_job.notification_config:
        if transfer_job.notification_config.pubsub_topic: notification_config["pubsub_topic"] = transfer_job.notification_config.pubsub_topic
        if transfer_job.notification_config.event_types: notification_config["event_types"] = dict(transfer_job.notification_config.event_types)
        if transfer_job.notification_config.payload_format: notification_config["payload_format"] = str(transfer_job.notification_config.payload_format)
        
    save_data["notification_config"] = notification_config

    logging_config = {}
    if transfer_job.logging_config:
        if transfer_job.logging_config.log_actions: logging_config["log_actions"] = str(transfer_job.logging_config.log_actions)
        if transfer_job.logging_config.log_action_states: logging_config["log_action_states"] = str(transfer_job.logging_config.log_action_states)
        if transfer_job.logging_config.enable_onprem_gcs_transfer_logs: logging_config["enable_onprem_gcs_transfer_logs"] = transfer_job.logging_config.enable_onprem_gcs_transfer_logs
    save_data["logging_config"] = logging_config

    schedule = {}
    if transfer_job.schedule:
        if transfer_job.schedule.schedule_start_date: schedule["schedule_start_date"] = str(transfer_job.schedule.schedule_start_date)
        if transfer_job.schedule.schedule_end_date: schedule["schedule_end_date"] = str(transfer_job.schedule.schedule_end_date)
        if transfer_job.schedule.start_time_of_day: schedule["start_time_of_day"] = str(transfer_job.schedule.start_time_of_day)
        if transfer_job.schedule.end_time_of_day: schedule["end_time_of_day"] = str(transfer_job.schedule.end_time_of_day)
        if transfer_job.schedule.repeat_interval: schedule["repeat_interval"] = str(transfer_job.schedule.repeat_interval)
    save_data["schedule"] = schedule

    event_stream = {}
    if transfer_job.event_stream:
        if transfer_job.event_stream.name: event_stream["name"] = transfer_job.event_stream.name
        if transfer_job.event_stream.event_stream_start_time: event_stream["event_stream_start_time"] = str(transfer_job.event_stream.event_stream_start_time)
        if transfer_job.event_stream.event_stream_expiration_time: event_stream["event_stream_expiration_time"] = str(transfer_job.event_stream.event_stream_expiration_time)
    save_data["event_stream"] = event_stream

    if transfer_job.status: save_data["status"] = str(transfer_job.status)
    if transfer_job.creation_time: save_data["creation_time"] = str(transfer_job.creation_time)
    if transfer_job.last_modification_time: save_data["last_modification_time"] = str(transfer_job.last_modification_time)
    if transfer_job.deletion_time: save_data["deletion_time"] = str(transfer_job.deletion_time)
    if transfer_job.latest_operation_name: save_data["latest_operation_name"] = str(transfer_job.latest_operation_name)
    
    session.insert_data(table_name, save_data)


def list_agent_pools(agent_pool_client, project_id, debug = False):
    
    if debug:
        print(f"[DEUBG] Listing agent pools...")

    agent_pool_list = None

    try:

        request = storage_transfer_v1.ListAgentPoolsRequest(
            project_id=project_id,
        )
        agent_pool_list = list(agent_pool_client.list_agent_pools(request=request))


    except Forbidden as e:
        if "does not have storagetransfer.agentpools.list" in str(e):
            print(f"{UtilityTools.RED}[X] The user does not have storagetransfer.agentpools.list permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storagetransfer.agentpools.list operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successfuly completed list_agent_pools...")

    return agent_pool_list



def get_agent_pool(agent_pool_client, agent_pool_name, debug = False):
    
    if debug:
        print(f"[DEUBG] Getting transfer jobs...")

    agent_job_meta = None

    try:

        request = storage_transfer_v1.GetAgentPoolRequest(
            name=agent_pool_name,
        )

        agent_job_meta = agent_pool_client.get_agent_pool(request=request)

    except Forbidden as e:
        if "does not have storagetransfer.agentpools.get" in str(e):
            print(f"{UtilityTools.RED}[X] The user does not have storagetransfer.agentpools.get permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storagetransfer.agentpools.get operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed get_agent_pool...")

    return agent_job_meta














def list_transfer_jobs(transfer_job_client, project_id, debug = False):
    
    if debug:
        print(f"[DEUBG] Listing transfer jobs...")

    transfer_job_list = None

    try:
        filter_value = { "projectId":"production-project-1-426001"}
        filter_value = json.dumps(filter_value)
        request = storage_transfer_v1.ListTransferJobsRequest(filter=filter_value)
        transfer_job_list = transfer_job_client.list_transfer_jobs(request=request)


    except Forbidden as e:
        if "does not have storagetransfer.jobs.list" in str(e):
            print(f"{UtilityTools.RED}[X] The user does not have storagetransfer.jobs.list permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storagetransfer.jobs.list operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successfuly completed list_storage_transfer_jobs...")

    return transfer_job_list

def get_transfer_job(transfer_job_client, job_name, job_project_id, debug = False):
    
    if debug:
        print(f"[DEUBG] Getting transfer jobs...")

    transfer_job_meta = None

    try:

        request = storage_transfer_v1.GetTransferJobRequest(
            job_name=job_name,
            project_id=job_project_id,
        )

        transfer_job_meta = transfer_job_client.get_transfer_job(request=request)

    except Forbidden as e:
        if "does not have storagetransfer.jobs.get" in str(e):
            print(f"{UtilityTools.RED}[X] The user does not have storagetransfer.jobs.get permissions on bucket{UtilityTools.RESET}")
    
    except Exception as e:
        print(f"The storagetransfer.jobs.get operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print(f"[DEUBG] Successful completed get_storage_transfer_jobs...")

    return transfer_job_meta