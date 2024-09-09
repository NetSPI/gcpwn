from Modules.StorageTransfer.utils.util_helpers import *

# Passively collect bucket and blob names
# end up with 
# job name 
# Extenral URLs:
#    - URL 1
#    - URL 2
# Entrypoint; Try-Catch Exists on Caller
def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Storage Transfer Jobs", allow_abbrev=False)
    parser.add_argument("--transfer-jobs", type=str, help="Transfer jobs to check in the format transferJobs/[id_number]")

    parser.add_argument("--download", type=str, help="If anything points to secrets, try to download the corresponding files")

    # Debug/non-module specific
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    debug = args.debug

    action_dict, storage_transfer_list_project = {}, {}
    
    # for summary
    resources_to_print = set([])

    if args.transfer_jobs:
        pass
    else:

        transfer_jobs_id = session.project_id

        storage_transfer_client = storage_transfer_v1.StorageTransferServiceClient(credentials = session.credentials)

        storage_transfer_list_output = list_transfer_jobs(storage_transfer_client, transfer_jobs_id, debug = debug)
        
        if storage_transfer_list_output:
            storage_transfer_list_project.setdefault(transfer_jobs_id, []).extend(storage_transfer_list_output)
        else:
            storage_transfer_list_project = None

    print(f"[*] Checking {transfer_jobs_id} for Storage Transfer Jobs...")

    if storage_transfer_list_project:  

        for transfer_jobs_id, storage_transfer_job_list in storage_transfer_list_project.items():

            storage_transfer_client = storage_transfer_v1.StorageTransferServiceClient(credentials = session.credentials)

            for storage_transfer_job in storage_transfer_job_list: 

                if not args.transfer_jobs:
                    storage_transfer_job_name = storage_transfer_job.name
                    action_dict.setdefault('project_permissions', {}).setdefault(transfer_jobs_id, set()).add('storagetransfer.jobs.list')
                    save_transfer_job(storage_transfer_job, session)

                else:
                    storage_transfer_job_name = storage_transfer_job
                                
                if not args.minimal_calls:
                    storage_transfer_job_metadata = get_transfer_job(storage_transfer_client,  storage_transfer_job_name,transfer_jobs_id,debug = debug)
                    if storage_transfer_job_metadata:
                        if args.transfer_jobs:
                            pass
                            #string_to_store = f"[{hmac_project_id}] {hmac_key_metadata.access_id} - {hmac_key_metadata.state}\n     SA: {hmac_key_metadata.service_account_email}"
                            #resources_to_print.add(string_to_store)
                        action_dict.setdefault('project_permissions', {}).setdefault(transfer_jobs_id, set()).add('storagetransfer.jobs.get')
                        save_transfer_job(storage_transfer_job_metadata,  session)

    session.insert_actions(action_dict)