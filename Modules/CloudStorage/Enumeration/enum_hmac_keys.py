import argparse
from Modules.CloudStorage.utils.util_helpers import *
from collections import defaultdict
from google.cloud import storage

def dprint(msg, debug):
    if debug:
        print(f"[DEBUG] {msg}")

def run_module(user_args, session, first_run=False, last_run=False, output_format=["table"]):
    parser = argparse.ArgumentParser(description="Enumerate HMAC Keys Options", allow_abbrev=False)
    exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_access_key_group.add_argument("--access-keys", type=str)
    exclusive_access_key_group.add_argument("--access-keys-file", type=str)
    parser.add_argument("--minimal-calls", action="store_true")
    parser.add_argument("-v", "--debug", action="store_true")
    args = parser.parse_args(user_args)

    debug = args.debug
    project_id = session.project_id
    storage_client = storage.Client(credentials=session.credentials, project=project_id)
    print(f"[*] Checking {project_id} for HMAC keys...")

    all_hmacs = defaultdict(set)

    resource_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {}
    }
    hmac_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    if args.access_keys or args.access_keys_file:
        input_keys = UtilityTools.gather_non_automated_input(
            4, cmdline_in=args.access_keys, file_in=args.access_keys_file
        )
        if input_keys != -1:
            for key_path in input_keys:
                _, hmac_project_id, _, access_id = key_path.split("/")
                hmac_obj = HMACKeyMetadata(client=storage_client, access_id=access_id, project_id=hmac_project_id)
                all_hmacs[hmac_project_id].add(HashableHMACKeyMetadata(hmac_obj, validated = False))
    else:
       
        dprint(f"Getting HMAC KEYS in {project_id}", debug)
        every_hmac_key = list_hmac_keys(storage_client, debug=debug)
        if every_hmac_key == "Not Enabled" or every_hmac_key is None:
            all_hmacs[project_id] = set()
        else:
            resource_actions['project_permissions'][project_id].add("storage.hmacKeys.list")
            all_hmacs[project_id].update(HashableHMACKeyMetadata(h) for h in every_hmac_key)
            for h in every_hmac_key:
                save_hmac_key(h, session, dont_change=["secret"])

    for hmac_project_id, hmac_list in all_hmacs.items():
        storage_client = storage.Client(credentials=session.credentials, project=hmac_project_id)

        dprint(f"{len(hmac_list)} HMAC keys found" if hmac_list else f"[DEBUG] No HMAC keys found", debug)

        for hmac in hmac_list:
            access_id = hmac.access_id
            validated = hmac.validated

            print(f"[**] Reviewing {access_id}")
            if not args.minimal_calls:
                print(f"[***] GET HMAC Key")
                hmac_get = get_hmac_key(storage_client, access_id, debug=debug)
                if hmac_get:
                    if (args.access_keys or args.access_keys_file) and not validated:
                        all_hmacs[hmac_project_id].discard(hmac)
                        all_hmacs[hmac_project_id].add(HashableHMACKeyMetadata(hmac_get))
                    resource_actions['project_permissions'][hmac_project_id].add("storage.hmacKeys.get")
                    save_hmac_key(hmac_get, session, dont_change=["secret"])

        session.insert_actions(resource_actions, hmac_project_id, column_name="storage_actions_allowed")
        session.insert_actions(hmac_actions, hmac_project_id, column_name="storage_actions_allowed")

    for project_id, hmac_data in all_hmacs.items():
        validated_hmacs = [obj for obj in hmac_data if getattr(obj, 'validated', True)]
        UtilityTools.summary_wrapup(
            project_id,
            "Cloud Storage HMAC Keys",
            list(validated_hmacs),
            ["access_id", "secret", "state", "service_account_email"],
            primary_resource="HMAC keys",
            output_format=output_format,
            primary_sort_key="service_account_email"
        )