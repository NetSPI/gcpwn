from Modules.SecretsManager.utils.util_helpers import *
from collections import defaultdict

def parse_range(range_str):
    """
    Parse a range string (e.g., "1-5,7,latest") and return a list of numbers
    or the string 'latest'.
    """
    numbers = []
    for part in range_str.split(','):
        if part == 'latest':
            numbers.append(part)
        elif '-' in part:
            start, end = part.split('-')
            numbers.extend(range(int(start), int(end) + 1))
        else:
            numbers.append(int(part))
    return numbers

def dprint(msg, debug):
    if debug:
        print(f"[DEBUG] {msg}")

# Entrypoint; Try-Catch Exists on Caller
def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate Secrets", allow_abbrev=False)
    
    exclusive_access_key_group = parser.add_mutually_exclusive_group(required=False)
    exclusive_access_key_group.add_argument("--secret-names", type=str, help="Secrets to check in the format projects/[project_number]/secrets/[secret_name]")
    exclusive_access_key_group.add_argument("--secret-names-file", type=str, help="File name to get secrets in format projects/[project_number]/secrets/[secret_name] per line")
    parser.add_argument("--version-range", type=parse_range,  help="Range of secret versions to try (ex. 1-100)")

    parser.add_argument("--iam",action="store_true",required=False,help="Call TestIAMPermissions on Compute Instances")
    parser.add_argument("--download",action="store_true",required=False,help="Download all secret VALUES to a local CSV")
 
    # Debug/non-module specific
    parser.add_argument("--minimal-calls", action="store_true",  help="Perform just List calls or minimal set of API calls")

    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data during the module run")

    args = parser.parse_args(user_args)
    
    debug, project_id = args.debug, session.project_id
    resource_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {}
    }
    secret_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    secrets = defaultdict(dict)
    client = secretmanager_v1.SecretManagerServiceClient(credentials=session.credentials)

    if args.secret_names or args.secret_names_file:
        input_list = UtilityTools.gather_non_automated_input(4, args.secret_names, args.secret_names_file)
        for s in input_list:
            secrets[project_id][HashableSecret(Secret(name=s), validated=False)] = {}
    else:
        parent = f"projects/{project_id}"
        found = list_secrets(client, parent, debug)
        if found not in ("Not Enabled", None):
            resource_actions["project_permissions"][project_id].add("secretmanager.secrets.list")
            for s in found:
                obj = HashableSecret(s)
                secrets[project_id][obj] = {}
                save_secret(s, session, project_id)

    for pid, secret_dict in secrets.items():
        for secret in list(secret_dict):
            name = secret.name
            if not args.minimal_calls:
                get_resp = get_secret(client, name, debug)
                if get_resp and get_resp != 404:
                    secret_actions[pid]['secretmanager.secrets.get']['secrets'].add(name.split('/')[-1])
                    save_secret(get_resp, session, pid)
                    secret.validated = True

            if args.iam:
                perms = check_secret_permissions(client, name, debug)
                for p in perms:
                    secret_actions[pid][p]['secrets'].add(name.split('/')[-1])
                    secret.validated = True

            versions = [f"{name}/versions/{v}" for v in args.version_range] if args.version_range else list_secret_versions(client, name)
            
            if versions in [None, 404]:
                continue
            
            if not args.version_range and versions and versions not in [404, None]:
                for v in versions:
                    secret_dict[secret][v.name.split('/')[-1]] = None
                    save_secret_version(v, session, pid)

            for v in versions:
                vname = v if isinstance(v, str) else v.name
                version_id = vname.split('/')[-1]
                label = f"{name} (Version: {version_id})"

                if not args.minimal_calls:
                    vget = get_secret_version(client, vname, debug)
                    if vget and vget != 404:
                        secret_actions[pid]['secretmanager.versions.get']['secret version'].add(label)
                        save_secret_version(vget, session, pid)
                        secret_dict[secret][version_id] = None

                if args.iam:
                    perms = check_secret_version_permissions(client, vname, debug)
                    for p in perms:
                        secret_actions[pid][p]['secret version'].add(label)
                        secret_dict[secret][version_id] = None

                val = access_secret_value(client, vname, debug)
                if val:
                    print(f"[*] Retrieved value for {label}")
                    secret_actions[pid]['secretmanager.versions.access']['secret version'].add(label)
                    decoded = val.payload.data.decode('utf-8')
                    secret_dict[secret][version_id] = decoded
                    session.insert_data('secretsmanager-secretversions', {
                        "primary_keys_to_match": {"name": vname},
                        "data_to_insert": {"secret_value": val.payload.data}
                    }, update_only=True)
                    if args.download:
                        download_secret_version(session, pid, label, val.payload.data)

        session.insert_actions(resource_actions, pid, column_name="secret_actions_allowed")
        session.insert_actions(secret_actions, pid, column_name="secret_actions_allowed")

    for pid, secret_dict in secrets.items():
        final = {}
        for s, versions in secret_dict.items():
            if s.validated:
                short_name = s.name.split("/")[-1]
                final[HashableSecret(Secret(name=short_name), validated=True)] = [f"{v}: {val}" for v, val in versions.items()]
        UtilityTools.summary_wrapup(
            pid,
            "Secrets Secrest/Versions",
            final,
            ["name", "expire_time"],
            primary_resource="Secret Names",
            secondary_title_name="versions: <secrets>",
            output_format=output_format
        )