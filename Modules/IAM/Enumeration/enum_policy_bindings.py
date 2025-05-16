from Modules.IAM.utils.util_helpers import *
from collections import defaultdict
  
def run_module(user_args, session, first_run = False, last_run = False, output_format = ["table"]):

    project_id = session.project_id

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)

    debug = args.debug

    action_dict = {}

    # Initialize clients
    clients = {
        "org": resourcemanager_v3.OrganizationsClient(credentials=session.credentials),
        "project": resourcemanager_v3.ProjectsClient(credentials=session.credentials),
        "folder": resourcemanager_v3.FoldersClient(credentials=session.credentials),
        "function": functions_v2.FunctionServiceClient(credentials=session.credentials, transport="rest"),
        "compute": compute_v1.InstancesClient(credentials=session.credentials),
        "iam": iam_admin_v1.IAMClient(credentials=session.credentials),
        "secret": secretmanager_v1.SecretManagerServiceClient(credentials=session.credentials),
    }

    # Fetch resource data
    resources = {
        "orgs": session.get_data("abstract-tree-hierarchy", columns=["name"], conditions="type=\"org\""),
        "folders": session.get_data("abstract-tree-hierarchy", columns=["name"], conditions="type=\"folder\""),
        "projects": session.get_data("abstract-tree-hierarchy", columns=["name", "project_id"], conditions="type=\"project\""),
        "buckets": session.get_data("cloudstorage-buckets", columns=["name", "project_id"]),
        "functions": session.get_data("cloudfunctions-functions", columns=["name", "project_id", "environment"]),
        "instances": session.get_data("cloudcompute-instances", columns=["name", "zone", "project_id"]),
        "service_accounts": session.get_data("iam-principals", columns=["name", "email", "project_id"], conditions="type =\"service_account\""),
        "secrets": session.get_data("secretsmanager-secrets", columns=["name", "project_id"]),
    }


    # ORG/FOLDER/PROJECT IAM
    def handle_iam_binding(type_key, get_policy_fn, resource_list, column_key, resource_key):
        print(f"[*] Checking IAM Policy for {type_key.title()}...")
        perms = defaultdict(set)
        for item in resource_list:
            name = item[column_key]
            policy = get_policy_fn(clients[type_key], name, debug=debug)
            if policy:
                perms[name].add(f"resourcemanager.{type_key}s.getIamPolicy")
                parse_iam_bindings_by_members(policy.bindings, session, type_key, name, "N/A")
        return {f"{type_key}_permissions": perms}

    iam_perms = {}
    iam_perms.update(handle_iam_binding("org", organization_get_iam_policy, resources["orgs"], "name", "org"))
    iam_perms.update(handle_iam_binding("folder", folder_get_iam_policy, resources["folders"], "name", "folder"))
    iam_perms.update(handle_iam_binding("project", project_get_iam_policy, resources["projects"], "name", "project"))
    session.insert_actions(iam_perms)

    # BUCKET IAM
    print("[*] Checking IAM Policy for Buckets...")
    bucket_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    storage_client = storage.Client(credentials=session.credentials, project=project_id)
    for b in resources["buckets"]:
        name, pid = b["name"], b["project_id"]
        policy = bucket_get_iam_policy(storage_client, name, debug=debug)
        if policy and policy != 404:
            bucket_actions[pid]["storage.buckets.getIamPolicy"]["buckets"].add(name)
            parse_iam_bindings_by_members(policy._bindings, session, "bucket", name, pid, policy_type="google.api_core.iam.Policy")
    session.insert_actions(bucket_actions, column_name="storage_actions_allowed")


    # FUNCTION IAM
    print("[*] Checking IAM Policy for CloudFunctions...")
    function_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for f in resources["functions"]:
        name, pid, env = f["name"], f["project_id"], f["environment"]
        loc, short = name.split("/")[3], name.split("/")[5]
        display = f"[{loc}] {short}"
        policy = cloudfunction_get_iam_policy(clients["function"], name, debug=debug)
        if policy and policy != 404:
            key = "functions_v2" if env == 2 else "functions_v1"
            function_actions[pid]["cloudfunctions.functions.getIamPolicy"][key].add(display)
            parse_iam_bindings_by_members(policy.bindings, session, "cloudfunction", name, pid)
    session.insert_actions(function_actions, column_name="function_actions_allowed")

    # INSTANCE IAM
    print("[*] Checking IAM Policy for Compute Instances...")
    instance_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for i in resources["instances"]:
        name, pid, zone = i["name"], i["project_id"], i["zone"].split("/")[-1]
        policy = compute_instance_get_iam_policy(clients["compute"], pid, name, zone, debug=debug)
        if policy and policy != 404:
            instance_actions[pid]["compute.instances.getIamPolicy"]["instances"].add(name)
            parse_iam_bindings_by_members(policy.bindings, session, "computeinstance", name, pid)
    session.insert_actions(instance_actions, column_name="compute_actions_allowed")

    # SA IAM
    print("[*] Checking IAM Policy for Service Accounts...")
    sa_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for sa in resources["service_accounts"]:
        name, pid = sa["name"], sa["project_id"]
        policy = sa_get_iam_policy(clients["iam"], name, debug=debug)
        if policy and policy != 404:
            sa_actions[pid]["iam.serviceAccounts.getIamPolicy"]["service account"].add(name)
            parse_iam_bindings_by_members(policy.bindings, session, "saaccounts", name, pid)
    session.insert_actions(sa_actions, column_name="service_account_actions_allowed")

    # SECRET IAM
    print("[*] Checking IAM Policy for Secrets...")
    secret_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for s in resources["secrets"]:
        name, pid = s["name"], s["project_id"]
        policy = secret_get_iam_policy(clients["secret"], name, debug=debug)
        if policy and policy != 404:
            short = name.split("/")[-1]
            secret_actions[pid]["secretmanager.secrets.getIamPolicy"]["secrets"].add(short)
            parse_iam_bindings_by_members(policy.bindings, session, "secrets", name, pid)
    session.insert_actions(secret_actions, column_name="secret_actions_allowed")

    # Users are gathered via IAM table
    session.sync_users()