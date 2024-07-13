from Modules.IAM.utils.util_helpers import *
  
def run_module(user_args, session, first_run = False, last_run = False):

    project_id = session.project_id

    # Set up Argparser to handle flag arguments
    parser = argparse.ArgumentParser(description="Enumerate IAM Policy", allow_abbrev=False)
    parser.add_argument("-v","--debug",action="store_true",required=False,help="Get verbose data returned")
    args = parser.parse_args(user_args)

    debug = args.debug


    action_dict = {}

   
    organization_client = resourcemanager_v3.OrganizationsClient(credentials = session.credentials)
    project_client = resourcemanager_v3.ProjectsClient(credentials = session.credentials)
    folder_client = resourcemanager_v3.FoldersClient(credentials=session.credentials)
    function_client = functions_v2.FunctionServiceClient(credentials=session.credentials,  transport="rest")
    instance_client = compute_v1.InstancesClient(credentials = session.credentials)    
    iam_client = iam_admin_v1.IAMClient(credentials = session.credentials)
    secret_client = secretmanager_v1.SecretManagerServiceClient(credentials = session.credentials)   

    organizations = session.get_data("abstract-tree-hierarchy", columns=["name"], conditions="type=\"org\"")
    folders = session.get_data("abstract-tree-hierarchy", columns=["name"], conditions="type=\"folder\"")
    projects = session.get_data("abstract-tree-hierarchy", columns=["name","project_id"], conditions="type=\"project\"")
    buckets = session.get_data("cloudstorage-buckets", columns=["name","project_id"])
    cloudfunctions = session.get_data("cloudfunctions-functions", columns=["name","project_id", "environment"])
    compute_instances = session.get_data("cloudcompute-instances", columns=["name", "zone", "project_id"])
    sa_accounts = session.get_data("iam-principals", columns=["name", "email", "project_id"], conditions = "type =\"service_account\"")
    secrets = session.get_data("secretsmanager-secrets", columns=["name", "project_id"])

    print(f"[*] Checking IAM Policy for Organizations...")
    action_dict = {}
    for org_name in organizations:
        org_name = org_name["name"]
        
        org_iam_policy = organization_get_iam_policy(organization_client, org_name, debug=debug)
        if org_iam_policy:
            action_dict.setdefault('organization_permissions', {}).setdefault(org_name, set()).add('resourcemanager.organizations.getIamPolicy')

            parse_iam_bindings_by_members(org_iam_policy.bindings, session, "org", org_name, "N/A")

    print(f"[*] Checking IAM Policy for Folders...")
    for folder_name in folders:
        folder_name = folder_name["name"]
        
        folder_iam_policy = folder_get_iam_policy(folder_client, folder_name, debug=debug)
        if folder_iam_policy:
            
            action_dict.setdefault('folder_permissions', {}).setdefault(folder_name, set()).add('resourcemanager.folders.getIamPolicy')

            parse_iam_bindings_by_members(folder_iam_policy.bindings, session, "folder", folder_name,"N/A")
    
    print(f"[*] Checking IAM Policy for Projects...")
    for project_data in projects:
        project_name, project_id = project_data["name"], project_data["project_id"]
        
        project_iam_policy = project_get_iam_policy(project_client, project_name, debug=debug)
        if project_iam_policy:
            action_dict.setdefault('project_permissions', {}).setdefault(project_id, set()).add('resourcemanager.projects.getIamPolicy')
            parse_iam_bindings_by_members(project_iam_policy.bindings, session, "project", project_name,project_id)
        
    session.insert_actions(action_dict)


    print(f"[*] Checking IAM Policy for Buckets...")
    action_dict = {}
    for bucket_data in buckets:
        bucket_name, bucket_project_id = bucket_data["name"], bucket_data["project_id"]
        storage_client = storage.Client(credentials = session.credentials, project = project_id)    
        
        bucket_iam_policy = bucket_get_iam_policy(storage_client, bucket_name, debug=debug)
        if bucket_iam_policy:
            action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.getIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)
            parse_iam_bindings_by_members(bucket_iam_policy._bindings, session, "bucket", bucket_name, bucket_project_id, policy_type = "google.api_core.iam.Policy")

    session.insert_actions(action_dict,  column_name = "storage_actions_allowed")


    print(f"[*] Checking IAM Policy for CloudFunctions...")
    action_dict = {}
    for function_data in cloudfunctions:
        function_name = function_data["name"]
        function_version = function_data["environment"]

        function_project_id = function_name.split("/")[1]
        function_location = function_name.split("/")[3]
        function_simple_name = function_name.split("/")[5]
        function_stored_entry = f"[{function_location}] {function_simple_name}"

        function_iam_policy = cloudfunction_get_iam_policy(function_client, function_name, debug=debug)
        if function_iam_policy:

            if function_version == 2:
                action_dict.setdefault(function_project_id, {}).setdefault("cloudfunctions.functions.getIamPolicy", {}).setdefault("functions_v2", set()).add(function_stored_entry)
            else:
                action_dict.setdefault(function_project_id, {}).setdefault("cloudfunctions.functions.getIamPolicy", {}).setdefault("functions_v1", set()).add(function_stored_entry)

            parse_iam_bindings_by_members(function_iam_policy.bindings, session, "cloudfunction", function_name, function_project_id)

    session.insert_actions(action_dict,  column_name = "function_actions_allowed")


    print(f"[*] Checking IAM Policy for Compute Instances...")
    action_dict = {}
    for instance_data in compute_instances:
        instance_name  = instance_data["name"]
        instance_project_id = instance_data["project_id"]
        zone_id = instance_data["zone"].split("/")[-1]
        
        instance_iam_policy = compute_instance_get_iam_policy(instance_client, instance_project_id, instance_name, zone_id, debug=debug)
        if instance_iam_policy:

            action_dict.setdefault(instance_project_id, {}).setdefault("compute.instances.getIamPolicy", {}).setdefault("instances", set()).add(instance_name)

            parse_iam_bindings_by_members(instance_iam_policy.bindings, session, "computeinstance", instance_name, instance_project_id)

    session.insert_actions(action_dict,  column_name = "compute_actions_allowed")


    print(f"[*] Checking IAM Policy for Service Accounts...")
    action_dict = {}
    for account in sa_accounts:
        
       
        sa_name  = account["name"]
        sa_project_id = account["project_id"]
        sa_email = account["email"]
        
        sa_iam_policy = sa_get_iam_policy(iam_client, sa_name, debug=debug)
        if sa_iam_policy:
            action_dict.setdefault(sa_project_id, {}).setdefault("iam.serviceAccounts.getIamPolicy", {}).setdefault("service account", set()).add(sa_name)

            parse_iam_bindings_by_members(sa_iam_policy.bindings, session, "saaccounts", sa_name, sa_project_id)

    session.insert_actions(action_dict,  column_name = "service_account_actions_allowed")

    print(f"[*] Checking IAM Policy for Secrets...")
    action_dict = {}
    for secret in secrets:
        secret_project_id = secret["project_id"]
        secret_name  = secret["name"]
        secret_iam_policy = secret_get_iam_policy(secret_client, secret_name, debug=debug)
        if secret_iam_policy:
          
            action_dict.setdefault(secret_project_id, {}).setdefault("secretmanager.secrets.getIamPolicy", {}).setdefault("secrets", set()).add(secret_name.split("/")[-1])

            parse_iam_bindings_by_members(secret_iam_policy.bindings, session, "secrets", secret_name, secret_project_id)
    
    session.insert_actions(action_dict,  column_name = "secret_actions_allowed")


    # Users are gathered via IAM table
    session.sync_users()

    #  TODO bug not saving all getIampermissions for each resource
