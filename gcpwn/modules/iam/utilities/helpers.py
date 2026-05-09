from google.cloud import (
    compute_v1,
    iam_admin_v1,
    iam_credentials_v1,
)
from google.iam.v1 import iam_policy_pb2
from gcpwn.core.console import UtilityTools

from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import FailedPrecondition
from google.api_core.exceptions import ResourceExhausted
from gcpwn.core.contracts import HashableResourceProxy
from gcpwn.core.utils.service_runtime import build_discovery_service
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, extract_project_id_from_resource
from gcpwn.core.utils.service_runtime import is_api_disabled_error


class _IAMBaseDiscoveryResource:
    SERVICE_LABEL = "IAM"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    IAM_REST_BASE_URL = "https://iam.googleapis.com/v1"

    def __init__(self, session) -> None:
        self.session = session
        self._discovery_service = None
        self._rest_state = {}

    def _get_discovery_service(self):
        if self._discovery_service is None:
            self._discovery_service = build_discovery_service(
                getattr(self.session, "credentials", None),
                "iam",
                "v1",
                scopes=(self.CLOUD_PLATFORM_SCOPE,),
            )
        return self._discovery_service

    def _get_rest_auth(self):
        session_info = self._rest_state.get("session_info")
        if session_info:
            return session_info

        try:
            import google.auth.credentials  # type: ignore
            import google.auth.transport.requests  # type: ignore
            import requests  # type: ignore
        except Exception as exc:
            UtilityTools.print_500("IAM REST", "google-auth/requests import", exc)
            return None

        credentials = getattr(self.session, "credentials", None)
        if credentials is None:
            UtilityTools.print_500("IAM REST", "session credentials", Exception("No credentials configured for session"))
            return None

        try:
            credentials = google.auth.credentials.with_scopes_if_required(
                credentials,
                (self.CLOUD_PLATFORM_SCOPE,),
            )
        except Exception:
            pass

        request_session = requests.Session()
        auth_request = google.auth.transport.requests.Request(session=request_session)
        self._rest_state["session_info"] = (request_session, auth_request, credentials)
        return self._rest_state["session_info"]

    def _refresh_access_token(self):
        auth = self._get_rest_auth()
        if auth is None:
            return None

        request_session, auth_request, credentials = auth
        access_token = str(getattr(self.session, "access_token", "") or getattr(credentials, "token", "") or "").strip()
        if access_token and not getattr(credentials, "expired", False):
            return access_token

        if hasattr(credentials, "refresh"):
            credentials.refresh(auth_request)
            access_token = str(getattr(credentials, "token", "") or "").strip()
            if access_token:
                self.session.access_token = access_token
            return access_token
        return access_token or None

    def _request_iam_rest_json(
        self,
        *,
        api_name: str,
        method: str,
        path: str,
        params: dict | None = None,
        print_client_error: bool = True,
    ):
        auth = self._get_rest_auth()
        if auth is None:
            return None, None

        request_session, _auth_request, _credentials = auth
        request_params = dict(params or {})
        endpoint = f"{self.IAM_REST_BASE_URL}/{str(path or '').lstrip('/')}"

        try:
            access_token = self._refresh_access_token()
            if not access_token:
                UtilityTools.print_500("IAM REST", api_name, Exception("Unable to acquire access token"))
                return None, None

            def _do_request(token):
                return request_session.request(
                    method=method,
                    url=endpoint,
                    params=request_params,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30,
                )

            response = _do_request(access_token)
            if response.status_code == 401 and access_token:
                new_token = self._refresh_access_token()
                if new_token and new_token != access_token:
                    response = _do_request(new_token)
        except Exception as exc:
            UtilityTools.print_500(endpoint, api_name, exc)
            return None, None

        if response.status_code == 400:
            try:
                error_payload = response.json()
                error_msg = (
                    error_payload.get("error", {})
                    .get("details", [{}])[0]
                    .get("message")
                    or error_payload.get("error", {}).get("message")
                    or response.text
                )
            except Exception:
                error_msg = response.text
            if print_client_error:
                print(
                    f"{UtilityTools.YELLOW}[!] {api_name} returned a client error for {path}: "
                    f"{error_msg}{UtilityTools.RESET}"
                )
            return None, response
        if response.status_code == 403:
            UtilityTools.print_403_api_denied(api_name, project_id=getattr(self.session, "project_id", None))
            return None, response
        if response.status_code == 404:
            UtilityTools.print_404_resource(path)
            return None, response
        if response.status_code != 200:
            UtilityTools.print_500(path, api_name, response.text)
            return None, response

        return response.json(), response


def _get_iam_policy_generic(
    iam_client,
    resource_name: str,
    *,
    permission: str,
    not_found_message: str,
    debug_label: str | None = None,
):
    if debug_label:
        print(f"[DEBUG] Getting IAM bindings for {resource_name} ...")

    try:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=str(resource_name or "").strip())
        return iam_client.get_iam_policy(request=request)
    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(not_found_message)
        return 404
    except Forbidden as e:
        if f"does not have {permission}" in str(e):
            print(f"[X] 403: The user does not have {permission} permissions on {resource_name}")
    except Exception as e:
        print(f"The {permission} operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug_label:
        print(f"[DEBUG] Successfully completed {debug_label} getIamPolicy ..")

    return None


def _set_iam_policy_generic(
    iam_client,
    resource_name: str,
    policy,
    *,
    permission: str,
    not_found_message: str | None = None,
    debug_label: str | None = None,
):
    if debug_label:
        print(f"[DEBUG] Setting IAM bindings for {resource_name} ...")

    try:
        request = iam_policy_pb2.SetIamPolicyRequest(resource=str(resource_name or "").strip(), policy=policy)
        return iam_client.set_iam_policy(request=request)
    except NotFound as e:
        if not_found_message and "404" in str(e) and "does not exist" in str(e):
            print(not_found_message)
        return 404
    except Forbidden as e:
        if f"does not have {permission}" in str(e):
            print(f"[X] 403: The user does not have {permission} permissions")
    except Exception as e:
        print(f"The {permission} operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug_label:
        print(f"[DEBUG] Successfully completed {debug_label} setIamPolicy ..")

    return None


class HashableServiceAccount(HashableResourceProxy):
    def __init__(self, sa_account, validated = True):
        self._sa_account = sa_account
        super().__init__(
            sa_account,
            key_fields=("unique_id",),
            validated=validated,
            repr_fields=("unique_id", "email"),
        )
########## SAVE ROLES

def iam_disable_service_account_key(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Disabling IAM service account key {sa_name} ..")

    status = None

    try:
        request = iam_admin_v1.DisableServiceAccountKeyRequest(
            name=sa_name,
        )

        # For some reason this does not throw an error and just returns none if fails :/ 
        status = iam_client.disable_service_account_key(request=request)

    except Forbidden as e:
        if "does not have iam.serviceAccountKeys.disable" in str(e):
            UtilityTools.print_403_api_denied("iam.serviceAccountKeys.disable", resource_name = sa_name)


    except Exception as e:
        UtilityTools.print_500(sa_name, "iam.serviceAccountKeys.disable", e)

    if debug:
        print("[DEBUG] Successfully completed IAM disable_service_account_key ..")

    return status

def iam_enable_service_account_key(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Enabling IAM service account key {sa_name} ..")

    status = None

    try:
        request = iam_admin_v1.EnableServiceAccountKeyRequest(
            name=sa_name,
        )

        # For some reason this does not throw an error and just returns none if fails :/ 
        status = iam_client.enable_service_account_key(request=request)

    except Forbidden as e:
        if "does not have iam.serviceAccountKeys.enable" in str(e):
            UtilityTools.print_403_api_denied("iam.serviceAccountKeys.enable", resource_name = sa_name)

    except Exception as e:
        UtilityTools.print_500(sa_name, "iam.serviceAccountKeys.enable", e)

    if debug:
        print("[DEBUG] Successfully completed IAM enable_service_account_key ..")

    return status

# private_key_data only provided in this APi call so store and use for later
def iam_generate_service_account_key(iam_client, sa_name, debug=False):
    
    if debug:
        print(f"[DEBUG] Creating IAM service account key for {sa_name} ..")

    name_account_key = None

    try:
        request = iam_admin_v1.CreateServiceAccountKeyRequest(
            name=sa_name,
        )

        # For some reason this does not throw an error and just returns none if fails :/ 
        name_account_key = iam_client.create_service_account_key(request=request)

    except Forbidden as e:
        
        if "does not have iam.serviceAccountKeys.create" in str(e):
            UtilityTools.print_403_api_denied("iam.serviceAccountKeys.create", resource_name = sa_name)

    except FailedPrecondition as e:
        err = str(e)
        if "disableServiceAccountKeyCreation" in err or "Key creation is not allowed on this service account" in err:
            UtilityTools.print_error(
                "Service account key creation is blocked by organization policy "
                "(constraints/iam.disableServiceAccountKeyCreation)."
            )
        else:
            UtilityTools.print_500(sa_name, "iam.serviceAccountKeys.create", e)

    except ResourceExhausted as e:
        UtilityTools.print_error(
            "Service account key creation failed due to quota/limit exhaustion "
            "(for example, too many active user-managed keys)."
        )
        UtilityTools.print_500(sa_name, "iam.serviceAccountKeys.create", e)

    except Exception as e:
        UtilityTools.print_500(sa_name, "iam.serviceAccountKeys.create", e)

    if debug:
        if name_account_key:
            print("[DEBUG] Successfully completed IAM generate_service_account_key ..")
        else:
            print("[DEBUG] IAM generate_service_account_key returned no key object.")

    return name_account_key

def iam_generate_access_token(iam_client, sa_name, delegation = None, debug=False):
    
    if debug:
        print(f"[DEBUG] Getting IAM access token for {sa_name} ..")

    name_access_token = None

    try:
        request = iam_credentials_v1.GenerateAccessTokenRequest(
            name=sa_name,
            scope=[
                "https://www.googleapis.com/auth/cloud-platform"
            ]
        )
        if delegation:
            request.delegates = delegation

        name_access_token = iam_client.generate_access_token(request=request)
    
    # API Seems bugged and does not return Forbidden on access error
    except Forbidden as e:
        if "does not have iam.serviceAccounts.getAccessToken" in str(e):
            print("[X] 403: The user does not have iam.serviceAccounts.getAccessToken permissions")
        else:
            print(str(e))
    except Exception as e:
        print("The iam.serviceAccounts.getAccessToken operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print("[DEBUG] Successfully completed IAM generate_access_token ..")
    
    if not name_access_token:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Was unable to get access token for {sa_name}, most likely permission denied{UtilityTools.RESET}")

    return name_access_token

def organization_set_iam_policy(organization_client, organization_name, policy, debug = False):
    return _set_iam_policy_generic(
        organization_client,
        organization_name,
        policy,
        permission="resourcemanager.organizations.setIamPolicy",
        not_found_message=f"[X] 404: Organization {organization_name} does not exist.",
        debug_label="organizations",
    )

def folder_set_iam_policy(folder_client, folder_name, policy, debug = False):
    return _set_iam_policy_generic(
        folder_client,
        folder_name,
        policy,
        permission="resourcemanager.folders.setIamPolicy",
        not_found_message=f"[X] 404: Folder {folder_name} does not exist.",
        debug_label="folders",
    )


def project_set_iam_policy(project_client, project_name, policy, debug = False):
    return _set_iam_policy_generic(
        project_client,
        project_name,
        policy,
        permission="resourcemanager.projects.setIamPolicy",
        not_found_message=f"[X] 404: Project {project_name} does not exist.",
        debug_label="projects",
    )

def project_get_iam_policy(project_client, project_name, debug = False):
    return _get_iam_policy_generic(
        project_client,
        project_name,
        permission="resourcemanager.projects.getIamPolicy",
        not_found_message=f"[X] 404: Project {project_name} does not exist.",
        debug_label="projects",
    )


def folder_get_iam_policy(folder_client, folder_name, debug = False):
    return _get_iam_policy_generic(
        folder_client,
        folder_name,
        permission="resourcemanager.folders.getIamPolicy",
        not_found_message=f"[X] 404: Folder {folder_name} does not exist.",
        debug_label="folders",
    )


def organization_get_iam_policy(organization_client, organization_name, debug = False):
    return _get_iam_policy_generic(
        organization_client,
        organization_name,
        permission="resourcemanager.organizations.getIamPolicy",
        not_found_message=f"[X] 404: Organization {organization_name} does not exist.",
        debug_label="organizations",
    )


def instance_set_iam_policy(instance_client, instance_name, project_id, zone_id, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {instance_name} ...")

    try:
        zone_set_policy_request_resource = {"policy": policy}
        request = compute_v1.SetIamPolicyInstanceRequest(
            project=project_id,
            resource=instance_name,
            zone=zone_id,
            zone_set_policy_request_resource=zone_set_policy_request_resource,
        )
        return instance_client.set_iam_policy(request=request)
    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Instance {instance_name} does not exist.")
        return 404
    except Forbidden as e:
        if "does not have compute.instances.setIamPolicy" in str(e):
            print("[X] 403: The user does not have compute.instances.setIamPolicy permissions")
    except Exception as e:
        print("The compute.instances.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print("[DEBUG] Successfully completed instances setIamPolicy ..")
    return None

def bucket_set_iam_policy(storage_client, bucket_name, policy, debug = False):
    if debug:
        print(f"[DEBUG] Setting IAM bindings for {bucket_name} ...")
    try:
        bucket_object  = storage_client.bucket(bucket_name)
        return bucket_object.set_iam_policy(policy)
    except NotFound as e:
        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Bucket {bucket_name} does not exist.")
        return 404
    except Forbidden:
        print("[X] User is not allowed to call storage.buckets.setIamPolicy on existing bucket.")
    except Exception as e:
        print("[X] The buckets set IAM policy has failed for uknonw reasons shown below:")
        print(str(e))
    return None

def bucket_get_iam_policy(storage_client, bucket_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {bucket_name} ...")
   
    bucket_iam_policy = None

    try:

        bucket_object  = storage_client.bucket(bucket_name)
        bucket_iam_policy = bucket_object.get_iam_policy()

    except NotFound as e:

        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Bucket {bucket_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have storage.buckets.getIamPolicy" in str(e):
            print(f"[X] 403: The user does not have storage.buckets.getIamPolicy permissions on bucket {bucket_name}")


    except Exception as e:
        print("The storage.buckets.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))


    if debug:
        print("[DEBUG] Successfully completed buckets getIamPolicy ..")

    return bucket_iam_policy





def secret_set_iam_policy(secret_client, secret_name, policy, debug = False):
    if debug:
        print(f"[DEBUG] Setting IAM bindings for {secret_name} ...")
    try:
        request = iam_policy_pb2.SetIamPolicyRequest(resource=secret_name, policy=policy)
        return secret_client.set_iam_policy(request=request)
    except NotFound:
        return 404
    except Forbidden as e:
        if "does not have secretmanager.secrets.setIamPolicy" in str(e):
            print("[X] 403: The user does not have secretmanager.secrets.setIamPolicy permissions")
    except Exception as e:
        print("The secretmanager.secrets.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print("[DEBUG] Successfully completed secrets setIamPolicy ..")
    return None

def secret_get_iam_policy(secret_client, secret_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {secret_name} ...")
    try:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=secret_name)
        return secret_client.get_iam_policy(request=request)
    except NotFound as e:
        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Secret {secret_name} does not exist.")
        return 404
    except Forbidden as e:
        if "does not have secretmanager.secrets.getIamPolicy" in str(e):
            print("[X] 403: The user does not have secretmanager.secrets.getIamPolicy permissions")
    except Exception as e:
        print("The secretmanager.secrets.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print("[DEBUG] Successfully completed secrets getIamPolicy ..")
    return None







def cloudfunction_set_iam_policy(function_client, function_name, policy, debug = False):

    if debug:
        print(f"[DEBUG] Setting IAM bindings for {function_name} ...")
    try:
        request = iam_policy_pb2.SetIamPolicyRequest(resource=function_name, policy=policy)
        return function_client.set_iam_policy(request=request)
    except NotFound as e:
        if "404" in str(e) and "was not found" in str(e):
            print(f"[X] 404: Function {function_name} does not exist.")
        return 404
    except Forbidden as e:
        if "does not have cloudfunctions.functions.setIamPolicy" in str(e):
            print("[X] 403: The user does not have cloudfunctions.functions.setIamPolicy permissions")
    except Exception as e:
        print("[X] The cloudfunctions.functions.setIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print("[DEBUG] Successfully completed functions setIamPolicy ..")
    return None

def cloudfunction_get_iam_policy(function_client, function_name, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {function_name} ...")
    try:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=function_name)
        return function_client.get_iam_policy(request=request)
    except NotFound as e:
        if "404" in str(e) and "The specified bucket does not exist" in str(e):
            print(f"[X] 404: Function {function_name} does not exist.")
        return 404
    except Forbidden as e:
        if "does not have cloudfunctions.functions.getIamPolicy" in str(e):
            print("[X] 403: The user does not have cloudfunctions.functions.getIamPolicy permissions")
    except Exception as e:
        print("[X] The cloudfunctions.functions.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))
    if debug:
        print("[DEBUG] Successfully completed functions getIamPolicy ..")
    return None


def compute_instance_get_iam_policy(instance_client, project_id, instance_name, zone_id, debug = False):

    if debug:
        print(f"[DEBUG] Getting IAM bindings for {instance_name} ...")
   
    instances_iam_policy = None

    try:
        request = compute_v1.GetIamPolicyInstanceRequest(
            project=project_id,
            resource=instance_name,
            zone=zone_id,
        )

        # Make the request
        instances_iam_policy = instance_client.get_iam_policy(request=request)


    except NotFound as e:
        if "404" in str(e) and "does not exist" in str(e):
            print(f"[X] 404: Instance {instance_name} does not exist.")

        return 404

    except Forbidden as e:
        if "does not have compute.instances.getIamPolicy" in str(e):
            print("[X] 403: The user does not have compute.instances.getIamPolicy permissions")

    except Exception as e:
        print("The compute.instances.getIamPolicy operation failed for unexpected reasons. See below:")
        print(str(e))

    if debug:
        print("[DEBUG] Successfully completed instances getIamPolicy ..")

    return instances_iam_policy




class HashableCustomRole(HashableResourceProxy):
    role_stage = None

    def __init__(self, custom_role, validated: bool = True):
        role = custom_role
        self._custom_role = custom_role
        super().__init__(
            custom_role,
            key_fields=("name",),
            validated=validated,
            repr_fields=("name", "title"),
        )
        stage = getattr(role, "stage", None)
        if isinstance(stage, int):
            self.role_stage = {
                0: "ALPHA",
                1: "BETA",
                2: "GA",
                3: "DEPRECATED",
                4: "DISABLED",
                5: "EAP",
            }.get(stage)
        elif isinstance(stage, str):
            normalized = stage.strip().upper()
            if normalized in {"ALPHA", "BETA", "GA", "DEPRECATED", "DISABLED", "EAP"}:
                self.role_stage = normalized
            else:
                self.role_stage = stage
                if stage.isdigit():
                    numeric_value = int(stage)
                    self.role_stage = {
                        0: "ALPHA",
                        1: "BETA",
                        2: "GA",
                        3: "DEPRECATED",
                        4: "DISABLED",
                        5: "EAP",
                    }.get(numeric_value, stage)
        else:
            self.role_stage = None

        try:
            if self.role_stage:
                setattr(self._custom_role, "stage", self.role_stage)
        except Exception:
            pass


class IAMServiceAccountsResource:
    TABLE_NAME = "iam_service_accounts"
    KEYS_TABLE_NAME = "iam_sa_keys"
    COLUMNS = ["email", "display_name"]
    LIST_PERMISSION = "iam.serviceAccounts.list"
    GET_PERMISSION = "iam.serviceAccounts.get"
    KEY_LIST_PERMISSION = "iam.serviceAccountKeys.list"
    KEY_GET_PERMISSION = "iam.serviceAccountKeys.get"
    ACTION_RESOURCE_TYPE = "service account"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "iam.serviceAccounts.",
        exclude_permissions=(
            "iam.serviceAccounts.create",
            "iam.serviceAccounts.list",
        ),
    )
    TEST_PERMISSIONS = TEST_IAM_PERMISSIONS

    def __init__(self, session):
        self.session = session
        self.client = iam_admin_v1.IAMClient(credentials=session.credentials)

    def _list(self, project_id, debug=False):
        if debug:
            print(f"[DEBUG] Getting IAM service accounts for {project_id} ...")

        service_account_list = []

        try:
            request = iam_admin_v1.ListServiceAccountsRequest(
                name=f"projects/{project_id}",
            )
            service_account_list = list(self.client.list_service_accounts(request=request))
        except Forbidden as e:
            if "does not have iam.serviceAccounts.list" in str(e):
                print("[X] 403: The user does not have iam.serviceAccounts.list permissions")
            elif is_api_disabled_error(e):
                print("[X] 403: Identity and Access Management (IAM) API has not been used or enabled")
            return None
        except Exception as e:
            print("The iam.serviceAccounts.list operation failed for unexpected reasons. See below:")
            print(str(e))
            return None

        if debug:
            print("[DEBUG] Successfully completed list_service_accounts ..")

        return service_account_list

    def _get(self, email, debug=False):
        if debug:
            print(f"[DEBUG] Getting IAM service account for {email} ...")

        service_account = None

        try:
            request = iam_admin_v1.GetServiceAccountRequest(
                name=f"projects/-/serviceAccounts/{email}",
            )
            service_account = self.client.get_service_account(request=request)
        except Forbidden as e:
            if "does not have iam.serviceAccounts.get" in str(e):
                print("[X] 403: The user does not have iam.serviceAccounts.get permissions")
            elif is_api_disabled_error(e):
                print("[X] 403: Identity and Access Management (IAM) API has not been used or enabled")
        except Exception as e:
            print("The iam.serviceAccounts.get operation failed for unexpected reasons. See below:")
            print(str(e))

        if debug:
            print("[DEBUG] Successfully completed get_service_account ..")

        return service_account

    def _list_keys(self, name, debug=False):
        if debug:
            print(f"[DEBUG] Getting IAM service accounts for {name} ...")

        service_account_key_list = None
        try:
            request = iam_admin_v1.ListServiceAccountKeysRequest(
                name=name,
            )
            service_account_key_list = list(self.client.list_service_account_keys(request=request).keys)
        except Forbidden as e:
            if "does not have iam.serviceAccounts.list" in str(e):
                print("[X] 403: The user does not have iam.serviceAccounts.list permissions")
        except Exception as e:
            print("The iam.serviceAccounts.list operation failed for unexpected reasons. See below:")
            print(str(e))

        return service_account_key_list

    def _get_key(self, key_name, debug=False):
        if debug:
            print(f"[DEBUG] Getting IAM service account key {key_name} ...")

        service_account_key = None
        try:
            request = iam_admin_v1.GetServiceAccountKeyRequest(
                name=key_name,
            )
            service_account_key = self.client.get_service_account_key(request=request)
        except Forbidden as e:
            if "does not have iam.serviceAccounts.get" in str(e):
                print("[X] 403: The user does not have iam.serviceAccounts.get permissions")
        except Exception as e:
            print("The iam.serviceAccounts.get operation failed for unexpected reasons. See below:")
            print(str(e))
        return service_account_key

    def _get_iam_policy(self, resource_name, debug=False):
        if debug:
            print(f"[DEBUG] Getting IAM bindings for {resource_name} ...")
        return _get_iam_policy_generic(
            self.client,
            resource_name,
            permission="iam.serviceAccounts.getIamPolicy",
            not_found_message=f"[X] 404: Service account {resource_name} does not exist.",
            debug_label="service account",
        )

    def list(self, *, project_id: str, action_dict=None):
        rows = self._list(project_id, debug=getattr(self.session, "debug", False))
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def get(self, *, resource_id: str, action_dict=None):
        email = extract_path_tail(resource_id)
        row = self._get(email, debug=getattr(self.session, "debug", False))
        if row:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=extract_project_id_from_resource(resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=email,
            )
        return row

    def test_iam_permissions(self, *, resource_id: str, action_dict=None):
        if getattr(self.session, "debug", False):
            print(f"[DEBUG] Testing IAM permissions for {resource_id} ...")
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name="iam.serviceAccounts.testIamPermissions",
            service_label="IAM",
            project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(
                    resource_id,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
        return permissions

    def get_iam_permissions(self, *, resource_id: str, action_dict=None):
        return self.test_iam_permissions(resource_id=resource_id, action_dict=action_dict)

    def test_permissions(self, *, resource_id: str, action_dict=None):
        return self.test_iam_permissions(resource_id=resource_id, action_dict=action_dict)

    def list_keys(self, *, resource_id: str, action_dict=None):
        rows = self._list_keys(resource_id, debug=getattr(self.session, "debug", False))
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.KEY_LIST_PERMISSION,
                project_id=extract_project_id_from_resource(resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
        return rows

    def get_key(self, *, resource_id: str, action_dict=None):
        row = self._get_key(resource_id, debug=getattr(self.session, "debug", False))
        if row:
            name = str(getattr(row, "name", "") or resource_id)
            sa_name = name.partition("/keys/")[0] if "/keys/" in name else ""
            record_permissions(
                action_dict,
                permissions=self.KEY_GET_PERMISSION,
                project_id=extract_project_id_from_resource(sa_name or resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(sa_name or resource_id, default=str(sa_name or resource_id or "").strip()),
            )
        return row

    def save(self, rows):
        for row in rows or []:
            save_to_table(self.session, "iam_service_accounts", row, extras={"type": "service_account"})

    def save_keys(self, rows):
        for row in rows or []:
            save_to_table(
                self.session,
                "iam_sa_keys",
                row,
                extra_builder=lambda _obj, raw: {
                    "disabled": raw.get("disabled", False) if raw.get("disabled", "") != "" else False,
                },
            )

    def get_iam_policy(self, *, resource_id: str, action_dict=None):
        row = self._get_iam_policy(resource_id, debug=getattr(self.session, "debug", False))
        if row:
            record_permissions(
                action_dict,
                permissions="iam.serviceAccounts.getIamPolicy",
                project_id=extract_project_id_from_resource(resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
        return row


class IAMCustomRolesResource:
    TABLE_NAME = "iam_roles"
    COLUMNS = ["name", "title", "stage", "included_permissions"]
    LIST_PERMISSION = "iam.roles.list"
    GET_PERMISSION = "iam.roles.get"

    def __init__(self, session):
        self.session = session
        self.client = iam_admin_v1.IAMClient(credentials=session.credentials)

    def _list_roles(self, parent, debug=False):
        if debug:
            print(f"[DEBUG] Getting IAM bindings for {parent} ..")
        iam_roles = None
        try:
            request = iam_admin_v1.ListRolesRequest(
                parent=parent,
                view=iam_admin_v1.RoleView.FULL,
                page_size=900,
            )
            iam_roles = list(self.client.list_roles(request=request))
        except Forbidden as e:
            if "does not have iam.roles.list" in str(e):
                print(
                    f"{UtilityTools.RED}[X] 403: The user does not have iam.roles.list permissions{UtilityTools.RESET}"
                )
            elif "permission" in str(e).lower():
                print(f"{UtilityTools.RED}[X] 403: iam.roles.list was not permitted for {parent}{UtilityTools.RESET}")
            else:
                print(f"{UtilityTools.RED}[X] 403: iam.roles.list failed for {parent}{UtilityTools.RESET}")
        except Exception as e:
            print("The iam.roles.list operation failed for unexpected reasons. See below:")
            print(str(e))
        if debug:
            print("[DEBUG] Successfully completed organization getIamPolicy ..")
        return iam_roles

    def _get_role(self, resource_id, debug=False):
        if debug:
            print(f"[DEBUG] Getting {resource_id} ..")
        role = None
        try:
            request = iam_admin_v1.GetRoleRequest(
                name=resource_id,
            )
            role = self.client.get_role(request=request)
        except Forbidden as e:
            if "does not have iam.roles.get" in str(e):
                print(f"{UtilityTools.RED}[X] 403: The user does not have iam.roles.get permissions{UtilityTools.RESET}")
        except NotFound as e:
            if f"404 The role named {resource_id} was not found." in str(e):
                print(f"{UtilityTools.RED}[X] 404: The role does not appear to exist in the specified project{UtilityTools.RESET}")
        except Exception as e:
            print("The iam.roles.get operation failed for unexpected reasons. See below:")
            print(str(e))
        if debug:
            print("[DEBUG] Successfully completed organization getIamPolicy ..")
        return role

    def list(self, *, project_id: str | None = None, org_id: str | None = None, action_dict=None):
        if org_id:
            parent = str(org_id).strip()
            if not parent.startswith("organizations/"):
                parent = f"organizations/{parent}"
            scope_key = "organization_permissions"
            scope_label = extract_path_tail(parent, default=parent)
        else:
            parent = str(project_id or "").strip()
            if not parent.startswith("projects/"):
                parent = f"projects/{parent}"
            scope_key = "project_permissions"
            scope_label = extract_path_tail(parent, default=parent)

        rows = self._list_roles(parent, debug=getattr(self.session, "debug", False))
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key=scope_key,
                scope_label=scope_label,
            )
        return rows

    def get(self, *, resource_id: str, action_dict=None):
        row = self._get_role(resource_id, debug=getattr(self.session, "debug", False))
        if row:
            scope_key = "project_permissions"
            scope_label = extract_project_id_from_resource(resource_id)
            if str(resource_id).startswith("organizations/"):
                scope_key = "organization_permissions"
                scope_label = extract_path_tail(resource_id, default=str(resource_id))
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                scope_key=scope_key,
                scope_label=scope_label,
            )
        return row

    def save(self, rows):
        def _scope_of_role(name: str) -> str:
            name_text = str(name or "").strip()
            if name_text.startswith("organizations/"):
                return "organization"
            if name_text.startswith("projects/"):
                return "project"
            return "project"

        for row in rows or []:
            save_to_table(
                self.session,
                "iam_roles",
                row,
                extras={"scope_of_custom_role": _scope_of_role(getattr(row, "name", ""))},
            )


class IAMWorkloadIdentityPoolsResource(_IAMBaseDiscoveryResource):
    TABLE_NAME = "workload_identity_pools"
    COLUMNS = ["pool_id", "name", "display_name", "state", "disabled"]
    LIST_API_NAME = "iam.workloadIdentityPools.list"
    GET_API_NAME = "iam.workloadIdentityPools.get"
    ACTION_RESOURCE_TYPE = "workload_identity_pool"

    def __init__(self, session):
        super().__init__(session)

    def list(self, *, project_id: str, action_dict=None):
        parent = f"projects/{str(project_id or '').strip()}/locations/global"
        page_token = None
        rows: list[dict] = []
        while True:
            params = {"pageSize": 1000}
            if page_token:
                params["pageToken"] = page_token
            payload, response = self._request_iam_rest_json(
                api_name=self.LIST_API_NAME,
                method="GET",
                path=f"{parent}/workloadIdentityPools",
                params=params,
            )
            if payload is None:
                if response is not None and response.status_code == 400:
                    return []
                break
            page_entries = payload.get("workloadIdentityPools", []) if isinstance(payload, dict) else []
            rows.extend(item for item in page_entries if isinstance(item, dict))
            page_token = payload.get("nextPageToken") if isinstance(payload, dict) else None
            if not page_token:
                break

        if rows:
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(parent, fallback_project=getattr(self.session, "project_id", "")),
            )
        return rows

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        payload, response = self._request_iam_rest_json(
            api_name=self.GET_API_NAME,
            method="GET",
            path=str(resource_id or ""),
        )
        if payload:
            record_permissions(
                action_dict,
                permissions=self.GET_API_NAME,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
            return payload
        if response is not None and response.status_code == 400:
            return "Not Enabled"
        return None

    def save(self, rows, *, project_id: str, project_number: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "project_number": project_number, "location": "global"},
                extra_builder=lambda _obj, raw: {
                    "pool_id": extract_path_tail(raw.get("name", "")),
                },
            )


class IAMWorkloadIdentityProvidersResource(_IAMBaseDiscoveryResource):
    TABLE_NAME = "workload_identity_providers"
    COLUMNS = ["provider_id", "pool_name", "name", "display_name", "state", "disabled"]
    LIST_API_NAME = "iam.workloadIdentityPoolProviders.list"
    GET_API_NAME = "iam.workloadIdentityPoolProviders.get"
    ACTION_RESOURCE_TYPE = "workload_identity_provider"

    def __init__(self, session):
        super().__init__(session)

    def list(self, *, pool_name: str, action_dict=None):
        if not pool_name:
            return []
        page_token = None
        rows: list[dict] = []
        while True:
            params = {"pageSize": 1000}
            if page_token:
                params["pageToken"] = page_token

            payload, response = self._request_iam_rest_json(
                api_name=self.LIST_API_NAME,
                method="GET",
                path=f"{str(pool_name).rstrip('/')}/providers",
                params=params,
                print_client_error=False,
            )
            if payload is None:
                if response is not None and response.status_code == 400:
                    try:
                        error_payload = response.json()
                        error_msg = (
                            error_payload.get("error", {})
                            .get("details", [{}])[0]
                            .get("message")
                            or error_payload.get("error", {}).get("message")
                            or response.text
                        )
                    except Exception:
                        error_msg = str(response.text)

                    if "not supported on resource" in error_msg.lower():
                        print(
                            f"{UtilityTools.YELLOW}[!] {self.LIST_API_NAME} is not supported on pool "
                            f"{pool_name}; skipping provider enumeration for this pool.{UtilityTools.RESET}"
                        )
                    else:
                        print(
                            f"{UtilityTools.YELLOW}[!] {self.LIST_API_NAME} returned a client error for "
                            f"{pool_name}/providers: {error_msg}{UtilityTools.RESET}"
                        )
                    return []
                break
            page_entries = payload.get("workloadIdentityPoolProviders", []) if isinstance(payload, dict) else []
            rows.extend(item for item in page_entries if isinstance(item, dict))
            page_token = payload.get("nextPageToken") if isinstance(payload, dict) else None
            if not page_token:
                break

        if rows:
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                project_id=extract_project_id_from_resource(pool_name, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(pool_name, default=pool_name),
            )
        return rows

    def get(self, *, resource_id: str, action_dict=None):
        if not resource_id:
            return None
        payload, response = self._request_iam_rest_json(
            api_name=self.GET_API_NAME,
            method="GET",
            path=str(resource_id or ""),
        )
        if payload:
            record_permissions(
                action_dict,
                permissions=self.GET_API_NAME,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
            return payload
        if response is not None and response.status_code == 400:
            return "Not Enabled"
        return None

    def save(self, rows, *, project_id: str, project_number: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "project_number": project_number, "location": "global"},
                extra_builder=lambda _obj, raw: {
                    "provider_id": extract_path_tail(raw.get("name", "")),
                    "pool_name": str(raw.get("name", "")).partition("/providers/")[0] if str(raw.get("name", "")) else "",
                    "pool_id": extract_path_segment(str(raw.get("name", "")), "workloadIdentityPools"),
                },
            )
