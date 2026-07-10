"""IAM helpers: service-account/role/WIP enumeration plus the privesc primitives.

Two layers live here:
 - Resource classes (IAMServiceAccountsResource, IAMCustomRolesResource,
   IAMWorkloadIdentity*Resource) that enumerate IAM objects into workspace-scoped tables.
 - Module-level get/set IAM policy helpers (per resource type) and the service-account
   key/token primitives (iam_generate_service_account_key, iam_generate_access_token) that
   exploit modules use to escalate or pivot. The *_get/set_iam_policy helpers all return the
   sentinel ``404`` (int) on NotFound, the policy on success, and None on denied/other errors
   so callers can branch on a missing resource vs a permission denial.
"""

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
from gcpwn.core.utils.service_runtime import (
    build_discovery_service,
    extract_discovery_http_error,
    handle_discovery_error,
    is_api_disabled_error,
    paged_list,
)
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, extract_project_id_from_resource


class _IAMBaseDiscoveryResource:
    SERVICE_LABEL = "IAM"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

    def __init__(self, session) -> None:
        self.session = session
        self._discovery_service = None

    def _get_discovery_service(self):
        if self._discovery_service is None:
            self._discovery_service = build_discovery_service(
                getattr(self.session, "credentials", None),
                "iam",
                "v1",
                scopes=(self.CLOUD_PLATFORM_SCOPE,),
            )
        return self._discovery_service


def _get_iam_policy_generic(
    iam_client,
    resource_name: str,
    *,
    permission: str,
    not_found_message: str,
    debug_label: str | None = None,
):
    """Generic getIamPolicy over the v1 iam_policy proto API; returns policy / ``404`` / None.

    Shared by the per-resource get_iam_policy wrappers. Returns the int ``404`` on NotFound
    (resource gone), the Policy on success, and None on 403/unexpected errors -- letting callers
    distinguish "missing" from "denied".
    """
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
    """Generic setIamPolicy over the v1 iam_policy proto API; returns policy / ``404`` / None.

    Mirrors _get_iam_policy_generic. Returns the updated Policy on success, int ``404`` on
    NotFound, None on 403/unexpected. WHY: the shared write path behind IAM privesc modules.
    """
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
    """Mint a new SA key (the classic privesc primitive); returns the key object or None.

    The private_key_data is returned ONLY by this call -- callers must persist it for reuse.
    Distinguishes org-policy blocks (disableServiceAccountKeyCreation) and quota exhaustion
    with specific messages. Returns None on any denial/failure.
    """
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
    """Impersonate a service account by minting a cloud-platform access token (privesc/pivot).

    Requires iam.serviceAccounts.getAccessToken on the target SA. ``delegation`` supplies a
    delegate chain for multi-hop impersonation. Returns the token response or None (the API is
    buggy and may not raise Forbidden on denial, so None is the failure signal).
    """
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
    """setIamPolicy on a Compute instance (zone-scoped request); returns policy / ``404`` / None."""
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
    """setIamPolicy on a GCS bucket via the storage client; returns policy / ``404`` / None."""
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
    """getIamPolicy on a GCS bucket via the storage client; returns policy / ``404`` / None."""
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









def compute_instance_get_iam_policy(instance_client, project_id, instance_name, zone_id, debug = False):
    """getIamPolicy on a Compute instance (zone-scoped request); returns policy / ``404`` / None."""
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
    """Hashable wrapper for a custom role that normalizes its launch ``stage`` to a label.

    GCP returns stage as an enum int or string; __init__ maps it to ALPHA/BETA/GA/DEPRECATED/
    DISABLED/EAP and writes the normalized label back onto the proxied role so downstream
    display/save use the readable value.
    """

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
    """Enumerate service accounts into ``iam_service_accounts`` and their keys into ``iam_sa_keys``.

    Hand-rolled (not GcpListResource): also exposes testIamPermissions, getIamPolicy, and
    key list/get. Permissions are recorded as evidence (provenance test_iam_permissions for the
    testIamPermissions path, direct_api for the list/get paths). DB writes via save/save_keys
    are main-thread only.
    """

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

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        rows = self._list(project_id, debug=getattr(self.session, "debug", False))
        if rows in ("Not Enabled", None):
            return rows
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return [resource_to_dict(service_account) for service_account in rows]

    def get(self, *, resource_id: str, action_dict=None, **_):
        email = extract_path_tail(resource_id)
        row = self._get(email, debug=getattr(self.session, "debug", False))
        if not row:
            return row
        record_permissions(
            action_dict,
            permissions=self.GET_PERMISSION,
            project_id=extract_project_id_from_resource(resource_id),
            resource_type=self.ACTION_RESOURCE_TYPE,
            resource_label=email,
        )
        return resource_to_dict(row)

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

    def list_keys(self, *, resource_id: str, action_dict=None):
        """List a service account's keys, recording iam.serviceAccountKeys.list as evidence."""
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

    def save(self, rows, *, project_id: str | None = None, location: str | None = None, **_):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, extras={"type": "service_account"})

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
    """Enumerate custom roles (project- or org-scoped) into ``iam_roles`` with full permission lists.

    list() picks the parent (organizations/<id> vs projects/<id>) from org_id/project_id and
    records the list permission against the matching scope. Uses RoleView.FULL so
    included_permissions are populated. save() tags each row with its scope_of_custom_role.
    """

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
    """Enumerate workload identity pools (global location) into ``workload_identity_pools``.

    Uses the IAM v1 discovery client (not GAPIC). list/get treat HTTP 400 as a benign
    client error (return [] / "Not Enabled") and route other failures through
    handle_discovery_error, which yields the "Not Enabled" sentinel on a disabled API.
    """

    TABLE_NAME = "workload_identity_pools"
    COLUMNS = ["pool_id", "name", "display_name", "state", "disabled"]
    LIST_API_NAME = "iam.workloadIdentityPools.list"
    GET_API_NAME = "iam.workloadIdentityPools.get"
    ACTION_RESOURCE_TYPE = "workload_identity_pool"

    def __init__(self, session):
        super().__init__(session)

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        parent = f"projects/{str(project_id or '').strip()}/locations/global"
        try:
            service = self._get_discovery_service()
            rows = paged_list(
                lambda page_token: service.projects().locations().workloadIdentityPools().list(
                    parent=parent,
                    pageSize=1000,
                    **({"pageToken": page_token} if page_token else {}),
                ),
                items_key="workloadIdentityPools",
            )
        except Exception as exc:
            status, error_msg = extract_discovery_http_error(exc)
            if status == 400:
                print(
                    f"{UtilityTools.YELLOW}[!] {self.LIST_API_NAME} returned a client error for {parent}: "
                    f"{error_msg}{UtilityTools.RESET}"
                )
                return []
            result = handle_discovery_error(
                self.session,
                self.LIST_API_NAME,
                parent,
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return result if result in ("Not Enabled", None) else []

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
        try:
            service = self._get_discovery_service()
            payload = service.projects().locations().workloadIdentityPools().get(name=str(resource_id or "")).execute()
        except Exception as exc:
            status, error_msg = extract_discovery_http_error(exc)
            if status == 400:
                print(
                    f"{UtilityTools.YELLOW}[!] {self.GET_API_NAME} returned a client error for {resource_id}: "
                    f"{error_msg}{UtilityTools.RESET}"
                )
                return "Not Enabled"
            result = handle_discovery_error(
                self.session,
                self.GET_API_NAME,
                str(resource_id or ""),
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return "Not Enabled" if result == "Not Enabled" else None

        if isinstance(payload, dict) and payload:
            record_permissions(
                action_dict,
                permissions=self.GET_API_NAME,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
            return payload
        return None

    def save(self, rows, *, project_id: str | None = None, location: str | None = None, project_number: str = "", **_):
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
    """Enumerate WIP providers (nested under each pool) into ``workload_identity_providers``.

    NESTED: list() receives the parent pool name via ``parent`` (aliased to pool_name).
    Tolerates pools where provider listing is "not supported on resource" (returns []),
    and otherwise applies the same 400-vs-disabled handling as the pools resource.
    """

    TABLE_NAME = "workload_identity_providers"
    COLUMNS = ["provider_id", "pool_name", "name", "display_name", "state", "disabled"]
    LIST_API_NAME = "iam.workloadIdentityPoolProviders.list"
    GET_API_NAME = "iam.workloadIdentityPoolProviders.get"
    ACTION_RESOURCE_TYPE = "workload_identity_provider"

    def __init__(self, session):
        super().__init__(session)

    def list(self, *, pool_name: str = "", parent: str = "", location: str | None = None, action_dict=None):
        pool_name = pool_name or parent  # NESTED passes the parent pool name as `parent`
        if not pool_name:
            return []
        try:
            service = self._get_discovery_service()
            rows = paged_list(
                lambda page_token: service.projects().locations().workloadIdentityPools().providers().list(
                    parent=str(pool_name or "").rstrip("/"),
                    pageSize=1000,
                    **({"pageToken": page_token} if page_token else {}),
                ),
                items_key="workloadIdentityPoolProviders",
            )
        except Exception as exc:
            status, error_msg = extract_discovery_http_error(exc)
            if status == 400:
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
            result = handle_discovery_error(
                self.session,
                self.LIST_API_NAME,
                str(pool_name or ""),
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return result if result in ("Not Enabled", None) else []

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
        try:
            service = self._get_discovery_service()
            payload = (
                service.projects()
                .locations()
                .workloadIdentityPools()
                .providers()
                .get(name=str(resource_id or ""))
                .execute()
            )
        except Exception as exc:
            status, error_msg = extract_discovery_http_error(exc)
            if status == 400:
                print(
                    f"{UtilityTools.YELLOW}[!] {self.GET_API_NAME} returned a client error for {resource_id}: "
                    f"{error_msg}{UtilityTools.RESET}"
                )
                return "Not Enabled"
            result = handle_discovery_error(
                self.session,
                self.GET_API_NAME,
                str(resource_id or ""),
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return "Not Enabled" if result == "Not Enabled" else None

        if isinstance(payload, dict) and payload:
            record_permissions(
                action_dict,
                permissions=self.GET_API_NAME,
                project_id=extract_project_id_from_resource(resource_id, fallback_project=getattr(self.session, "project_id", "")),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=extract_path_tail(resource_id, default=str(resource_id or "").strip()),
            )
            return payload
        return None

    def save(self, rows, *, project_id: str | None = None, location: str | None = None, project_number: str = "", **_):
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
