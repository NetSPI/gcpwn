"""Cloud Functions enumeration/exploit helpers (gen1 + gen2).

Covers both API generations: ``version`` "1" routes to functions_v1, "2" to functions_v2,
which differ in request shape (v1 takes source_archive_url; v2 a storageSource bucket/object).
The create/update/call helpers are the privesc surface -- deploying a function with an attached
service account, or invoking one, lets an attacker pivot. V2 invoke has no Python client, so it
is hand-built over REST with an OAuth identity token. CloudFunctionsResource enumerates into
``cloudfunctions_functions`` and can download a function's source zip from its backing GCS object.
"""

from __future__ import annotations

import json
import re
import requests
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, Optional, Union

from gcpwn.core.console import UtilityTools

# Typing libraries
from google.cloud.functions_v1 import CloudFunction
from google.cloud.functions_v2 import Function
from google.cloud.functions_v2 import FunctionServiceClient
from google.iam.v1.policy_pb2 import Policy
from google.iam.v1 import iam_policy_pb2
from google.cloud import storage

# Main GCP Libraries
from google.cloud import functions_v1
from google.cloud import functions_v2

# Error Codes
from google.api_core.exceptions import InvalidArgument

# Utilities
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_segment,
    extract_project_id_from_resource,
    read_lines,
    resource_name_from_value,
    static_locations,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error, parse_csv_arg

# Utility for regex checking
def check_format(value: str, pattern: str, label: str):
    if re.match(pattern, value):
        return 1
    else:
        print(f"[X] Input string does not follow the correct format. It should be in the format: {label}")
        return None

########### Save Operations for Objects

def _create_function(
        function_client: FunctionServiceClient, 
        function_name: str, 
        bucket_source: str, 
        version: str, 
        entry_point: str,
        sa: Optional[str] = None, 
        debug: Optional[bool] = None
    ) -> Union[CloudFunction, Function, None]:
    """Deploy a new function (gen1 or gen2) from a GCS source archive; return the created function.

    PRIVESC: passing ``sa`` attaches a chosen service account to the function, so an attacker who
    can create functions can run code as that SA. Blocks until the long-running create op
    completes. Returns None on denial/disabled-API/error.
    """
    update_status = None
    project_id = extract_path_segment(function_name, "projects")
    region = extract_path_segment(function_name, "locations")
    function_id = extract_path_segment(function_name, "functions")
    parent = f"projects/{project_id}/locations/{region}" if project_id and region else ""

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


        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.create [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=project_id,
                return_not_enabled=False,
            )


    elif version == "2":

        try:

            parsed = urlparse(bucket_source)
            bucket_name = str(parsed.netloc or "").strip()
            object_path = str(parsed.path or "").lstrip("/")

            
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


        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.create [v2]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=project_id,
                return_not_enabled=False,
            )


    print(f"[*] Successfully created {function_name}")

    return update_status

# Note add generate_upload_url option
def _update_function(
    function_client: FunctionServiceClient, 
    function_name: str, 
    bucket_source: str, 
    version: str,  
    entry_point: str,
    sa: Optional[str] = None, 
    debug: Optional[bool]=None
    )-> Union[Policy, None]:
    """Update an existing function's source/entrypoint/SA (gen1 or gen2); return the updated function.

    PRIVESC: like create, ``sa`` re-points the function at a chosen service account and the new
    source code runs as it. Uses an update_mask so only code/SA fields change. Blocks on the op.
    """
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


        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.update [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=function_name,
                return_not_enabled=False,
            )

    elif version == "2":
        
        try:

            # object_zip format will be gs://bucket_name/path
            parsed = urlparse(bucket_source)
            object_zip = str(parsed.path or "").lstrip("/")
            bucket = str(parsed.netloc or "").strip()

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

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.update [v2]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=function_name,
                return_not_enabled=False,
            )

    print("[*] Successfully uploaded the designated function")

    return update_status


def _call_function(
        function_client_v1: FunctionServiceClient, 
        function_name: str, 
        version:str, 
        auth_json: Optional[Dict] = None, 
        debug: Optional[str] = False
    )-> Union[Policy, None]:
    """Invoke a function and return its response body; gen2 is hand-rolled over REST.

    gen1 uses the call_function client API. gen2 has no Python client, so this exchanges the
    supplied OAuth refresh-token creds (auth_json) for an id_token and POSTs to the function URL.
    Returns the response data, or -1 when gen2 creds/id_token are missing (prints guidance).
    """
    if debug:
        print(f"[*] Calling {function_name} [v{version}]...")

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

        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudfunctions.functions.invoke [v1]",
                resource_name=function_name,
                service_label="Cloud Functions",
                project_id=function_name,
                return_not_enabled=False,
            )
        
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
                
                    simple_name = extract_path_segment(function_name, "functions")
                    region = extract_path_segment(function_name, "locations")
                    project = extract_project_id_from_resource(function_name)


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

            UtilityTools.print_500(project, "cloudfunctions.functions.invoke [v2 - custom]", e)  

    if debug:
        print("[DEBUG] Successfully completed functions cloudfunctions.functions.invoke ..")

    return response_data


# Mirroring check_bucket_existence from Rhino Security: https://github.com/RhinoSecurityLabs/GCPBucketBrute
def check_anonymous_external(
        function_name: Optional[str] = None, 
        function_url: Optional[str] = None, 
        printout: Optional[bool] = False,
        debug: Optional[bool] = False
    ):
    """Probe whether a function's HTTPS endpoint is invocable by anonymous (allUsers) callers.

    Derives the public cloudfunctions.net URL from the resource name when no URL is given, then
    does an unauthenticated GET. A non-4xx response lacking the GCP permission-denied marker means
    the function is publicly reachable. Returns True if anonymously accessible.
    """
    if debug:
        print(f"[DEBUG] Checking {function_url}")

    if not function_url:
        project = extract_project_id_from_resource(function_name)
        location = extract_path_segment(function_name, "locations")
        name = extract_path_segment(function_name, "functions")

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
    """List functions (gen1+gen2) under a project/location parent via the v2 client.

    Returns the list on success, the sentinel "Not Enabled" when the API is disabled (to
    short-circuit region fan-out), or None on denial/404/error.
    """
    if debug:
        print(f"[DEBUG] Listing functions for project {parent} ...")
    
    function_list = []

    try:

        request = functions_v2.ListFunctionsRequest(
            parent=parent
        )

        function_list = list(function_client.list_functions(request=request))

    except Exception as exc:
        result = handle_service_error(
            exc,
            api_name="cloudfunctions.functions.list",
            resource_name=extract_project_id_from_resource(parent),
            service_label="Cloud Functions",
            project_id=extract_project_id_from_resource(parent),
        )
        return "Not Enabled" if result == "Not Enabled" else None

    if debug:
        print(f"[DEBUG] Successfully called list_functions for {parent} ...")
    
    return function_list

def get_function(
        function_client: FunctionServiceClient, 
        function_name: str, 
        debug: Optional[bool] = False
    ):
    """Fetch a single function's metadata via the v2 client; returns the function or None."""
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

    except Exception as exc:
        handle_service_error(
            exc,
            api_name="cloudfunctions.functions.get",
            resource_name=function_name,
            service_label="Cloud Functions",
            project_id=function_name,
            return_not_enabled=False,
        )

    if debug:
        print(f"[DEBUG] Successfully called list_functions for {function_name} ...")

    # Handle the response
    
    return function_meta


class CloudFunctionsResource:
    """Enumerate functions into ``cloudfunctions_functions`` and download their source archives.

    Hand-rolled resource over the functions_v2 client (which lists both gen1 and gen2). Normalizes
    proto state/environment enums to readable strings (_STATE_MAP / _normalize_environment) and
    extracts the backing GCS source location so download() can pull the function's code zip.
    test_iam_permissions adaptively drops permissions the API rejects as unsupported (gen1 vs gen2
    differ) and caches them so later functions skip the bad ones.
    """

    TABLE_NAME = "cloudfunctions_functions"
    COLUMNS = ["name", "region_val", "env", "state_output", "url"]
    LIST_PERMISSION = "cloudfunctions.functions.list"
    GET_PERMISSION = "cloudfunctions.functions.get"
    TEST_IAM_API_NAME = "cloudfunctions.functions.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "cloudfunctions.functions.",
        exclude_permissions=(
            "cloudfunctions.functions.create",
            "cloudfunctions.functions.list"
        ),
    )
    SERVICE_LABEL = "Cloud Functions"
    _STATE_MAP = {
        1: "ACTIVE",
        2: "FAILED",
        3: "DEPLOYING",
        4: "DELETING",
        5: "UNKNOWN",
        "ACTIVE": "ACTIVE",
        "FAILED": "FAILED",
        "DEPLOYING": "DEPLOYING",
        "DELETING": "DELETING",
        "UNKNOWN": "UNKNOWN",
    }

    def __init__(self, session):
        self.session = session
        self.client = functions_v2.FunctionServiceClient(credentials=session.credentials)
        self._unsupported_test_iam_permissions: set[str] = set()

    @staticmethod
    def _resource_name(row_or_name):
        return resource_name_from_value(row_or_name, "name")

    def resource_name(self, row_or_name: Any) -> str:
        return self._resource_name(row_or_name)

    @staticmethod
    def _safe_filename_component(value: str) -> str:
        token = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
        return token or "cloudfunction"

    @staticmethod
    def _build_download_path(
        *, 
        function_name: str, 
        environment: str,
        output: str | None, 
        project_id: str | None,
        session,
    ) -> Path:
        filename = f"{CloudFunctionsResource._safe_filename_component(function_name)}_{environment}_source.zip"
        if output:
            requested = Path(output).expanduser()
            if requested.exists() and requested.is_dir():
                return requested / filename
            if not requested.suffix:
                requested.mkdir(parents=True, exist_ok=True)
                return requested / filename
            # output was a file path; avoid overwriting unrelated requests by appending a token
            if requested.name == requested.stem:
                return requested.with_name(f"{requested.stem}_{CloudFunctionsResource._safe_filename_component(function_name)}{requested.suffix}")
            return requested

        return Path(
            session.get_download_save_path(
                service_name="cloudfunctions",
                project_id=project_id,
                subdirs=["function_sources"],
                filename=filename,
            )
        )

    @staticmethod
    def _normalize_environment(environment: Any) -> str:
        value = str(environment or "").strip()
        if value in {"1", "GEN_1"}:
            return "GEN_1"
        if value in {"2", "GEN_2"}:
            return "GEN_2"
        if not value:
            return "GEN_2"
        if value.isdigit():
            return "GEN_1" if value == "1" else "GEN_2"
        return value

    @staticmethod
    def _action_resource_type(row_or_name):
        environment = getattr(row_or_name, "environment", None)
        if environment in (None, "") and isinstance(row_or_name, dict):
            environment = row_or_name.get("environment")
        if str(environment) == "1":
            return "functions_v1"
        return "functions_v2"

    def _action_label(self, row_or_name):
        function_name = self._resource_name(row_or_name)
        location = extract_path_segment(function_name, "locations")
        function_id = extract_path_segment(function_name, "functions")
        if location and function_id:
            return f"[{location}] {function_id}"
        return function_name

    @staticmethod
    def _extract_field(payload: dict[str, Any], *keys: str):
        for key in keys:
            value = payload.get(key)
            if value not in (None, "", []):
                return value
        return None

    def _normalize_row(self, row_or_name: Any) -> dict[str, Any]:
        payload = resource_to_dict(row_or_name) if not isinstance(row_or_name, dict) else dict(row_or_name)
        if not payload:
            return {}
        payload = dict(payload)
        payload["region_val"] = extract_location_from_resource_name(payload)
        payload["env"] = self._normalize_environment(payload.get("environment"))
        payload["state_output"] = self._STATE_MAP.get(payload.get("state"), payload.get("state"))
        return payload

    def _extract_source_location(self, payload: dict[str, Any]) -> tuple[str, str] | None:
        """Find the function's source in GCS as (bucket, object_path); handles gen1 + gen2 shapes.

        gen1 carries a gs:// sourceArchiveUrl; gen2 nests it under buildConfig.source.storageSource.
        Returns None when no GCS source is present.
        """
        candidates = [
            self._extract_field(payload, "source_archive_url", "sourceArchiveUrl"),
            self._extract_field(payload, "source_archive", "sourceArchive"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str):
                parsed = urlparse(candidate.strip())
                if parsed.scheme == "gs":
                    bucket = parsed.netloc
                    object_path = parsed.path.lstrip("/")
                    if bucket and object_path:
                        return bucket, object_path

        build_config = self._extract_field(payload, "build_config", "buildConfig") or {}
        source_config = self._extract_field(build_config, "source")
        storage_source = self._extract_field(source_config or {}, "storage_source", "storageSource")
        if isinstance(storage_source, dict):
            bucket = self._extract_field(storage_source, "bucket")
            object_path = self._extract_field(storage_source, "object_", "object")
            if bucket and object_path:
                return str(bucket).strip(), str(object_path).strip().lstrip("/")
        return None

    def resolve_regions(self, *, v1_regions=False, v2_regions=False, v1v2_regions=False, regions_list=None, regions_file=None):
        """Resolve the region list to enumerate: gen1/gen2/both static lists, a CLI list/file, or workspace default.

        gen1 and gen2 support different region sets (the [cloudfunctions_v1] /
        [cloudfunctions_v2] sections of mappings/service_locations.txt); the flags pick
        which to fan out over. Explicit regions_list/regions_file override.
        """
        if v1_regions:
            return static_locations("cloudfunctions_v1")
        if v2_regions:
            return static_locations("cloudfunctions_v2")
        if v1v2_regions:
            return sorted(set(static_locations("cloudfunctions_v1")) | set(static_locations("cloudfunctions_v2")))
        if regions_list:
            return parse_csv_arg(regions_list)
        if regions_file:
            return read_lines(regions_file)
        return getattr(self.session.workspace_config, "preferred_regions", None)

    def list(self, *, project_id: str, location: str | None = None, parent: str | None = None, action_dict=None):
        if parent is None and location is not None:
            parent = f"projects/{project_id}/locations/{location}"
        rows = list_functions(self.client, parent, debug=getattr(self.session, "debug", False))
        if rows not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        if rows in ("Not Enabled", None):
            return rows
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if isinstance(row, dict) and row:
                normalized_rows.append(row)
                continue
            row_payload = self._normalize_row(row)
            if row_payload:
                normalized_rows.append(row_payload)
        return normalized_rows

    def get(self, *, resource_id: str, action_dict=None):
        row = get_function(self.client, resource_id, debug=getattr(self.session, "debug", False))
        if row:
            row = self._normalize_row(row)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=extract_project_id_from_resource(resource_id),
                resource_type=self._action_resource_type(row),
                resource_label=self._action_label(row),
            )
        return row

    def test_iam_permissions(self, *, resource_id: str, action_dict=None):
        """Probe granted perms on a function; degrade gracefully when the API rejects some.

        Tries the full set at once; on InvalidArgument it retries permission-by-permission to
        find which are unsupported for this function (gen1/gen2 differ), caches them on
        self._unsupported_test_iam_permissions so subsequent functions skip them, and records the
        granted set as evidence (provenance test_iam_permissions).
        """
        project_id = extract_project_id_from_resource(resource_id) or None
        candidate_permissions = [
            permission
            for permission in self.TEST_IAM_PERMISSIONS
            if permission not in self._unsupported_test_iam_permissions
        ]
        if not candidate_permissions:
            return []

        def _invoke(permission_list: list[str]) -> list[str]:
            request = iam_policy_pb2.TestIamPermissionsRequest(
                resource=str(resource_id or "").strip(),
                permissions=permission_list,
            )
            response = self.client.test_iam_permissions(request=request)
            return list(getattr(response, "permissions", []) or [])

        try:
            permissions = _invoke(candidate_permissions)
        except InvalidArgument:
            granted: set[str] = set()
            newly_unsupported: set[str] = set()
            for permission in candidate_permissions:
                try:
                    granted.update(_invoke([permission]))
                except InvalidArgument:
                    newly_unsupported.add(permission)
                except Exception as exc:
                    result = handle_service_error(
                        exc,
                        api_name=self.TEST_IAM_API_NAME,
                        resource_name=resource_id,
                        service_label=self.SERVICE_LABEL,
                        project_id=project_id,
                        return_not_enabled=False,
                    )
                    return [] if result in (None, "Not Enabled") else list(result or [])
            if newly_unsupported:
                unseen = newly_unsupported - self._unsupported_test_iam_permissions
                self._unsupported_test_iam_permissions.update(newly_unsupported)
                if unseen:
                    print(
                        f"[!] cloudfunctions.functions.testIamPermissions rejected "
                        f"{len(unseen)} unsupported permission(s); skipping them for remaining functions."
                    )
            permissions = sorted(granted)
        except Exception as exc:
            result = handle_service_error(
                exc,
                api_name=self.TEST_IAM_API_NAME,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
            permissions = [] if result in (None, "Not Enabled") else list(result or [])

        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self._action_resource_type(resource_id),
                resource_label=self._action_label(resource_id),
            )
        return permissions

    def save(self, rows, *, project_id=None, location=None, **_):
        for row in rows or []:
            payload = self._normalize_row(row)
            if not payload:
                continue
            save_to_table(
                self.session,
                "cloudfunctions_functions",
                payload,
                extra_builder=lambda _obj, raw: {
                    "project_id": extract_project_id_from_resource(raw.get("name", "")),
                },
            )

    def check_external_curl(self, *, function_url: str):
        return check_anonymous_external(function_url=function_url)

    def download(self, *, row: Any | None = None, resource_id: str | None = None, output: str | None = None) -> list[Path]:
        """Download a function's source-code zip from its backing GCS object to disk.

        Resolves the (bucket, object) source location, then pulls it with a storage client
        (requires storage.objects.get). Returns the written path(s), or [] when there's no GCS
        source or the download is denied/missing. Side effect: writes a zip under the loot dir.
        """
        payload = self._normalize_row(row or {"name": resource_id})
        function_name = str(payload.get("name") or "").strip()
        if not function_name:
            return []

        source_artifact = self._extract_source_location(payload)
        if not source_artifact:
            return []

        bucket_name, object_path = source_artifact
        project_id = extract_project_id_from_resource(payload)

        output_path = self._build_download_path(
            function_name=function_name,
            environment=self._normalize_environment(payload.get("environment")),
            output=output,
            project_id=project_id,
            session=self.session,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            storage_client = storage.Client(credentials=self.session.credentials, project=project_id or None)
            blob = storage_client.bucket(bucket_name).blob(object_path)
            blob.download_to_filename(str(output_path))
            return [output_path]
        except Exception as exc:
            handle_service_error(
                exc,
                api_name="storage.objects.get",
                resource_name=f"gs://{bucket_name}/{object_path}",
                service_label="Cloud Storage",
                project_id=project_id,
                return_not_enabled=False,
            )
            return []
