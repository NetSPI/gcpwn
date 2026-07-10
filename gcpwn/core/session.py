from datetime import datetime, timezone
import ast
import json
import os
import re
import traceback
from pathlib import Path
from typing import Any

import google.auth
import google.auth.transport.requests
import requests
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google.auth.exceptions import DefaultCredentialsError

from gcpwn.core.action_schema import ACTION_EVIDENCE_DIRECT_API
from gcpwn.core.config import WorkspaceConfig
from gcpwn.core.console import UtilityTools
from gcpwn.core.db import DataController
from gcpwn.core.utils.module_helpers import extract_project_id_from_resource
from gcpwn.core.output_paths import (
    build_output_path,
    make_workspace_slug,
)


class SessionUtility:
    """Central per-workspace session object passed to every module's run_module.

    Holds the active credentials (project context, email, scopes, access token)
    and exposes the data API that modules use to read/write the SQLite-backed
    model: get_data/get_session_data (read), insert_data (write rows),
    insert_actions (record discovered permissions as evidence), plus identity/
    ancestry helpers and interactive choice prompts.

    Key invariants this object enforces/relies on:
      - All service-table reads/writes are workspace-scoped. get_data/insert_data
        inject self.workspace_id automatically; never query service tables
        without it.
      - SQLite is single-threaded. self.data_master (DataController) is opened in
        the constructing (main) thread with check_same_thread=True. Modules may
        fan out with parallel_map/ThreadPoolExecutor, but workers must only do
        network/CPU work and RETURN results; calling get_data/insert_data/
        insert_actions from a worker thread raises sqlite3.ProgrammingError.
        Collect worker results on the main thread, then call insert_*.
      - Permissions are recorded as evidence with provenance (direct_api vs
        test_iam_permissions), not booleans. See insert_actions / action_schema.
    """

    def __init__(
        self,
        workspace_id,
        workspace_name,
        credname,
        auth_type,
        filepath=None,
        oauth_token=None,
        resume=None,
        adc_filepath=None,
        tokeninfo=False,
        quiet=False,
    ):
        """Build a workspace session and optionally load/assume credentials.

        Creates the workspace's SQLite databases (idempotent), restores workspace
        config and the cached project list, then dispatches on auth_type to add &
        assume creds: "adc"/"adc-file" (gcloud Application Default Credentials),
        "oauth2" (raw token), or "service" (SA key file). If resume=True instead,
        re-loads previously stored creds matching credname for this workspace.
        With no creds/auth_type/resume the session is created credential-less
        (used for workspace setup before any creds are added).
        """
        self.data_master = DataController()
        self.data_master.create_service_databases()
        self.workspace_id = workspace_id
        self.workspace_name = workspace_name
        self.workspace_directory_name = make_workspace_slug(workspace_id, workspace_name)

        self.default_project_id = None
        self.project_id = None
        self.credname = None
        self.credentials = None

        self.email = None
        self.access_token = None
        self.scopes = []
        self.global_project_list = []
        self.workspace_config = WorkspaceConfig()

        self.get_configs()
        self.global_project_list = self.data_master.sync_workspace_projects(self.workspace_id) or []

        if not credname and not auth_type and not resume:
            pass
        elif auth_type == "adc":
            self.add_oauth2_account(credname, tokeninfo=tokeninfo, assume=True)
        elif auth_type == "adc-file":
            self.add_oauth2_account(credname, adc_filepath=adc_filepath, tokeninfo=tokeninfo, assume=True)
        elif auth_type == "oauth2":
            self.add_oauth2_account(credname, token=oauth_token, tokeninfo=tokeninfo, assume=True)
        elif auth_type == "service":
            self.add_service_account(filepath, credname, assume=True)
        elif resume:
            current_workspace_creds = self.data_master.list_creds(workspace_id) or []
            if any(credname == row["credname"] for row in current_workspace_creds):
                self.load_stored_creds(credname)
            elif not quiet:
                print("[X] Could not resume credentials as they do not appear to exist for this workspace")

    def _workspace_select_rows(self, table_name, *, db="service", columns="*", conditions=None, params=None, where=None):
        """Run a SELECT with this workspace's workspace_id forced into the WHERE.

        The single chokepoint that enforces workspace scoping for every read path
        (get_data, get_session_data, sync_users). Always merges
        workspace_id into `where` so callers can never accidentally read another
        workspace's rows. Prefer the `where=` bound-parameter form over building
        raw `conditions=` strings (injection-safe).
        """
        scoped_where = dict(where or {})
        scoped_where["workspace_id"] = self.workspace_id
        return self.data_master.select_rows(
            table_name,
            db=db,
            columns=columns,
            conditions=conditions,
            params=params,
            where=scoped_where,
        )

    def delete_data(self, table_name, where):
        """Delete this workspace's rows from a service table matching ``where``.

        Forces workspace_id into the WHERE (same scoping guarantee as get_data), so
        callers can never delete another workspace's rows. Returns rows deleted.
        """
        scoped_where = dict(where or {})
        scoped_where["workspace_id"] = self.workspace_id
        return self.data_master.delete_service_rows(table_name, where=scoped_where)

    @staticmethod
    def _print_adc_setup_instructions():
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] ADC not setup. See below for next steps:{UtilityTools.RESET}")
        print("1. From the Tool:")
        print("   a) GCPwn should forward you to a (None:None)> prefix")
        print("   b) From the tool, run 'gcloud auth login' and sign in")
        print("   c) From the tool, run 'gcloud auth application-default login' and sign in")
        print("   d) Run 'creds add <credname> --type adc --assume' to add & assume ADC creds")
        print("2. Outside the Tool:")
        print("   a) Exit GCPwn via Ctrl+C")
        print("   b) From command line, Run 'gcloud auth login' and sign in")
        print("   c) From command line, Run 'gcloud auth application-default login' and sign in")
        print("   d) Launch the tool again via 'python3 main.py'")
        print("   e) At the screen to add creds, try 'adc <credname>' again and it should work")

    def _load_new_oauth_credentials(self, *, token=None, token_file=None, authorized_info=None, adc_filepath=None):
        """Build google-auth Credentials from a raw token, ADC file, or ambient ADC.

        Precedence: `authorized_info` (dict from an OAuth login flow) >
        `token_file` (a token.json authorized-user file, incl. refresh token) >
        `token` (a bare access token string) > `adc_filepath` (adc-file) > the
        ambient gcloud Application Default Credentials (adc). On a missing-ADC
        DefaultCredentialsError, prints setup instructions and returns
        (None, None, None) rather than raising.

        The `authorized_info`/`token_file` paths carry a refresh token, so the
        stored credential auto-renews (see refresh_credentials_if_needed); a bare
        `token` cannot be refreshed and expires in ~1 hour. All three are stored
        as the same "oauth2" credtype (the load path uses from_authorized_user_info).

        Returns:
            (credentials, type_of_cred, detected_project_id) tuple; type_of_cred
            is one of "oauth2"/"adc-file"/"adc". project_id is only discovered for
            the file/ambient paths.
        """
        if authorized_info:
            return Credentials.from_authorized_user_info(authorized_info), "oauth2", None
        if token_file:
            return Credentials.from_authorized_user_file(token_file), "oauth2", None
        if token:
            return Credentials(token=token), "oauth2", None
        if adc_filepath:
            credentials, project_id = google.auth.load_credentials_from_file(adc_filepath)
            return credentials, "adc-file", project_id
        try:
            credentials, project_id = google.auth.default()
            return credentials, "adc", project_id
        except DefaultCredentialsError:
            self._print_adc_setup_instructions()
            return None, None, None

    def get_actions(self, credname = None, include_provenance = False):
        """Return the recorded permission/action evidence tree for a credential.

        Reads the per-credential action tree (defaults to the active credname).
        With include_provenance=True the result is tagged with how each permission
        was learned (direct_api vs test_iam_permissions) rather than collapsed.
        """
        return self.data_master.get_actions(self.workspace_id, credname = credname, include_provenance = include_provenance)

    @property
    def config_regions_list(self):
        return self.workspace_config.preferred_regions

    @property
    def config_zones_list(self):
        return self.workspace_config.preferred_zones

    def get_download_save_path(
        self,
        *,
        service_name: str,
        filename: str = "",
        project_id: str | None = None,
        subdirs: list[str] | None = None,
        mkdir: bool = True,
    ) -> Path:
        """Compute the on-disk path for a file downloaded from a GCP service.

        Builds a workspace-scoped path under the "downloads" bucket, partitioned
        by service and scope (project_id, falling back to the session project or
        "global"). Creates parent dirs by default (mkdir=True).
        """
        # Identical to resolve_output_path(target="download") -- delegate to avoid two
        # copies of the downloads-bucket path assembly.
        return self.resolve_output_path(
            service_name=service_name,
            filename=filename,
            project_id=project_id,
            subdirs=subdirs,
            target="download",
            mkdir=mkdir,
        )

    def resolve_output_path(
        self,
        *,
        requested_path: str | os.PathLike | None = None,
        service_name: str,
        filename: str = "",
        project_id: str | None = None,
        subdirs: list[str] | None = None,
        target: str = "export",
        mkdir: bool = True,
    ) -> Path:
        """Resolve where a module should write output, honoring an explicit override.

        If the caller passed requested_path, that wins verbatim (expanded; parent
        created). Otherwise builds a workspace-scoped path under "exports" (or
        "downloads" when target=="download"), partitioned by service/scope like
        get_download_save_path. Centralizes the user-path-vs-default-layout choice
        so modules don't each reinvent it.
        """
        if requested_path:
            output_path = Path(requested_path).expanduser()
            if mkdir:
                output_path.parent.mkdir(parents=True, exist_ok=True)
            return output_path

        if str(target or "export").strip().lower() == "download":
            bucket = "downloads"
        else:
            bucket = "exports"
        if not self.workspace_directory_name:
            self.workspace_directory_name = make_workspace_slug(self.workspace_id, self.workspace_name)
        scope = project_id or self.project_id or "global"
        return build_output_path(
            self.workspace_directory_name,
            bucket=bucket,
            service_name=service_name,
            filename=filename,
            scope=scope if service_name else None,
            subdirs=subdirs,
            mkdir=mkdir,
        )

    ### Main Core Authentication Functions 
    def attempt_cred_refresh(self, auth_json):
        """Refresh the active OAuth/ADC credentials if expired/invalid; persist on success.

        No-op (returns 1) when the current credentials are still valid. Otherwise
        uses the stored refresh token to mint a fresh access token and writes the
        re-serialized creds back via update_oauth2_account. Distinguishes the
        common failure modes (reauth-needed, network error) with actionable
        messages.

        Returns:
            1 on success/already-valid; None on failure or when there are no
            credentials loaded.
        """
        credentials = self.credentials
        if not credentials:
            return None

        needs_refresh = credentials.expired or not credentials.valid or credentials.token is None
        if not needs_refresh:
            return 1

        expiry_timestamp = auth_json.get("expiry")
        if credentials.expired and expiry_timestamp:
            expiry_datetime = datetime.fromisoformat(expiry_timestamp.rstrip('Z'))
            if expiry_datetime < datetime.now(timezone.utc).replace(tzinfo=None) and credentials.token:
                print(
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Expired Credentials. "
                    f"Timestamp expiration for the access_token was {expiry_datetime}. "
                    f"Refresh is required{UtilityTools.RESET}"
                )
        else:
            print("[X] Invalid credentials or no access token stored")

        print("[*] Attempting to refresh the credentials using the stored refresh token. Note this is normal for brand new OAuth2 credentials added/updated.")

        request_session = requests.Session()
        auth_req = google.auth.transport.requests.Request(session=request_session)

        try:
            credentials.refresh(auth_req)
            print(f"{UtilityTools.GREEN}[*] Credentials sucessfully refreshed...{UtilityTools.RESET}")
            self.update_oauth2_account(self.credname, email=self.email, scopes = self.scopes, session_creds = credentials.to_json())
            print(f"{UtilityTools.GREEN}[*] Credentials sucessfully stored/updated...{UtilityTools.RESET}")
            return 1
        except Exception as e:
            if "Reauthentication is needed" in str(e) and "gcloud auth application-default login" in str(e):
                message = (
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Tried refreshing the credentials but ran into "
                    f"google.auth.exceptions.RefreshError error. The stored refresh token seems to no longer work "
                    f"(might be limited time-wise){UtilityTools.RESET}. To update your creds once in the tool:\n"
                    f"1. Run 'gcloud auth application-default login' to get a new set of credentials\n"
                    f"2. Run 'creds update <credname>' to update your current default credentials to the newest set"
                )
            elif "Max retries exceeded with url" in str(e):
                message = (
                    f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Received network error when trying to refresh. Make sure"
                    f"you have a reliable internet connection or check your connectivity. "
                )
            else:
                message = f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to refresh credentials:{UtilityTools.RESET} {e}"
            print(message)
        return None

    def load_stored_creds(self, credname, tokeninfo_check = False):
        """Load a stored credential into the live session and make it the active one.

        Hydrates self.credentials/credname/email/scopes/project_id/access_token
        from the workspace's creds table. For adc/adc-file it refreshes the token
        (and, if tokeninfo_check, re-derives scopes/email from the tokeninfo
        endpoint); for service accounts it pulls project/email/scopes off the key.
        A "service" cred has no access_token (the client library signs JWTs
        itself). Side effect: mutates session state in place.

        Returns:
            1 on success, -1 if credentials failed to materialize, None if no such
            credential exists (or on unexpected exception, which is printed).
        """
        try:
            cred = self.data_master.get_credential(self.workspace_id, credname)
            if not cred:
                return None
            
            # Set current creds at command line
            self.default_project_id = cred["default_project"]

            self.project_id = cred["default_project"]
            
            if self.project_id  == "Unknown":
                print("[*] The project associated with these creds is unknown. Set it with `creds set <credname> --project-id <project_id>`. Otherwise you might have limited functionality with non-global resources.")
            
            self.credname = cred["credname"]
            scopes_str = cred.get("scopes", "[]")
            if scopes_str is None:
                scopes_str = "[]"
            self.scopes = ast.literal_eval(scopes_str)
            self.email = cred["email"]
            
            if cred["credtype"] in ["adc","adc-file","oauth2"]:
                auth_json = json.loads(cred["session_creds"])
                # An "oauth2" cred carries a refresh_token when it came from `--token-file`
                # (an authorized-user credential, same shape as ADC) -- reload it the same
                # full way so it auto-renews. A bare `--token` oauth2 cred has no refresh
                # material, so it keeps the simple bare-token path.
                if cred["credtype"] in ["adc", "adc-file"] or auth_json.get("refresh_token"):
                    print("[*] Loading in ADC/OAuth2 user credentials...")
                    self.credentials = Credentials.from_authorized_user_info(auth_json)
                    status = self.attempt_cred_refresh(auth_json)
                    if status:
                        self.access_token = self.credentials.token
                        if tokeninfo_check:
                            scopes, email = self.get_and_save_tokeninfo(credname)
                            if scopes:
                                self.scopes = scopes
                            if email:
                                self.email = email
                        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Proceeding with up-to-date credentials for {credname}...{UtilityTools.RESET}")
                    else:
                        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Proceeding with erroneous credentials for {credname}...{UtilityTools.RESET}")
                elif cred["credtype"] == "oauth2":
                    print("Loading in OAuth2 token. Note it might be expired based on how long its existed...")
                    token = auth_json["token"]
                    self.access_token = token
                    self.credentials = Credentials(token=token)

            elif cred["credtype"] == "service":
                print("Loading in Service Credentials...")
                details_json = json.loads(cred["session_creds"])
                self.credentials = service_account.Credentials.from_service_account_info(details_json)
                if self.credentials.project_id:
                    self.project_id = self.credentials.project_id
                if self.credentials.service_account_email:
                    self.email = self.credentials.service_account_email
                if self.credentials.scopes:
                    self.scopes = self.credentials.scopes
                
                self.access_token = None

            if self.credentials is None:
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] There was an error loading your credentials. These credentials might not work/be passed onto the service{UtilityTools.RESET}")
                return -1
            else:
                print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded credentials {credname}{UtilityTools.RESET}")
                return 1

        except Exception:
            print(f"[X] Credentials {credname} could not be assumed.")
            print(traceback.format_exc())

    def build_stored_credentials(self, credname):
        """Build a google credential object from a stored cred WITHOUT activating it.

        Unlike ``load_stored_creds`` (which mutates the active session), this just
        materializes and returns the credential for a *different* identity -- e.g. a
        Drive downloader you pass via ``--downloader-cred``. Authorized-user creds
        (ADC / ``--token-file``, carrying a refresh_token) come back self-refreshing;
        a bare ``--token`` oauth2 cred returns a static token; a service account returns
        its signing credential. Returns ``(credentials, email)`` or ``(None, "")`` when
        the credential is missing or cannot be built.
        """
        cred = self.data_master.get_credential(self.workspace_id, credname)
        if not cred:
            return None, ""
        credtype = str(cred.get("credtype") or "")
        email = str(cred.get("email") or "")
        try:
            blob = cred.get("session_creds")
            if credtype in ("adc", "adc-file", "oauth2"):
                auth_json = json.loads(blob)
                if credtype in ("adc", "adc-file") or auth_json.get("refresh_token"):
                    # Full authorized-user credential -> auto-refreshes on use.
                    return Credentials.from_authorized_user_info(auth_json), email
                return Credentials(token=auth_json["token"]), email
            if credtype == "service":
                return service_account.Credentials.from_service_account_info(json.loads(blob)), email
        except Exception:
            print(f"{UtilityTools.RED}[X] Could not build credential '{credname}'.{UtilityTools.RESET}")
            return None, ""
        return None, ""

    def add_oauth2_account(self, credname, token=None, token_file=None, authorized_info=None, project_id=None,adc_filepath = None, tokeninfo = False, scopes = None, email = None, assume = False, refresh_attempt = False):
        """Register a new OAuth2/ADC credential under credname and store it in the DB.

        Builds credentials from a raw token, an ADC file, or ambient gcloud ADC
        (see _load_new_oauth_credentials), optionally enriches scopes/email via the
        tokeninfo endpoint, inserts the cred row, and seeds an
        abstract_tree_hierarchy entry + global project cache when a project id is
        known. refresh_attempt=True bypasses the duplicate-name guard (used when
        re-storing rotated creds). assume=True immediately loads it as the active
        credential.

        Returns:
            None on duplicate credname; -1 if no credentials could be built;
            otherwise no explicit value (creds added, possibly assumed).
        """
        if not refresh_attempt and self.data_master.get_credential(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists. Try again with a new credname.{UtilityTools.RESET}")
            return None

        credentials, type_of_cred, detected_project_id = None, None, None
        tokeninfo_check = False
        project_id = project_id or "Unknown"
       
        try:
            credentials, type_of_cred, detected_project_id = self._load_new_oauth_credentials(
                token=token,
                token_file=token_file,
                authorized_info=authorized_info,
                adc_filepath=adc_filepath,
            )
            if credentials is None:
                return -1

            if detected_project_id:
                project_id = detected_project_id

            serialized_creds = credentials.to_json()
            json_creds = json.loads(serialized_creds)
            
            if tokeninfo:
                if type_of_cred == "oauth2" and json_creds.get("token"):
                    scopes, email = self.call_tokeninfo(json_creds["token"])
                else:
                    tokeninfo_check = True
               
                                        
            if project_id and project_id != "Unknown":
                print("[*] Project ID of credentials is: " + project_id)
            else:
                print("[*] Project ID of credentials is Unknown. Set it via workspace with `projects set <project_id>`.")
            
            self.data_master.insert_creds(self.workspace_id, credname, type_of_cred, project_id, serialized_creds, email = email, scopes = str(scopes)) 
            if project_id and project_id != "Unknown":
                self.insert_data('abstract_tree_hierarchy', {"project_id":project_id,"name":"Unknown"}, only_if_new_columns = ["project_id"])

            if project_id and project_id != "Unknown" and project_id not in self.global_project_list:
                self.global_project_list.append(project_id)

            # Assume the creds we just inserted

            print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Credentials successfuly added{UtilityTools.RESET}") 

            if assume:
                self.load_stored_creds(credname, tokeninfo_check = tokeninfo_check)
                
        except Exception:
            print("No default credentials were detected. If needed exit ths program and run 'gcloud auth login'")
            print(traceback.format_exc())

    # https://google-auth.readthedocs.io/en/master/reference/google.oauth2.service_account.html
    # Add service account. If successfull add to database
    def add_service_account(self, filename, credname, email = None, sa_info = None, assume = False, refresh_attempt = False):
        """Register a service-account key under credname and store it in the DB.

        Loads the SA key from `filename` (or inline JSON `sa_info`), extracts
        project_id/client_email/scopes, inserts the cred row as type "service", and
        optionally assumes it. refresh_attempt=True bypasses the duplicate-name
        guard. Unlike OAuth creds, SA creds carry no access_token; the Google
        client library signs requests from the key directly.

        Returns:
            None on duplicate credname; otherwise no explicit value.
        """
        if not refresh_attempt and self.data_master.get_credential(self.workspace_id, credname):
            print(f"[X] Apologies, {credname} already exists. Try again with a new credname.")
            return None

        if sa_info:
            serialized_creds = json.loads(sa_info)
        else:
            with open(filename) as handle:
                serialized_creds = json.load(handle)

        project_id = serialized_creds.get("project_id", "Unknown")
        
        if not email:
            email = serialized_creds.get("client_email")
        
        scopes = serialized_creds.get("scopes")

        if project_id == "Unknown":
            self.data_master.save_service_row(
                "abstract_tree_hierarchy",
                {"type":"project","parent":"None","project_id":project_id,"name":"NA"},
            )
                
        self.data_master.insert_creds(self.workspace_id, credname, "service", project_id, json.dumps(serialized_creds), email = email, scopes = scopes) 
   
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Credentials successfuly added{UtilityTools.RESET}") 

        if assume:
            
            self.load_stored_creds(credname)


    def get_session_data(self, table_name, columns="*", conditions=None, *, where=None, params=None):
        """Read workspace-scoped rows from the SESSION database (vs the service DB).

        Same contract as get_data but targets the session DB. Main-thread only
        (DataController is single-threaded); do not call from a worker thread.
        """
        return self._workspace_select_rows(
            table_name,
            db="session",
            columns=columns,
            conditions=conditions,
            where=where,
            params=params,
        )

    def update_oauth2_account(self, credname, credtype=None, email=None, default_project=None,scopes=None, session_creds=None):
        """Update fields of a stored credential, defaulting unset fields to session values.

        For email/scopes/default_project, a None argument means "keep the current
        session value" (and these are written back), not "leave the DB column
        alone" -- so the row stays consistent with the live session. Used by the
        refresh path to persist rotated session_creds.
        """
        try:
            updates = {}

            if credtype:
                updates["credtype"] = credtype

            if email:
                updates["email"] = email
                self.email = email
            else:
                updates["email"] = self.email

            if scopes:
                updates["scopes"] = str(scopes)
                self.scopes = scopes
            else:
                updates["scopes"] = str(self.scopes)

            if session_creds:
                updates["session_creds"] = session_creds

            if default_project:
                updates["default_project"] = default_project
                self.default_project_id = default_project
            else:
                updates["default_project"] = self.default_project_id

            self.data_master.update_credential(self.workspace_id, credname, updates)

        except Exception as e:
            print(str(e))
            print("Exception when trying to update oauth creds")

    def get_credinfo(self, credname = None, self_credname = False):
        return self.data_master.get_credential(self.workspace_id, self.credname if self_credname else credname)

    def get_and_save_tokeninfo(self, credname):
        """Query Google's tokeninfo endpoint for an OAuth cred and persist scopes/email.

        Only valid for non-service creds (SA tokens aren't introspectable here).
        Side effect: writes discovered scopes/email back to the cred row.

        Returns:
            (scopes, email) tuple, or (None, None) for service creds / failures.
        """
        cred = self.data_master.get_credential(self.workspace_id, credname)
        if cred["credtype"] != "service":
            access_token = json.loads(cred["session_creds"])["token"]
            scopes, email = self.call_tokeninfo(access_token)
            if scopes or email:
                self.update_oauth2_account(credname, scopes=scopes, email=email)
            return scopes, email
        else:
            print("[X] Can't perform tokeninfo operations with a service account token")
            return None, None

    def call_tokeninfo(self, token: str):
        """Introspect a raw access token via the public tokeninfo endpoint.

        Returns (scopes_list, email) parsed from the response, or (None, None) on a
        non-200. Does not persist anything (see get_and_save_tokeninfo for that).
        """
        print("[*] Checking credentials against https://oauth2.googleapis.com/tokeninfo endpoint...")
        token_url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"

        conn = requests.get(token_url)
        conn_json = conn.json()

        if conn.status_code == 200:
            print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Succeeded in querying tokeninfo. The response is shown below:{UtilityTools.RESET}")
            print(conn_json)

        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed in querying tokeninfo. The response is shown below:{UtilityTools.RESET}")
            print(conn_json)
            return None, None

        scopes = conn_json["scope"].split() if "scope" in conn_json else None
        email = conn_json["email"] if "email" in conn_json else None

        return scopes, email

    ### Project Utility FUnctions

    def sync_projects(self):
        """Promote newly enumerated projects from the asset tree into the workspace list.

        Scans abstract_tree_hierarchy for project rows not yet in the cached
        global_project_list, appends them, and persists the updated set to the
        workspace's projects table. Main-thread only.
        """
        new_projects = [
            row["project_id"]
            for row in self.get_data("abstract_tree_hierarchy", columns=["project_id"], conditions='type="project"')
            if row["project_id"] not in self.global_project_list
        ]
        if not new_projects:
            return
        self.global_project_list.extend(new_projects)
        self.data_master.sync_workspace_projects(self.workspace_id, add=self.global_project_list)
    
    ### Database Bindings/Permissions//Ancestry Utility Functions

    # only_if_new ONLY adds entryif columns don't match what is passed in 
    # update_columns will update columns (as opposed to rewriting everyting)
    def insert_data(self, table_name, save_data, only_if_new_columns = None, update_only = False, dont_change = None, if_column_matches  = None):
        """Upsert one row into a workspace-scoped service table (the primary write API).

        Always injects workspace_id, so callers never write cross-workspace rows.
        Values are stringified before storage (SQLite columns are text). The
        mutually-exclusive modifiers control merge semantics:
          - only_if_new_columns: insert only if no existing row matches these
            columns (won't overwrite).
          - dont_change: preserve these columns on an existing row.
          - if_column_matches: replace the row only when these columns match.
          - update_only: targeted UPDATE keyed by save_data["primary_keys_to_match"]
            (workspace_id is added to the key set); save_data is the update payload.

        INVARIANT: main-thread only. DataController is single-threaded; calling
        this from a parallel_map/ThreadPoolExecutor worker raises
        sqlite3.ProgrammingError. Workers must return results; insert here on the
        main thread.
        """
        if only_if_new_columns:
            save_kwargs = {"only_if_missing": only_if_new_columns}
        elif dont_change:
            save_kwargs = {"dont_change": dont_change}
        elif if_column_matches:
            save_kwargs = {"replace_on": if_column_matches}
        else:
            save_kwargs = {}

        if update_only:
            save_data["primary_keys_to_match"]["workspace_id"] = self.workspace_id
            self.data_master.save_service_row(table_name, update_data=save_data)
            return

        save_payload = {key: str(value) for key, value in save_data.items()}
        save_payload["workspace_id"] = self.workspace_id
        self.data_master.save_service_row(table_name, save_payload, **save_kwargs)

    # Project ID None when more than one is specified
    def insert_actions(
        self,
        actions,
        project_id = None,
        column_name = None,
        evidence_type = ACTION_EVIDENCE_DIRECT_API,
        credname_override = None,
    ):
        """Record discovered permissions as EVIDENCE against one or more credentials.

        Merges `actions` (permission identifiers) into the per-credential action
        tree, tagged with provenance via evidence_type: direct_api (a real API call
        succeeded, implying the permission) vs test_iam_permissions (a
        testIamPermissions probe reported it). Permissions are stored as evidence,
        NOT booleans -- use the correct evidence_type so analysis can tell proven
        access from probed access.

        credname_override targets credentials other than the active one (accepts a
        str or list; blanks are dropped). project_id is accepted for caller symmetry
        but intentionally unused (the action tree is credential-, not project-,
        keyed). column_name optionally scopes the merge to a specific action column.

        INVARIANT: main-thread only (DataController is single-threaded); calling
        from a worker thread raises sqlite3.ProgrammingError.
        """
        _ = project_id
        target_crednames = credname_override or self.credname
        if isinstance(target_crednames, str):
            target_crednames = [target_crednames]

        for target_credname in [str(cred or "").strip() for cred in (target_crednames or []) if str(cred or "").strip()]:
            self.data_master.insert_actions(
                self.workspace_id,
                target_credname,
                actions,
                column_name = column_name,
                evidence_type = evidence_type,
            )

    def find_ancestors(self, asset_name):
        """Return the org/folder/project ancestry chain for a resource from the asset tree.

        Walks the persisted abstract_tree_hierarchy upward from asset_name within
        this workspace. Used for IAM inheritance analysis (a binding on an ancestor
        applies to descendants). Requires the tree to have been populated by a
        prior enumeration run.
        """
        workspace_id = self.workspace_id
        tree = self.data_master.find_ancestors(asset_name, workspace_id)
       
        return tree

    def get_data(self, table_name, columns="*", conditions=None, *, where=None, params=None):
        """Read workspace-scoped rows from a SERVICE table (the primary read API).

        workspace_id is injected automatically, so results are always confined to
        this workspace. Prefer `where={col: value}` (bound parameters) over raw
        `conditions=` strings, which are an injection surface if they interpolate
        caller-supplied values.

        Returns:
            list[dict] of rows (possibly empty); callers commonly `or []` it.

        INVARIANT: main-thread only; do not call from a worker thread.
        """
        return self._workspace_select_rows(
            table_name,
            columns=columns,
            conditions=conditions,
            where=where,
            params=params,
        )

    def execute_sql(self, query: str, *, db: str = "service", fetch_limit: int = 200) -> dict[str, Any]:
        """Run a raw read-only SQL query against one of the DBs (interactive `data` cmd).

        NOT workspace-scoped automatically -- the query is passed through as-is, so
        the caller is responsible for any workspace_id filter. Results are capped at
        fetch_limit rows. Main-thread only.
        """
        return self.data_master.execute_sql(query, db=db, fetch_limit=fetch_limit)

    def add_unauthenticated_permissions(self, unauthenticated_info, project_id = None):
        """Record a permission reachable WITHOUT credentials (member fixed to allUsers).

        Stores a row in iam_unauth_permissions scoped to this workspace and the
        given/session project, hard-coding member="users:allUsers" -- the finding
        that the resource is accessible to anonymous callers. Main-thread only.
        """
        table_name = "iam_unauth_permissions"
        unauthenticated_info["workspace_id"] = self.workspace_id
        if project_id:
            unauthenticated_info["project_id"] = project_id
        else:
            unauthenticated_info["project_id"] = self.project_id
        unauthenticated_info["member"] = "users:allUsers"

        self.data_master.save_service_row(table_name, unauthenticated_info)

    ### Utility Prompt Functions

    def choice_prompt(self, prompt:str, regex = None):
        """Prompt for a free-text answer, optionally re-prompting until it matches regex.

        Returns the entered string, or None if the user hits Ctrl+C (used as a
        cancel signal throughout the interactive flows). In non-interactive
        (drive-through) mode it never blocks on stdin: it returns None (the same
        cancel signal callers already handle) so a module that needs interactive
        input fails/skips cleanly instead of hanging.
        """
        if getattr(self, "_non_interactive", False):
            print(
                f"{UtilityTools.YELLOW}[!] Interactive prompt reached in non-interactive mode; treating as "
                f"cancelled. Run this module in the REPL, or supply the needed values as flags.{UtilityTools.RESET}"
            )
            return None
        try:
            while True:
                user_input = input("> " + prompt).strip()
                if regex:
                    if re.match(regex, user_input):
                        return user_input
                    else:
                        print("Input doesn't match the required pattern. Please try again.")
                else:
                    return user_input
        except KeyboardInterrupt:
            return None
        except Exception as e:
            print("An error occurred:", e)
            print("Try again")

    def choice_selector(self, rows_returned=None, custom_message="", fields=None, chunk_mappings=None, footer_title=None, footer_list=None, header=None):
        """Render a numbered menu and return the selected item (or None on exit/cancel).

        Two modes: a flat list (rows_returned, displaying `fields` of each dict) or
        grouped sections (chunk_mappings, each {"title","data_values"}); empty
        chunks are skipped. An auto-appended "Exit" choice and Ctrl+C both return
        None. The continuous 1-based numbering across chunks is mapped back to the
        originating item via per-chunk offsets.

        Returns:
            The chosen element of rows_returned / a chunk's data_values, or None.
        """
        if getattr(self, "_non_interactive", False):
            # Drive-through: auto-pick when there is exactly one candidate; otherwise
            # skip (return None) rather than block on stdin. Callers already handle None.
            candidates = list(rows_returned or [])
            if not candidates and chunk_mappings:
                for chunk in chunk_mappings:
                    candidates.extend(chunk.get("data_values", []) or [])
            if len(candidates) == 1:
                return candidates[0]
            print(
                f"{UtilityTools.YELLOW}[!] Interactive selection ({len(candidates)} options) reached in "
                f"non-interactive mode; skipping. Run this module in the REPL to select.{UtilityTools.RESET}"
            )
            return None

        def print_entries(entries, start_index, fields):
            for index, entry in enumerate(entries):
                line = f">> [{start_index + index + 1}]"
                if fields:
                    line += " " + ", ".join(str(entry[field]) for field in fields)
                else:
                    line += f" {entry}"
                print(line)

        def calculate_chunk_offsets(chunk_mappings):
            offsets = [0]
            for chunk in chunk_mappings:
                total_length = len(chunk['data_values'])
                offsets.append(offsets[-1] + total_length)
            return offsets

        total_choices = 0
        chunk_offsets = []

        if header:
            print("\n" + header)

        if not chunk_mappings:
            print(f"{UtilityTools.BOLD}> " + custom_message + UtilityTools.RESET)
            if rows_returned:
                print_entries(rows_returned, 0, fields)
                total_choices = len(rows_returned)
        else:
            chunk_offsets = calculate_chunk_offsets(chunk_mappings)
            for i, chunk in enumerate(chunk_mappings):
                title = chunk.get("title", "")
                data_values = chunk.get("data_values", [])
                
                if not data_values:  # Skip chunks with empty data_values
                    continue
                
                print("\n> " + title)
                start_index = chunk_offsets[i]
                print_entries(data_values, start_index, fields)
                total_choices += len(data_values)

        if footer_title:
            print(f"{UtilityTools.BOLD}\n> " + footer_title + UtilityTools.RESET)
            if footer_list:
                for choice in footer_list:
                    print(">> " + choice)

        print(f"> [{total_choices + 1}] Exit\n")

        while True:
            try:
                option = int(input("> Choose an option: ").strip())
                if 1 <= option <= total_choices:
                    break
                elif option == total_choices + 1:
                    return None
                else:
                    print("Choose an index from the ones above.")
            except ValueError:
                print("Please enter a valid number.")
            except KeyboardInterrupt:
                return None

        if not chunk_mappings:
            return rows_returned[option - 1]
        else:
            chunk_offsets = calculate_chunk_offsets(chunk_mappings)
            for i, start_index in enumerate(chunk_offsets[:-1]):
                end_index = chunk_offsets[i + 1]
                if start_index < option <= end_index:
                    data_values = chunk_mappings[i]['data_values']
                    return data_values[option - start_index - 1]

   

    def get_project_name(self, project_id):
        """Look up the human-readable display name for a project id from the asset tree.

        Filters out placeholder "Unknown"/"Uknown" names (note the deliberate match
        of the historical misspelling). Returns the matching abstract_tree_hierarchy
        rows (empty if only a placeholder name is known).
        """
        return self.get_data(
            "abstract_tree_hierarchy",
            columns=["name"],
            conditions='name != "Unknown" AND name != "Uknown"',
            where={"project_id": project_id},
        )
   
    def choose_member(self, type_of_member = None, full_name = False):
        """Interactively resolve an IAM member principal for exploit/grant modules.

        Resolution order: (1) offer the session's own email (disambiguating if
        self.email is a list); (2) otherwise let the user pick an already-enumerated
        SA/user (from iam_service_accounts + workspace_users + sync_users()) or type
        a new member. type_of_member="service_accounts" restricts to SAs only.

        Returns:
            A member string in GCP form: "serviceAccount:<email>", "user:<email>",
            or (for service accounts when full_name=True) the full
            projects/-/serviceAccounts/<email> resource name. None if cancelled or
            nothing is available.
        """
        session_email = self.email
        if isinstance(session_email, list):
            normalized_emails = [
                str(value).strip()
                for value in session_email
                if value is not None and str(value).strip() and str(value).strip() != "None"
            ]
            if len(normalized_emails) == 1:
                session_email = normalized_emails[0]
            elif len(normalized_emails) > 1:
                session_email = self.choice_selector(
                    normalized_emails,
                    "Multiple emails are set on the session. Choose one to use:",
                )
            else:
                session_email = None
            self.email = session_email

        if session_email != "None" and session_email is not None:

            choice = self.choice_prompt(f"Do you want to use {session_email} set on the session? [y/n]")

            if choice and choice.lower() == "y":
                return session_email
        
        # If email is not supplied and not set in config, list serivce accoutns ]

        choice = self.choice_selector(["Existing SA/User","New Member"],"Do you want to use an enumerated SA/User or enter a new email?")
        if choice == "Existing SA/User":
            rows_returned: list[dict[str, str]] = []

            service_accounts = self.get_data(
                "iam_service_accounts",
                columns=["name", "email", "type"],
            ) or []
            for entity in service_accounts:
                email_of_entity = str(entity.get("email") or "").strip()
                if not email_of_entity:
                    continue
                name = str(entity.get("name") or "").strip()
                project_id = extract_project_id_from_resource(name, fallback_project="-")
                rows_returned.append(
                    {
                        "name": name,
                        "email": email_of_entity,
                        "type": "service_account",
                        "printout": f"(service_account) - {project_id} - {email_of_entity}",
                    }
                )

            if type_of_member != "service_accounts":
                known_user_emails: set[str] = set()
                for row in (self.get_data("workspace_users", columns=["email"]) or []):
                    email_of_entity = str(row.get("email") or "").strip()
                    if not email_of_entity or email_of_entity in known_user_emails:
                        continue
                    known_user_emails.add(email_of_entity)
                    rows_returned.append(
                        {
                            "name": f"user:{email_of_entity}",
                            "email": email_of_entity,
                            "type": "user",
                            "printout": f"(user) - {email_of_entity}",
                        }
                    )

                for email_of_entity in self.sync_users():
                    if not email_of_entity or email_of_entity in known_user_emails:
                        continue
                    known_user_emails.add(email_of_entity)
                    rows_returned.append(
                        {
                            "name": f"user:{email_of_entity}",
                            "email": email_of_entity,
                            "type": "user",
                            "printout": f"(user) - {email_of_entity}",
                        }
                    )

            if len(rows_returned) == 0:
                print("[X] No service accounts/users have been enumerated. Consider re-running IAM/Cloud Identity modules or specify --member.")
                return None

            sorted_data = sorted(rows_returned, key=lambda x: x["printout"])
            selected = self.choice_selector(
                sorted_data,
                "Choose an existing member from below. Type New if you want to manually specify the name:",
                fields=["printout"],
            )
            if not selected:
                return None

            selected_type = str(selected.get("type") or "").strip().lower()
            selected_email = str(selected.get("email") or "").strip()
            selected_name = str(selected.get("name") or "").strip()

            if selected_type == "service_account":
                if full_name:
                    return selected_name or f"projects/-/serviceAccounts/{selected_email}"
                return "serviceAccount:" + selected_email

            return "user:" + selected_email

        elif choice == "New Member":
                choice = self.choice_prompt("Provide the member account email below in the format user:<email> or serviceAccount:<email>: ", regex = r'(\w+):([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
            
                return choice

        print("[X] No members found. Consider running rerunning the module specifying the \"--member\" flag")   
        return None

    def choose_role(self, suggested_roles, chosen_role = None, default_role = None):
        """Interactively resolve an IAM role, short-circuiting if one is already chosen.

        If chosen_role is provided it's returned as-is (non-interactive path).
        Otherwise presents suggested_roles plus a "Different Role" free-text escape
        hatch. A label containing "(Default)" is stripped to its bare role id.

        Returns:
            A "roles/<name>" string, default_role, or None if cancelled.
        """
        if chosen_role:
            return chosen_role

        suggested_roles.append("Different Role")
        
        role_choice = self.choice_selector(suggested_roles,"A list of roles are supplied below. Choose one or enter your own:")
        
        if not role_choice:
            return None

        if role_choice == "Different Role":
            return self.choice_prompt("Provide the role name to attach in the format roles/role_name: ")

        if "(Default)" in role_choice:
            return role_choice.split()[0]
        return role_choice

    def sync_users(self):
        """
        Discover principal emails from IAM allow policies and keep lightweight
        identity rows in Workspace tables:
          - user:*  -> workspace_users
          - group:* -> workspace_groups

        Returns:
            list[str]: unique user emails (for caller convenience prompts).
        """
        from gcpwn.modules.everything.utilities.helpers import iter_member_roles_from_policy, policy_dict

        allow_rows = self._workspace_select_rows("iam_allow_policies", columns=["policy"])

        discovered_user_emails: set[str] = set()
        discovered_group_emails: set[str] = set()
        for row in allow_rows or []:
            policy = policy_dict(row.get("policy"))
            if not policy:
                continue
            for member_token, _roles in iter_member_roles_from_policy(policy):
                token = str(member_token or "").strip()
                if token.startswith("user:"):
                    email = token.replace("user:", "", 1).strip()
                    if email:
                        discovered_user_emails.add(email)
                elif token.startswith("group:"):
                    email = token.replace("group:", "", 1).strip()
                    if email:
                        discovered_group_emails.add(email)

        workspace_user_rows = self.get_data("workspace_users", columns=["customer_id", "email"]) or []
        workspace_group_rows = self.get_data("workspace_groups", columns=["customer_id", "name", "email"]) or []
        known_user_emails = {
            str(row.get("email") or "").strip()
            for row in workspace_user_rows
            if str(row.get("email") or "").strip()
        }
        known_group_emails = {
            str(row.get("email") or "").strip()
            for row in workspace_group_rows
            if str(row.get("email") or "").strip()
        }

        customer_id = str(getattr(self.workspace_config, "workspace_customer_id", "") or "").strip()
        if not customer_id:
            for row in workspace_user_rows + workspace_group_rows:
                candidate = str(row.get("customer_id") or "").strip()
                if candidate:
                    customer_id = candidate
                    break
        if not customer_id:
            customer_id = "unknown"

        for email in sorted(discovered_user_emails - known_user_emails):
            self.insert_data(
                "workspace_users",
                {
                    "customer_id": customer_id,
                    "email": email,
                    "user_id": "",
                    "display_name": email,
                    "raw_json": json.dumps(
                        {"source": "iam_allow_policies", "discovered_member": f"user:{email}"},
                        ensure_ascii=False,
                    ),
                },
                only_if_new_columns=["customer_id", "email"],
            )

        for email in sorted(discovered_group_emails - known_group_emails):
            group_name = f"groups/discovered/{email}"
            self.insert_data(
                "workspace_groups",
                {
                    "customer_id": customer_id,
                    "name": group_name,
                    "email": email,
                    "display_name": email,
                    "description": "",
                    "labels": "",
                    "create_time": "",
                    "update_time": "",
                    "raw_json": json.dumps(
                        {"source": "iam_allow_policies", "discovered_member": f"group:{email}"},
                        ensure_ascii=False,
                    ),
                },
                only_if_new_columns=["customer_id", "name"],
            )

        # Return union of known + discovered users for interactive member prompts.
        return sorted(known_user_emails.union(discovered_user_emails))

    def get_configs(self):
        """Load this workspace's persisted config into self.workspace_config.

        Side effect: also applies the saved std_output_format to the global
        UtilityTools.TABLE_OUTPUT_FORMAT so table rendering matches the workspace
        preference. Tolerates a missing/blank config (warns, keeps defaults).
        """
        potential_config = self.data_master.get_workspace(self.workspace_id, columns="workspace_config")
        if potential_config:
            self.workspace_config.from_json(potential_config)
            try:
                UtilityTools.TABLE_OUTPUT_FORMAT = str(self.workspace_config.std_output_format or "text").strip().lower()
            except Exception:
                pass
        else:
            print("[X] Proceeding but no workspace configuration was loaded")

    def set_configs(self):
        """Persist the in-memory workspace_config back to the DB and re-apply output format.

        Inverse of get_configs: serializes self.workspace_config to the workspace
        row and refreshes the global table output format. Call after mutating
        config so changes survive across sessions.
        """
        new_config_settings = self.workspace_config.to_json_string()
        self.data_master.update_workspace(self.workspace_id, {"workspace_config": new_config_settings})
        try:
            UtilityTools.TABLE_OUTPUT_FORMAT = str(self.workspace_config.std_output_format or "text").strip().lower()
        except Exception:
            pass
