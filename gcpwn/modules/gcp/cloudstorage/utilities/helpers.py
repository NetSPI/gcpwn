"""Cloud Storage enumeration/exploit helpers (buckets, blobs, HMAC keys).

Unlike most services these resources do NOT subclass GcpListResource; they wrap the
google-cloud-storage client directly and support two access modes selected per call:
 - "standard": JSON API via google.cloud.storage with the session credentials.
 - "hmac": S3-compatible XML API via boto3 using an HMAC access_id/secret (see
   _build_hmac_s3_client). XML rows are partial (name/time only) so save() switches to
   insert-if-new. HMAC mode is how stolen HMAC keys are exercised against buckets/objects.
Bucket access is probed both authenticated and UNAUTHENTICATED (allUsers) -- the unauth
results land in a dedicated unauth table, not the uniform action tree.
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import sys
import time
from threading import Lock
from types import SimpleNamespace
from typing import List, Union, Optional, Tuple
import textwrap

# Typing libraries
from gcpwn.core.session import SessionUtility
from google.cloud.storage.client import Client
from google.cloud.storage.blob import Blob
from google.cloud.storage.bucket import Bucket
from google.cloud.storage.hmac_key import HMACKeyMetadata

from gcpwn.modules.gcp.iam.utilities.helpers import bucket_get_iam_policy,bucket_set_iam_policy

import json
import os
import requests
import re
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import DownloadBudget, get_cached_rows, handle_service_error, parse_csv_file_args
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict

from google.cloud import storage
from google.api_core.iam import Policy

from google.api_core.exceptions import NotFound
from google.api_core.exceptions import Forbidden
from gcpwn.core.contracts import HashableResourceProxy


class HashableHMACKeyMetadata(HashableResourceProxy):
    def __init__(self, hmac_key, validated=True):
        super().__init__(
            hmac_key,
            key_fields=("access_id",),
            validated=validated,
            repr_fields=("access_id", "service_account_email"),
        )


def _build_hmac_s3_client(access_id: str, secret_key: str):
    """Build a boto3 S3 client pointed at storage.googleapis.com for HMAC/XML access.

    Returns None (with a printed hint) if boto3 is unavailable. Uses s3v4 signing and
    path-style addressing so GCS's S3-interop XML API accepts the request. WHY: lets gcpwn
    exercise stolen HMAC keys against Cloud Storage without GCP-native credentials.
    """
    try:
        import boto3  # type: ignore
        from botocore.config import Config  # type: ignore
    except ImportError:
        print(
            f"{UtilityTools.RED}[X] HMAC XML API access requires `boto3`. "
            f"Install project dependencies or `pip install boto3`.{UtilityTools.RESET}"
        )
        return None

    return boto3.client(
        "s3",
        region_name="auto",
        endpoint_url="https://storage.googleapis.com",
        aws_access_key_id=access_id,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
     
class HashableCloudStorageBucket(HashableResourceProxy):
    def __init__(self, bucket, validated: bool = True):
        super().__init__(bucket, key_fields=("name",), validated=validated, repr_fields=("name",))


class HashableCloudStorageBlob(HashableResourceProxy):
    def __init__(self, blob, validated: bool = True):
        super().__init__(blob, key_fields=("name",), validated=validated, repr_fields=("name",))


class _CloudStorageBaseResource:
    def __init__(self, session):
        self.session = session

    @property
    def debug(self) -> bool:
        return getattr(self.session, "debug", False)

    def build_client(self, project_id: str):
        return storage.Client(credentials=self.session.credentials, project=project_id)


class CloudStorageHmacKeysResource(_CloudStorageBaseResource):
    """Enumerate/create/update HMAC keys into ``cloudstorage_hmac_keys`` (incl. captured secrets).

    HMAC secrets are only returned by create_hmac_key, so create_with_client returns
    (metadata, secret) and save() preserves the secret column (dont_change). These secrets
    feed the XML/HMAC access mode used to read buckets without GCP-native credentials.
    """

    TABLE_NAME = "cloudstorage_hmac_keys"
    COLUMNS = ["access_id", "state", "service_account_email", "secret"]
    LIST_PERMISSION = "storage.hmacKeys.list"
    GET_PERMISSION = "storage.hmacKeys.get"

    @staticmethod
    def list_with_client(storage_client: Client, debug: Optional[bool] = False) -> Union[List, None]:
        if debug:
            print("[DEBUG] Listing HMAC keys...")
        try:
            keys = list(storage_client.list_hmac_keys(show_deleted_keys=True))
        except Exception as e:
            project_id = getattr(storage_client, "project", None)
            handle_service_error(
                e,
                api_name="storage.hmacKeys.list",
                resource_name=f"projects/{project_id}",
                service_label="Cloud Storage",
                project_id=project_id,
                return_not_enabled=False,
            )
            return None
        if debug:
            print("[DEBUG] Successful completed list_hmac_keys...")
        return keys

    @staticmethod
    def get_with_client(storage_client: Client, access_id: str, debug: Optional[bool] = False) -> Union[HMACKeyMetadata, None]:
        if debug:
            print(f"[DEBUG] Getting HMAC key {access_id}...")
        try:
            key = storage_client.get_hmac_key_metadata(access_id)
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.hmacKeys.get",
                resource_name=access_id,
                service_label="Cloud Storage",
                project_id=getattr(storage_client, "project", None),
                return_not_enabled=False,
            )
            return None
        if debug:
            print("[DEBUG] Successful completed get_hmac_key...")
        return key

    @staticmethod
    def create_with_client(storage_client: Client, sa_email: str, debug: Optional[bool] = False) -> Union[Tuple[None, None], Tuple[str, HMACKeyMetadata]]:
        """Create an HMAC key for a service account; return (metadata, secret) or (None, None).

        The secret is shown ONLY here, never on subsequent get/list -- callers must persist it
        immediately (see save_key). 403 on hmacKeys.create yields (None, None).
        """
        if debug:
            print(f"[DEBUG] Creating HMAC key for {sa_email}...")
        try:
            key, secret = storage_client.create_hmac_key(sa_email)
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.hmacKeys.create",
                resource_name=sa_email,
                service_label="Cloud Storage",
                project_id=getattr(storage_client, "project", None),
                return_not_enabled=False,
            )
            return (None, None)
        if debug:
            print("[DEBUG] Successful completed create_hmac_key...")
        return (key, secret)

    @staticmethod
    def update_with_client(storage_client: Client, access_id: str, state: str, debug: Optional[bool] = False) -> Union[int, None]:
        if debug:
            print(f"[DEBUG] Updating HMAC key for {access_id}...")
        try:
            hmac_object = storage_client.get_hmac_key_metadata(access_id)
            hmac_object.state = state
            hmac_object.update()
            if debug:
                print("[DEBUG] Successful completed update_hmac_key...")
            return 1
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.hmacKeys.update",
                resource_name=access_id,
                service_label="Cloud Storage",
                project_id=getattr(storage_client, "project", None),
                return_not_enabled=False,
            )
        return None

    @staticmethod
    def _to_dict(key) -> dict:
        # HMAC keys carry no resource "name"; the framework keys on row["name"],
        # so mirror access_id there. The secret only exists after create_hmac_key.
        if isinstance(key, dict):
            row = dict(key)
        else:
            row = {
                "access_id": str(getattr(key, "access_id", "") or ""),
                "state": str(getattr(key, "state", "") or ""),
                "service_account_email": str(getattr(key, "service_account_email", "") or ""),
            }
            secret = getattr(key, "secret", None)
            if secret:
                row["secret"] = secret
        row.setdefault("name", row.get("access_id", ""))
        return row

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        rows = self.list_with_client(self.build_client(project_id), debug=self.debug)
        if rows in ("Not Enabled", None):
            return rows
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return [self._to_dict(key) for key in rows]

    def get(self, *, resource_id: str, action_dict=None, project_id: str | None = None, **_):
        pid = str(project_id or self.session.project_id or "")
        row = self.get_with_client(self.build_client(pid), resource_id, debug=self.debug)
        if not row:
            return row
        record_permissions(
            action_dict,
            permissions=self.GET_PERMISSION,
            scope_key="project_permissions",
            scope_label=pid,
        )
        return self._to_dict(row)

    def save(self, rows, *, project_id: str | None = None, location: str | None = None, **_):
        pid = str(project_id or self.session.project_id or "")
        for row in rows or []:
            payload = {k: v for k, v in row.items() if k != "name"} if isinstance(row, dict) else row
            save_to_table(
                self.session,
                self.TABLE_NAME,
                payload,
                extra_builder=lambda obj, raw: {
                    "project_id": raw.get("project_id") or raw.get("project") or pid or getattr(obj, "project", ""),
                },
                dont_change=["secret"],
            )

    @staticmethod
    def save_key(key: HMACKeyMetadata, session: SessionUtility, secret: Optional[str] = None) -> None:
        """Attach a freshly-created secret to the key metadata and persist the row (main thread)."""
        if key and secret is not None:
            setattr(key, "secret", secret)
        CloudStorageHmacKeysResource(session).save([key] if key else [])

    def list_saved_secrets(self):
        """Return previously-captured HMAC keys that have a non-empty secret (usable for XML mode)."""
        rows_returned = self.session.get_data(
            "cloudstorage_hmac_keys",
            columns=["access_id", "secret", "service_account_email"],
            conditions="secret != ?",
            params=("",),
        )
        return rows_returned or None

    def resolve_service_account_email(self, *, project_id: str, access_id: str) -> str | None:
        normalized_access_id = str(access_id or "").strip()
        if not normalized_access_id:
            return None

        cached = self.session.get_data(
            "cloudstorage_hmac_keys",
            columns=["service_account_email"],
            where={"access_id": normalized_access_id},
        ) or []
        for row in cached:
            email = str((row or {}).get("service_account_email") or "").strip()
            if email:
                return email

        row = self.get(project_id=project_id, resource_id=access_id)
        if row:
            self.save([row])
            return str(getattr(row, "service_account_email", "") or "").strip() or None
        return None

    def resolve_action_crednames(self, *, project_id: str, access_id: str) -> list[str]:
        """Map an HMAC access_id to the credname(s) of its owning SA for action provenance.

        Resolves the key's service-account email, then looks up matching session crednames.
        Falls back to the SA email, or ``hmac:<access_id>`` when nothing resolves, so HMAC-mode
        actions are still attributable.
        """
        email = self.resolve_service_account_email(project_id=project_id, access_id=access_id)
        if not email:
            normalized_access_id = str(access_id or "").strip()
            return [f"hmac:{normalized_access_id}"] if normalized_access_id else []

        rows = self.session.get_session_data("session", columns=["credname"], where={"email": email}) or []
        crednames = [str((row or {}).get("credname") or "").strip() for row in rows if str((row or {}).get("credname") or "").strip()]
        return crednames or [email]

class CloudStorageBucketsResource(_CloudStorageBaseResource):
    """Enumerate buckets into ``cloudstorage_buckets`` and probe per-bucket IAM (auth + unauth).

    Supports standard (JSON) and HMAC/XML listing; the active mode is remembered on
    _access_mode so save() knows whether rows are full or partial. Bucket permission
    discovery (test_bucket_permissions / get_iam_permissions) checks both the current
    credentials AND anonymous allUsers access.
    """

    TABLE_NAME = "cloudstorage_buckets"
    COLUMNS = ["name", "location", "storage_class", "time_created"]
    LIST_PERMISSION = "storage.buckets.list"
    GET_PERMISSION = "storage.buckets.get"
    ACTION_RESOURCE_TYPE = "buckets"
    # Non-empty so the framework runs IAM; the real probe is test_bucket_permissions
    # (authenticated AND unauthenticated), encapsulated in test_iam_permissions below.
    TEST_IAM_PERMISSIONS = ("storage.buckets.getIamPolicy",)
    _access_mode = "standard"

    @staticmethod
    def _to_dict(bucket) -> dict:
        # resource_to_dict surfaces Bucket._properties flat (location/storageClass/...);
        # HMAC/XML SimpleNamespaces and dict rows pass through unchanged.
        row = resource_to_dict(bucket)
        row.setdefault("name", str(getattr(bucket, "name", "") or ""))
        return row

    @staticmethod
    def check_existence(bucket_name: str, debug: Optional[bool] = False) -> bool:
        """Probe whether a bucket name exists via an unauthenticated HEAD (400/404 == absent).

        Used by bucket-bruteforce flows to detect valid global bucket names with no creds.
        """
        if debug:
            bucket_url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
            print(f"[DEBUG] Checking {bucket_url}")
        response = requests.head(f"https://www.googleapis.com/storage/v1/b/{bucket_name}")
        if response.status_code not in [400, 404]:
            print(f"[*] Bucket {bucket_name} appears to exist with status code {response.status_code}")
            return True
        if debug:
            print(f"[DEBUG] Bucket {bucket_name} returned {response.status_code}. Does not exist.")
        return False

    @staticmethod
    def test_bucket_permissions(
        client: Union[Client, None],
        bucket_name: str,
        gcpbucketbrute: Optional[bool] = False,
        authenticated: Optional[bool] = False,
        unauthenticated: Optional[bool] = False,
        debug: Optional[bool] = False,
    ) -> Tuple[List, List]:
        """Test a fixed set of bucket/object perms both authenticated and unauthenticated (allUsers).

        Authenticated check uses bucket.test_iam_permissions; the unauthenticated check hits the
        public testPermissions REST endpoint with no auth header. With gcpbucketbrute=True it
        prints a gcpbucketbrute-style vulnerability report (setIamPolicy = privesc, etc.).
        Returns (authenticated_permissions, unauthenticated_permissions).
        """
        authenticated_permissions, unauthenticated_permissions = [], []

        if client and authenticated:
            try:
                authenticated_permissions = client.bucket(bucket_name).test_iam_permissions(
                    permissions=[
                        "storage.buckets.delete",
                        "storage.buckets.get",
                        "storage.buckets.getIamPolicy",
                        "storage.buckets.setIamPolicy",
                        "storage.buckets.update",
                        "storage.objects.create",
                        "storage.objects.delete",
                        "storage.objects.get",
                        "storage.objects.list",
                        "storage.objects.update",
                    ]
                )
            except NotFound:
                print(f"[-] 404  {bucket_name} does not appear to exist ")
                authenticated_permissions = []
            except Forbidden:
                print(f"[-] 403 Bucket Exists, but the user does not have storage.testIamPermissions permissions on bucket {bucket_name} ")
                authenticated_permissions = []
            except Exception as e:
                print(f"[-] 403 TestIAMPermissions failed for {bucket_name} for the following reason:\n{e}")
                authenticated_permissions = []

            if gcpbucketbrute and authenticated_permissions:
                print(f"\n    AUTHENTICATED ACCESS ALLOWED: {bucket_name}")
                if "storage.buckets.setIamPolicy" in authenticated_permissions:
                    print("        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)")
                if "storage.objects.list" in authenticated_permissions:
                    print("        - AUTHENTICATED LISTABLE (storage.objects.list)")
                if "storage.objects.get" in authenticated_permissions:
                    print("        - AUTHENTICATED READABLE (storage.objects.get)")
                if (
                    "storage.objects.create" in authenticated_permissions
                    or "storage.objects.delete" in authenticated_permissions
                    or "storage.objects.update" in authenticated_permissions
                ):
                    print("        - AUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)")
                print("        - ALL PERMISSIONS:")
                print(textwrap.indent(f"{json.dumps(authenticated_permissions, indent=4)}\n", "        "))
            elif gcpbucketbrute:
                print("\n    NO AUTHENTICATED ACCESS ALLOWED")

        if unauthenticated:
            unauth_url = (
                "https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions"
                "?permissions=storage.buckets.delete&permissions=storage.buckets.get"
                "&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy"
                "&permissions=storage.buckets.update&permissions=storage.objects.create"
                "&permissions=storage.objects.delete&permissions=storage.objects.get"
                "&permissions=storage.objects.list&permissions=storage.objects.update"
            ).format(bucket_name)
            unauthenticated_permissions_request = requests.get(unauth_url).json()
            if unauthenticated_permissions_request.get("permissions"):
                unauthenticated_permissions = unauthenticated_permissions_request["permissions"]
                if gcpbucketbrute:
                    print(f"\n    UNAUTHENTICATED ACCESS ALLOWED: {bucket_name}")
                    if "storage.buckets.setIamPolicy" in unauthenticated_permissions:
                        print("        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)")
                    if "storage.objects.list" in unauthenticated_permissions:
                        print("        - UNAUTHENTICATED LISTABLE (storage.objects.list)")
                    if "storage.objects.get" in unauthenticated_permissions:
                        print("        - UNAUTHENTICATED READABLE (storage.objects.get)")
                    if (
                        "storage.objects.create" in unauthenticated_permissions
                        or "storage.objects.delete" in unauthenticated_permissions
                        or "storage.objects.update" in unauthenticated_permissions
                    ):
                        print("        - UNAUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)")
                    print("        - ALL PERMISSIONS:")
                    print(textwrap.indent(f"{json.dumps(unauthenticated_permissions, indent=4)}\n", "            "))

            if gcpbucketbrute and not (authenticated_permissions or unauthenticated_permissions):
                print(f"    EXISTS: {bucket_name}")

        return authenticated_permissions, unauthenticated_permissions

    @staticmethod
    def list_with_client(storage_client: Client, debug: Optional[bool] = False) -> Union[List, None]:
        if debug:
            print("[DEBUG] Getting buckets...")
        try:
            bucket_list = list(storage_client.list_buckets())
        except Exception as e:
            project_id = getattr(storage_client, "project", None)
            handle_service_error(
                e,
                api_name="storage.buckets.list",
                resource_name=f"projects/{project_id}",
                service_label="Cloud Storage",
                project_id=project_id,
                return_not_enabled=False,
            )
            return None
        if debug:
            print("[DEBUG] Successful completed list_buckets...")
        return bucket_list

    @staticmethod
    def get_with_client(storage_client: Client, bucket_name: str, debug: Optional[bool] = False) -> Union[Bucket, None]:
        if debug:
            print(f"[DEBUG] Getting bucket metadata for {bucket_name} ...")
        try:
            bucket_meta = storage_client.get_bucket(bucket_name)
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.buckets.get",
                resource_name=bucket_name,
                service_label="Cloud Storage",
                project_id=getattr(storage_client, "project", None),
                return_not_enabled=False,
            )
            return None
        if debug:
            print("[DEBUG] Successfully completed get_bucket ...")
        return bucket_meta

    @staticmethod
    def list_with_hmac(storage_client, access_id, secret, project_id, debug=False):
        """List buckets via the S3/XML API using an HMAC key; rows are partial SimpleNamespaces.

        Only name/time_created are available over XML, so downstream save() uses insert-if-new.
        Returns None on failure.
        """
        _ = (storage_client, project_id, debug)
        client = _build_hmac_s3_client(access_id, secret)
        if client is None:
            return None
        try:
            response = client.list_buckets()
            return [
                SimpleNamespace(
                    name=str(bucket.get("Name") or ""),
                    time_created=str(bucket.get("CreationDate") or ""),
                )
                for bucket in response.get("Buckets", [])
                if bucket.get("Name")
            ]
        except Exception as e:
            print("[X] Failed to list buckets via boto3 XML API client for following reason:")
            print(str(e))
            return None

    def manual_targets(self, *, project_id: str, bucket_names: str | None = None, bucket_file: str | None = None):
        """Build Bucket objects for caller-supplied bucket names (CSV string or file), skipping list."""
        client = self.build_client(project_id)
        return [client.bucket(name) for name in parse_csv_file_args(bucket_names, bucket_file)]

    def list(self, *, project_id: str, location: str | None = None, access_mode: str = "standard",
             access_id: str | None = None, hmac_secret: str | None = None, action_dict=None):
        self._access_mode = access_mode  # remembered so save() picks XML dedup in HMAC mode
        client = self.build_client(project_id)
        if access_mode == "hmac":
            rows = self.list_with_hmac(client, access_id, hmac_secret, project_id, self.debug)
        else:
            rows = self.list_with_client(client, debug=self.debug)
        if rows in ("Not Enabled", None):
            return rows
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return [self._to_dict(bucket) for bucket in rows]

    def get(self, *, resource_id: str, action_dict=None, project_id: str | None = None,
            access_mode: str = "standard", **_):
        if access_mode == "hmac":
            return None  # XML/HMAC API has no bucket-metadata get; keep the listed row
        pid = str(project_id or self.session.project_id or "")
        row = self.get_with_client(self.build_client(pid), resource_id, debug=self.debug)
        if not row:
            return row
        record_permissions(
            action_dict,
            permissions=self.GET_PERMISSION,
            project_id=pid,
            resource_type=self.ACTION_RESOURCE_TYPE,
            resource_label=resource_id,
        )
        return self._to_dict(row)

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        auth_perms, unauth_perms = self.test_bucket_permissions(
            self.build_client(project_id),
            resource_id,
            authenticated=True,
            unauthenticated=True,
            debug=self.debug,
        )
        if auth_perms:
            record_permissions(
                action_dict,
                permissions=auth_perms,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return auth_perms, unauth_perms

    def test_iam_permissions(self, *, resource_id: str, action_dict=None, **_):
        """Uniform IAM entry point: record authenticated perms as evidence, route unauth to its table.

        Authenticated bucket perms merge into action_dict (the uniform action tree, provenance
        test_iam_permissions); anonymous allUsers perms go to the dedicated unauthenticated table
        via session.add_unauthenticated_permissions. Returns the authenticated permission list.
        """
        # Uniform IAM entry point: authenticated perms -> action_dict (uniform tree);
        # unauthenticated allUsers perms -> the dedicated unauth table (storage-specific).
        pid = str(self.session.project_id or "")
        auth_perms, unauth_perms = self.get_iam_permissions(
            project_id=pid, resource_id=resource_id, action_dict=action_dict
        )
        if unauth_perms:
            self.session.add_unauthenticated_permissions(
                {"name": resource_id, "type": "bucket", "permissions": str(unauth_perms)},
                project_id=pid,
            )
        return auth_perms

    @staticmethod
    def add_iam_member(
        storage_client: Client,
        bucket_name: Bucket,
        member: str,
        bucket_project_id: str,
        action_dict: dict,
        brute: Optional[bool] = False,
        role: Optional[str] = None,
        debug: Optional[bool] = False,
    ):
        """Add (or with --brute, OVERWRITE) a member/role binding on a bucket's IAM policy.

        Default appends to the fetched policy. brute=True replaces the ENTIRE policy with just the
        new binding (destroys all existing bindings) -- used when getIamPolicy is denied but
        setIamPolicy is allowed. Records getIamPolicy/setIamPolicy into action_dict. Returns the
        set-policy status, or -1 when the bucket is missing / policy can't be built (404 handled).
        """
        policy, additional_bind = None, {"role": role, "members": [member]}

        if brute:
            print(f"[*] Overwiting {bucket_name} to just be {member}")
            policy = Policy()
            policy.bindings = [additional_bind]
            policy.version = 3
        else:
            print(f"[*] Fetching current policy for {bucket_name}...")
            policy = bucket_get_iam_policy(storage_client, bucket_name, debug=debug)

            if policy:
                if policy == 404:
                    print(f"{UtilityTools.RED}[X] Exiting the module as {bucket_name} does not exist. Double check the name. Note the gs:// prefix is not included{UtilityTools.RESET}")
                    return -1
                action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.getIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)
                policy.bindings.append(additional_bind)
            else:
                print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire bucket IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
                return -1

        if policy is None:
            print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
            return -1

        print(f"[*] New policy below being added to {bucket_name} \n{policy.bindings}")
        status = bucket_set_iam_policy(storage_client, bucket_name, policy, debug=debug)

        if status:
            if status == 404:
                print(f"{UtilityTools.RED}[X] Exiting the module as {bucket_name} does not exist. Double check the name. Note the gs:// prefix is not included{UtilityTools.RESET}")
                return -1
            action_dict.setdefault(bucket_project_id, {}).setdefault("storage.buckets.setIamPolicy", {}).setdefault("buckets", set()).add(bucket_name)

        return status

    def save(self, rows, *, project_id: str | None = None, location: str | None = None, xml_mode: bool | None = None):
        """Persist bucket rows; XML/HMAC rows (partial) are insert-if-new, standard rows full upsert.

        Mode defaults to the last list()'s _access_mode unless xml_mode overrides. Main-thread only.
        """
        # HMAC/XML rows are partial (name+time only) -> insert-if-new; standard rows are full.
        use_xml = self._access_mode == "hmac" if xml_mode is None else xml_mode
        pid = str(project_id or self.session.project_id or "")
        for row in rows or []:
            if use_xml:
                save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": pid}, only_if_new_columns=["name"])
            else:
                save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": pid})


class CloudStorageBlobsResource(_CloudStorageBaseResource):
    """Enumerate/download/upload bucket objects into ``cloudstorage_bucketblobs``.

    NESTED resource: list()'s ``parent`` is the bucket name. Supports standard and HMAC/XML
    modes for list/upload/download. download_blobs re-lists live Blob objects and writes bytes
    to disk, optionally across a thread pool (workers only do network/file IO -- DB writes stay
    on the main thread per the project's single-threaded SQLite invariant).
    """

    TABLE_NAME = "cloudstorage_bucketblobs"
    COLUMNS = ["bucket_name", "name", "size", "updated"]
    LIST_PERMISSION = "storage.objects.list"
    GET_PERMISSION = "storage.objects.get"
    _access_mode = "standard"

    @staticmethod
    def _bucket_name(bucket) -> str:
        return str(getattr(bucket, "name", "") or "").strip() or str(bucket)

    @staticmethod
    def _to_dict(blob, bucket_name: str) -> dict:
        # resource_to_dict surfaces Blob._properties flat (size/updated/...).
        row = resource_to_dict(blob)
        row.setdefault("name", str(getattr(blob, "name", "") or ""))
        if not row.get("bucket_name"):
            row["bucket_name"] = bucket_name
        return row

    @staticmethod
    def upload_with_client(
        storage_client: Client,
        bucket_name: str,
        remote_path: str,
        local_blob_path: Optional[str] = None,
        data_string: Optional[str] = None,
        debug: Optional[bool] = False,
    ) -> Union[None, bool]:
        """Upload a local file or an in-memory string to a blob via the JSON API.

        Exactly one of local_blob_path/data_string should be supplied. Returns True on success,
        None on missing file / 403 storage.objects.create / unexpected error.
        """
        if debug:
            if local_blob_path:
                print(f"[DEBUG] Proceeding to upload {local_blob_path} to {bucket_name}/{remote_path} ...")
            elif data_string:
                print(f"[DEBUG] Proceeding to upload {data_string} to {bucket_name}/{remote_path} ...")

        try:
            uploading_bucket = storage_client.bucket(bucket_name)
            uploading_blob = uploading_bucket.blob(remote_path)
            if local_blob_path:
                uploading_blob.upload_from_filename(local_blob_path)
            elif data_string is not None:
                uploading_blob.upload_from_string(data_string)
        except FileNotFoundError as e:
            if f"No such file or directory: '{local_blob_path}'" in str(e):
                print(f"{UtilityTools.RED}[X] File {local_blob_path} does not exist. Exiting...{UtilityTools.RESET}")
            return None
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.objects.create",
                resource_name=bucket_name,
                service_label="Cloud Storage",
                project_id=getattr(storage_client, "project", None),
                return_not_enabled=False,
            )
            return None

        if debug:
            print("[DEBUG] Completed upload_with_client")
        return True

    @staticmethod
    def upload_with_hmac(
        bucket_name,
        local_blob_path,
        remote_blob_path,
        access_id,
        secret_key,
        data_string: Optional[str] = None,
        debug: Optional[bool] = None,
    ):
        """Upload a file/string to a blob via the S3/XML API using an HMAC key. Returns True/None."""
        client = _build_hmac_s3_client(access_id, secret_key)
        if client is None:
            return None

        try:
            if debug:
                print(f"[DEBUG] Uploading HMAC object to {bucket_name}/{remote_blob_path}")
            if data_string is not None:
                client.put_object(Bucket=bucket_name, Key=remote_blob_path, Body=data_string.encode("utf-8"))
            elif local_blob_path:
                with open(local_blob_path, "rb") as input_file:
                    client.put_object(Bucket=bucket_name, Key=remote_blob_path, Body=input_file)
            else:
                print(f"{UtilityTools.RED}[X] No upload data was provided for HMAC upload.{UtilityTools.RESET}")
                return None
            return True
        except FileNotFoundError:
            print(f"{UtilityTools.RED}[X] File {local_blob_path} does not exist. Exiting...{UtilityTools.RESET}")
        except Exception as e:
            print("[X] Failed to upload blob via XML API for following reason:")
            print(str(e))
        return None

    # Emit a running-count line every N blobs so a bucket with tens of thousands of
    # objects shows progress instead of looking hung (GCS pages 1000 at a time, so this
    # is ~one update per page).
    _LIST_PROGRESS_EVERY = 1000

    @staticmethod
    def _prompt_continue_after_list_interrupt(session, bucket_name: str, partial: list):
        """Handle a Ctrl+C hit mid-listing: keep the blobs listed so far and continue the
        module, or abort the whole run. Auto-continues (never blocks) in drive-through/
        non-interactive mode. Raising KeyboardInterrupt propagates up to the module
        dispatcher, which stops the entire module run cleanly."""
        count = len(partial)
        print(
            f"\n{UtilityTools.YELLOW}[!] Interrupted while listing bucket {bucket_name} "
            f"({count} blob(s) listed so far).{UtilityTools.RESET}"
        )
        if session is None or getattr(session, "_non_interactive", False):
            print(f"{UtilityTools.YELLOW}[*] Continuing the module with the {count} blob(s) listed so far.{UtilityTools.RESET}")
            return partial
        answer = session.choice_prompt(
            f"[c] continue the module with these {count} blob(s), or [q] quit the entire module run? [c/q]: "
        )
        # A second Ctrl+C at the prompt (choice_prompt returns None) or an explicit quit -> abort.
        if answer is None or answer.strip().lower() in ("q", "quit", "a", "abort", "exit"):
            print(f"{UtilityTools.RED}[X] Aborting the module run.{UtilityTools.RESET}")
            raise KeyboardInterrupt
        print(f"{UtilityTools.GREEN}[*] Continuing with the {count} blob(s) listed so far.{UtilityTools.RESET}")
        return partial

    @classmethod
    def list_with_client(cls, storage_client: Client, bucket_name: str, debug: Optional[bool] = False, session=None) -> Union[List, None]:
        """List a bucket's blobs, streaming page-by-page with a running progress count.

        Iterates lazily instead of materializing the whole bucket up front, so a huge
        bucket reports progress rather than appearing frozen, and a Ctrl+C is actionable
        (see _prompt_continue_after_list_interrupt). Returns the blob list, or None on
        403/404/error."""
        if debug:
            print(f"[DEBUG] Listing blobs for {bucket_name}")
        blob_list: list = []
        showed_progress = False
        try:
            for blob in storage_client.list_blobs(bucket_name):
                blob_list.append(blob)
                if len(blob_list) % cls._LIST_PROGRESS_EVERY == 0:
                    print(f"\r[***] Bucket {bucket_name}: listed {len(blob_list)} blobs so far...", end="")
                    sys.stdout.flush()
                    showed_progress = True
        except KeyboardInterrupt:
            if showed_progress:
                print()
            return cls._prompt_continue_after_list_interrupt(session, bucket_name, blob_list)
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.objects.list",
                resource_name=bucket_name,
                service_label="Cloud Storage",
                project_id=getattr(storage_client, "project", None),
                return_not_enabled=False,
            )
            return None
        if showed_progress:
            print()  # close the trailing \r progress line
        if debug:
            print("[DEBUG] Successful completed list_blobs...")
        return blob_list

    @staticmethod
    def get_with_bucket(bucket: Bucket, blob_name: str, debug: Optional[bool] = False) -> Union[Blob, None]:
        if debug:
            print(f"[DEBUG] Getting blob meta {blob_name} for {bucket.name}")
        try:
            blob_meta = bucket.get_blob(blob_name)
        except Exception as e:
            handle_service_error(
                e,
                api_name="storage.objects.get",
                resource_name=blob_name,
                service_label="Cloud Storage",
                project_id=getattr(getattr(bucket, "client", None), "project", None),
                return_not_enabled=False,
            )
            return None
        if debug:
            print("[DEBUG] Successful completed get_blob...")
        return blob_meta

    @classmethod
    def list_with_hmac(cls, storage_client, access_id, secret, bucket_name, project_id, debug=False, session=None):
        """List a bucket's objects via the S3/XML API using an HMAC key.

        PAGINATES (boto3 ``list_objects`` returns at most 1000 keys per call) so large
        buckets are not silently truncated to their first 1000 objects, streaming a
        running count and handling Ctrl+C like the standard-mode path."""
        _ = (storage_client, project_id, debug)
        client = _build_hmac_s3_client(access_id, secret)
        if client is None:
            return None
        rows: list = []
        showed_progress = False
        try:
            for page in client.get_paginator("list_objects").paginate(Bucket=bucket_name):
                for blob in page.get("Contents", []):
                    if not blob.get("Key"):
                        continue
                    rows.append(
                        SimpleNamespace(
                            name=str(blob.get("Key") or ""),
                            size=blob.get("Size"),
                            updated=str(blob.get("LastModified") or ""),
                            generation=str(blob.get("Generation") or ""),
                            metageneration=str(blob.get("MetaGeneration") or ""),
                            etag=str(blob.get("ETag") or ""),
                            bucket_name=bucket_name,
                        )
                    )
                    if len(rows) % cls._LIST_PROGRESS_EVERY == 0:
                        print(f"\r[***] Bucket {bucket_name}: listed {len(rows)} blobs so far...", end="")
                        sys.stdout.flush()
                        showed_progress = True
        except KeyboardInterrupt:
            if showed_progress:
                print()
            return cls._prompt_continue_after_list_interrupt(session, bucket_name, rows)
        except Exception as e:
            print("[X] Failed to list blobs via boto3 XML API client for following reason:")
            print(str(e))
            return None
        if showed_progress:
            print()
        return rows

    @staticmethod
    def download_with_client(
        storage_client,
        bucket,
        blob,
        project_id,
        debug=False,
        output_folder=None,
        user_regex_pattern=None,
        blob_size_limit=None,
    ):
        """Download one blob (JSON API) to ``<output>/REST/<bucket>/<blob>`` on disk.

        ``<output>`` is already scoped to the project by ``resolve_output_path``; the
        bucket name (globally unique in GCS) partitions blobs beneath it. Skips the blob
        when it fails the optional name regex or size cap. Recreates the blob's path
        prefix as local directories. Returns 1 (incl. when skipped/folder placeholder),
        None on 403/error. Side effect: creates dirs and writes files.
        """
        _ = storage_client
        bucket_name = bucket.name
        blob_name = blob.name
        blob_size = blob.size
        if (user_regex_pattern is None or re.search(user_regex_pattern, blob_name)) and (
            blob_size_limit is None or blob_size <= blob_size_limit
        ):
            if debug:
                print(f"[DEBUG] Downloading blob {blob_name}...")
            directory_to_store = f"{output_folder}/REST/{bucket_name}/"
            os.makedirs(directory_to_store, exist_ok=True)
            if "/" in blob_name:
                parent_prefix = blob_name.rpartition("/")[0]
                final_folder = f"{directory_to_store}{parent_prefix}" if parent_prefix else directory_to_store
                if not os.path.exists(final_folder):
                    os.makedirs(final_folder, exist_ok=True)
            destination_filename = directory_to_store + blob_name
            if destination_filename[-1] != "/":
                try:
                    blob.download_to_filename(destination_filename)
                except Exception as e:
                    handle_service_error(
                        e,
                        api_name="storage.objects.get",
                        resource_name=blob_name,
                        service_label="Cloud Storage",
                        project_id=project_id,
                        return_not_enabled=False,
                    )
                    return None
        return 1

    @staticmethod
    def download_with_hmac(storage_client, access_id, secret_key, bucket_name, blob_name, project_id, debug=False, output_folder=None):
        """Download one blob via the S3/XML API to ``<output>/XML/<bucket>/<blob>``.

        HMAC counterpart of download_with_client (note the XML/ vs REST/ subdir);
        ``<output>`` is already project-scoped. Returns 1/None.
        """
        _ = (storage_client, debug, project_id)
        client = _build_hmac_s3_client(access_id, secret_key)
        if client is None:
            return None
        try:
            directory_to_store = f"{output_folder}/XML/{bucket_name}/"
            os.makedirs(directory_to_store, exist_ok=True)
            if "/" in blob_name:
                parent_prefix = blob_name.rpartition("/")[0]
                final_folder = f"{directory_to_store}{parent_prefix}" if parent_prefix else directory_to_store
                if not os.path.exists(final_folder):
                    os.makedirs(final_folder, exist_ok=True)
            destination_filename = directory_to_store + blob_name
            if destination_filename[-1] != "/":
                response = client.get_object(Bucket=bucket_name, Key=blob_name)
                with open(destination_filename, "wb") as output_file:
                    output_file.write(response["Body"].read())
        except Exception as e:
            print("[X] Failed to download blob via boto3 XML API client for following reason:")
            print(str(e))
            return None
        return 1

    def resolve_cached_buckets(self, *, project_id: str):
        """Rebuild Bucket objects from previously-enumerated bucket rows (avoids re-listing)."""
        client = self.build_client(project_id)
        rows = get_cached_rows(self.session, "cloudstorage_buckets", project_id=project_id, columns=["name"])
        return [client.bucket(row["name"]) for row in rows if row.get("name")]

    def list(self, *, parent: str = "", bucket=None, project_id: str | None = None, location: str | None = None,
             access_mode: str = "standard", access_id: str | None = None, hmac_secret: str | None = None, action_dict=None):
        """List blobs in a bucket (standard or HMAC mode); ``parent`` is the bucket name.

        Records storage.objects.list as evidence against the bucket. Returns dicts (or the
        "Not Enabled"/None sentinel) for the framework to save/summarize.
        """
        # NESTED: ``parent`` is the bucket name; ``bucket`` (object) is still accepted
        # for the download path. Returns dicts so the framework can save/summarize.
        self._access_mode = access_mode
        pid = str(project_id or self.session.project_id or "")
        bucket_name = self._bucket_name(bucket) if bucket is not None else str(parent or "").strip()
        if not bucket_name:
            return []
        client = self.build_client(pid)
        if access_mode == "hmac":
            rows = self.list_with_hmac(client, access_id, hmac_secret, bucket_name, pid, self.debug, session=self.session)
        else:
            rows = self.list_with_client(client, bucket_name, debug=self.debug, session=self.session)
        if rows in ("Not Enabled", None):
            return rows
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            project_id=pid,
            resource_type="buckets",
            resource_label=bucket_name,
        )
        return [self._to_dict(blob, bucket_name) for blob in rows]

    def get(self, *, bucket, resource_id: str):
        return self.get_with_bucket(bucket, resource_id, debug=self.debug)

    def save(self, rows, *, project_id: str | None = None, location: str | None = None, xml_mode: bool | None = None):
        use_xml = self._access_mode == "hmac" if xml_mode is None else xml_mode
        pid = str(project_id or self.session.project_id or "")
        for row in rows or []:
            if use_xml:
                save_to_table(
                    self.session,
                    self.TABLE_NAME,
                    row,
                    defaults={"project_id": pid},
                    only_if_new_columns=["project_id", "name"],
                )
            else:
                save_to_table(
                    self.session,
                    self.TABLE_NAME,
                    row,
                    defaults={"project_id": pid},
                    extra_builder=lambda obj, raw: {
                        "bucket_name": (raw.get("bucket_name") if isinstance(raw, dict) else "")
                        or getattr(getattr(obj, "bucket", None), "name", "")
                        or getattr(obj, "bucket_name", ""),
                    },
                )

    def download(
        self,
        *,
        project_id: str,
        bucket,
        blob,
        output_folder: str | None = None,
        user_regex_pattern: str | None = None,
        blob_size_limit: int | None = None,
        access_id: str | None = None,
        hmac_secret: str | None = None,
        access_mode: str = "standard",
        action_dict=None,
    ) -> bool:
        """Download a single blob (standard or HMAC), recording storage.objects.get on success."""
        client = self.build_client(project_id)
        if access_mode == "hmac":
            status = self.download_with_hmac(
                client,
                access_id,
                hmac_secret,
                bucket.name,
                blob.name,
                project_id,
                debug=getattr(self.session, "debug", False),
                output_folder=output_folder,
            )
        else:
            status = self.download_with_client(
                client,
                bucket,
                blob,
                project_id,
                debug=self.debug,
                output_folder=output_folder,
                user_regex_pattern=user_regex_pattern,
                blob_size_limit=blob_size_limit,
            )
        if status:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type="buckets",
                resource_label=bucket.name,
            )
        return status

    def _process_blob_download(
        self,
        *,
        project_id: str,
        bucket,
        blob,
        output_dir: str,
        user_regex_pattern: str | None,
        blob_size_limit: int | None,
        access_id: str | None,
        hmac_secret: str | None,
        access_mode: str,
        action_dict,
        lock: Lock,
        counter: dict[str, int],
        total: int,
        budget=None,
    ) -> bool:
        # Per-type download budget (shared across all buckets): once "storage blobs"
        # has run past --download-timeout, every remaining blob (single- or multi-
        # threaded) short-circuits here instead of downloading.
        if budget is not None and budget.exceeded():
            return False
        bucket_name = self._bucket_name(bucket)
        self.download(
            project_id=project_id,
            bucket=bucket,
            blob=blob,
            output_folder=output_dir,
            user_regex_pattern=user_regex_pattern,
            blob_size_limit=blob_size_limit,
            access_id=access_id,
            hmac_secret=hmac_secret,
            access_mode=access_mode,
            action_dict=action_dict,
        )
        with lock:
            counter["count"] += 1
            print(
                f"\r[***] Bucket {bucket_name}: Processed {counter['count']} of {total} blobs...",
                end="",
            )
            sys.stdout.flush()
        return True

    def download_blobs(
        self,
        *,
        project_id: str,
        bucket_names: list[str],
        blob_name_inputs: list[str],
        output: str | None = None,
        good_regex: str | None = None,
        file_size: int | None = None,
        time_limit: str | None = None,
        threads: int = 1,
        access_id: str | None = None,
        hmac_secret: str | None = None,
        access_mode: str = "standard",
    ):
        """Bulk-download blobs across one or more buckets, optionally multi-threaded.

        Re-lists live Blob objects (needed for download_to_filename), filters out folder
        placeholders and optionally to specific blob names, then downloads each -- single-threaded
        or via a ThreadPoolExecutor of ``threads`` workers. Workers only do network/file IO and
        update a shared progress counter under a lock; permissions are accumulated into the
        returned nested action_dict (NOT written to SQLite from workers -- DB writes are main-thread
        only). Honors an optional wall-clock time_limit per bucket and Ctrl-C to skip a bucket.
        Returns the per-bucket/permission action_dict for the caller to record.
        """
        # The framework already listed+saved blob metadata; re-list live Blob objects
        # here (needed for download_to_filename) and write the bytes. Records only the
        # download (storage.objects.get) permission -- list was recorded during enum.
        blob_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        client = self.build_client(project_id)
        output_dir = str(
            self.session.resolve_output_path(
                requested_path=output,
                service_name="storage",
                project_id=project_id,
                target="download",
            )
        )
        for bucket_name in bucket_names:
            bucket_name = str(bucket_name or "").strip()
            if not bucket_name:
                continue
            bucket = client.bucket(bucket_name)
            if access_mode == "hmac":
                blob_list = self.list_with_hmac(client, access_id, hmac_secret, bucket_name, project_id, self.debug, session=self.session)
            else:
                blob_list = self.list_with_client(client, bucket_name, debug=self.debug, session=self.session)
            if blob_list in ("Not Enabled", None) or not blob_list:
                continue
            if blob_name_inputs:
                allowed_blob_names = set(blob_name_inputs)
                blob_list = [blob for blob in blob_list if getattr(blob, "name", "") in allowed_blob_names]
            non_folder_blobs = [
                blob for blob in blob_list if getattr(blob, "name", None) and not blob.name.endswith("/")
            ]
            if not non_folder_blobs:
                print(f"[*] Bucket {bucket_name}: no downloadable blobs found.")
                continue
            print(f"[*] Bucket {bucket_name}: downloading {len(non_folder_blobs)} blob(s)...")
            start_time = time.time()
            # Per-BUCKET download-time budget (--download-timeout): once THIS bucket's blob
            # downloads exceed it, skip the bucket's remaining blobs and move to the next bucket.
            budget = DownloadBudget(self.session, label=f"bucket {bucket_name}")
            lock = Lock()
            counter = {"count": 0}

            try:
                if threads == 1:
                    for blob in non_folder_blobs:
                        if budget.exceeded():
                            break
                        if time_limit and (time.time() - start_time) > int(time_limit):
                            print(f"\n[-] Time limit of {time_limit} reached for bucket {bucket_name}")
                            break
                        self._process_blob_download(
                            project_id=project_id,
                            bucket=bucket,
                            blob=blob,
                            output_dir=output_dir,
                            user_regex_pattern=good_regex,
                            blob_size_limit=file_size,
                            access_id=access_id,
                            hmac_secret=hmac_secret,
                            access_mode=access_mode,
                            action_dict=blob_actions,
                            lock=lock,
                            counter=counter,
                            total=len(non_folder_blobs),
                            budget=budget,
                        )
                else:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        list(
                            executor.map(
                                lambda blob: self._process_blob_download(
                                    project_id=project_id,
                                    bucket=bucket,
                                    blob=blob,
                                    output_dir=output_dir,
                                    user_regex_pattern=good_regex,
                                    blob_size_limit=file_size,
                                    access_id=access_id,
                                    hmac_secret=hmac_secret,
                                    access_mode=access_mode,
                                    action_dict=blob_actions,
                                    lock=lock,
                                    counter=counter,
                                    total=len(non_folder_blobs),
                                    budget=budget,
                                ),
                                non_folder_blobs,
                            )
                        )
                if non_folder_blobs:
                    print()
            except KeyboardInterrupt:
                print(f"\n[*] Interrupted blob processing for bucket {bucket_name}. Moving to the next bucket...")

        return blob_actions
