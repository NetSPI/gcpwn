from __future__ import annotations

import json
import traceback
import urllib.parse
from collections import defaultdict
from typing import Any

from google.cloud import (
    compute_v1,
    functions_v2,
    iam_admin_v1,
    resourcemanager_v3,
    run_v2,
    secretmanager_v1,
    storage,
)
try:
    from google.cloud import bigquery  # type: ignore
except Exception:  # pragma: no cover
    bigquery = None  # type: ignore
try:
    from google.cloud import tasks_v2  # type: ignore
except Exception:  # pragma: no cover
    tasks_v2 = None  # type: ignore
try:
    from google.cloud import iam_v2  # type: ignore  # IAM v2 deny-policy API
except Exception:  # pragma: no cover
    iam_v2 = None  # type: ignore

from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import NotFound
from google.iam.v1 import iam_policy_pb2

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import build_discovery_service
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import is_api_disabled_error
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, extract_project_id_from_resource, normalize_str_set


class IAMPolicyBindingsResource:
    """getIamPolicy/setIamPolicy engine for every supported GCP resource type.

    Two responsibilities: (1) ``run()`` sweeps the cached resource tables and
    fetches allow-policies (read), caching them into ``iam_allow_policies`` and
    recording the getIamPolicy permission as evidence; (2) ``set_resource_iam_member``
    and its helpers add a member to a resource's policy (write/exploit).

    Resources reach the right API via one of three transports, chosen per type:
      * SDK clients (``_sdk_get_iam_policy``) for RM/functions/compute/IAM/secrets/run/tasks;
      * the Storage and BigQuery clients (special-cased: buckets use the storage
        client; BigQuery datasets have NO getIamPolicy and go through the dataset
        ACL path, see ``_dataset_access_to_policy``);
      * cached discovery clients (``_discovery_get_iam_policy``) for AR/KMS/pubsub/
        servicedirectory/cloudtasks.

    THREADING: instances are constructed and ``run()`` is invoked on the same
    thread that owns the DataController (it calls session.get_data/insert_*).
    enum_all's pipeline runs one IAMPolicyBindingsResource PER hierarchy node but
    still on the orchestrator thread (the worker pool only schedules, the run does
    DB I/O on the main thread). Do not call run() from inside a ThreadPoolExecutor
    worker -- it will raise sqlite3.ProgrammingError.
    """

    @staticmethod
    def _safe_client(factory):
        """Build a client via ``factory()``, returning None if construction raises.

        Used for optional clients (run/tasks/bigquery) whose libs may be missing
        or whose API may be unavailable; callers treat None as "skip this service".
        """
        try:
            return factory()
        except Exception:
            return None

    def __init__(self, session):
        self.session = session
        self.clients = {
            "org": resourcemanager_v3.OrganizationsClient(credentials=session.credentials),
            "project": resourcemanager_v3.ProjectsClient(credentials=session.credentials),
            "folder": resourcemanager_v3.FoldersClient(credentials=session.credentials),
            "function": functions_v2.FunctionServiceClient(credentials=session.credentials, transport="rest"),
            "compute": compute_v1.InstancesClient(credentials=session.credentials),
            "iam": iam_admin_v1.IAMClient(credentials=session.credentials),
            "secret": secretmanager_v1.SecretManagerServiceClient(credentials=session.credentials),
            "run_services": self._safe_client(lambda: run_v2.ServicesClient(credentials=session.credentials)),
            "run_jobs": self._safe_client(lambda: run_v2.JobsClient(credentials=session.credentials)),
            "cloudtasks": (
                self._safe_client(lambda: tasks_v2.CloudTasksClient(credentials=session.credentials))
                if tasks_v2 is not None
                else None
            ),
        }
        self.storage_client = storage.Client(credentials=session.credentials, project=session.project_id)
        self.bigquery_client = self._safe_client(
            lambda: bigquery.Client(credentials=session.credentials, project=session.project_id)
        )
        self._discovery_clients: dict[tuple[str, str], Any] = {}

    def _sdk_get_iam_policy(self, client, resource_name: str, *, api_name: str, service_label: str, project_id: str):
        """Call getIamPolicy on a GAPIC SDK client, normalizing errors to sentinels.

        Returns the Policy proto on success, None on missing client / 404 / denied /
        unexpected error, and the string "Not Enabled" when the 403 indicates the
        API is disabled (so callers can short-circuit further fan-out for that
        service). Prints the matching 403/404/500 banner as a side effect.
        """
        if client is None or not resource_name:
            return None
        try:
            request = iam_policy_pb2.GetIamPolicyRequest(resource=resource_name)
            return client.get_iam_policy(request=request)
        except NotFound:
            UtilityTools.print_404_resource(resource_name)
            return None
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled(service_label, project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(api_name, resource_name=resource_name, project_id=project_id)
            return None
        except Exception as exc:
            UtilityTools.print_500(resource_name, api_name, exc)
            return None

    def _policy_to_dict(self, policy):
        """Convert a Policy proto (or already-dict) into a plain dict; pass None through.

        This is the single canonical Policy->dict converter. None passes through
        unchanged because every consumer must distinguish a MISSING policy (fetch
        failed) from an empty one (no bindings). Policy proto field names are all
        single-word, so resource_to_dict's snake_case output matches the prior
        camelCase for every key consumed downstream (bindings/role/members/condition.*).
        """
        # Canonical converter (this was the last direct MessageToDict caller). None
        # passes through because callers distinguish a missing policy from an empty one;
        # Policy proto fields are all single-word so snake_case output matches the prior
        # camelCase for every consumed key (bindings/role/members/condition.*).
        return None if policy is None else resource_to_dict(policy)

    @staticmethod
    def _policy_add_iam_member(*, policy: dict[str, Any], member: str, role: str) -> dict[str, Any]:
        """Add ``member`` under ``role`` in an allow-policy dict, merging in place.

        If a binding for the role already exists the member is appended (deduped);
        otherwise a new binding is created. Mutates and returns ``policy`` -- used
        for the non-brute (additive) setIamPolicy path so existing bindings survive.
        """
        normalized_member = str(member or "").strip()
        normalized_role = str(role or "").strip()
        if not policy:
            policy = {}
        bindings = policy.get("bindings")
        if not isinstance(bindings, list):
            bindings = []
            policy["bindings"] = bindings

        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            if str(binding.get("role") or "") != normalized_role:
                continue
            members = binding.get("members")
            if not isinstance(members, list):
                members = []
                binding["members"] = members
            if normalized_member and normalized_member not in members:
                members.append(normalized_member)
            return policy

        bindings.append({"role": normalized_role, "members": [normalized_member]})
        return policy

    @staticmethod
    def _policy_for_member_update(
        current_policy: dict[str, Any] | None,
        *,
        member: str,
        role: str,
        brute: bool,
    ) -> dict[str, Any]:
        """Build the policy to send to setIamPolicy for a single member/role grant.

        brute=True (--overwrite) replaces the WHOLE policy with just this one
        binding (destructive, but works when the current policy could not be read,
        preserving version/etag if present). brute=False additively merges the
        member into the existing policy via _policy_add_iam_member.
        """
        policy_dict = dict(current_policy or {})
        if brute:
            updated_policy = {
                "bindings": [{"role": str(role).strip(), "members": [str(member).strip()]}],
                "version": int(policy_dict.get("version") or 1),
            }
            etag = policy_dict.get("etag")
            if etag:
                updated_policy["etag"] = etag
            return updated_policy
        return IAMPolicyBindingsResource._policy_add_iam_member(
            policy=policy_dict,
            member=member,
            role=role,
        )

    def _sdk_set_iam_policy(
        self,
        client,
        resource_name: str,
        policy,
        *,
        api_name: str,
        service_label: str,
        project_id: str,
    ):
        if client is None or not resource_name:
            return None
        try:
            request = iam_policy_pb2.SetIamPolicyRequest(
                resource=str(resource_name).strip(),
                policy=policy,
            )
            return client.set_iam_policy(request=request)
        except NotFound:
            UtilityTools.print_404_resource(resource_name)
            return 404
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled(service_label, project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(api_name, resource_name=resource_name, project_id=project_id)
            return None
        except Exception as exc:
            UtilityTools.print_500(resource_name, api_name, exc)
            return None

    # BigQuery datasets have NO getIamPolicy REST/SDK method (that is table/view
    # only -- Client.get_iam_policy() runs TableReference.from_string(), so a
    # "project.dataset" string mis-parses to dataset.table). Dataset-level access
    # is the dataset's ACL (access_entries), read via get_dataset() and exposed as
    # AccessEntry(role, entity_type, entity_id). Basic roles map to predefined IAM
    # roles; see https://cloud.google.com/bigquery/docs/access-control-basic-roles
    _BQ_BASIC_ROLE_TO_IAM = {
        "READER": "roles/bigquery.dataViewer",
        "WRITER": "roles/bigquery.dataEditor",
        "OWNER": "roles/bigquery.dataOwner",
    }
    # Legacy specialGroup ACLs -> IAM convenience members (OpenGraph already skips
    # projectOwner/projectEditor/projectViewer as derived, so this stays graph-safe).
    _BQ_SPECIAL_GROUP_TO_MEMBER = {
        "projectOwners": "projectOwner",
        "projectWriters": "projectEditor",
        "projectReaders": "projectViewer",
    }

    @classmethod
    def _bigquery_access_member(cls, entry, *, project_id: str) -> str | None:
        """Map one BigQuery dataset AccessEntry to a canonical IAM member, or None.

        Translates BQ ACL entity types (userByEmail/groupByEmail/domain/iamMember/
        specialGroup) into "user:/group:/domain:/..." members. specialGroup
        projectOwners/Writers/Readers become projectOwner/Editor/Viewer convenience
        members. Returns None for entries that are authorized resources (view /
        routine / dataset), which grant no role to a principal.
        """
        entity_type = str(getattr(entry, "entity_type", "") or "").strip()
        value = str(getattr(entry, "entity_id", "") or "").strip()
        if entity_type == "userByEmail":
            return f"user:{value}" if value else None
        if entity_type == "groupByEmail":
            return f"group:{value}" if value else None
        if entity_type == "domain":
            return f"domain:{value}" if value else None
        if entity_type == "iamMember":
            return value or None  # already a full IAM member (serviceAccount:/principalSet:/allUsers/...)
        if entity_type == "specialGroup":
            if value in ("allAuthenticatedUsers", "allUsers"):
                return value
            convenience = cls._BQ_SPECIAL_GROUP_TO_MEMBER.get(value)
            if convenience:
                # A convenience member is meaningless without its project; a bare
                # "projectOwner" is not a valid IAM member, so drop it.
                return f"{convenience}:{project_id}" if project_id else None
            return None
        # view / routine / dataset entries are authorized resources, not principals.
        return None

    def _dataset_access_to_policy(self, dataset) -> dict[str, Any]:
        """Convert a Dataset's access_entries ACL into an allow-policy dict so it
        flows through the same _reorganize_allow_policy / iam_allow_policies path
        as every getIamPolicy-backed resource."""
        project_id = str(getattr(dataset, "project", "") or "").strip()
        role_members: dict[str, set[str]] = {}
        for entry in (getattr(dataset, "access_entries", None) or []):
            role = str(getattr(entry, "role", "") or "").strip()
            if not role:
                continue  # authorized view/routine/dataset: grants no role to a principal
            iam_role = self._BQ_BASIC_ROLE_TO_IAM.get(role.upper(), role)
            member = self._bigquery_access_member(entry, project_id=project_id)
            if member:
                role_members.setdefault(iam_role, set()).add(member)
        policy: dict[str, Any] = {
            "bindings": [{"role": role, "members": sorted(members)} for role, members in sorted(role_members.items())]
        }
        etag = getattr(dataset, "etag", None)
        if etag:
            policy["etag"] = str(etag)
        return policy

    def _bigquery_get_iam_policy(self, dataset_id: str, *, project_id: str):
        """Read a BigQuery dataset's access (ACL) as an allow-policy dict.

        Datasets have no getIamPolicy method, so this calls get_dataset() (the
        bigquery.datasets.get permission) and converts access_entries via
        _dataset_access_to_policy. Same sentinel contract as _sdk_get_iam_policy:
        None on missing/404/denied/error, "Not Enabled" when the API is disabled.
        """
        if self.bigquery_client is None or not dataset_id:
            return None
        try:
            dataset = self.bigquery_client.get_dataset(dataset_id)
        except NotFound:
            UtilityTools.print_404_resource(dataset_id)
            return None
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled("BigQuery", project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(
                "bigquery.datasets.get",
                resource_name=dataset_id,
                project_id=project_id,
            )
            return None
        except Exception as exc:
            UtilityTools.print_500(dataset_id, "bigquery.datasets.get", exc)
            return None
        return self._dataset_access_to_policy(dataset)

    def _bucket_get_iam_policy(self, bucket_name: str, debug: bool = False):
        if debug:
            print(f"[DEBUG] Getting IAM bindings for {bucket_name} ...")
        project_id = self._resource_id_to_project_id(bucket_name)
        try:
            bucket_object = self.storage_client.bucket(bucket_name)
            return bucket_object.get_iam_policy()
        except NotFound:
            UtilityTools.print_404_resource(bucket_name)
            return 404
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled("Cloud Storage", project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(
                "storage.buckets.getIamPolicy",
                resource_name=bucket_name,
                project_id=project_id,
            )
            return None
        except Exception as exc:
            UtilityTools.print_500(bucket_name, "storage.buckets.getIamPolicy", exc)
            return None

    def _bucket_set_iam_policy(self, bucket_name: str, policy, debug: bool = False):
        if debug:
            print(f"[DEBUG] Setting IAM bindings for {bucket_name} ...")
        project_id = self._resource_id_to_project_id(bucket_name)
        try:
            bucket_object = self.storage_client.bucket(bucket_name)
            return bucket_object.set_iam_policy(policy)
        except NotFound:
            UtilityTools.print_404_resource(bucket_name)
            return 404
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled("Cloud Storage", project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(
                "storage.buckets.setIamPolicy",
                resource_name=bucket_name,
                project_id=project_id,
            )
            return None
        except Exception as exc:
            UtilityTools.print_500(bucket_name, "storage.buckets.setIamPolicy", exc)
            return None

    def _compute_instance_get_iam_policy(self, project_id: str, instance_name: str, zone_id: str, debug: bool = False):
        if debug:
            print(f"[DEBUG] Getting IAM bindings for {instance_name} ...")
        normalized_project_id = str(project_id or "").strip()
        try:
            request = compute_v1.GetIamPolicyInstanceRequest(
                project=normalized_project_id,
                resource=instance_name,
                zone=zone_id,
            )
            return self.clients.get("compute").get_iam_policy(request=request)
        except NotFound:
            UtilityTools.print_404_resource(f"projects/{normalized_project_id}/zones/{zone_id}/instances/{instance_name}")
            return 404
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled("Compute Engine", normalized_project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(
                "compute.instances.getIamPolicy",
                resource_name=f"projects/{normalized_project_id}/zones/{zone_id}/instances/{instance_name}",
                project_id=normalized_project_id,
            )
            return None
        except Exception as exc:
            UtilityTools.print_500(
                f"projects/{normalized_project_id}/zones/{zone_id}/instances/{instance_name}",
                "compute.instances.getIamPolicy",
                exc,
            )
            return None

    def _compute_instance_set_iam_policy(
        self,
        instance_name: str,
        project_id: str,
        zone_id: str,
        policy,
        debug: bool = False,
    ):
        if debug:
            print(f"[DEBUG] Setting IAM bindings for {instance_name} ...")
        normalized_project_id = str(project_id or "").strip()
        try:
            zone_set_policy_request_resource = {"policy": policy}
            request = compute_v1.SetIamPolicyInstanceRequest(
                project=normalized_project_id,
                resource=instance_name,
                zone=zone_id,
                zone_set_policy_request_resource=zone_set_policy_request_resource,
            )
            return self.clients.get("compute").set_iam_policy(request=request)
        except NotFound:
            UtilityTools.print_404_resource(f"projects/{normalized_project_id}/zones/{zone_id}/instances/{instance_name}")
            return 404
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled("Compute Engine", normalized_project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(
                "compute.instances.setIamPolicy",
                resource_name=f"projects/{normalized_project_id}/zones/{zone_id}/instances/{instance_name}",
                project_id=normalized_project_id,
            )
            return None
        except Exception as exc:
            UtilityTools.print_500(
                f"projects/{normalized_project_id}/zones/{zone_id}/instances/{instance_name}",
                "compute.instances.setIamPolicy",
                exc,
            )
            return None

    def _resource_id_to_project_id(self, resource_name: str) -> str:
        fallback = str(getattr(self.session, "project_id", "") or "").strip()
        return extract_project_id_from_resource(resource_name, fallback_project=fallback)

    @staticmethod
    def _include_service(services: set[str] | None, key: str) -> bool:
        if not services:
            return True
        return str(key or "").strip().lower() in services

    def _get_discovery_client(self, api_name: str, api_version: str):
        cache_key = (str(api_name).strip(), str(api_version).strip())
        if cache_key in self._discovery_clients:
            return self._discovery_clients[cache_key]
        client = build_discovery_service(self.session.credentials, api_name, api_version)
        self._discovery_clients[cache_key] = client
        return client

    def _discovery_get_iam_policy(
        self,
        resource_service,
        *,
        resource_name: str,
        api_name: str,
        service_label: str,
        project_id: str,
    ):
        """Call getIamPolicy via a discovery (REST) resource, normalizing errors.

        Tries the bare ``getIamPolicy(resource=...)`` first; some APIs require a
        body, so a TypeError triggers a retry with ``body={}``. Same sentinel
        contract as the SDK path: None on missing/error, "Not Enabled" when the
        403 text indicates the API is disabled.
        """
        if resource_service is None or not resource_name:
            return None
        try:
            return resource_service.getIamPolicy(resource=resource_name).execute()
        except TypeError:
            try:
                return resource_service.getIamPolicy(resource=resource_name, body={}).execute()
            except Exception as exc:
                text = str(exc)
                if is_api_disabled_error(text):
                    UtilityTools.print_403_api_disabled(service_label, project_id)
                    return "Not Enabled"
                UtilityTools.print_500(resource_name, api_name, exc)
                return None
        except Exception as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled(service_label, project_id)
                return "Not Enabled"
            UtilityTools.print_500(resource_name, api_name, exc)
            return None

    def _discovery_set_iam_policy(
        self,
        resource_service,
        *,
        resource_name: str,
        policy: dict[str, Any],
        api_name: str,
        service_label: str,
        project_id: str,
    ):
        if resource_service is None or not resource_name:
            return None
        try:
            return resource_service.setIamPolicy(resource=resource_name, body={"policy": policy}).execute()
        except TypeError:
            try:
                return resource_service.setIamPolicy(resource=resource_name, body={"policy": policy, "updateMask": ""}).execute()
            except Exception as exc:
                text = str(exc)
                if is_api_disabled_error(text):
                    UtilityTools.print_403_api_disabled(service_label, project_id)
                    return "Not Enabled"
                UtilityTools.print_500(resource_name, api_name, exc)
                return None
        except Exception as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled(service_label, project_id)
                return "Not Enabled"
            UtilityTools.print_500(resource_name, api_name, exc)
            return None

    def _discovery_resource_for_type(self, resource_type: str):
        """Resolve an internal resource-type token to its discovery resource handle.

        Maps tokens like "kms_key" / "pubsub_topic" / "cloudtasks_queue" to the
        right nested ``.projects().locations()...`` accessor on a cached discovery
        client. Returns None for unknown tokens.
        """
        token = str(resource_type or "").strip().lower()
        if token == "artifactregistry_repository":
            return self._get_discovery_client("artifactregistry", "v1").projects().locations().repositories()
        if token == "kms_keyring":
            return self._get_discovery_client("cloudkms", "v1").projects().locations().keyRings()
        if token == "kms_key":
            return self._get_discovery_client("cloudkms", "v1").projects().locations().keyRings().cryptoKeys()
        if token == "pubsub_topic":
            return self._get_discovery_client("pubsub", "v1").projects().topics()
        if token == "pubsub_subscription":
            return self._get_discovery_client("pubsub", "v1").projects().subscriptions()
        if token == "pubsub_snapshot":
            return self._get_discovery_client("pubsub", "v1").projects().snapshots()
        if token == "pubsub_schema":
            return self._get_discovery_client("pubsub", "v1").projects().schemas()
        if token == "servicedirectory_namespace":
            return self._get_discovery_client("servicedirectory", "v1").projects().locations().namespaces()
        if token == "servicedirectory_service":
            return self._get_discovery_client("servicedirectory", "v1").projects().locations().namespaces().services()
        if token == "cloudtasks_queue":
            return self._get_discovery_client("cloudtasks", "v2").projects().locations().queues()
        return None

    @staticmethod
    def _condition_sort_key(condition) -> str:
        if not condition:
            return ""
        if isinstance(condition, dict):
            expr = str(condition.get("expression") or "")
            title = str(condition.get("title") or "")
            desc = str(condition.get("description") or "")
            loc = str(condition.get("location") or "")
            return f"{expr}|{title}|{desc}|{loc}"
        return str(condition)

    def _reorganize_allow_policy(self, policy_dict: dict) -> dict:
        """Normalize a raw allow-policy into the canonical cached shape.

        Produces a deterministic dict so the same policy always serializes
        identically (members deduped+sorted, bindings sorted by role+condition).
        Adds a ``by_member`` inverse map (member -> {roles, conditional_bindings})
        plus ``bindings_count``/``members_count``, which downstream readers
        (iter_member_roles_from_policy, the materialized member view, OpenGraph)
        rely on. Original ``bindings`` are preserved alongside ``by_member``.
        """
        base = dict(policy_dict or {})
        bindings = base.get("bindings", [])
        if not isinstance(bindings, list):
            bindings = []

        normalized_bindings: list[dict] = []
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            role = str(binding.get("role") or "").strip()
            if not role:
                continue
            members = binding.get("members") or []
            if not isinstance(members, list):
                members = [members]
            member_list = sorted(normalize_str_set(members))

            out = {"role": role, "members": member_list}
            condition = binding.get("condition")
            if condition not in (None, "", [], {}):
                out["condition"] = condition
            normalized_bindings.append(out)

        normalized_bindings.sort(key=lambda b: (str(b.get("role") or ""), self._condition_sort_key(b.get("condition"))))

        by_member: dict[str, dict] = {}
        for binding in normalized_bindings:
            role = str(binding.get("role") or "")
            condition = binding.get("condition")
            for member in binding.get("members") or []:
                entry = by_member.setdefault(member, {"roles": set(), "conditional_bindings": []})
                entry["roles"].add(role)
                if condition not in (None, "", [], {}):
                    entry["conditional_bindings"].append({"role": role, "condition": condition})

        by_member_sorted: dict[str, dict] = {}
        for member in sorted(by_member.keys()):
            entry = by_member[member]
            by_member_sorted[member] = {
                "roles": sorted(list(entry.get("roles") or set())),
                "conditional_bindings": entry.get("conditional_bindings") or [],
            }

        base["bindings"] = normalized_bindings
        base["by_member"] = by_member_sorted
        base["bindings_count"] = len(normalized_bindings)
        base["members_count"] = len(by_member_sorted)
        return base

    def _save_raw_policy(self, *, project_id: str, resource_type: str, resource_name: str, policy) -> None:
        """Persist a resource's normalized allow-policy into iam_allow_policies.

        Converts (via _policy_to_dict) and reorganizes the policy, then JSON-encodes
        it with sort_keys for stable rows and upserts keyed on resource_type +
        resource_name. SIDE EFFECT: a DB write -- main-thread only (workspace_id is
        added by session/save_to_table). Skips silently when the policy is None.
        """
        payload = self._policy_to_dict(policy)
        if payload is None:
            return
        payload = self._reorganize_allow_policy(payload)
        save_to_table(
            self.session,
            "iam_allow_policies",
            {
                "resource_type": resource_type,
                "resource_name": resource_name,
                "policy": json.dumps(payload, ensure_ascii=False, sort_keys=True),
            },
            defaults={"project_id": project_id},
        )

    @staticmethod
    def _bigquery_dataset_id(row: dict[str, Any]) -> str:
        full_dataset_id = str(row.get("full_dataset_id") or "").strip()
        if full_dataset_id and "." in full_dataset_id:
            return full_dataset_id
        project_id = str(row.get("project_id") or "").strip()
        dataset_id = str(row.get("dataset_id") or "").strip()
        if project_id and dataset_id:
            return f"{project_id}.{dataset_id}"
        return ""

    def _capture_policy(
        self,
        *,
        project_id: str,
        resource_type: str,
        resource_name: str,
        policy,
        save_raw_policies: bool,
    ) -> None:
        """Normalize a fetched policy and (optionally) persist it to iam_allow_policies.

        The single funnel every enumerate-spec calls after a successful fetch. When
        save_raw_policies is False the policy is validated/normalized but NOT stored
        (permission evidence is still recorded by the caller). DB write is main-thread.
        """
        payload = self._policy_to_dict(policy)
        if payload is None:
            return
        if save_raw_policies:
            self._save_raw_policy(
                project_id=project_id,
                resource_type=resource_type,
                resource_name=resource_name,
                policy=payload,
            )

    # ---- IAM v2 DENY policies -------------------------------------------------
    # Deny policies (iam.googleapis.com v2) are a SEPARATE API from allow-policy
    # getIamPolicy and can REVOKE permissions an allow grant would otherwise give.
    # gcpwn caches them per org/folder/project scope for completeness (and future
    # effective-access analysis); enumeration is best-effort and never affects the
    # allow-policy pass.

    @staticmethod
    def _deny_attachment_point(scope_type: str, scope_name: str, project_id: str, rm_collection: str) -> tuple[str, str]:
        """Return (attachment_point, attach_id) for a deny-policy scope, or ("","")."""
        if scope_type == "project":
            attach_id = project_id or extract_path_tail(scope_name)
            attach_res = f"projects/{attach_id}"
        else:
            attach_id = extract_path_tail(scope_name)
            attach_res = f"{rm_collection}/{attach_id}"
        if not attach_id:
            return "", ""
        return f"cloudresourcemanager.googleapis.com/{attach_res}", attach_id

    def _list_deny_policies(self, client, parent: str):
        """List deny policies for a scope; None on any denied/disabled/error (skip)."""
        try:
            request = iam_v2.ListPoliciesRequest(parent=parent)
            return list(client.list_policies(request=request))
        except (Forbidden, NotFound):
            return None
        except Exception:
            return None

    def _get_deny_policy(self, client, name: str):
        """Fetch a deny policy's FULL form (list returns metadata only -- the rules, and
        thus denied principals/permissions, only come back from get). None on any error
        (e.g. missing iam.denypolicies.get or a transient read-quota 429), in which case
        the caller falls back to the list metadata."""
        if not name:
            return None
        try:
            return client.get_policy(request=iam_v2.GetPolicyRequest(name=name))
        except Exception:
            return None

    def _save_deny_policy(self, policy, *, scope_type: str, scope_name: str, project_id: str) -> None:
        raw = resource_to_dict(policy)
        policy_id = extract_path_tail(str(raw.get("name") or ""))
        if not policy_id:
            return
        rules = raw.get("rules") or []
        denied_principals: set[str] = set()
        denied_permissions: set[str] = set()
        exception_principals: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            deny = rule.get("deny_rule") or rule.get("denyRule") or {}
            denied_principals.update(deny.get("denied_principals") or deny.get("deniedPrincipals") or [])
            denied_permissions.update(deny.get("denied_permissions") or deny.get("deniedPermissions") or [])
            exception_principals.update(deny.get("exception_principals") or deny.get("exceptionPrincipals") or [])
        self.session.insert_data(
            "iam_deny_policies",
            {
                "scope_type": scope_type,
                "scope_name": scope_name,
                "project_id": project_id,
                "policy_id": policy_id,
                "display_name": str(raw.get("display_name") or raw.get("displayName") or ""),
                "etag": str(raw.get("etag") or ""),
                "rule_count": len(rules),
                "denied_principals": "; ".join(sorted(denied_principals)),
                "denied_permissions": "; ".join(sorted(denied_permissions)),
                "exception_principals": "; ".join(sorted(exception_principals)),
                "rules_json": json.dumps(rules, default=str, ensure_ascii=False),
                "raw_json": json.dumps(raw, default=str, ensure_ascii=False),
            },
        )

    def _collect_deny_policies(self, resources: dict) -> None:
        """Enumerate + cache IAM deny policies for every org/folder/project scope in
        ``resources`` (which is already scope-sliced by run()). Records the
        ``iam.denypolicies.list`` permission as evidence per scope. Best-effort."""
        if iam_v2 is None:
            return
        scope_specs = (
            ("org", resources.get("orgs") or [], "organizations", "organization_permissions"),
            ("folder", resources.get("folders") or [], "folders", "folder_permissions"),
            ("project", resources.get("projects") or [], "projects", "project_permissions"),
        )
        if not any(rows for _scope, rows, _rm, _key in scope_specs):
            return
        client = self._safe_client(lambda: iam_v2.PoliciesClient(credentials=self.session.credentials))
        if client is None:
            return

        deny_actions: dict[str, Any] = {}
        stored = 0
        for scope_type, rows, rm_collection, scope_key in scope_specs:
            perms_by_scope: dict[str, set] = defaultdict(set)
            for row in rows:
                scope_name = str(row.get("name") or "").strip()
                project_id = str(row.get("project_id") or "").strip()
                attachment, attach_id = self._deny_attachment_point(scope_type, scope_name, project_id, rm_collection)
                if not attach_id:
                    continue
                parent = f"policies/{urllib.parse.quote(attachment, safe='')}/denypolicies"
                policies = self._list_deny_policies(client, parent)
                if policies is None:
                    continue
                perms_by_scope[scope_name or attach_id].add("iam.denypolicies.list")
                for policy in policies:
                    # list returns metadata only -> fetch the full policy for its rules;
                    # fall back to the list summary if get is denied / quota-limited.
                    full = self._get_deny_policy(client, str(getattr(policy, "name", "") or ""))
                    if full is not None:
                        perms_by_scope[scope_name or attach_id].add("iam.denypolicies.get")
                    self._save_deny_policy(full if full is not None else policy, scope_type=scope_type, scope_name=scope_name, project_id=project_id)
                    stored += 1
            if perms_by_scope:
                deny_actions[scope_key] = perms_by_scope
        if deny_actions:
            self.session.insert_actions(deny_actions)
        if stored:
            print(f"[*] IAM deny policies cached: {stored}")

    def run(
        self,
        *,
        save_raw_policies: bool = True,
        services: set[str] | None = None,
        scope: dict | None = None,
        sync_users: bool = True,
    ):
        """Fetch getIamPolicy for every cached resource in scope and cache the policies.

        Iterates the cached service tables (resources discovered by prior enum
        modules), fetches each resource's allow-policy, caches it into
        iam_allow_policies (when save_raw_policies), and records each successful
        getIamPolicy as PERMISSION EVIDENCE (provenance direct_api) via
        session.insert_actions. Prints a per-service cached/attempted/success/failed
        summary.

        scope selects which slice of the cached hierarchy/resources to collect so
        enum_all can PIPELINE binding collection per hierarchy node instead of one
        end-of-run barrier:
          * None / {}              -> everything (standalone / aggregate run)
          * {"hierarchy": True}    -> org + folder nodes only (no resources)
          * {"project_id": <pid>}  -> that project's node + its resources
          * {"orphans": True}      -> resources missing/out-of-scope project_id
                                      (pass known_projects to exclude already-covered ones)
        services (a set of service keys) optionally restricts which services run.

        sync_users: when True (standalone) rebuilds the principal/user table and
        materializes member_permissions_summary at the end. Pipelined per-node runs
        pass sync_users=False and the orchestrator does that ONCE after all nodes land.

        THREADING/INVARIANT: this does session.get_data + insert_actions + DB writes,
        so it must run on the DataController-owning (main) thread, never inside a
        ThreadPoolExecutor worker.
        """
        selected_services = {str(service).strip().lower() for service in (services or set()) if str(service).strip()}

        # ``scope`` selects which slice of the cached hierarchy/resources this run
        # collects bindings for, so enum_all can pipeline policy collection per
        # hierarchy node instead of one barrier at the end:
        #   None                    -> everything (standalone / aggregate)
        #   {"hierarchy": True}     -> org + folder nodes only (no resources)
        #   {"project_id": "<pid>"} -> that project's node + its resources
        #   {"orphans": True}       -> resources missing a project_id (reconcile)
        scope = scope or {}
        hierarchy_only = bool(scope.get("hierarchy"))
        project_filter = str(scope.get("project_id") or "").strip()
        orphan_mode = bool(scope.get("orphans"))
        # Resources covered by the per-project tasks; the orphan pass collects
        # everything NOT among these (missing or out-of-scope project_id) so the
        # pipelined partition matches the old whole-cache sweep exactly.
        known_projects = [str(p).strip() for p in (scope.get("known_projects") or []) if str(p).strip()]
        if hierarchy_only:
            wanted_levels = {"org", "folder"}
            include_resources = False
        elif project_filter:
            wanted_levels = {"project"}
            include_resources = True
        elif orphan_mode:
            wanted_levels = set()  # project nodes always carry a project_id
            include_resources = True
        else:
            wanted_levels = {"org", "folder", "project"}
            include_resources = True

        def _load(
            service_key: str,
            table: str,
            *,
            columns: list[str],
            conditions: str | None = None,
            hierarchy_level: str | None = None,
        ):
            if not self._include_service(selected_services, service_key):
                return []
            if hierarchy_level is not None:
                if hierarchy_level not in wanted_levels:
                    return []
                where = {"project_id": project_filter} if (hierarchy_level == "project" and project_filter) else None
                return self.session.get_data(table, columns=columns, conditions=conditions, where=where) or []
            if not include_resources:
                return []
            if project_filter:
                return self.session.get_data(table, columns=columns, conditions=conditions, where={"project_id": project_filter}) or []
            if orphan_mode:
                clauses = ["project_id IS NULL", "TRIM(project_id) = ''"]
                orphan_params: list = []
                if known_projects:
                    placeholders = ",".join("?" for _ in known_projects)
                    clauses.append(f"project_id NOT IN ({placeholders})")
                    orphan_params = list(known_projects)
                orphan_condition = "(" + " OR ".join(clauses) + ")"
                merged = f"{conditions} AND {orphan_condition}" if conditions else orphan_condition
                return self.session.get_data(table, columns=columns, conditions=merged, params=orphan_params) or []
            return self.session.get_data(table, columns=columns, conditions=conditions) or []

        resources = {
            "orgs": _load("resource_manager", "abstract_tree_hierarchy", columns=["name", "project_id"], conditions='type="org"', hierarchy_level="org"),
            "folders": _load("resource_manager", "abstract_tree_hierarchy", columns=["name", "project_id"], conditions='type="folder"', hierarchy_level="folder"),
            "projects": _load("resource_manager", "abstract_tree_hierarchy", columns=["name", "project_id"], conditions='type="project"', hierarchy_level="project"),
            "buckets": _load("storage", "cloudstorage_buckets", columns=["name", "project_id"]),
            "bigquery_datasets": _load("bigquery", "bigquery_datasets", columns=["full_dataset_id", "dataset_id", "project_id"]),
            "functions": _load("functions", "cloudfunctions_functions", columns=["name", "project_id", "environment"]),
            "instances": _load("compute", "cloudcompute_instances", columns=["name", "zone", "project_id", "id"]),
            "service_accounts": _load("service_accounts", "iam_service_accounts", columns=["name", "email", "project_id", "unique_id", "type"]),
            "secrets": _load("secrets", "secretsmanager_secrets", columns=["name", "project_id"]),
            "cloudrun_services": _load("cloudrun", "cloudrun_services", columns=["name", "project_id"]),
            "cloudrun_jobs": _load("cloudrun", "cloudrun_jobs", columns=["name", "project_id"]),
            "cloudtasks_queues": _load("cloudtasks", "cloudtasks_queues", columns=["name", "project_id"]),
            "artifactregistry_repositories": _load("artifactregistry", "artifactregistry_repositories", columns=["name", "project_id"]),
            "kms_keyrings": _load("kms", "kms_keyrings", columns=["name", "project_id"]),
            "kms_keys": _load("kms", "kms_keys", columns=["name", "project_id"]),
            "pubsub_topics": _load("pubsub", "pubsub_topics", columns=["name", "project_id"]),
            "pubsub_subscriptions": _load("pubsub", "pubsub_subscriptions", columns=["name", "project_id"]),
            "pubsub_snapshots": _load("pubsub", "pubsub_snapshots", columns=["name", "project_id"]),
            "pubsub_schemas": _load("pubsub", "pubsub_schemas", columns=["name", "project_id"]),
            "servicedirectory_namespaces": _load("servicedirectory", "servicedirectory_namespaces", columns=["name", "project_id"]),
            "servicedirectory_services": _load("servicedirectory", "servicedirectory_services", columns=["name", "project_id"]),
        }

        total_cached_resources = sum(len(rows or []) for rows in resources.values())
        print(f"[*] Enumerating IAM policies across {total_cached_resources} cached resources")
        policy_stats: dict[str, dict[str, int]] = {
            key: {"cached": len(resources.get(key) or []), "attempted": 0, "success": 0}
            for key in resources.keys()
        }

        def _announce(stats_key: str, label: str) -> None:
            cached = int(policy_stats.get(stats_key, {}).get("cached", 0))
            if cached > 0:
                print(f"[*] Checking {label}: cached={cached}")

        def _mark_attempt(stats_key: str) -> None:
            if stats_key in policy_stats:
                policy_stats[stats_key]["attempted"] += 1

        def _mark_success(stats_key: str) -> None:
            if stats_key in policy_stats:
                policy_stats[stats_key]["success"] += 1

        def _sdk_spec(
            service_key: str,
            client_key: str,
            stats_key: str,
            label: str,
            resource_key: str,
            permission: str,
            service_label: str,
            action_group: str,
            policy_type: str,
        ) -> dict[str, str]:
            return {
                "service_key": service_key,
                "client_key": client_key,
                "stats_key": stats_key,
                "label": label,
                "resource_key": resource_key,
                "permission": permission,
                "service_label": service_label,
                "action_group": action_group,
                "policy_type": policy_type,
            }

        def _discovery_spec(
            service_key: str,
            stats_key: str,
            label: str,
            resource_key: str,
            discovery_resource_type: str,
            permission: str,
            service_label: str,
            action_group: str,
            policy_type: str,
        ) -> dict[str, str]:
            return {
                "service_key": service_key,
                "stats_key": stats_key,
                "label": label,
                "resource_key": resource_key,
                "discovery_resource_type": discovery_resource_type,
                "permission": permission,
                "service_label": service_label,
                "action_group": action_group,
                "policy_type": policy_type,
            }

        def _policy_fetch_ok(policy: Any) -> bool:
            return bool(policy) and policy not in (404, "Not Enabled")

        def _enumerate_scope_specs(*, specs: list[dict[str, str]]) -> dict[str, Any]:
            scope_actions: dict[str, Any] = {}
            for spec in specs:
                if not self._include_service(selected_services, str(spec["service_key"])):
                    continue
                client = self.clients.get(str(spec["client_key"]))
                if not client:
                    continue
                _announce(str(spec["stats_key"]), str(spec["label"]))
                permissions = defaultdict(set)
                for row in resources.get(str(spec["resource_key"])) or []:
                    name = str(row.get("name") or "").strip()
                    project_id = str(row.get("project_id") or "").strip() or getattr(self.session, "project_id", "N/A")
                    if not name:
                        continue
                    _mark_attempt(str(spec["stats_key"]))
                    policy = self._sdk_get_iam_policy(
                        client,
                        name,
                        api_name=str(spec["permission"]),
                        service_label=str(spec["service_label"]),
                        project_id=project_id,
                    )
                    if _policy_fetch_ok(policy):
                        _mark_success(str(spec["stats_key"]))
                        permissions[name].add(str(spec["permission"]))
                        self._capture_policy(
                            project_id=project_id,
                            resource_type=str(spec["policy_type"]),
                            resource_name=name,
                            policy=policy,
                            save_raw_policies=save_raw_policies,
                        )
                if permissions:
                    scope_actions[str(spec["scope_key"])] = permissions
            return scope_actions

        def _enumerate_resource_specs(*, specs: list[dict[str, Any]], actions) -> None:
            for spec in specs:
                if not self._include_service(selected_services, str(spec["service_key"])):
                    continue
                _announce(str(spec["stats_key"]), str(spec["label"]))
                for row in resources.get(str(spec["resource_key"])) or []:
                    context_builder = spec.get("context_builder")
                    if not callable(context_builder):
                        continue
                    context = context_builder(row) or {}
                    resource_name = str(context.get("resource_name") or "").strip()
                    if not resource_name:
                        continue
                    project_id = str(context.get("project_id") or "").strip() or getattr(self.session, "project_id", "")
                    _mark_attempt(str(spec["stats_key"]))
                    policy_fetcher = spec.get("policy_fetcher")
                    if not callable(policy_fetcher):
                        continue
                    policy = policy_fetcher(context, project_id)
                    if _policy_fetch_ok(policy):
                        _mark_success(str(spec["stats_key"]))
                        action_label = str(context.get("action_label") or resource_name).strip()
                        action_group = str(context.get("action_group") or spec["action_group"])
                        actions[project_id][str(spec["permission"])][action_group].add(action_label)
                        self._capture_policy(
                            project_id=project_id,
                            resource_type=str(spec["policy_type"]),
                            resource_name=str(context.get("capture_name") or resource_name).strip(),
                            policy=policy,
                            save_raw_policies=save_raw_policies,
                        )

        def _enumerate_sdk_specs(*, specs: list[dict[str, str]], actions) -> None:
            for spec in specs:
                service_key = str(spec.get("service_key") or "").strip()
                if service_key and not self._include_service(selected_services, service_key):
                    continue
                client = self.clients.get(str(spec["client_key"]))
                if not client:
                    continue
                _announce(str(spec["stats_key"]), str(spec["label"]))
                for row in resources.get(str(spec["resource_key"])) or []:
                    name = str(row.get("name") or "").strip()
                    project_id = str(row.get("project_id") or "").strip() or getattr(self.session, "project_id", "")
                    if not name:
                        continue
                    _mark_attempt(str(spec["stats_key"]))
                    policy = self._sdk_get_iam_policy(
                        client,
                        resource_name=name,
                        api_name=str(spec["permission"]),
                        service_label=str(spec["service_label"]),
                        project_id=project_id,
                    )
                    if _policy_fetch_ok(policy):
                        _mark_success(str(spec["stats_key"]))
                        actions[project_id][str(spec["permission"])][str(spec["action_group"])].add(name)
                        self._capture_policy(
                            project_id=project_id,
                            resource_type=str(spec["policy_type"]),
                            resource_name=name,
                            policy=policy,
                            save_raw_policies=save_raw_policies,
                        )

        def _enumerate_discovery_specs(*, specs: list[dict[str, str]], actions) -> None:
            for spec in specs:
                service_key = str(spec.get("service_key") or "").strip()
                if service_key and not self._include_service(selected_services, service_key):
                    continue
                _announce(str(spec["stats_key"]), str(spec["label"]))
                service = self._discovery_resource_for_type(str(spec["discovery_resource_type"]))
                for row in resources.get(str(spec["resource_key"])) or []:
                    name = str(row.get("name") or "").strip()
                    project_id = str(row.get("project_id") or "").strip() or self._resource_id_to_project_id(name)
                    if not name:
                        continue
                    _mark_attempt(str(spec["stats_key"]))
                    policy = self._discovery_get_iam_policy(
                        service,
                        resource_name=name,
                        api_name=str(spec["permission"]),
                        service_label=str(spec["service_label"]),
                        project_id=project_id,
                    )
                    if _policy_fetch_ok(policy):
                        _mark_success(str(spec["stats_key"]))
                        actions[project_id][str(spec["permission"])][str(spec["action_group"])].add(name)
                        self._capture_policy(
                            project_id=project_id,
                            resource_type=str(spec["policy_type"]),
                            resource_name=name,
                            policy=policy,
                            save_raw_policies=save_raw_policies,
                        )

        iam_actions = _enumerate_scope_specs(
            specs=[
                {
                    **_sdk_spec("resource_manager", "org", "orgs", "organization IAM policies", "orgs", "resourcemanager.organizations.getIamPolicy", "Resource Manager", "organizations", "org"),
                    # MUST be the canonical scope_key from action_schema.ACTION_SCOPE_SPECS --
                    # db._merge does record.get("organization_permissions"), so "org_permissions"
                    # silently drops org-scope getIamPolicy evidence into no column.
                    "scope_key": "organization_permissions",
                },
                {
                    **_sdk_spec("resource_manager", "folder", "folders", "folder IAM policies", "folders", "resourcemanager.folders.getIamPolicy", "Resource Manager", "folders", "folder"),
                    "scope_key": "folder_permissions",
                },
                {
                    **_sdk_spec("resource_manager", "project", "projects", "project IAM policies", "projects", "resourcemanager.projects.getIamPolicy", "Resource Manager", "projects", "project"),
                    "scope_key": "project_permissions",
                },
            ]
        )
        if iam_actions:
            self.session.insert_actions(iam_actions)

        for column_name, specs in (
            (
                "storage_actions_allowed",
                [
                    {
                        "service_key": "storage",
                        "stats_key": "buckets",
                        "label": "bucket IAM policies",
                        "resource_key": "buckets",
                        "permission": "storage.buckets.getIamPolicy",
                        "action_group": "buckets",
                        "policy_type": "bucket",
                        "context_builder": lambda row: {
                            "resource_name": str(row.get("name") or "").strip(),
                            "project_id": str(row.get("project_id") or "").strip(),
                        },
                        "policy_fetcher": lambda context, _project_id: self._bucket_get_iam_policy(
                            str(context.get("resource_name") or ""),
                            debug=getattr(self.session, "debug", False),
                        ),
                    },
                ],
            ),
            (
                "bigquery_actions_allowed",
                [
                    {
                        "service_key": "bigquery",
                        "stats_key": "bigquery_datasets",
                        "label": "BigQuery dataset IAM policies",
                        "resource_key": "bigquery_datasets",
                        "permission": "bigquery.datasets.get",
                        "action_group": "datasets",
                        "policy_type": "bigquerydataset",
                        "context_builder": lambda row: {
                            "resource_name": self._bigquery_dataset_id(row),
                            "project_id": str(row.get("project_id") or "").strip(),
                        },
                        "policy_fetcher": lambda context, project_id: self._bigquery_get_iam_policy(
                            str(context.get("resource_name") or ""),
                            project_id=project_id,
                        ),
                    },
                ],
            ),
            (
                "function_actions_allowed",
                [
                    {
                        "service_key": "functions",
                        "stats_key": "functions",
                        "label": "Cloud Functions IAM policies",
                        "resource_key": "functions",
                        "permission": "cloudfunctions.functions.getIamPolicy",
                        "action_group": "functions",
                        "policy_type": "cloudfunction",
                        "context_builder": lambda row: (
                            lambda name, environment, project_id: {
                                "resource_name": name,
                                "project_id": project_id,
                                "action_label": f"[{extract_path_segment(name, 'locations')}] {extract_path_tail(name, default=name)}",
                                "action_group": "functions_v2" if str(environment) == "2" else "functions_v1",
                            }
                            if name
                            else {}
                        )(
                            str(row.get("name") or "").strip(),
                            row.get("environment"),
                            str(row.get("project_id") or "").strip(),
                        ),
                        "policy_fetcher": lambda context, project_id: self._sdk_get_iam_policy(
                            self.clients.get("function"),
                            str(context.get("resource_name") or ""),
                            api_name="cloudfunctions.functions.getIamPolicy",
                            service_label="Cloud Functions",
                            project_id=project_id,
                        ),
                    },
                ],
            ),
            (
                "compute_actions_allowed",
                [
                    {
                        "service_key": "compute",
                        "stats_key": "instances",
                        "label": "Compute instance IAM policies",
                        "resource_key": "instances",
                        "permission": "compute.instances.getIamPolicy",
                        "action_group": "instances",
                        "policy_type": "computeinstance",
                        "context_builder": lambda row: (
                            lambda name, zone, project_id: {
                                "resource_name": name,
                                "project_id": project_id,
                                "zone": zone,
                                "capture_name": f"projects/{project_id}/zones/{zone}/instances/{name}",
                            }
                            if name and zone and project_id
                            else {}
                        )(
                            str(row.get("name") or "").strip(),
                            extract_path_tail(str(row.get("zone") or ""), default=str(row.get("zone") or "")),
                            str(row.get("project_id") or "").strip(),
                        ),
                        "policy_fetcher": lambda context, project_id: self._compute_instance_get_iam_policy(
                            project_id,
                            str(context.get("resource_name") or ""),
                            str(context.get("zone") or ""),
                            debug=getattr(self.session, "debug", False),
                        ),
                    },
                ],
            ),
            (
                "service_account_actions_allowed",
                [
                    {
                        "service_key": "service_accounts",
                        "stats_key": "service_accounts",
                        "label": "service account IAM policies",
                        "resource_key": "service_accounts",
                        "permission": "iam.serviceAccounts.getIamPolicy",
                        "action_group": "service account",
                        "policy_type": "service-account",
                        "context_builder": lambda row: {
                            "resource_name": str(row.get("name") or "").strip(),
                            "project_id": str(row.get("project_id") or "").strip(),
                        },
                        "policy_fetcher": lambda context, project_id: self._sdk_get_iam_policy(
                            self.clients.get("iam"),
                            str(context.get("resource_name") or ""),
                            api_name="iam.serviceAccounts.getIamPolicy",
                            service_label="IAM",
                            project_id=project_id,
                        ),
                    },
                ],
            ),
            (
                "secret_actions_allowed",
                [
                    {
                        "service_key": "secrets",
                        "stats_key": "secrets",
                        "label": "Secret Manager IAM policies",
                        "resource_key": "secrets",
                        "permission": "secretmanager.secrets.getIamPolicy",
                        "action_group": "secrets",
                        "policy_type": "secrets",
                        "context_builder": lambda row: (
                            lambda name, project_id: {
                                "resource_name": name,
                                "project_id": project_id,
                                "action_label": extract_path_tail(name, default=name) if name else "",
                            }
                            if name
                            else {}
                        )(
                            str(row.get("name") or "").strip(),
                            str(row.get("project_id") or "").strip(),
                        ),
                        "policy_fetcher": lambda context, project_id: self._sdk_get_iam_policy(
                            self.clients.get("secret"),
                            str(context.get("resource_name") or ""),
                            api_name="secretmanager.secrets.getIamPolicy",
                            service_label="Secret Manager",
                            project_id=project_id,
                        ),
                    },
                ],
            ),
        ):
            actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
            _enumerate_resource_specs(specs=specs, actions=actions)
            if actions:
                self.session.insert_actions(actions, column_name=column_name)

        for column_name, enumerator, specs in (
            (
                "cloudrun_actions_allowed",
                _enumerate_sdk_specs,
                [
                    _sdk_spec("cloudrun", "run_services", "cloudrun_services", "Cloud Run service IAM policies", "cloudrun_services", "run.services.getIamPolicy", "Cloud Run", "services", "cloudrunservice"),
                    _sdk_spec("cloudrun", "run_jobs", "cloudrun_jobs", "Cloud Run job IAM policies", "cloudrun_jobs", "run.jobs.getIamPolicy", "Cloud Run", "jobs", "cloudrunjob"),
                ],
            ),
            (
                "cloudtasks_actions_allowed",
                _enumerate_sdk_specs,
                [
                    _sdk_spec("cloudtasks", "cloudtasks", "cloudtasks_queues", "Cloud Tasks queue IAM policies", "cloudtasks_queues", "cloudtasks.queues.getIamPolicy", "Cloud Tasks", "queues", "cloudtasksqueue"),
                ],
            ),
            (
                "artifactregistry_actions_allowed",
                _enumerate_discovery_specs,
                [
                    _discovery_spec("artifactregistry", "artifactregistry_repositories", "Artifact Registry repository IAM policies", "artifactregistry_repositories", "artifactregistry_repository", "artifactregistry.repositories.getIamPolicy", "Artifact Registry", "repositories", "artifactregistryrepo"),
                ],
            ),
            (
                "kms_actions_allowed",
                _enumerate_discovery_specs,
                [
                    _discovery_spec("kms", "kms_keyrings", "Cloud KMS keyring IAM policies", "kms_keyrings", "kms_keyring", "cloudkms.keyRings.getIamPolicy", "Cloud KMS", "keyrings", "kmskeyring"),
                    _discovery_spec("kms", "kms_keys", "Cloud KMS cryptokey IAM policies", "kms_keys", "kms_key", "cloudkms.cryptoKeys.getIamPolicy", "Cloud KMS", "keys", "kmscryptokey"),
                ],
            ),
            (
                "pubsub_actions_allowed",
                _enumerate_discovery_specs,
                [
                    _discovery_spec("pubsub", "pubsub_topics", "Pub/Sub topics IAM policies", "pubsub_topics", "pubsub_topic", "pubsub.topics.getIamPolicy", "Pub/Sub", "topics", "pubsubtopic"),
                    _discovery_spec("pubsub", "pubsub_subscriptions", "Pub/Sub subscriptions IAM policies", "pubsub_subscriptions", "pubsub_subscription", "pubsub.subscriptions.getIamPolicy", "Pub/Sub", "subscriptions", "pubsubsubscription"),
                    _discovery_spec("pubsub", "pubsub_snapshots", "Pub/Sub snapshots IAM policies", "pubsub_snapshots", "pubsub_snapshot", "pubsub.snapshots.getIamPolicy", "Pub/Sub", "snapshots", "pubsubsnapshot"),
                    _discovery_spec("pubsub", "pubsub_schemas", "Pub/Sub schemas IAM policies", "pubsub_schemas", "pubsub_schema", "pubsub.schemas.getIamPolicy", "Pub/Sub", "schemas", "pubsubschema"),
                ],
            ),
            (
                "servicedirectory_actions_allowed",
                _enumerate_discovery_specs,
                [
                    _discovery_spec("servicedirectory", "servicedirectory_namespaces", "Service Directory namespaces IAM policies", "servicedirectory_namespaces", "servicedirectory_namespace", "servicedirectory.namespaces.getIamPolicy", "Service Directory", "namespaces", "servicedirectorynamespace"),
                    _discovery_spec("servicedirectory", "servicedirectory_services", "Service Directory services IAM policies", "servicedirectory_services", "servicedirectory_service", "servicedirectory.services.getIamPolicy", "Service Directory", "services", "servicedirectoryservice"),
                ],
            ),
        ):
            actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
            enumerator(specs=specs, actions=actions)
            if actions:
                self.session.insert_actions(actions, column_name=column_name)

        print("[*] IAM policy fetch summary (cached/attempted/success/failed):")
        for stats_key in sorted(policy_stats.keys()):
            stats = policy_stats[stats_key]
            cached = int(stats.get("cached", 0))
            attempted = int(stats.get("attempted", 0))
            success = int(stats.get("success", 0))
            failed = max(attempted - success, 0)
            if cached == 0 and attempted == 0:
                continue
            print(f"[*]   {stats_key}: cached={cached} attempted={attempted} success={success} failed={failed}")

        # IAM DENY policies (iam.googleapis.com v2) for the SAME org/folder/project scopes.
        # A deny policy can revoke permissions an allow grant would give, so cache them for
        # completeness. Best-effort: a failure here never affects the allow-policy pass above.
        try:
            self._collect_deny_policies(resources)
        except Exception:
            if getattr(self.session, "debug", False):
                traceback.print_exc()

        # Per-node pipelined runs defer sync_users to a single main-thread pass so
        # the principal/user table is rebuilt once after all bindings land. The
        # member-inverted view is materialized at the same point so OpenGraph and
        # the `data` command always see a current member_permissions_summary.
        if sync_users:
            self.session.sync_users()
            materialize_member_permissions(self.session)

    def _set_sdk_iam_member(
        self,
        *,
        client,
        resource_name: str,
        member: str,
        role: str,
        brute: bool,
        action_dict: dict | None,
        api_name_get: str,
        api_name_set: str,
        service_label: str,
        resource_type: str,
        debug: bool = False,
    ):
        """Grant a member/role on an SDK-backed resource: read policy, merge, setIamPolicy.

        Read-modify-write. Returns -1 on missing args; "Not Enabled" if the API is
        disabled; "GetPolicyFailed" if the current policy could not be read and
        brute is False (use --overwrite to force a full replace). On a successful
        write, records setIamPolicy as evidence into action_dict (if given).
        """
        normalized_resource_name = str(resource_name or "").strip()
        normalized_member = str(member or "").strip()
        normalized_role = str(role or "").strip()
        if not normalized_resource_name or not normalized_member or not normalized_role:
            if debug:
                print(f"{UtilityTools.RED}[X] Missing resource name/member/role for setIamPolicy member operation.{UtilityTools.RESET}")
            return -1

        project_id = self._resource_id_to_project_id(normalized_resource_name)
        current_policy = self._sdk_get_iam_policy(
            client,
            normalized_resource_name,
            api_name=api_name_get,
            service_label=service_label,
            project_id=project_id,
        )
        if current_policy == "Not Enabled":
            return current_policy
        if not current_policy and not brute:
            print(
                f"{UtilityTools.RED}[X] Could not read policy for {normalized_resource_name}. "
                f"Use --overwrite to attempt a full replace.{UtilityTools.RESET}"
            )
            return "GetPolicyFailed"

        policy_dict = self._policy_for_member_update(
            self._policy_to_dict(current_policy),
            member=normalized_member,
            role=normalized_role,
            brute=brute,
        )

        set_resp = self._sdk_set_iam_policy(
            client,
            normalized_resource_name,
            policy_dict,
            api_name=api_name_set,
            service_label=service_label,
            project_id=project_id,
        )
        if set_resp and set_resp != "Not Enabled" and set_resp != 404 and action_dict is not None:
            record_permissions(
                action_dict,
                permissions=api_name_set,
                project_id=project_id,
                resource_type=resource_type,
                resource_label=normalized_resource_name,
            )
        return set_resp

    def _set_discovery_iam_member(
        self,
        *,
        resource_type: str,
        resource_name: str,
        member: str,
        role: str,
        brute: bool,
        action_dict: dict | None,
        api_name_get: str,
        api_name_set: str,
        service_label: str,
        action_resource_type: str,
        debug: bool = False,
    ):
        """Grant a member/role on a discovery (REST) resource: read, merge, setIamPolicy.

        Same read-modify-write contract and return sentinels as _set_sdk_iam_member,
        but routes through the discovery client resolved from ``resource_type``.
        Returns -1 if the resource_type has no discovery handle.
        """
        normalized_resource_name = str(resource_name or "").strip()
        normalized_member = str(member or "").strip()
        normalized_role = str(role or "").strip()
        if not normalized_resource_name or not normalized_member or not normalized_role:
            if debug:
                print(f"{UtilityTools.RED}[X] Missing resource name/member/role for setIamPolicy member operation.{UtilityTools.RESET}")
            return -1

        project_id = self._resource_id_to_project_id(normalized_resource_name)
        service = self._discovery_resource_for_type(resource_type)
        if service is None:
            return -1

        current_policy = self._discovery_get_iam_policy(
            service,
            resource_name=normalized_resource_name,
            api_name=api_name_get,
            service_label=service_label,
            project_id=project_id,
        )
        if current_policy == "Not Enabled":
            return current_policy
        if not current_policy and not brute:
            print(
                f"{UtilityTools.RED}[X] Could not read policy for {normalized_resource_name}. "
                f"Use --overwrite to attempt a full replace.{UtilityTools.RESET}"
            )
            return "GetPolicyFailed"

        policy_dict = self._policy_for_member_update(
            self._policy_to_dict(current_policy),
            member=normalized_member,
            role=normalized_role,
            brute=brute,
        )

        set_resp = self._discovery_set_iam_policy(
            service,
            resource_name=normalized_resource_name,
            policy=policy_dict,
            api_name=api_name_set,
            service_label=service_label,
            project_id=project_id,
        )
        if set_resp and set_resp != "Not Enabled" and action_dict is not None:
            record_permissions(
                action_dict,
                permissions=api_name_set,
                project_id=project_id,
                resource_type=action_resource_type,
                resource_label=normalized_resource_name,
            )
        return set_resp

    _SDK_SET_CONFIG: dict[str, dict[str, str]] = {
        "organization": {
            "client_key": "org",
            "api_name_get": "resourcemanager.organizations.getIamPolicy",
            "api_name_set": "resourcemanager.organizations.setIamPolicy",
            "service_label": "Resource Manager",
            "resource_type": "organizations",
        },
        "folder": {
            "client_key": "folder",
            "api_name_get": "resourcemanager.folders.getIamPolicy",
            "api_name_set": "resourcemanager.folders.setIamPolicy",
            "service_label": "Resource Manager",
            "resource_type": "folders",
        },
        "project": {
            "client_key": "project",
            "api_name_get": "resourcemanager.projects.getIamPolicy",
            "api_name_set": "resourcemanager.projects.setIamPolicy",
            "service_label": "Resource Manager",
            "resource_type": "projects",
        },
        "cloudfunction": {
            "client_key": "function",
            "api_name_get": "cloudfunctions.functions.getIamPolicy",
            "api_name_set": "cloudfunctions.functions.setIamPolicy",
            "service_label": "Cloud Functions",
            "resource_type": "functions",
        },
        "secret": {
            "client_key": "secret",
            "api_name_get": "secretmanager.secrets.getIamPolicy",
            "api_name_set": "secretmanager.secrets.setIamPolicy",
            "service_label": "Secret Manager",
            "resource_type": "secrets",
        },
        "cloudrun_service": {
            "client_key": "run_services",
            "api_name_get": "run.services.getIamPolicy",
            "api_name_set": "run.services.setIamPolicy",
            "service_label": "Cloud Run",
            "resource_type": "services",
        },
        "cloudrun_job": {
            "client_key": "run_jobs",
            "api_name_get": "run.jobs.getIamPolicy",
            "api_name_set": "run.jobs.setIamPolicy",
            "service_label": "Cloud Run",
            "resource_type": "jobs",
        },
        "service_account": {
            "client_key": "iam",
            "api_name_get": "iam.serviceAccounts.getIamPolicy",
            "api_name_set": "iam.serviceAccounts.setIamPolicy",
            "service_label": "IAM",
            "resource_type": "service accounts",
        },
    }

    _DISCOVERY_SET_CONFIG: dict[str, dict[str, str]] = {
        "artifactregistry_repository": {
            "api_name_get": "artifactregistry.repositories.getIamPolicy",
            "api_name_set": "artifactregistry.repositories.setIamPolicy",
            "service_label": "Artifact Registry",
            "resource_type": "repositories",
        },
        "kms_keyring": {
            "api_name_get": "cloudkms.keyRings.getIamPolicy",
            "api_name_set": "cloudkms.keyRings.setIamPolicy",
            "service_label": "Cloud KMS",
            "resource_type": "keyrings",
        },
        "kms_key": {
            "api_name_get": "cloudkms.cryptoKeys.getIamPolicy",
            "api_name_set": "cloudkms.cryptoKeys.setIamPolicy",
            "service_label": "Cloud KMS",
            "resource_type": "keys",
        },
        "pubsub_topic": {
            "api_name_get": "pubsub.topics.getIamPolicy",
            "api_name_set": "pubsub.topics.setIamPolicy",
            "service_label": "Pub/Sub",
            "resource_type": "topics",
        },
        "pubsub_subscription": {
            "api_name_get": "pubsub.subscriptions.getIamPolicy",
            "api_name_set": "pubsub.subscriptions.setIamPolicy",
            "service_label": "Pub/Sub",
            "resource_type": "subscriptions",
        },
        "pubsub_snapshot": {
            "api_name_get": "pubsub.snapshots.getIamPolicy",
            "api_name_set": "pubsub.snapshots.setIamPolicy",
            "service_label": "Pub/Sub",
            "resource_type": "snapshots",
        },
        "pubsub_schema": {
            "api_name_get": "pubsub.schemas.getIamPolicy",
            "api_name_set": "pubsub.schemas.setIamPolicy",
            "service_label": "Pub/Sub",
            "resource_type": "schemas",
        },
        "servicedirectory_namespace": {
            "api_name_get": "servicedirectory.namespaces.getIamPolicy",
            "api_name_set": "servicedirectory.namespaces.setIamPolicy",
            "service_label": "Service Directory",
            "resource_type": "namespaces",
        },
        "servicedirectory_service": {
            "api_name_get": "servicedirectory.services.getIamPolicy",
            "api_name_set": "servicedirectory.services.setIamPolicy",
            "service_label": "Service Directory",
            "resource_type": "services",
        },
        "cloudtasks_queue": {
            "api_name_get": "cloudtasks.queues.getIamPolicy",
            "api_name_set": "cloudtasks.queues.setIamPolicy",
            "service_label": "Cloud Tasks",
            "resource_type": "queues",
        },
    }

    def _set_bucket_iam_member(
        self,
        *,
        bucket_name: str,
        member: str,
        action_dict: dict | None = None,
        brute: bool = False,
        role: str = "roles/storage.admin",
        debug: bool = False,
    ):
        normalized_bucket_name = str(bucket_name or "").strip()
        normalized_member = str(member or "").strip()
        normalized_role = str(role or "roles/storage.admin").strip()
        if not normalized_bucket_name or not normalized_member:
            return -1

        project_id = self._resource_id_to_project_id(normalized_bucket_name)
        current_policy = self._bucket_get_iam_policy(normalized_bucket_name, debug=debug)
        if current_policy in ("Not Enabled", 404):
            return current_policy
        if not current_policy and not brute:
            print(
                f"{UtilityTools.RED}[X] Could not read policy for {normalized_bucket_name}. "
                f"Use --overwrite to attempt a full replace.{UtilityTools.RESET}"
            )
            return "GetPolicyFailed"
        policy_dict = self._policy_for_member_update(
            self._policy_to_dict(current_policy),
            member=normalized_member,
            role=normalized_role,
            brute=brute,
        )

        set_resp = self._bucket_set_iam_policy(normalized_bucket_name, policy_dict, debug=debug)
        if set_resp and set_resp not in ("Not Enabled", 404) and action_dict is not None:
            record_permissions(
                action_dict,
                permissions="storage.buckets.setIamPolicy",
                project_id=project_id,
                resource_type="buckets",
                resource_label=normalized_bucket_name,
            )
        return set_resp

    def _set_instance_iam_member(
        self,
        *,
        instance_name: str,
        project_id: str,
        zone_id: str,
        member: str,
        action_dict: dict | None = None,
        brute: bool = False,
        role: str = "roles/compute.admin",
        debug: bool = False,
    ):
        normalized_instance_name = str(instance_name or "").strip()
        normalized_project_id = str(project_id or "").strip()
        normalized_zone_id = str(zone_id or "").strip()
        normalized_member = str(member or "").strip()
        normalized_role = str(role or "roles/compute.admin").strip()
        if not (normalized_instance_name and normalized_project_id and normalized_zone_id and normalized_member):
            return -1

        current_policy = self._compute_instance_get_iam_policy(
            normalized_project_id,
            normalized_instance_name,
            normalized_zone_id,
            debug=debug,
        )
        if current_policy in ("Not Enabled", 404):
            return current_policy
        if not current_policy and not brute:
            print(
                f"{UtilityTools.RED}[X] Could not read policy for projects/{normalized_project_id}/zones/{normalized_zone_id}/instances/{normalized_instance_name}. "
                f"Use --overwrite to attempt a full replace.{UtilityTools.RESET}"
            )
            return "GetPolicyFailed"
        policy_dict = self._policy_for_member_update(
            self._policy_to_dict(current_policy),
            member=normalized_member,
            role=normalized_role,
            brute=brute,
        )

        set_resp = self._compute_instance_set_iam_policy(
            normalized_instance_name,
            normalized_project_id,
            normalized_zone_id,
            policy_dict,
            debug=debug,
        )
        if set_resp and set_resp not in ("Not Enabled", 404) and action_dict is not None:
            record_permissions(
                action_dict,
                permissions="compute.instances.setIamPolicy",
                project_id=normalized_project_id,
                resource_type="instances",
                resource_label=f"projects/{normalized_project_id}/zones/{normalized_zone_id}/instances/{normalized_instance_name}",
            )
        return set_resp

    def set_resource_iam_member(
        self,
        *,
        resource_type: str,
        resource_name: str,
        member: str,
        role: str,
        action_dict: dict | None = None,
        brute: bool = False,
        debug: bool = False,
        project_id: str | None = None,
        zone_id: str | None = None,
    ):
        """Public dispatcher: add ``member`` at ``role`` to any resource's IAM policy.

        Routes resource_type to the matching writer: bucket/instance (storage and
        compute special cases), SDK-backed types via _SDK_SET_CONFIG, or discovery
        types via _DISCOVERY_SET_CONFIG. For instances, parses project/zone/name out
        of a full "projects/.../zones/.../instances/..." name when not passed.
        Raises ValueError for an unsupported resource_type. Return values follow the
        underlying _set_* helpers (set response, "Not Enabled", 404, "GetPolicyFailed",
        or -1).
        """
        token = str(resource_type or "").strip().lower()
        if token == "function":
            token = "cloudfunction"
        name = str(resource_name or "").strip()
        if token == "bucket":
            return self._set_bucket_iam_member(
                bucket_name=name,
                member=member,
                action_dict=action_dict,
                brute=brute,
                role=role,
                debug=debug,
            )
        if token == "instance":
            local_project_id = str(project_id or "").strip()
            local_zone_id = str(zone_id or "").strip()
            local_name = name
            if name.startswith("projects/") and "/zones/" in name and "/instances/" in name:
                parsed_project = extract_path_segment(name, "projects")
                parsed_zone = extract_path_segment(name, "zones")
                parsed_name = extract_path_segment(name, "instances")
                if parsed_project and parsed_zone and parsed_name:
                    local_project_id = local_project_id or parsed_project
                    local_zone_id = local_zone_id or parsed_zone
                    local_name = parsed_name
            return self._set_instance_iam_member(
                instance_name=local_name,
                project_id=local_project_id,
                zone_id=local_zone_id,
                member=member,
                action_dict=action_dict,
                brute=brute,
                role=role,
                debug=debug,
            )

        sdk_config = self._SDK_SET_CONFIG.get(token)
        if sdk_config:
            return self._set_sdk_iam_member(
                client=self.clients.get(sdk_config["client_key"]),
                resource_name=name,
                member=member,
                role=role,
                action_dict=action_dict,
                brute=brute,
                api_name_get=sdk_config["api_name_get"],
                api_name_set=sdk_config["api_name_set"],
                service_label=sdk_config["service_label"],
                resource_type=sdk_config["resource_type"],
                debug=debug,
            )

        discovery_config = self._DISCOVERY_SET_CONFIG.get(token)
        if discovery_config:
            return self._set_discovery_iam_member(
                resource_type=token,
                resource_name=name,
                member=member,
                role=role,
                brute=brute,
                action_dict=action_dict,
                api_name_get=discovery_config["api_name_get"],
                api_name_set=discovery_config["api_name_set"],
                service_label=discovery_config["service_label"],
                action_resource_type=discovery_config["resource_type"],
                debug=debug,
            )

        raise ValueError(f"Unsupported IAM resource_type for set_resource_iam_member: {resource_type}")


def materialize_member_permissions(session) -> list[dict]:
    """Invert the resource-keyed iam_allow_policies into the member-keyed
    member_permissions_summary table (a materialized view kept in sync after
    bindings enumeration). Pure transform off cached bindings -- no network.

    Returns ``[{"member", "data_dict", "crednames"}]`` so a caller (the report
    module) can render without re-deriving. Runs inherently at the bindings
    sync_users point so OpenGraph + the `data` command never depend on a manual
    process_gcp_iam_bindings run.
    """
    from gcpwn.core.utils.iam_simplifier import create_simplified_hierarchy_permissions
    from gcpwn.modules.everything.utilities.helpers import (
        build_roles_and_assets_for_member,
        canonical_iam_member,
        consolidate_convenience_roles,
        split_members_by_kind,
    )

    simplified = create_simplified_hierarchy_permissions(
        session.get_data(
            "iam_allow_policies",
            columns=["project_id", "resource_type", "resource_name", "policy"],
        ) or [],
        include_inheritance=False,
        normalize_member=canonical_iam_member,
        is_convenience_member=lambda member: str(member or "").strip().startswith(
            ("projectViewer:", "projectEditor:", "projectOwner:")
        ),
    )
    bindings = list(simplified.get("flattened_member_rows") or [])
    if not bindings:
        return []

    members = normalize_str_set([b["member"] for b in bindings])
    _conv_members, valid_members = split_members_by_kind(members)

    # Group bindings by member ONCE (O(bindings)) so each member's tree is built from its
    # own rows -- build_roles_and_assets_for_member used to rescan the full binding set per
    # member (O(members x bindings)).
    bindings_by_member: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings:
        member_token = str(binding.get("member") or "").strip()
        if member_token:
            bindings_by_member.setdefault(member_token, []).append(binding)

    # Shared across all members so the recursive-CTE find_ancestors and project-name
    # lookups run once per distinct asset/project instead of O(members x assets).
    project_name_cache: dict[str, str] = {}
    ancestor_cache: dict[str, list] = {}
    convenience_summary = consolidate_convenience_roles(
        session, _conv_members, bindings, project_name_cache=project_name_cache,
    )

    # email -> crednames, fetched once instead of a per-member get_session_data (N+1).
    creds_by_email: dict[str, list[str]] = {}
    for srow in session.get_session_data("session", columns=["credname", "email"]) or []:
        email = str(srow.get("email") or "").strip()
        cred = str(srow.get("credname") or "").strip()
        if email and cred:
            creds_by_email.setdefault(email, []).append(cred)

    entries: list[dict] = []
    for member in valid_members:
        data_dict = build_roles_and_assets_for_member(
            session, member=member, member_bindings=bindings_by_member.get(member, []),
            convenience_summary=convenience_summary,
            project_name_cache=project_name_cache, ancestor_cache=ancestor_cache,
        )
        if not data_dict:
            continue
        crednames = None
        if member not in ("allUsers", "allAuthenticatedUsers") and ":" in member:
            email = member.split(":", 1)[1]
            # Always a list of credname strings (the report + `data` command do
            # `credname in crednames`); the old non-debug path stored raw dicts.
            crednames = creds_by_email.get(email) or None
        row = {"member": member, "roles_and_assets": data_dict}
        if crednames:
            row["crednames"] = crednames
        save_to_table(session, "member_permissions_summary", row)
        entries.append({"member": member, "data_dict": data_dict, "crednames": crednames})
    return entries
