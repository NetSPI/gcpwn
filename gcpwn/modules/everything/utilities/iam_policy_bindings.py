from __future__ import annotations

import json
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

from google.api_core.exceptions import Forbidden
from google.api_core.exceptions import NotFound
from google.iam.v1 import iam_policy_pb2
from google.protobuf.json_format import MessageToDict

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import build_discovery_service
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.service_runtime import is_api_disabled_error
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_project_id_from_resource


def _path_tail(value: Any, *, default: str = "") -> str:
    text = str(value or "").strip()
    if not text:
        return str(default or "").strip()
    parts = [part for part in text.split("/") if str(part).strip()]
    if not parts:
        return str(default or "").strip()
    return str(parts[-1]).strip()


class IAMPolicyBindingsResource:
    @staticmethod
    def _safe_client(factory):
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
        if policy is None:
            return None
        if isinstance(policy, dict):
            return dict(policy)
        if hasattr(policy, "to_api_repr") and callable(getattr(policy, "to_api_repr")):
            try:
                payload = policy.to_api_repr()
                return payload if isinstance(payload, dict) else {}
            except Exception:
                return {}
        if hasattr(policy, "_pb"):
            try:
                return MessageToDict(policy._pb)  # type: ignore[arg-type]
            except Exception:
                return {}
        try:
            return MessageToDict(policy)  # type: ignore[arg-type]
        except Exception:
            return {}

    @staticmethod
    def _policy_add_iam_member(*, policy: dict[str, Any], member: str, role: str) -> dict[str, Any]:
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

    def _bigquery_get_iam_policy(self, dataset_id: str, *, project_id: str):
        if self.bigquery_client is None or not dataset_id:
            return None
        try:
            return self.bigquery_client.get_iam_policy(dataset_id)
        except NotFound:
            UtilityTools.print_404_resource(dataset_id)
            return None
        except Forbidden as exc:
            text = str(exc)
            if is_api_disabled_error(text):
                UtilityTools.print_403_api_disabled("BigQuery", project_id)
                return "Not Enabled"
            UtilityTools.print_403_api_denied(
                "bigquery.datasets.getIamPolicy",
                resource_name=dataset_id,
                project_id=project_id,
            )
            return None
        except Exception as exc:
            UtilityTools.print_500(dataset_id, "bigquery.datasets.getIamPolicy", exc)
            return None

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
            member_list = sorted({str(m).strip() for m in members if str(m).strip()})

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

    def run(self, *, save_raw_policies: bool = True, services: set[str] | None = None):
        selected_services = {str(service).strip().lower() for service in (services or set()) if str(service).strip()}

        def _load(service_key: str, table: str, *, columns: list[str], conditions: str | None = None):
            if not self._include_service(selected_services, service_key):
                return []
            return self.session.get_data(table, columns=columns, conditions=conditions) or []

        resources = {
            "orgs": _load("resource_manager", "abstract_tree_hierarchy", columns=["name", "project_id"], conditions='type="org"'),
            "folders": _load("resource_manager", "abstract_tree_hierarchy", columns=["name", "project_id"], conditions='type="folder"'),
            "projects": _load("resource_manager", "abstract_tree_hierarchy", columns=["name", "project_id"], conditions='type="project"'),
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
                    "scope_key": "org_permissions",
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
                        "permission": "bigquery.datasets.getIamPolicy",
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
                                "action_label": f"[{extract_path_segment(name, 'locations')}] {_path_tail(name, default=name)}",
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
                            _path_tail(str(row.get("zone") or ""), default=str(row.get("zone") or "")),
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
                                "action_label": _path_tail(name, default=name) if name else "",
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

        self.session.sync_users()

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
