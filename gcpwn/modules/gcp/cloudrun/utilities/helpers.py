from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_segment,
    extract_path_tail,
    region_resolver_for,
)
from gcpwn.core.utils.service_runtime import DownloadBudget, lazy_download_budget


resolve_regions = region_resolver_for("cloudrun")


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_lines(value: Any, *, indent: int = 0) -> list[str]:
    prefix = " " * max(0, int(indent))
    if isinstance(value, dict):
        if not value:
            return [prefix + "{}"]
        lines: list[str] = []
        for key, item in value.items():
            key_text = json.dumps(str(key), ensure_ascii=False)
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key_text}:")
                lines.extend(_yaml_lines(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}{key_text}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [prefix + "[]"]
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(prefix + "-")
                lines.extend(_yaml_lines(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [prefix + _yaml_scalar(value)]


def _to_yaml_text(payload: Any) -> str:
    return "\n".join(_yaml_lines(payload)) + "\n"


def _extract_revision_env_snapshot(revision_row: dict[str, Any], *, project_id: str) -> dict[str, Any]:
    revision_name = str(revision_row.get("name") or "").strip()
    location = extract_location_from_resource_name(revision_name)
    service_id = extract_path_segment(revision_name, "services")
    revision_id = extract_path_segment(revision_name, "revisions") or extract_path_tail(revision_name, default="revision")

    container_rows = revision_row.get("containers")
    if not isinstance(container_rows, list):
        template = revision_row.get("template")
        if isinstance(template, dict):
            nested = template.get("containers")
            container_rows = nested if isinstance(nested, list) else []
        else:
            container_rows = []

    containers: list[dict[str, Any]] = []
    for idx, container in enumerate(container_rows):
        if not isinstance(container, dict):
            continue
        env_rows = container.get("env")
        if not isinstance(env_rows, list):
            env_rows = []

        env_entries: list[dict[str, Any]] = []
        for env in env_rows:
            if not isinstance(env, dict):
                continue
            entry: dict[str, Any] = {}
            env_name = str(env.get("name") or "").strip()
            if env_name:
                entry["name"] = env_name
            if "value" in env:
                entry["value"] = env.get("value")
            value_source = env.get("value_source")
            if value_source is None:
                value_source = env.get("valueSource")
            if value_source not in (None, "", {}):
                entry["value_source"] = value_source
            if entry:
                env_entries.append(entry)

        if not env_entries:
            continue
        containers.append(
            {
                "name": str(container.get("name") or "").strip() or f"container-{idx}",
                "image": str(container.get("image") or "").strip(),
                "env": env_entries,
            }
        )

    return {
        "kind": "CloudRunRevisionEnvSnapshot",
        "project_id": str(project_id or "").strip(),
        "location": location,
        "service_id": service_id,
        "revision_id": revision_id,
        "revision_name": revision_name,
        "containers": containers,
    }


class _CloudRunResource(GcpListResource):
    SERVICE_LABEL = "Cloud Run"
    CLIENT_ATTR = ""  # attribute on google.cloud.run_v2

    def _build_client(self, session):
        try:
            from google.cloud import run_v2  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Run enumeration requires the `google-cloud-run` package."
            ) from exc
        return getattr(run_v2, self.CLIENT_ATTR)(credentials=session.credentials)


class CloudRunServicesResource(_CloudRunResource):
    TABLE_NAME = "cloudrun_services"
    COLUMNS = ["location", "service_id", "name", "url", "ingress", "latest_ready_revision"]
    ACTION_RESOURCE_TYPE = "services"
    LIST_PERMISSION = "run.services.list"
    LIST_API_NAME = "run.projects.locations.services.list"
    GET_PERMISSION = "run.services.get"
    GET_API_NAME = "run.projects.locations.services.get"
    TEST_IAM_API_NAME = "run.services.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("run.services.")
    CLIENT_ATTR = "ServicesClient"
    LIST_METHOD = "list_services"
    GET_METHOD = "get_service"
    ID_FIELD = "service_id"

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "url": raw.get("uri") or "",
            "ingress": raw.get("ingress") or "",
            "latest_ready_revision": raw.get("latest_ready_revision") or "",
        }

    def get_by_name(self, *, name: str) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        return client.get_service(request=run_v2.GetServiceRequest(name=name))

    def create(self, *, parent: str, service_id: str, service: Any) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        op = client.create_service(request=run_v2.CreateServiceRequest(
            parent=parent, service_id=service_id, service=service,
        ))
        return op.result(timeout=300)

    def update(self, *, service: Any) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        op = client.update_service(request=run_v2.UpdateServiceRequest(service=service))
        return op.result(timeout=300)

    def delete(self, *, name: str) -> None:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        try:
            op = client.delete_service(request=run_v2.DeleteServiceRequest(name=name))
            op.result(timeout=120)
        except Exception:  # best-effort
            pass


class CloudRunRevisionsResource(_CloudRunResource):
    # Revisions are listed/fetched (for env download) but not persisted to a table.
    ACTION_RESOURCE_TYPE = "revisions"
    LIST_PERMISSION = "run.revisions.list"
    LIST_RESOURCE_TYPE = "services"  # listing revisions is a permission on the service
    LIST_API_NAME = "run.projects.locations.services.revisions.list"
    GET_PERMISSION = "run.revisions.get"
    GET_API_NAME = "run.projects.locations.services.revisions.get"
    CLIENT_ATTR = "RevisionsClient"
    LIST_METHOD = "list_revisions"
    GET_METHOD = "get_revision"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent service

    def _revision_env_download_budget(self) -> DownloadBudget:
        return lazy_download_budget(self, "cloud run revision env")

    def download_env_yaml(self, *, revision_row: dict[str, Any], project_id: str) -> Path | None:
        if self._revision_env_download_budget().exceeded():
            return None
        if not isinstance(revision_row, dict) or not revision_row:
            return None
        revision_name = str(revision_row.get("name") or "").strip()
        if not revision_name:
            return None
        snapshot = _extract_revision_env_snapshot(revision_row, project_id=project_id)
        if not list(snapshot.get("containers") or []):
            return None
        filename = compact_filename_component(
            f"{snapshot.get('location')}_{snapshot.get('service_id')}_{snapshot.get('revision_id')}_env.yaml"
        )
        destination = self.session.get_download_save_path(
            service_name="cloudrun",
            project_id=project_id,
            subdirs=["revisions"],
            filename=filename,
        )
        destination.write_text(_to_yaml_text(snapshot), encoding="utf-8")
        return destination


class CloudRunJobsResource(_CloudRunResource):
    TABLE_NAME = "cloudrun_jobs"
    COLUMNS = ["location", "job_id", "name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "run.jobs.list"
    LIST_API_NAME = "run.projects.locations.jobs.list"
    GET_PERMISSION = "run.jobs.get"
    GET_API_NAME = "run.projects.locations.jobs.get"
    TEST_IAM_API_NAME = "run.jobs.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("run.jobs.")
    CLIENT_ATTR = "JobsClient"
    LIST_METHOD = "list_jobs"
    GET_METHOD = "get_job"
    ID_FIELD = "job_id"

    def get_by_name(self, *, name: str) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        return client.get_job(request=run_v2.GetJobRequest(name=name))

    def create(self, *, parent: str, job_id: str, job: Any) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        op = client.create_job(request=run_v2.CreateJobRequest(
            parent=parent, job_id=job_id, job=job,
        ))
        return op.result(timeout=300)

    def update(self, *, job: Any) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        op = client.update_job(request=run_v2.UpdateJobRequest(job=job))
        return op.result(timeout=300)

    def run_job(self, *, name: str) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        op = client.run_job(request=run_v2.RunJobRequest(name=name))
        return op.result(timeout=600)

    def delete(self, *, name: str) -> None:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        try:
            op = client.delete_job(request=run_v2.DeleteJobRequest(name=name))
            op.result(timeout=60)
        except Exception:  # best-effort
            pass


class CloudRunJobExecutionsResource(_CloudRunResource):
    """Lists executions for an enumerated Cloud Run Job.

    Unlike other resources, executions are per-job, not per-location.
    Use list_for_job(job_name=...) rather than the standard list() method.
    """
    TABLE_NAME = "cloudrun_job_executions"
    COLUMNS = ["location", "job_name", "execution_id", "name", "running_count",
               "succeeded_count", "failed_count", "create_time"]
    CLIENT_ATTR = "ExecutionsClient"
    LIST_PERMISSION = "run.executions.list"
    LIST_API_NAME = "run.projects.locations.jobs.executions.list"

    def list_for_job(self, *, job_name: str) -> list[dict[str, Any]]:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        results = []
        try:
            for exec_obj in client.list_executions(
                request=run_v2.ListExecutionsRequest(parent=job_name)
            ):
                raw = type(exec_obj).to_dict(exec_obj)
                location = extract_location_from_resource_name(
                    str(raw.get("name") or "")
                )
                exec_id = extract_path_tail(str(raw.get("name") or ""), default="")
                create = raw.get("create_time") or ""
                results.append({
                    "location": location,
                    "job_name": job_name,
                    "execution_id": exec_id,
                    "name": str(raw.get("name") or ""),
                    "running_count": str(raw.get("running_count") or 0),
                    "succeeded_count": str(raw.get("succeeded_count") or 0),
                    "failed_count": str(raw.get("failed_count") or 0),
                    "create_time": str(create),
                    "raw_json": json.dumps(raw, default=str),
                })
        except Exception:
            pass
        return results


class CloudRunWorkerPoolsResource(_CloudRunResource):
    TABLE_NAME = "cloudrun_worker_pools"
    COLUMNS = ["location", "worker_pool_id", "name", "service_account", "min_instance_count", "create_time"]
    ACTION_RESOURCE_TYPE = "workerPools"
    LIST_PERMISSION = "run.workerPools.list"
    LIST_API_NAME = "run.projects.locations.workerPools.list"
    GET_PERMISSION = "run.workerPools.get"
    GET_API_NAME = "run.projects.locations.workerPools.get"
    CLIENT_ATTR = "WorkerPoolsClient"
    LIST_METHOD = "list_worker_pools"
    GET_METHOD = "get_worker_pool"
    ID_FIELD = "worker_pool_id"

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        template = raw.get("template") or {}
        scaling = raw.get("scaling") or {}
        return {
            "service_account": template.get("service_account") or "",
            "min_instance_count": scaling.get("min_instance_count") or scaling.get("manual_instance_count") or 0,
        }

    def get_by_name(self, *, name: str) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        return client.get_worker_pool(request=run_v2.GetWorkerPoolRequest(name=name))

    def create(self, *, parent: str, worker_pool_id: str, worker_pool: Any) -> Any:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        op = client.create_worker_pool(request=run_v2.CreateWorkerPoolRequest(
            parent=parent, worker_pool_id=worker_pool_id, worker_pool=worker_pool,
        ))
        return op.result(timeout=300)

    def update(self, *, worker_pool: Any, update_mask: list[str] | None = None) -> Any:
        from google.cloud import run_v2  # type: ignore
        from google.protobuf import field_mask_pb2  # type: ignore
        client = self.client
        req = run_v2.UpdateWorkerPoolRequest(worker_pool=worker_pool)
        if update_mask:
            req.update_mask = field_mask_pb2.FieldMask(paths=update_mask)
        op = client.update_worker_pool(request=req)
        return op.result(timeout=300)

    def delete(self, *, name: str) -> None:
        from google.cloud import run_v2  # type: ignore
        client = self.client
        try:
            op = client.delete_worker_pool(request=run_v2.DeleteWorkerPoolRequest(name=name))
            op.result(timeout=120)
        except Exception:  # best-effort
            pass


def _extract_worker_pool_revision_env_snapshot(revision_row: dict[str, Any], *, project_id: str) -> dict[str, Any]:
    revision_name = str(revision_row.get("name") or "").strip()
    location = extract_location_from_resource_name(revision_name)
    pool_id = extract_path_segment(revision_name, "workerPools")
    revision_id = extract_path_segment(revision_name, "revisions") or extract_path_tail(revision_name, default="revision")

    container_rows = revision_row.get("containers")
    if not isinstance(container_rows, list):
        template = revision_row.get("template")
        if isinstance(template, dict):
            nested = template.get("containers")
            container_rows = nested if isinstance(nested, list) else []
        else:
            container_rows = []

    containers: list[dict[str, Any]] = []
    for idx, container in enumerate(container_rows):
        if not isinstance(container, dict):
            continue
        env_rows = container.get("env")
        if not isinstance(env_rows, list):
            env_rows = []

        env_entries: list[dict[str, Any]] = []
        for env in env_rows:
            if not isinstance(env, dict):
                continue
            entry: dict[str, Any] = {}
            env_name = str(env.get("name") or "").strip()
            if env_name:
                entry["name"] = env_name
            if "value" in env:
                entry["value"] = env.get("value")
            value_source = env.get("value_source") or env.get("valueSource")
            if value_source not in (None, "", {}):
                entry["value_source"] = value_source
            if entry:
                env_entries.append(entry)

        if not env_entries:
            continue
        containers.append(
            {
                "name": str(container.get("name") or "").strip() or f"container-{idx}",
                "image": str(container.get("image") or "").strip(),
                "env": env_entries,
            }
        )

    return {
        "kind": "CloudRunWorkerPoolRevisionEnvSnapshot",
        "project_id": str(project_id or "").strip(),
        "location": location,
        "worker_pool_id": pool_id,
        "revision_id": revision_id,
        "revision_name": revision_name,
        "containers": containers,
    }


class CloudRunWorkerPoolRevisionsResource(_CloudRunResource):
    """Lists and downloads env from Cloud Run Worker Pool revisions (REST-only; no SDK client)."""

    TABLE_NAME = ""  # not persisted
    ACTION_RESOURCE_TYPE = "workerPoolRevisions"
    LIST_PERMISSION = "run.workerPoolRevisions.list"
    LIST_API_NAME = "run.projects.locations.workerPools.revisions.list"
    GET_PERMISSION = "run.workerPoolRevisions.get"
    GET_API_NAME = "run.projects.locations.workerPools.revisions.get"
    CLIENT_ATTR = ""

    def _revision_env_download_budget(self) -> DownloadBudget:
        return lazy_download_budget(self, "cloud run worker pool revision env")

    def _authed_get(self, url: str) -> dict[str, Any]:
        import urllib.request as _ur
        from google.auth.transport.requests import Request as _Req

        creds = self.session.credentials
        if hasattr(creds, "with_scopes") and not getattr(creds, "scopes", None):
            creds = creds.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(_Req())
        req = _ur.Request(url, headers={"Authorization": f"Bearer {creds.token}"})
        with _ur.urlopen(req) as resp:
            return json.loads(resp.read())

    def list_for_worker_pool(self, *, pool_name: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        url = f"https://run.googleapis.com/v2/{pool_name}/revisions"
        try:
            while url:
                data = self._authed_get(url)
                for item in data.get("revisions") or []:
                    results.append(item)
                page_token = data.get("nextPageToken")
                if page_token:
                    base = url.split("?")[0]
                    url = f"{base}?pageToken={page_token}"
                else:
                    url = ""
        except Exception:
            pass
        return results

    def get_revision(self, *, revision_name: str) -> dict[str, Any] | None:
        try:
            return self._authed_get(f"https://run.googleapis.com/v2/{revision_name}")
        except Exception:
            return None

    def download_env_yaml(self, *, revision_row: dict[str, Any], project_id: str) -> Path | None:
        if self._revision_env_download_budget().exceeded():
            return None
        if not isinstance(revision_row, dict) or not revision_row:
            return None
        revision_name = str(revision_row.get("name") or "").strip()
        if not revision_name:
            return None
        snapshot = _extract_worker_pool_revision_env_snapshot(revision_row, project_id=project_id)
        if not list(snapshot.get("containers") or []):
            return None
        filename = compact_filename_component(
            f"{snapshot.get('location')}_{snapshot.get('worker_pool_id')}_{snapshot.get('revision_id')}_env.yaml"
        )
        destination = self.session.get_download_save_path(
            service_name="cloudrun",
            project_id=project_id,
            subdirs=["worker_pool_revisions"],
            filename=filename,
        )
        destination.write_text(_to_yaml_text(snapshot), encoding="utf-8")
        return destination
