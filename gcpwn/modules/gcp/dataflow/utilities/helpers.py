from __future__ import annotations

import json as _json

import requests as _rlib
from google.cloud import dataflow_v1beta3

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import get_bearer_token
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_project_id_from_resource,
    region_resolver_for,
)

# ── Dataflow (GAPIC) ──────────────────────────────────────────────────────────

resolve_locations = region_resolver_for("dataflow", ("dataflow", "v1b3"))


class DataflowJobsResource(GcpListResource):
    """List Dataflow jobs via the v1b3 GAPIC client.

    Dataflow's ``list_jobs`` takes a ``ListJobsRequest`` (project_id + location,
    not a ``parent=`` string), so ``_list_items`` parses the framework-built
    ``projects/<p>/locations/<region>`` parent back into those fields. The worker
    service account (``environment.service_account_email``) -- the identity a
    Flex-Template job runs arbitrary code as -- is only present under
    ``JOB_VIEW_ALL``, which the regional list usually honors; if a region rejects
    it we fall back to the summary view (jobs without the SA) rather than hide the
    jobs. ``supports_get=False`` (no per-job location to re-fetch with) and
    ``supports_iam=False`` (Dataflow has no per-job testIamPermissions).
    """

    SERVICE_LABEL = "Cloud Dataflow"
    TABLE_NAME = "dataflow_jobs"
    COLUMNS = ["location", "job_id", "name", "display_name", "job_type", "current_state", "service_account_email"]
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "dataflow.jobs.list"
    GET_PERMISSION = "dataflow.jobs.get"
    ID_FIELD = "job_id"

    def _build_client(self, session):
        return dataflow_v1beta3.JobsV1Beta3Client(credentials=session.credentials)

    def _list_items(self, parent, **_):
        project_id = extract_path_segment(str(parent or ""), "projects") or ""
        location = extract_path_segment(str(parent or ""), "locations") or ""
        for view in (dataflow_v1beta3.JobView.JOB_VIEW_ALL, dataflow_v1beta3.JobView.JOB_VIEW_SUMMARY):
            try:
                request = dataflow_v1beta3.ListJobsRequest(
                    project_id=project_id,
                    location=location,
                    filter=dataflow_v1beta3.ListJobsRequest.Filter.ALL,
                    view=view,
                )
                return list(self.client.list_jobs(request=request))
            except Exception:
                if view == dataflow_v1beta3.JobView.JOB_VIEW_SUMMARY:
                    raise  # a real error (denied/disabled) -> let the base handle it
        return []

    def _normalize_row(self, row):
        # A Job's stable unique key is its id (display "name" is not unique). Make
        # "name" the id so the shared save()/summary key on it, and keep the human
        # name as display_name.
        row["display_name"] = str(row.get("name", "") or "")
        row["name"] = str(row.get("id", "") or "")
        return row

    def _extra_save_fields(self, raw):
        environment = raw.get("environment") or {}
        return {
            "job_id": str(raw.get("name", "") or ""),
            "display_name": str(raw.get("display_name", "") or ""),
            "job_type": str(raw.get("type_", "") or raw.get("type", "") or ""),
            "current_state": str(raw.get("current_state", "") or ""),
            "service_account_email": str(environment.get("service_account_email", "") or ""),
        }


# ── Cloud Data Pipelines (REST — no GAPIC package) ───────────────────────────

_DP_BASE = "https://datapipelines.googleapis.com/v1"

resolve_dp_locations = region_resolver_for("datapipelines")

_DP_LIST_PERMISSION = "datapipelines.pipelines.list"
_DP_PERMISSIONS = tuple(permissions_with_prefixes(
    "datapipelines.pipelines.",
    exclude_permissions=["datapipelines.pipelines.create"],
))


def _dp_req(tok: str, method: str, url: str,
            body=None, params=None) -> "tuple[int, dict]":
    """Authenticated REST call to the Data Pipelines API."""
    hdrs = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
    r = _rlib.request(method, url, headers=hdrs, json=body, params=params, timeout=30)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"_raw": r.text[:600]}


def _dp_list_pipelines(tok: str, project: str, region: str) -> list[dict]:
    """Return the raw pipeline dicts for a project/region, or [] on any error."""
    parent = f"projects/{project}/locations/{region}"
    status, data = _dp_req(tok, "GET", f"{_DP_BASE}/{parent}/pipelines")
    if status == 200:
        return data.get("pipelines", [])
    return []


def _extract_worker_sa(pipeline: dict) -> str:
    """Pull the workerServiceAccount email out of a pipeline workload block."""
    workload = pipeline.get("workload") or {}
    for key in ("dataflowFlexTemplateRequest", "dataflowLaunchTemplateRequest"):
        sub = workload.get(key) or {}
        lp = sub.get("launchParameter") or sub.get("launchParameters") or {}
        env = lp.get("environment") or {}
        sa = env.get("serviceAccountEmail", "")
        if sa:
            return sa
    return ""


def _dp_normalize_pipeline(p: dict, location: str) -> dict:
    """Flatten a raw Data Pipelines API pipeline dict into a DB-ready row."""
    name = p.get("name", "")
    pipeline_id = name.rsplit("/", 1)[-1] if "/" in name else name
    schedule_info = p.get("scheduleInfo") or {}
    return {
        "name": name,
        "pipeline_id": pipeline_id,
        "display_name": p.get("displayName", ""),
        "state": p.get("state", ""),
        "pipeline_type": p.get("type", ""),
        "schedule": schedule_info.get("schedule", ""),
        "worker_service_account": _extract_worker_sa(p),
        "location": location,
        "raw_json": _json.dumps(p),
    }


class DataPipelinesResource(GcpListResource):
    """List Cloud Data Pipelines via REST (no GAPIC package exists).

    Overrides list() and test_iam_permissions() to use the REST helpers above;
    save() is inherited unchanged since _dp_normalize_pipeline already produces
    flat rows with exactly the right column names.
    """

    SERVICE_LABEL = "Cloud Data Pipelines"
    TABLE_NAME = "datapipelines_pipelines"
    COLUMNS = ["project_id", "location", "pipeline_id", "name", "display_name",
               "state", "pipeline_type", "schedule", "worker_service_account", "raw_json"]
    ACTION_RESOURCE_TYPE = "pipelines"
    LIST_PERMISSION = _DP_LIST_PERMISSION
    TEST_IAM_PERMISSIONS = _DP_PERMISSIONS
    TEST_IAM_API_NAME = "datapipelines.googleapis.com"
    ID_FIELD = "pipeline_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None  # REST-only; token is fetched fresh in each list/iam call

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        tok = get_bearer_token(self.session)
        parent_path = f"projects/{project_id}/locations/{location}"
        status, data = _dp_req(tok, "GET", f"{_DP_BASE}/{parent_path}/pipelines")
        if status == 200:
            rows = [_dp_normalize_pipeline(p, location) for p in data.get("pipelines", [])]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        msg = (data.get("error", {}).get("message") or data.get("message", "")).lower()
        if any(k in msg for k in ("api not enabled", "disabled", "has not been used")):
            return "Not Enabled"
        return None

    def test_iam_permissions(self, *, resource_id, action_dict=None):
        if not self.TEST_IAM_PERMISSIONS:
            return []
        tok = get_bearer_token(self.session)
        status, data = _dp_req(
            tok, "POST",
            f"{_DP_BASE}/{resource_id}:testIamPermissions",
            body={"permissions": list(self.TEST_IAM_PERMISSIONS)},
        )
        if status != 200:
            return []
        granted = data.get("permissions", [])
        if granted:
            project_id = extract_project_id_from_resource(
                resource_id, fallback_project=self._fallback_project()
            )
            record_permissions(
                action_dict,
                permissions=granted,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return granted
