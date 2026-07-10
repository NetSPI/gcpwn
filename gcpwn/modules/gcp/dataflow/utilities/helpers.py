from __future__ import annotations

from google.cloud import dataflow_v1beta3

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)


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
