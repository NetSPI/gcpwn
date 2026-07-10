from __future__ import annotations

from typing import Any

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import resolve_regions_args

resolve_locations = resolve_regions_args


class BatchJobsResource(GcpListResource):
    """List/get Batch jobs per project+location via the batch_v1 GAPIC client."""

    TABLE_NAME = "batch_jobs"
    COLUMNS = ["location", "job_id", "name", "uid", "create_time", "status_state"]
    SERVICE_LABEL = "Batch"
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "batch.jobs.list"
    GET_PERMISSION = "batch.jobs.get"
    LIST_API_NAME = "batch.projects.locations.jobs.list"
    GET_API_NAME = "batch.projects.locations.jobs.get"
    LIST_METHOD = "list_jobs"
    GET_METHOD = "get_job"
    ID_FIELD = "job_id"
    # parent = projects/<p>/locations/<loc> and list recorded as a project-scope perm (base default)

    def _build_client(self, session):
        try:
            from google.cloud import batch_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Batch enumeration requires the `google-cloud-batch` package with `batch_v1` support."
            ) from exc
        return batch_v1.BatchServiceClient(credentials=session.credentials)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        status = raw.get("status")
        state = status.get("state") if isinstance(status, dict) else ""
        return {"status_state": state or raw.get("status_state") or ""}
