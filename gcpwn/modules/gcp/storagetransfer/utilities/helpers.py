from __future__ import annotations

import json
from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_project_id_from_resource, name_from_input
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


class StorageTransferJobsResource:
    """List/get Storage Transfer Service jobs (cross-bucket/cloud data-movement configs).

    Note list uses a JSON ``filter`` string ({"projectId": ...}) rather than a
    parent, and get must supply both job_name and project_id. Errors flow through
    handle_service_error (returns the "Not Enabled" sentinel on a disabled API).
    """

    TABLE_NAME = "storagetransfer_transferjobs"
    COLUMNS = [
        "name",
        "description",
        "status",
        "project_id",
        "latest_operation_name",
    ]
    SERVICE_LABEL = "Storage Transfer"
    LIST_PERMISSION = "storagetransfer.jobs.list"
    GET_PERMISSION = "storagetransfer.jobs.get"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import storage_transfer_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Storage Transfer enumeration requires the `google-cloud-storage-transfer` package."
            ) from exc

        self._storage_transfer_v1 = storage_transfer_v1
        self.client = storage_transfer_v1.StorageTransferServiceClient(credentials=session.credentials)

    @property
    def project_id(self) -> str:
        return str(getattr(self.session, "project_id", "") or "")

    def resource_name(self, row: Any) -> str:
        return resource_to_dict(row).get("name", "") if isinstance(row, (dict,)) else str(row or "").strip()

    def list(self, *, project_id: str, location: str | None = None, action_dict=None) -> list[dict[str, Any]] | str | None:
        project = str(project_id or "").strip() or self.project_id
        filter_value = json.dumps({"projectId": project}) if project else ""
        try:
            request = self._storage_transfer_v1.ListTransferJobsRequest(filter=filter_value)
            rows = [
                resource_to_dict(job)
                for job in self.client.list_transfer_jobs(request=request)
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_PERMISSION,
                resource_name=f"projects/{project}",
                service_label=self.SERVICE_LABEL,
                project_id=self.project_id,
            )

    def get(
        self,
        *,
        project_id: str | None = None,
        resource_id: str,
        action_dict=None,
    ) -> dict[str, Any] | None:
        """Fetch one transfer job, normalizing a bare id into a full transferJobs path.

        Expands ``resource_id`` to ``projects/<p>/transferJobs/<id>`` when needed,
        derives the project from the (now-qualified) name, and records the get
        permission as evidence. Returns the job dict, or None on error.
        """
        normalized_resource_id = str(resource_id or "").strip()
        if normalized_resource_id and not normalized_resource_id.startswith("projects/") and project_id:
            try:
                normalized_resource_id = name_from_input(
                    normalized_resource_id,
                    project_id=project_id,
                    template=("projects", "{project_id}", "transferJobs", 0),
                )
            except ValueError:
                normalized_resource_id = f"projects/{project_id}/transferJobs/{normalized_resource_id}"
        normalized_project = extract_project_id_from_resource(
            normalized_resource_id,
            fallback_project=project_id,
        )
        try:
            request = self._storage_transfer_v1.GetTransferJobRequest(
                job_name=normalized_resource_id,
                project_id=normalized_project,
            )
            row = resource_to_dict(self.client.get_transfer_job(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    scope_key="project_permissions",
                    scope_label=normalized_project,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=normalized_resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=self.project_id,
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str) -> None:
        for row in rows or []:
            payload = row if isinstance(row, dict) else resource_to_dict(row)
            save_to_table(
                self.session,
                self.TABLE_NAME,
                payload,
                defaults={
                    "project_id": extract_project_id_from_resource(payload, fallback_project=project_id),
                },
            )
