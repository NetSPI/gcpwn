"""BigQuery enumeration helpers for datasets, tables, and routines.

Hand-rolled resources (not GcpListResource) wrapping the google-cloud-bigquery client.
Resource identity is the dotted ``project.dataset[.table|.routine]`` form -- each class has a
_resource_id_from_row that reconstructs it from the many shapes a row can take (proto object,
dict, api_repr, reference) and mirrors it onto row["name"] so the framework's nesting/IAM/save
plumbing works. testIamPermissions is not on the GAPIC client, so it goes through the v2
discovery service. Table data download (download_table_data) is a sensitive read of row data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from google.cloud import bigquery

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import build_discovery_service, handle_service_error
from gcpwn.core.utils.iam_permissions import call_discovery_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    bigquery_routine_iam_resource_name,
    bigquery_table_iam_resource_name,
    normalize_bigquery_resource_id,
    split_bigquery_dataset_id,
    split_bigquery_routine_id,
    split_bigquery_table_id,
)
from gcpwn.core.utils.persistence import save_to_table, to_snake_key
from gcpwn.core.utils.serialization import resource_to_dict


def _normalize_payload_keys(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_payload_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_payload_keys(item) for item in value]
    return value


def _payload_from_resource(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return _normalize_payload_keys(dict(value))

    payload = resource_to_dict(value)
    if payload:
        return _normalize_payload_keys(payload)

    to_api_repr = getattr(value, "to_api_repr", None)
    if callable(to_api_repr):
        try:
            payload = to_api_repr()
            if isinstance(payload, dict):
                return _normalize_payload_keys(payload)
        except Exception:
            pass

    properties = getattr(value, "_properties", None)
    if isinstance(properties, dict):
        return _normalize_payload_keys(dict(properties))

    try:
        return _normalize_payload_keys(dict(vars(value)))
    except Exception:
        return {}


class _BigQueryBaseResource:
    SERVICE_LABEL = "BigQuery"

    #: Column that mirrors the canonical resource id (e.g. ``full_dataset_id``). Set per subclass.
    ID_FIELD = ""
    #: Discovery collection used for testIamPermissions (e.g. ``tables``/``routines``).
    TEST_IAM_COLLECTION = ""

    def __init__(self, session) -> None:
        self.session = session
        self.client = bigquery.Client(project=session.project_id, credentials=session.credentials)
        self._discovery_service = None

    def _default_row_fields(self, row: Any) -> dict[str, Any]:
        """Per-subclass extraction of display columns from a non-dict resource object."""
        return {}

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        rid = self._resource_id_from_row(row)
        out = dict(row) if isinstance(row, dict) else self._default_row_fields(row)
        out[self.ID_FIELD] = rid
        out["name"] = rid  # framework uses row["name"] for nesting/iam/save
        return out

    def _resource_id_from_row(self, row: Any) -> str:  # pragma: no cover - overridden per subclass
        raise NotImplementedError

    def _iam_resource_name(self, resource_id: str) -> str:
        """Build the discovery testIamPermissions resource path. Set per subclass."""
        raise NotImplementedError

    def _split_resource_id(self, resource_id: str):
        """Split a canonical id into (project, ...); return project as element 0. Per subclass."""
        raise NotImplementedError

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        iam_resource = self._iam_resource_name(resource_id)
        if not iam_resource:
            return []
        permissions = self._call_test_iam_permissions(
            resource_name=iam_resource,
            api_name=self.TEST_IAM_API_NAME,
            request_builder=lambda service, resource_name: getattr(service, self.TEST_IAM_COLLECTION)().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.TEST_IAM_PERMISSIONS)},
            ),
        )
        if permissions:
            project_id = self._split_resource_id(resource_id)[0]
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=self._resource_id_from_row(resource_id),
            )
        return permissions

    def _get_discovery_service(self):
        if self._discovery_service is None:
            self._discovery_service = build_discovery_service(self.session.credentials, "bigquery", "v2")
        return self._discovery_service

    def _call_test_iam_permissions(self, *, resource_name: str, request_builder, api_name: str) -> list[str]:
        """Run a testIamPermissions call via the v2 discovery service; return granted perms.

        ``request_builder(service, resource_name)`` builds the table/routine-specific request.
        Errors are funneled through handle_discovery_error and yield [] (the API isn't on the
        GAPIC client, hence the discovery hop).
        """
        return call_discovery_test_iam_permissions(
            session=self.session,
            discovery_service=self._get_discovery_service(),
            resource_name=resource_name,
            request_builder=request_builder,
            api_name=api_name,
            service_label="BigQuery",
        )

class BigQueryDatasetsResource(_BigQueryBaseResource):
    """Enumerate BigQuery datasets into ``bigquery_datasets`` (keyed by ``project.dataset``)."""

    TABLE_NAME = "bigquery_datasets"
    ACTION_RESOURCE_TYPE = "datasets"
    LIST_PERMISSION = "bigquery.datasets.list"
    GET_PERMISSION = "bigquery.datasets.get"
    ID_FIELD = "full_dataset_id"
    COLUMNS = ["full_dataset_id", "location", "friendly_name"]

    def _default_row_fields(self, row: Any) -> dict[str, Any]:
        return {
            "location": str(getattr(row, "location", "") or ""),
            "friendly_name": str(getattr(row, "friendly_name", "") or ""),
        }

    def list(self, *, project_id: str, location: str | None = None, action_dict=None) -> list[Any]:
        try:
            rows = list(self.client.list_datasets(project=project_id))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return [self._row_to_dict(row) for row in rows]
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.LIST_PERMISSION,
                resource_name=project_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_dataset(resource_id)
            resolved_id = self._resource_id_from_row(row)
            project_id, _dataset_id = split_bigquery_dataset_id(
                resolved_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resolved_id,
            )
            return self._row_to_dict(row)
        except Exception as exc:
            project_id, _dataset_id = split_bigquery_dataset_id(
                resource_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
        return None

    def _resource_id_from_row(self, row: Any) -> str:
        """Reconstruct the canonical ``project.dataset`` id from any row shape (str/dict/proto)."""
        if isinstance(row, str):
            return normalize_bigquery_resource_id(row)
        if isinstance(row, dict):
            full_dataset_id = str(row.get("full_dataset_id") or "").strip()
            if full_dataset_id:
                return normalize_bigquery_resource_id(full_dataset_id)
            project_id = str(row.get("project_id") or getattr(self.session, "project_id", "") or "").strip()
            dataset_id = str(row.get("dataset_id") or "").strip()
            if project_id and dataset_id:
                return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
            dataset_reference = row.get("dataset_reference") or {}
            if isinstance(dataset_reference, dict):
                project_id = str(dataset_reference.get("project_id") or "").strip()
                dataset_id = str(dataset_reference.get("dataset_id") or "").strip()
                if project_id and dataset_id:
                    return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
            return ""

        full_dataset_id = str(getattr(row, "full_dataset_id", "") or "").strip()
        if full_dataset_id:
            return normalize_bigquery_resource_id(full_dataset_id)
        reference = getattr(row, "reference", None)
        if reference is not None:
            project_id = str(getattr(reference, "project", "") or "").strip()
            dataset_id = str(getattr(reference, "dataset_id", "") or "").strip()
            if project_id and dataset_id:
                return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
        project_id = str(getattr(row, "project", "") or getattr(self.session, "project_id", "") or "").strip()
        dataset_id = str(getattr(row, "dataset_id", "") or "").strip()
        if project_id and dataset_id:
            return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}")
        return normalize_bigquery_resource_id(dataset_id)

    def save(self, datasets: Iterable[Any], *, project_id=None, location=None, **_) -> None:
        for dataset in datasets or []:
            resource_id = self._resource_id_from_row(dataset)
            if not resource_id:
                continue
            save_to_table(
                self.session,
                self.TABLE_NAME,
                dataset,
                extras={"full_dataset_id": resource_id},
            )


class BigQueryTablesResource(_BigQueryBaseResource):
    """Enumerate tables (nested under a dataset) into ``bigquery_tables``; download row data on demand.

    list() takes the parent dataset id via ``parent``/``dataset_id``. download_table_data streams
    every row of a table to a JSONL loot file (records bigquery.tables.getData as evidence).
    """

    TABLE_NAME = "bigquery_tables"
    ACTION_RESOURCE_TYPE = "tables"
    LIST_PERMISSION = "bigquery.tables.list"
    GET_PERMISSION = "bigquery.tables.get"
    DOWNLOAD_PERMISSION = "bigquery.tables.getData"
    TEST_IAM_API_NAME = "bigquery.tables.testIamPermissions"
    TEST_IAM_COLLECTION = "tables"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "bigquery.tables.",
        exclude_permissions=(
            "bigquery.tables.create",
            "bigquery.tables.list",
        ),
    )
    ID_FIELD = "full_table_id"
    COLUMNS = ["full_table_id", "table_type", "num_rows", "num_bytes"]

    def _default_row_fields(self, row: Any) -> dict[str, Any]:
        return {
            "table_type": str(getattr(row, "table_type", "") or ""),
            "num_rows": getattr(row, "num_rows", None) or "",
            "num_bytes": getattr(row, "num_bytes", None) or "",
        }

    def _iam_resource_name(self, resource_id: str) -> str:
        return bigquery_table_iam_resource_name(
            resource_id,
            fallback_project=getattr(self.session, "project_id", ""),
        )

    def _split_resource_id(self, resource_id: str):
        return split_bigquery_table_id(
            resource_id,
            fallback_project=getattr(self.session, "project_id", ""),
        )

    def list(self, *, dataset_id: str = "", parent: str = "", location: str | None = None, action_dict=None) -> list[Any]:
        dataset_id = dataset_id or parent
        try:
            project_id, resolved_dataset_id = split_bigquery_dataset_id(
                dataset_id, fallback_project=getattr(self.session, "project_id", "")
            )
            # Avoid passing "project:dataset" as dataset_id (client will treat it as the datasetId and error).
            dataset_ref = bigquery.DatasetReference(project_id, resolved_dataset_id)
            rows = list(self.client.list_tables(dataset_ref))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return [self._row_to_dict(row) for row in rows]
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.LIST_PERMISSION,
                resource_name=dataset_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_table(resource_id)
            resolved_id = self._resource_id_from_row(row)
            project_id, _dataset_id, _table_id = split_bigquery_table_id(
                resolved_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resolved_id,
            )
            return self._row_to_dict(row)
        except Exception as exc:
            project_id, _dataset_id, _table_id = split_bigquery_table_id(
                resource_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
        return None

    def _resource_id_from_row(self, row: Any) -> str:
        """Reconstruct the canonical ``project.dataset.table`` id from any row shape."""
        if isinstance(row, str):
            return normalize_bigquery_resource_id(row)
        if isinstance(row, dict):
            full_table_id = str(row.get("full_table_id") or "").strip()
            if full_table_id:
                return normalize_bigquery_resource_id(full_table_id)
            table_reference = row.get("table_reference") or {}
            if isinstance(table_reference, dict):
                project_id = str(table_reference.get("project_id") or "").strip()
                dataset_id = str(table_reference.get("dataset_id") or "").strip()
                table_id = str(table_reference.get("table_id") or "").strip()
                if project_id and dataset_id and table_id:
                    return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}.{table_id}")
            return ""

        full_table_id = str(getattr(row, "full_table_id", "") or "").strip()
        if full_table_id:
            return normalize_bigquery_resource_id(full_table_id)
        reference = getattr(row, "reference", None)
        if reference is not None:
            project_id = str(getattr(reference, "project", "") or "").strip()
            dataset_id = str(getattr(reference, "dataset_id", "") or "").strip()
            table_id = str(getattr(reference, "table_id", "") or "").strip()
            if project_id and dataset_id and table_id:
                return normalize_bigquery_resource_id(f"{project_id}.{dataset_id}.{table_id}")
        project_id = str(getattr(row, "project", "") or "").strip()
        dataset_id = str(getattr(row, "dataset_id", "") or "").strip()
        table_id = str(getattr(row, "table_id", "") or "").strip()
        return normalize_bigquery_resource_id(".".join(part for part in [project_id, dataset_id, table_id] if part))

    def save(self, tables: Iterable[Any], *, project_id=None, location=None, **_) -> None:
        for table in tables or []:
            resource_id = self._resource_id_from_row(table)
            if not resource_id:
                continue
            save_to_table(
                self.session,
                self.TABLE_NAME,
                table,
                extras={"full_table_id": resource_id},
            )

    def download_table_data(self, *, row: Any, project_id: str, action_dict=None) -> Path | None:
        """Stream all rows of a table to a JSONL loot file; return its path (or None on failure).

        Re-fetches the table (via get) if the row lacks a schema. Records bigquery.tables.getData
        once per attempt (covers empty tables too). Side effect: writes a file under the BigQuery
        download dir. This is a sensitive bulk read of table contents.
        """
        resolved_id = self._resource_id_from_row(row)
        if not resolved_id:
            return None

        table = row
        if not hasattr(table, "schema"):
            table = self.get(resource_id=resolved_id, action_dict=action_dict)
            if table is None:
                return None

        resolved_id = self._resource_id_from_row(table)
        if not resolved_id:
            return None

        resolved_project, dataset_id, table_id = split_bigquery_table_id(
            resolved_id,
            fallback_project=project_id,
        )
        destination = resolve_download_path(
            self.session,
            service_name="bigquery",
            project_id=project_id,
            subdirs=["tables", f"{resolved_project}_{dataset_id}"],
            filename=f"{table_id}.jsonl",
        )

        try:
            with destination.open("w", encoding="utf-8", newline="\n") as handle:
                row_iter = self.client.list_rows(table)
                # Record this once per download attempt (also covers empty tables).
                record_permissions(
                    action_dict,
                    permissions=self.DOWNLOAD_PERMISSION,
                    project_id=resolved_project,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resolved_id,
                )
                for table_row in row_iter:
                    handle.write(json.dumps(dict(table_row.items()), ensure_ascii=False, default=str))
                    handle.write("\n")
            return destination
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.DOWNLOAD_PERMISSION,
                resource_name=resolved_id,
                service_label=self.SERVICE_LABEL,
                project_id=resolved_project,
                return_not_enabled=False,
            )
        return None


class BigQueryRoutinesResource(_BigQueryBaseResource):
    """Enumerate routines (UDFs/procedures, nested under a dataset) into ``bigquery_routines``."""

    TABLE_NAME = "bigquery_routines"
    ACTION_RESOURCE_TYPE = "routines"
    LIST_PERMISSION = "bigquery.routines.list"
    GET_PERMISSION = "bigquery.routines.get"
    TEST_IAM_API_NAME = "bigquery.routines.testIamPermissions"
    TEST_IAM_COLLECTION = "routines"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("bigquery.routines.")
    ID_FIELD = "full_routine_id"
    COLUMNS = ["full_routine_id", "routine_type", "language", "creation_time", "last_modified_time"]

    def _default_row_fields(self, row: Any) -> dict[str, Any]:
        return {
            "routine_type": str(getattr(row, "type_", "") or getattr(row, "routine_type", "") or ""),
            "language": str(getattr(row, "language", "") or ""),
            "creation_time": getattr(row, "created", None) or getattr(row, "creation_time", None) or "",
            "last_modified_time": getattr(row, "modified", None) or getattr(row, "last_modified_time", None) or "",
        }

    def _iam_resource_name(self, resource_id: str) -> str:
        return bigquery_routine_iam_resource_name(
            resource_id,
            fallback_project=getattr(self.session, "project_id", ""),
        )

    def _split_resource_id(self, resource_id: str):
        return split_bigquery_routine_id(
            resource_id,
            fallback_project=getattr(self.session, "project_id", ""),
        )

    def list(self, *, dataset_id: str = "", parent: str = "", location: str | None = None, action_dict=None) -> list[Any] | str | None:
        dataset_id = dataset_id or parent
        try:
            project_id, resolved_dataset_id = split_bigquery_dataset_id(
                dataset_id, fallback_project=getattr(self.session, "project_id", "")
            )
            dataset_ref = bigquery.DatasetReference(project_id, resolved_dataset_id)
            rows = list(self.client.list_routines(dataset_ref))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return [self._row_to_dict(row) for row in rows]
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.LIST_PERMISSION,
                resource_name=dataset_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
        return []

    def get(self, *, resource_id: str, action_dict=None) -> Any | None:
        try:
            row = self.client.get_routine(resource_id)
            resolved_id = self._resource_id_from_row(row)
            project_id, _dataset_id, _routine_id = split_bigquery_routine_id(
                resolved_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resolved_id,
            )
            return self._row_to_dict(row)
        except Exception as exc:
            project_id, _dataset_id, _routine_id = split_bigquery_routine_id(
                resource_id,
                fallback_project=getattr(self.session, "project_id", ""),
            )
            handle_service_error(
                exc,
                api_name=self.GET_PERMISSION,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=project_id,
                return_not_enabled=False,
            )
        return None

    def _resource_id_from_row(self, row: Any) -> str:
        """Reconstruct the canonical ``project.dataset.routine`` id from any row shape."""
        if isinstance(row, str):
            return str(row).strip()
        if isinstance(row, dict):
            full_routine_id = str(row.get("full_routine_id") or "").strip()
            if full_routine_id:
                return full_routine_id
            reference = row.get("routine_reference") or {}
            if isinstance(reference, dict):
                project_id = str(reference.get("project_id") or "").strip()
                dataset_id = str(reference.get("dataset_id") or "").strip()
                routine_id = str(reference.get("routine_id") or "").strip()
                if project_id and dataset_id and routine_id:
                    return f"{project_id}.{dataset_id}.{routine_id}"
            project_id = str(row.get("project_id") or getattr(self.session, "project_id", "") or "").strip()
            dataset_id = str(row.get("dataset_id") or "").strip()
            routine_id = str(row.get("routine_id") or "").strip()
            if project_id and dataset_id and routine_id:
                return f"{project_id}.{dataset_id}.{routine_id}"
            return ""

        reference = getattr(row, "reference", None)
        if reference is not None:
            project_id = str(getattr(reference, "project", "") or "").strip()
            dataset_id = str(getattr(reference, "dataset_id", "") or "").strip()
            routine_id = str(getattr(reference, "routine_id", "") or "").strip()
            if project_id and dataset_id and routine_id:
                return f"{project_id}.{dataset_id}.{routine_id}"

        payload = _payload_from_resource(row)
        if payload:
            return self._resource_id_from_row(payload)
        return ""

    def save(self, rows: Iterable[Any], *, project_id=None, location=None, **_) -> None:
        for row in rows or []:
            resource_id = self._resource_id_from_row(row)
            if not resource_id:
                continue
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                extras={"full_routine_id": resource_id},
                extra_builder=lambda _obj, _raw, resource_id=resource_id: dict(
                    zip(
                        ("project_id", "dataset_id", "routine_id"),
                        split_bigquery_routine_id(
                            resource_id,
                            fallback_project=getattr(self.session, "project_id", ""),
                        ),
                    )
                ),
            )
