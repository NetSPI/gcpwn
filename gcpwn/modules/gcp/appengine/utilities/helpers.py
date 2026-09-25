from __future__ import annotations

import hashlib
from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error
from gcpwn.modules.gcp.appengine.utilities.exploit_payloads import build_gae_source_files  # noqa: F401


def stage_files_to_gcs(
    session,
    *,
    project_id: str,
    bucket_id: str,
    files: dict[str, bytes],
) -> dict[str, dict]:
    """Upload each file by its SHA1 hash (gcloud-style). Returns {filename: {sha1Sum, sourceUrl}}."""
    from google.cloud import storage as _gcs
    from google.api_core.exceptions import Conflict

    gcs = _gcs.Client(project=project_id, credentials=session.credentials)
    bucket = gcs.bucket(bucket_id)
    if not bucket.exists():
        try:
            bucket = gcs.create_bucket(bucket_id, location="US")
        except Conflict:
            bucket = gcs.bucket(bucket_id)
    result = {}
    for filename, content in files.items():
        sha1 = hashlib.sha1(content).hexdigest()
        blob = bucket.blob(sha1)
        if not blob.exists():
            blob.upload_from_string(content, content_type="application/octet-stream")
        result[filename] = {
            "sha1Sum": sha1,
            "sourceUrl": f"https://storage.googleapis.com/{bucket_id}/{sha1}",
        }
    return result


class _AppEngineBaseResource:
    """Base for App Engine admin resources: imports the appengine_admin_v1 SDK.

    App Engine resource names use the ``apps/<project>/...`` scheme (not
    ``projects/...``); project_id_from_name decodes that. Subclasses build the
    per-collection client and record permissions as evidence.
    """

    SERVICE_LABEL = "App Engine"
    ACTION_RESOURCE_TYPE = ""
    LIST_API_NAME = ""
    GET_API_NAME = ""

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import appengine_admin_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "App Engine enumeration requires the `google-cloud-appengine-admin` package."
            ) from exc
        self._appengine_admin_v1 = appengine_admin_v1

    @staticmethod
    def project_id_from_name(name: str) -> str:
        text = str(name or "").strip()
        if text.startswith("apps/"):
            return extract_path_segment(text, "apps")
        return text

    def resource_name(self, row: Any) -> str:
        payload = resource_to_dict(row)
        return field_from_row(row, payload, "name")


class AppEngineAppsResource(_AppEngineBaseResource):
    """Get the per-project App Engine application (a singleton; list() wraps get in a 1-list)."""

    TABLE_NAME = "appengine_apps"
    ACTION_RESOURCE_TYPE = "applications"
    GET_API_NAME = "appengine.applications.get"
    COLUMNS = ["name", "location_id", "auth_domain", "code_bucket"]

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._appengine_admin_v1.ApplicationsClient(credentials=session.credentials)

    def get(self, *, project_id: str = "", name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        normalized_name = str(name or "").strip() or f"apps/{project_id}"
        normalized_project = self.project_id_from_name(normalized_name) or str(project_id or "").strip()
        try:
            request = self._appengine_admin_v1.GetApplicationRequest(name=normalized_name)
            row = resource_to_dict(self.client.get_application(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=normalized_project,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or normalized_name,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        # App Engine apps are a per-project singleton; present it as a 1-element list.
        row = self.get(project_id=project_id, action_dict=action_dict)
        return [row] if isinstance(row, dict) and row else []

    def save(self, app, *, project_id: str, location: str | None = None, **_) -> None:
        for row in (app if isinstance(app, list) else [app]):
            if isinstance(row, dict) and row:
                save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    def update_service_account(self, *, project_id: str, service_account: str) -> dict:
        from google.protobuf import field_mask_pb2
        name = f"apps/{project_id}"
        application = self._appengine_admin_v1.Application(service_account=service_account)
        request = self._appengine_admin_v1.UpdateApplicationRequest(
            name=name,
            application=application,
            update_mask=field_mask_pb2.FieldMask(paths=["service_account"]),
        )
        op = self.client.update_application(request=request)
        result = op.result(timeout=120)
        return resource_to_dict(result)


class AppEngineServicesResource(_AppEngineBaseResource):
    """List/get App Engine services under apps/<project> (the traffic-split units)."""

    TABLE_NAME = "appengine_services"
    ACTION_RESOURCE_TYPE = "services"
    LIST_API_NAME = "appengine.services.list"
    GET_API_NAME = "appengine.services.get"
    COLUMNS = ["service_id", "name", "split"]

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._appengine_admin_v1.ServicesClient(credentials=session.credentials)

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        parent = f"apps/{project_id}"
        try:
            request = self._appengine_admin_v1.ListServicesRequest(parent=parent, page_size=200)
            rows = [resource_to_dict(service) for service in self.client.list_services(request=request)]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        try:
            request = self._appengine_admin_v1.GetServiceRequest(name=name)
            row = resource_to_dict(self.client.get_service(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=self.project_id_from_name(name),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or name,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, services: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for svc in services or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                svc,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {"service_id": extract_path_tail(raw.get("name", ""))},
            )


class AppEngineVersionsResource(_AppEngineBaseResource):
    """List/get App Engine versions under a service (carry runtime/env deploy details)."""

    TABLE_NAME = "appengine_versions"
    ACTION_RESOURCE_TYPE = "versions"
    LIST_API_NAME = "appengine.versions.list"
    GET_API_NAME = "appengine.versions.get"
    COLUMNS = ["version_id", "name", "runtime", "env"]

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._appengine_admin_v1.VersionsClient(credentials=session.credentials)

    def list(self, *, project_id: str | None = None, service_id: str = "", parent: str = "", location: str | None = None, action_dict=None):
        parent = parent or f"apps/{project_id}/services/{service_id}"
        project_id = project_id or self.project_id_from_name(parent)
        try:
            request = self._appengine_admin_v1.ListVersionsRequest(parent=parent, page_size=200)
            rows = [resource_to_dict(version) for version in self.client.list_versions(request=request)]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        try:
            request = self._appengine_admin_v1.GetVersionRequest(name=name)
            row = resource_to_dict(self.client.get_version(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=self.project_id_from_name(name),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or name,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, versions: Iterable[dict[str, Any]], *, project_id: str, service_name: str = "", location: str | None = None, **_) -> None:
        for version in versions or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                version,
                defaults={"project_id": project_id, "service_name": service_name},
                extra_builder=lambda _obj, raw: {"version_id": extract_path_tail(raw.get("name", ""))},
            )

    def create(
        self,
        *,
        project_id: str,
        service_id: str,
        version_id: str,
        service_account: str,
        deployment_files: dict,
        serving_status: str = "STOPPED",
    ) -> dict:
        from google.cloud.appengine_admin_v1.types.version import ServingStatus
        status_map = {"STOPPED": ServingStatus.STOPPED, "SERVING": ServingStatus.SERVING}
        parent = f"apps/{project_id}/services/{service_id}"
        files_map = {
            fname: self._appengine_admin_v1.FileInfo(
                source_url=info["sourceUrl"],
                sha1_sum=info["sha1Sum"],
            )
            for fname, info in deployment_files.items()
        }
        version = self._appengine_admin_v1.Version(
            id=version_id,
            runtime="python312",
            env="standard",
            service_account=service_account,
            serving_status=status_map.get(serving_status, ServingStatus.STOPPED),
            # Manual scaling is required to allow serving_status to be toggled
            # after deployment (automatic scaling versions ignore serving_status updates).
            manual_scaling=self._appengine_admin_v1.ManualScaling(instances=1),
            deployment=self._appengine_admin_v1.Deployment(files=files_map),
            entrypoint=self._appengine_admin_v1.Entrypoint(shell="gunicorn -b :$PORT main:app"),
        )
        request = self._appengine_admin_v1.CreateVersionRequest(parent=parent, version=version)
        op = self.client.create_version(request=request)
        result = op.result(timeout=360)
        return resource_to_dict(result)

    def update_serving_status(self, *, version_name: str, serving_status: str) -> dict:
        from google.cloud.appengine_admin_v1.types.version import ServingStatus
        from google.protobuf import field_mask_pb2
        status_map = {"STOPPED": ServingStatus.STOPPED, "SERVING": ServingStatus.SERVING}
        request = self._appengine_admin_v1.UpdateVersionRequest(
            name=version_name,
            version=self._appengine_admin_v1.Version(
                serving_status=status_map.get(serving_status, ServingStatus.SERVING)
            ),
            update_mask=field_mask_pb2.FieldMask(paths=["serving_status"]),
        )
        op = self.client.update_version(request=request)
        result = op.result(timeout=120)
        return resource_to_dict(result)

    def delete(self, *, name: str) -> None:
        request = self._appengine_admin_v1.DeleteVersionRequest(name=name)
        op = self.client.delete_version(request=request)
        op.result(timeout=120)


class AppEngineInstancesResource(_AppEngineBaseResource):
    """List/get the running VM instances backing an App Engine version."""

    TABLE_NAME = "appengine_instances"
    ACTION_RESOURCE_TYPE = "instances"
    LIST_API_NAME = "appengine.instances.list"
    GET_API_NAME = "appengine.instances.get"
    COLUMNS = ["instance_id", "name", "vm_id"]

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = self._appengine_admin_v1.InstancesClient(credentials=session.credentials)

    def list(self, *, project_id: str | None = None, service_id: str = "", version_id: str = "", parent: str = "", location: str | None = None, action_dict=None):
        parent = parent or f"apps/{project_id}/services/{service_id}/versions/{version_id}"
        project_id = project_id or self.project_id_from_name(parent)
        try:
            request = self._appengine_admin_v1.ListInstancesRequest(parent=parent, page_size=200)
            rows = [resource_to_dict(instance) for instance in self.client.list_instances(request=request)]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        try:
            request = self._appengine_admin_v1.GetInstanceRequest(name=name)
            row = resource_to_dict(self.client.get_instance(request=request))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=self.project_id_from_name(name),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row) or name,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, instances: Iterable[dict[str, Any]], *, project_id: str, version_name: str = "", location: str | None = None, **_) -> None:
        for instance in instances or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                instance,
                defaults={"project_id": project_id, "version_name": version_name},
                extra_builder=lambda _obj, raw: {"instance_id": extract_path_tail(raw.get("name", ""))},
            )
