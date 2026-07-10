from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


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
