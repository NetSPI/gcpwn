from __future__ import annotations

from typing import Any

from google.cloud import parametermanager_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail


class ParameterManagerParametersResource(GcpListResource):
    """Parameter Manager parameters — global, project-scoped config/secret store.

    Parent is always ``projects/{project_id}/locations/global``.
    With ``PARENT_FROM_PROJECT_LOCATION=True`` (the default) and ``scope=PROJECT``
    in the Component, the framework passes ``location="global"`` and the base
    ``list()`` builds the correct parent automatically.
    """

    SERVICE_LABEL = "Parameter Manager Parameters"
    TABLE_NAME = "parametermanager_parameters"
    COLUMNS = ["parameter_id", "name", "format", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "parameters"
    LIST_PERMISSION = "parametermanager.parameters.list"
    GET_PERMISSION = "parametermanager.parameters.get"
    ID_FIELD = "parameter_id"
    # PARENT_FROM_PROJECT_LOCATION=True (default): list() builds
    # projects/{project_id}/locations/{location} which, for scope=PROJECT,
    # is projects/{project_id}/locations/global — correct for this service.

    def _build_client(self, session):
        return parametermanager_v1.ParameterManagerClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_parameters(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_parameter(name=resource_id)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = str(raw.get("name", "") or "")
        return {
            "parameter_id": extract_path_tail(name),
            "format": str(raw.get("format", "") or ""),
            "create_time": str(raw.get("create_time", "") or ""),
            "update_time": str(raw.get("update_time", "") or ""),
        }


class ParameterManagerVersionsResource(GcpListResource):
    """Parameter Manager parameter versions — NESTED under each parameter.

    ``PARENT_FROM_PROJECT_LOCATION`` and ``PARENT_FROM_PROJECT`` are both False so
    the base ``list()`` uses the ``parent=`` kwarg passed by the framework directly
    (the full parameter resource name, e.g.
    ``projects/{p}/locations/global/parameters/{id}``).
    """

    SERVICE_LABEL = "Parameter Manager Parameter Versions"
    TABLE_NAME = "parametermanager_parameter_versions"
    COLUMNS = ["parameter_id", "version_id", "name", "parameter", "state", "create_time"]
    ACTION_RESOURCE_TYPE = "parameter versions"
    LIST_PERMISSION = "parametermanager.parameterVersions.list"
    GET_PERMISSION = "parametermanager.parameterVersions.get"
    ID_FIELD = "version_id"
    # NESTED: the caller (run_components) passes parent=<parameter_name> directly.
    PARENT_FROM_PROJECT_LOCATION = False
    PARENT_FROM_PROJECT = False

    def _build_client(self, session):
        return parametermanager_v1.ParameterManagerClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_parameter_versions(parent=parent)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = str(raw.get("name", "") or "")
        return {
            "version_id": extract_path_tail(name),
            "parameter_id": extract_path_segment(name, "parameters"),
            "parameter": extract_path_segment(name, "parameters"),
            "state": str(raw.get("state", "") or ""),
            "create_time": str(raw.get("create_time", "") or ""),
        }
