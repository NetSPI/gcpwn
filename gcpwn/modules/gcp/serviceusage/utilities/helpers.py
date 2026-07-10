from __future__ import annotations

from google.cloud import service_usage_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import extract_path_tail


class ServiceUsageServicesResource(GcpListResource):
    """List the APIs (services) enabled on a project via the service_usage_v1 GAPIC client.

    The enabled-API surface is foundational recon: it tells an operator which
    services are even reachable in the project (and therefore which other enum
    modules can possibly return data) and which managed services -- e.g.
    ``cloudfunctions.googleapis.com``, ``run.googleapis.com`` -- are live and
    worth probing for SA-impersonation or deploy-as-SA primitives.

    ``list_services`` takes a ``ListServicesRequest`` (with a required ``filter``)
    rather than a ``parent=`` kwarg, so ``_list_items`` is overridden. The parent
    is ``projects/<p>`` (PARENT_FROM_PROJECT), and the API exposes no useful
    per-service get or testIamPermissions for recon, so the component runs with
    ``supports_get=False`` / ``supports_iam=False``.
    """

    SERVICE_LABEL = "Service Usage"
    TABLE_NAME = "serviceusage_services"
    COLUMNS = ["name", "service_name", "state"]
    ACTION_RESOURCE_TYPE = "services"
    LIST_PERMISSION = "serviceusage.services.list"
    ID_FIELD = "service_name"
    PARENT_FROM_PROJECT = True  # parent = projects/<p>; list scoped as a project permission

    def _build_client(self, session):
        return service_usage_v1.ServiceUsageClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_services(
            request=service_usage_v1.ListServicesRequest(parent=parent, filter="state:ENABLED")
        )

    def _extra_save_fields(self, raw):
        return {
            "service_name": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
        }
