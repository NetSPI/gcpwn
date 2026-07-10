from __future__ import annotations

from google.cloud import servicedirectory_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_location_from_resource_name, region_resolver_for


resolve_regions = region_resolver_for("servicedirectory", ("servicedirectory", "v1"))


def _sd_test_iam(resource: str) -> tuple[str, ...]:
    return permissions_with_prefixes(
        f"servicedirectory.{resource}.",
        exclude_permissions=(f"servicedirectory.{resource}.create", f"servicedirectory.{resource}.list"),
    )


class _ServiceDirectoryResource(GcpListResource):
    """Base for Service Directory resources: shared client + location_id derivation."""

    SERVICE_LABEL = "Service Directory"
    # Service Directory rows carry a derived location_id column; populate it from
    # the resource name so callers never have to thread the region through save().
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return servicedirectory_v1.RegistrationServiceClient(credentials=session.credentials)

    def _normalize_row(self, row):
        location_id = extract_location_from_resource_name(str(row.get("name") or "").strip())
        if location_id:
            row["location_id"] = location_id
        return row


class ServiceDirectoryNamespacesResource(_ServiceDirectoryResource):
    TABLE_NAME = "servicedirectory_namespaces"
    COLUMNS = ["location_id", "namespace_id", "name", "labels"]
    ACTION_RESOURCE_TYPE = "namespaces"
    LIST_PERMISSION = "servicedirectory.namespaces.list"
    PARENT_FROM_PROJECT_LOCATION = True  # namespaces list under projects/<p>/locations/<region>
    GET_PERMISSION = "servicedirectory.namespaces.get"
    TEST_IAM_API_NAME = "servicedirectory.namespaces.testIamPermissions"
    TEST_IAM_PERMISSIONS = _sd_test_iam("namespaces")
    ID_FIELD = "namespace_id"

    def _list_items(self, parent, **_):
        return list(self.client.list_namespaces(request={"parent": parent}))

    def _get_item(self, resource_id, **_):
        return self.client.get_namespace(request={"name": resource_id})


class ServiceDirectoryServicesResource(_ServiceDirectoryResource):
    TABLE_NAME = "servicedirectory_services"
    COLUMNS = ["location_id", "service_id", "name", "namespace_name", "labels"]
    ACTION_RESOURCE_TYPE = "services"
    LIST_PERMISSION = "servicedirectory.services.list"
    LIST_RESOURCE_TYPE = "namespaces"  # listing services is a permission on the namespace
    GET_PERMISSION = "servicedirectory.services.get"
    TEST_IAM_API_NAME = "servicedirectory.services.testIamPermissions"
    TEST_IAM_PERMISSIONS = _sd_test_iam("services")
    ID_FIELD = "service_id"

    def _list_items(self, parent, **_):
        return list(self.client.list_services(request={"parent": parent}))

    def _get_item(self, resource_id, **_):
        return self.client.get_service(request={"name": resource_id})


class ServiceDirectoryEndpointsResource(_ServiceDirectoryResource):
    TABLE_NAME = "servicedirectory_endpoints"
    COLUMNS = ["location_id", "endpoint_id", "name", "service_name", "address", "port", "network"]
    ACTION_RESOURCE_TYPE = "endpoints"
    LIST_METHOD = "list_endpoints"
    ID_FIELD = "endpoint_id"
    # Endpoints record no permissions and have no get/testIamPermissions.

    def _list_items(self, parent, **_):
        return list(self.client.list_endpoints(request={"parent": parent}))
