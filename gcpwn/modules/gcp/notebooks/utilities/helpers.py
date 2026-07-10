from __future__ import annotations

from typing import Any

from google.cloud import notebooks_v2

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("notebooks", ("notebooks", "v2"))


def _service_account_email(raw: dict[str, Any]) -> str:
    """Return the run-as SA email of a Vertex AI Workbench instance.

    The instance's ``gce_setup.service_accounts[0].email`` is the identity its
    underlying GCE VM (and any notebook code executing on it) runs as. A principal
    who can create/update/SSH or proxy into the instance effectively acts as that
    SA -- the key offensive signal for privilege analysis, mirroring the SA-as-VM
    primitive elsewhere in gcpwn. Read it defensively: resource_to_dict yields
    nested dicts and the field is optional/repeated.
    """
    gce_setup = raw.get("gce_setup")
    if not isinstance(gce_setup, dict):
        return ""
    service_accounts = gce_setup.get("service_accounts")
    if not isinstance(service_accounts, list) or not service_accounts:
        return ""
    first = service_accounts[0]
    if not isinstance(first, dict):
        return ""
    return str(first.get("email") or "").strip()


class NotebooksInstancesResource(GcpListResource):
    """List/get Vertex AI Workbench Instances via the notebooks_v2 GAPIC client.

    The notebooks_v2 ``NotebookServiceClient`` exposes ``test_iam_permissions``,
    so per-instance IAM probing is supported.
    """

    SERVICE_LABEL = "Vertex AI Workbench"
    TABLE_NAME = "notebooks_instances"
    COLUMNS = ["location", "instance_id", "name", "state", "proxy_uri", "creator", "service_account"]
    ACTION_RESOURCE_TYPE = "instances"
    LIST_PERMISSION = "notebooks.instances.list"
    GET_PERMISSION = "notebooks.instances.get"
    TEST_IAM_API_NAME = "notebooks.instances.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "notebooks.instances.",
        exclude_permissions=("notebooks.instances.list",),
    )
    ID_FIELD = "instance_id"

    def _build_client(self, session):
        return notebooks_v2.NotebookServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_instances(request=notebooks_v2.ListInstancesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_instance(request=notebooks_v2.GetInstanceRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "instance_id": extract_path_tail(str(raw.get("name", "") or "")),
            "service_account": _service_account_email(raw),
        }
