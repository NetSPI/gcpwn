from __future__ import annotations

import time
from typing import Any

from google.cloud import notebooks_v1, notebooks_v2

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

    def create(self, *, parent: str, instance_id: str, instance, timeout: int = 600) -> object:
        lro = self.client.create_instance(
            request=notebooks_v2.CreateInstanceRequest(
                parent=parent,
                instance_id=instance_id,
                instance=instance,
            )
        )
        return lro.result(timeout=timeout)

    def get_by_name(self, *, name: str) -> object:
        return self.client.get_instance(request=notebooks_v2.GetInstanceRequest(name=name))

    def delete(self, *, name: str) -> None:
        try:
            lro = self.client.delete_instance(request=notebooks_v2.DeleteInstanceRequest(name=name))
            lro.result(timeout=120)
        except Exception:
            pass


class NotebooksExecutionsResource:
    """Thin wrapper around notebooks_v1 for Execution CRUD + polling."""

    _TERMINAL = frozenset(["SUCCEEDED", "FAILED", "CANCELLED"])

    def __init__(self, session):
        self._session = session
        self._client = notebooks_v1.NotebookServiceClient(credentials=session.credentials)

    def create(self, *, parent: str, execution_id: str, execution) -> object:
        return self._client.create_execution(
            request=notebooks_v1.CreateExecutionRequest(
                parent=parent,
                execution_id=execution_id,
                execution=execution,
            )
        )

    def poll(self, *, name: str, timeout: int = 600, interval: int = 15) -> str:
        """Poll until terminal state or timeout. Returns final state string."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(min(interval, deadline - time.time()))
            try:
                ex = self._client.get_execution(
                    request=notebooks_v1.GetExecutionRequest(name=name)
                )
                state = ex.state.name if hasattr(ex.state, "name") else str(ex.state)
                if state in self._TERMINAL:
                    return state
                print(f"  [poll] state={state}", flush=True)
            except Exception as e:
                print(f"  [poll] error: {e}", flush=True)
        return "TIMEOUT"

    def delete(self, *, name: str) -> None:
        try:
            self._client.delete_execution(
                request=notebooks_v1.DeleteExecutionRequest(name=name)
            )
        except Exception:
            pass
