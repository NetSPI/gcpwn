from google.cloud import dataplex_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_tail, region_resolver_for


resolve_locations = region_resolver_for("dataplex", ("dataplex", "v1"))

_LAKE_PERMISSIONS = tuple(permissions_with_prefixes(
    "dataplex.lakes.",
    exclude_permissions=["dataplex.lakes.create", "dataplex.lakes.list"],
))
_TASK_PERMISSIONS = tuple(permissions_with_prefixes(
    "dataplex.tasks.",
    exclude_permissions=["dataplex.tasks.create", "dataplex.tasks.list"],
))


class DataplexLakesResource(GcpListResource):
    """List/get Dataplex (Knowledge Catalog) lakes per region."""

    SERVICE_LABEL = "Knowledge Catalog (formerly Dataplex)"
    TABLE_NAME = "dataplex_lakes"
    COLUMNS = ["location", "lake_id", "name", "display_name", "state"]
    ACTION_RESOURCE_TYPE = "lakes"
    LIST_PERMISSION = "dataplex.lakes.list"
    GET_PERMISSION = "dataplex.lakes.get"
    TEST_IAM_API_NAME = "dataplex.lakes.testIamPermissions"
    TEST_IAM_PERMISSIONS = _LAKE_PERMISSIONS
    ID_FIELD = "lake_id"

    def _build_client(self, session):
        return dataplex_v1.DataplexServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_lakes(request=dataplex_v1.ListLakesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_lake(request=dataplex_v1.GetLakeRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        name = str(raw.get("name", "") or "")
        state = raw.get("state")
        return {
            "lake_id": extract_path_tail(name),
            "display_name": str(raw.get("display_name") or ""),
            "state": state.name if hasattr(state, "name") else str(state or ""),
        }


class DataplexTasksResource(GcpListResource):
    """List/get Dataplex tasks across all lakes in a region.

    Tasks are nested under lakes, so _list_items iterates over lakes first.
    """

    SERVICE_LABEL = "Knowledge Catalog (formerly Dataplex)"
    TABLE_NAME = "dataplex_tasks"
    COLUMNS = ["location", "lake_id", "task_id", "name", "service_account", "task_type", "state"]
    ACTION_RESOURCE_TYPE = "tasks"
    LIST_PERMISSION = "dataplex.tasks.list"
    GET_PERMISSION = "dataplex.tasks.get"
    TEST_IAM_API_NAME = "dataplex.tasks.testIamPermissions"
    TEST_IAM_PERMISSIONS = _TASK_PERMISSIONS
    ID_FIELD = "task_id"

    def _build_client(self, session):
        return dataplex_v1.DataplexServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        """parent = projects/{project}/locations/{location}.
        Iterate all lakes in that location, then yield tasks from each lake.
        """
        tasks = []
        try:
            lakes = list(self.client.list_lakes(
                request=dataplex_v1.ListLakesRequest(parent=parent)
            ))
        except Exception:
            return tasks
        for lake in lakes:
            try:
                lake_tasks = list(self.client.list_tasks(
                    request=dataplex_v1.ListTasksRequest(parent=lake.name)
                ))
                tasks.extend(lake_tasks)
            except Exception:
                pass
        return tasks

    def _get_item(self, resource_id, **_):
        return self.client.get_task(request=dataplex_v1.GetTaskRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        name = str(raw.get("name", "") or "")
        # name = projects/{proj}/locations/{loc}/lakes/{lake}/tasks/{task}
        parts = name.split("/")
        lake_id = parts[-3] if len(parts) >= 4 else ""
        task_id = parts[-1] if parts else ""
        exec_spec = raw.get("execution_spec") or {}
        sa = exec_spec.get("service_account", "") if isinstance(exec_spec, dict) else str(getattr(exec_spec, "service_account", "") or "")
        spark = raw.get("spark") or {}
        notebook = raw.get("notebook") or {}
        if spark:
            task_type = "SPARK"
        elif notebook:
            task_type = "NOTEBOOK"
        else:
            task_type = "UNKNOWN"
        state = raw.get("state")
        return {
            "lake_id": lake_id,
            "task_id": task_id,
            "service_account": str(sa or ""),
            "task_type": task_type,
            "state": state.name if hasattr(state, "name") else str(state or ""),
        }
