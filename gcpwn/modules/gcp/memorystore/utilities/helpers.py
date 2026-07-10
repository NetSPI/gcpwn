from __future__ import annotations

from google.cloud import redis_v1

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import extract_location_from_resource_name, extract_project_id_from_resource
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error

_SERVICE_LABEL = "Memorystore Redis"


def list_redis_instances(redis_client, parent, debug=False):
    if debug:
        print(f"[DEBUG] Listing Redis instances for: {parent}...")
    project_id = extract_project_id_from_resource(parent)
    try:
        request = redis_v1.ListInstancesRequest(parent=parent)
        return list(redis_client.list_instances(request=request))
    except Exception as e:
        # list short-circuits region fan-out on a disabled API -> keep "Not Enabled".
        return handle_service_error(
            e, api_name="redis.instances.list", resource_name=parent,
            service_label=_SERVICE_LABEL, project_id=project_id,
        )


def get_redis_instance(redis_instances_client, name, debug=False):
    if debug:
        print(f"[DEBUG] Getting {name}...")
    project_id = extract_project_id_from_resource(name)
    try:
        request = redis_v1.GetInstanceRequest(name=name)
        return redis_instances_client.get_instance(request=request)
    except Exception as e:
        # get returns None on every error (incl. disabled) -> return_not_enabled=False.
        return handle_service_error(
            e, api_name="redis.instances.get", resource_name=name,
            service_label=_SERVICE_LABEL, project_id=project_id, return_not_enabled=False,
        )


def get_redis_instance_auth_string(redis_instances_client, name, debug=False):
    """Fetch a Redis instance's AUTH string (the connection password); None on error.

    High-value pentest signal: when AUTH is enabled this returns the credential
    needed to connect. Errors are reported and swallowed (return_not_enabled=False).
    """
    if debug:
        print(f"[DEBUG] Getting auth string for {name}...")
    project_id = extract_project_id_from_resource(name)
    try:
        request = redis_v1.GetInstanceAuthStringRequest(name=name)
        return redis_instances_client.get_instance_auth_string(request=request)
    except Exception as e:
        return handle_service_error(
            e, api_name="redis.instances.getAuthString", resource_name=name,
            service_label=_SERVICE_LABEL, project_id=project_id, return_not_enabled=False,
        )


class MemorystoreRedisResource:
    """Enumerate Memorystore Redis instances and harvest their AUTH strings.

    Hand-rolled resource (no GcpListResource / no testIamPermissions API for
    Redis). get() deliberately folds the privileged getAuthString call into the
    instance read so a single get yields the connection credential. Permissions
    are recorded as evidence (direct_api) into action_dict; list() returns the
    "Not Enabled" sentinel unchanged to short-circuit region fan-out.
    """

    TABLE_NAME = "memorystore-redis"
    COLUMNS = ["name", "display_name", "state_output", "location_id", "host", "port", "auth_enabled", "auth_string"]
    LIST_PERMISSION = "redis.instances.list"
    GET_PERMISSION = "redis.instances.get"
    GET_AUTH_STRING_PERMISSION = "redis.instances.getAuthString"
    SERVICE_LABEL = "Memorystore Redis"
    ACTION_RESOURCE_TYPE = "redis"
    TEST_IAM_PERMISSIONS = ()  # Memorystore Redis has no testIamPermissions API

    _STATE = {
        0: "STATE_UNSPECIFIED", 1: "CREATING", 2: "READY", 3: "UPDATING",
        4: "DELETING", 5: "REPAIRING", 6: "MAINTENANCE", 7: "IMPORTING", 8: "FAILING_OVER",
    }

    def __init__(self, session):
        self.session = session
        self.client = redis_v1.CloudRedisClient(credentials=session.credentials)

    def _normalize(self, instance) -> dict:
        row = resource_to_dict(instance)
        row["state_output"] = self._STATE.get(row.get("state"), row.get("state"))
        row["location_id"] = extract_location_from_resource_name(str(row.get("name") or "").strip())
        return row

    def list(self, *, project_id: str | None = None, location: str | None = None, parent: str | None = None, action_dict=None):
        if parent is None:
            parent = f"projects/{project_id}/locations/{location or '-'}"
        rows = list_redis_instances(self.client, parent, debug=getattr(self.session, "debug", False))
        if rows in ("Not Enabled", None):
            return rows
        record_permissions(action_dict, permissions=self.LIST_PERMISSION, scope_key="project_permissions",
                            scope_label=extract_project_id_from_resource(parent))
        return [self._normalize(instance) for instance in rows]

    def get(self, *, resource_id: str, action_dict=None):
        """Read one Redis instance and, if AUTH is enabled, attach its auth_string.

        Records redis.instances.get and (when a secret comes back)
        redis.instances.getAuthString as evidence. Returns the normalized row, or
        None if the instance read failed.
        """
        instance = get_redis_instance(self.client, resource_id, debug=getattr(self.session, "debug", False))
        if not instance:
            return None
        project_id = extract_project_id_from_resource(resource_id)
        record_permissions(action_dict, permissions=self.GET_PERMISSION, project_id=project_id,
                           resource_type=self.ACTION_RESOURCE_TYPE, resource_label=resource_id)
        row = self._normalize(instance)
        # Folding the sensitive auth-string fetch into get() preserves that pentest signal.
        auth = get_redis_instance_auth_string(self.client, resource_id, debug=getattr(self.session, "debug", False))
        auth_string = getattr(auth, "auth_string", "") if auth is not None else ""
        if auth_string:
            record_permissions(action_dict, permissions=self.GET_AUTH_STRING_PERMISSION, project_id=project_id,
                               resource_type=self.ACTION_RESOURCE_TYPE, resource_label=resource_id)
            row["auth_string"] = auth_string
        return row

    def save(self, rows, *, project_id=None, location=None, **_):
        for row in rows or []:
            save_to_table(
                self.session,
                "memorystore-redis",
                row,
                extra_builder=lambda _obj, raw: {"project_id": extract_project_id_from_resource(raw.get("name", ""))},
            )
