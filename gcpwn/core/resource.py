"""Config-driven base for the standard GCP enumeration Resource pattern.

Across ~20 service Resource classes the ``list`` / ``get`` /
``test_iam_permissions`` / ``save`` bodies are identical; only the config
varies (table, columns, permission strings, SDK client + method names, the
id field). ``GcpListResource`` implements those bodies once. A subclass
declares the config as class attributes and implements ``_build_client``;
per-service quirks are expressed via the config flags or by overriding a
single method.

Method signatures intentionally match the long-standing per-service classes
so enum modules call them unchanged:
    list(*, project_id=, location=, parent=, action_dict=)
    get(*, resource_id=, action_dict=)
    test_iam_permissions(*, resource_id=, action_dict=)
    save(rows, *, project_id=, location=, **extra_defaults)
"""

from __future__ import annotations

from typing import Any, Iterable

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import (
    build_discovery_service,
    handle_discovery_error,
    handle_service_error,
)


class GcpListResource:
    """Config-driven base implementing the shared list/get/test_iam/save bodies.

    Subclasses declare config as class attributes and implement ``_build_client``;
    per-service quirks are handled by tweaking config flags or overriding one of
    the small hooks (``_list_items``, ``_get_item``, ``_normalize_row``,
    ``_extra_save_fields``). The four public methods keep the long-standing
    per-service signatures so enum modules call them unchanged.

    Config attributes:
      SERVICE_LABEL        Human label used in "API disabled" messages.
      TABLE_NAME/COLUMNS   Workspace-scoped DB table + its columns.
      ACTION_RESOURCE_TYPE resource_type recorded for get/iam/resource-mode list.
      LIST/GET_PERMISSION  Permission strings recorded as direct_api evidence on
                           a successful list/get.
      TEST_IAM_*           API name + permission tuple for the testIamPermissions probe.
      LIST/GET_METHOD      SDK client method names invoked by the default hooks.
      ID_FIELD             Column that stores the resource's short id (path tail).

    Parent-build modes (which determine how `list` forms its `parent=` and how
    the list permission is scoped):
      PARENT_FROM_PROJECT_LOCATION (default) -> projects/<p>/locations/<loc>;
                                                list recorded as a project-scope perm.
      PARENT_FROM_PROJECT                    -> projects/<p> (no location; pubsub/
                                                bigtable); list as a project-scope perm.
      neither set (both False)               -> caller passes parent= directly; list
                                                recorded as a resource permission on
                                                that parent (or project-scope if
                                                LIST_PROJECT_SCOPE).
    """

    # --- per-service config (set on subclasses) ---
    SERVICE_LABEL: str = ""
    TABLE_NAME: str = ""
    COLUMNS: list[str] = []
    ACTION_RESOURCE_TYPE: str = ""
    LIST_PERMISSION: str = ""
    GET_PERMISSION: str = ""
    TEST_IAM_API_NAME: str = ""
    TEST_IAM_PERMISSIONS: tuple[str, ...] = ()
    LIST_METHOD: str = ""
    GET_METHOD: str = ""
    ID_FIELD: str = ""
    # Parent-build mode for `list`:
    #   PARENT_FROM_PROJECT_LOCATION -> projects/<p>/locations/<loc> (default)
    #   PARENT_FROM_PROJECT          -> projects/<p>  (no location; e.g. pubsub/bigtable)
    #   neither                      -> caller passes parent= directly
    # The first two record the list as a project-scope permission.
    PARENT_FROM_PROJECT_LOCATION: bool = True
    PARENT_FROM_PROJECT: bool = False
    # Optional overrides (default to the values above):
    #   LIST_API_NAME/GET_API_NAME  -> the string shown in error messages
    #   LIST_RESOURCE_TYPE          -> resource_type recorded for a parent-mode
    #                                  list (e.g. listing keys is a keyring perm)
    LIST_API_NAME: str = ""
    GET_API_NAME: str = ""
    LIST_RESOURCE_TYPE: str = ""
    # Record a parent-mode list as a project-scope permission (project derived
    # from the parent) instead of a resource permission.
    LIST_PROJECT_SCOPE: bool = False

    def __init__(self, session) -> None:
        self.session = session
        self.client = self._build_client(session)

    def _build_client(self, session):  # pragma: no cover - subclass responsibility
        raise NotImplementedError("Resource subclasses must implement _build_client().")

    def _fallback_project(self) -> str:
        """Project id to attribute a permission to when it can't be parsed from a
        resource name (falls back to the active session's project)."""
        return getattr(self.session, "project_id", "") or ""

    # SDK-call hooks. Default to the common `parent=`/`name=` kwargs; services
    # whose clients use request={...} dicts, Request(...) objects, or response
    # wrappers override just these two (the rest of the bodies stay shared).
    # Extra per-call options (e.g. a tasks full_view) flow through as **kwargs.
    def _list_items(self, parent: str | None, **kwargs):
        """Return an iterable of raw SDK resources under ``parent``. Override for
        clients that take ``request={...}``/``Request(...)`` or wrap the response."""
        return getattr(self.client, self.LIST_METHOD)(parent=parent)

    def _get_item(self, resource_id: str, **kwargs):
        """Return one raw SDK resource by full name. Override for non-``name=`` clients."""
        return getattr(self.client, self.GET_METHOD)(name=resource_id)

    def _normalize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """Post-process each resource_to_dict row (override for field fixups)."""
        return row

    def list(self, *, project_id: str | None = None, location: str | None = None, parent: str | None = None, action_dict=None, **list_kwargs):
        """List resources, record the list permission as evidence, return rows.

        Builds ``parent`` per the PARENT_FROM_* mode (or uses the caller-supplied
        ``parent=`` when neither is set). On success each raw resource is run
        through ``resource_to_dict`` + ``_normalize_row``, and LIST_PERMISSION is
        recorded into ``action_dict`` as direct_api evidence scoped per the mode.

        Returns the list of row dicts, or the sentinel ``"Not Enabled"`` when the
        API is disabled (short-circuits region fan-out upstream), or ``None`` on a
        denied/404/500 error -- see ``handle_service_error``.
        """
        if self.PARENT_FROM_PROJECT:
            # explicit opt-in to a location-less parent (projects/<p>) wins over the
            # location default, so subclasses only need to set PARENT_FROM_PROJECT=True
            parent = f"projects/{project_id}"
        elif self.PARENT_FROM_PROJECT_LOCATION:
            parent = f"projects/{project_id}/locations/{location}"
        try:
            rows = [self._normalize_row(resource_to_dict(item)) for item in self._list_items(parent, **list_kwargs)]
            if self.LIST_PERMISSION:
                if self.PARENT_FROM_PROJECT_LOCATION or self.PARENT_FROM_PROJECT:
                    record_permissions(
                        action_dict,
                        permissions=self.LIST_PERMISSION,
                        scope_key="project_permissions",
                        scope_label=project_id,
                    )
                elif self.LIST_PROJECT_SCOPE:
                    record_permissions(
                        action_dict,
                        permissions=self.LIST_PERMISSION,
                        scope_key="project_permissions",
                        scope_label=extract_project_id_from_resource(parent, fallback_project=self._fallback_project()),
                    )
                else:
                    record_permissions(
                        action_dict,
                        permissions=self.LIST_PERMISSION,
                        project_id=extract_project_id_from_resource(parent, fallback_project=self._fallback_project()),
                        resource_type=self.LIST_RESOURCE_TYPE or self.ACTION_RESOURCE_TYPE,
                        resource_label=parent,
                    )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME or self.LIST_PERMISSION,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None, **get_kwargs):
        """Fetch one resource's full metadata by name; record GET_PERMISSION evidence.

        Returns the normalized row dict, ``None`` for an empty/missing id or a
        denied/404/500 error, or ``"Not Enabled"`` when the API is disabled.
        """
        if not resource_id:
            return None
        try:
            row = self._normalize_row(resource_to_dict(self._get_item(resource_id, **get_kwargs)))
            if row and self.GET_PERMISSION:
                record_permissions(
                    action_dict,
                    permissions=self.GET_PERMISSION,
                    project_id=extract_project_id_from_resource(resource_id, fallback_project=self._fallback_project()),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_id,
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME or self.GET_PERMISSION,
                resource_name=resource_id,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        """Probe TEST_IAM_PERMISSIONS against ``resource_id`` via testIamPermissions.

        Records any granted permissions into ``action_dict`` as test_iam_permissions
        evidence (distinct provenance from direct_api list/get findings). Returns the
        list of permissions the caller actually holds (empty if none/unconfigured).
        """
        if not self.TEST_IAM_PERMISSIONS:
            return []
        project_id = extract_project_id_from_resource(resource_id, fallback_project=self._fallback_project())
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label=self.SERVICE_LABEL,
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Extra derived columns to write alongside the id field (override as needed)."""
        return {}

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **extra_defaults: Any) -> None:
        """Upsert rows into TABLE_NAME (workspace-scoped via session).

        Stamps each row with ``project_id``, a ``location`` (from the arg or
        derived from the resource name) when the table has that column, the
        ID_FIELD (short path tail of the name), and any ``_extra_save_fields``.
        DB write -- MAIN THREAD ONLY (DataController is single-threaded); never
        call this from a parallel_map worker. All rows persist in ONE transaction
        (one fsync for the batch instead of one per row).
        """
        with self.session.batched_writes():
            for row in rows or []:
                name = str(row.get("name", "")).strip()
                defaults: dict[str, Any] = {"project_id": project_id, **extra_defaults}
                if "location" in self.COLUMNS:
                    defaults["location"] = location if location and location != "-" else extract_location_from_resource_name(name)
                save_to_table(
                    self.session,
                    self.TABLE_NAME,
                    row,
                    defaults=defaults,
                    extra_builder=lambda _obj, raw: {self.ID_FIELD: extract_path_tail(raw.get("name", "")), **self._extra_save_fields(raw)},
                )


class DiscoveryListResource:
    """Config-driven base for services backed by a *discovery* client.

    The discovery-client counterpart of ``GcpListResource``: for services whose
    client comes from ``build_discovery_service`` and whose list/get go through
    ``.execute()`` (returning ``{"items": [...]}`` for list, a dict for get). The
    shared list/get/save bodies -- error handling via ``handle_discovery_error``,
    permission recording, item filtering, upsert -- live here once. A subclass
    declares the discovery API/version + config and implements the two SDK-call
    hooks (``_list_request`` / ``_get_request``, which return the *un-executed*
    request object). Method signatures match the long-standing per-service classes
    so enum modules / run_components call them unchanged.

    List-permission scope mirrors ``GcpListResource``:
      LIST_PROJECT_SCOPE=True (default) -> recorded as a project-scope permission;
      LIST_PROJECT_SCOPE=False          -> recorded as a resource permission on the
                                           parent (e.g. listing databases is an
                                           instance-scoped perm).
    """

    SERVICE_LABEL: str = ""
    TABLE_NAME: str = ""
    COLUMNS: list[str] = []
    ACTION_RESOURCE_TYPE: str = ""
    LIST_PERMISSION: str = ""
    GET_PERMISSION: str = ""
    # Strings shown in error messages (default to the permission strings):
    LIST_API_NAME: str = ""
    GET_API_NAME: str = ""
    # Discovery client identity + optional short-id column:
    DISCOVERY_API: str = ""
    DISCOVERY_VERSION: str = ""
    ID_FIELD: str = ""
    # Record the list as a project-scope permission (default) vs a resource
    # permission on the parent (set False for NESTED per-parent lists):
    LIST_PROJECT_SCOPE: bool = True

    def __init__(self, session) -> None:
        self.session = session
        self.service = self._build_service(session)

    def _build_service(self, session):
        return build_discovery_service(session.credentials, self.DISCOVERY_API, self.DISCOVERY_VERSION)

    def _fallback_project(self) -> str:
        return getattr(self.session, "project_id", "") or ""

    # SDK-call hooks. Return the *un-executed* discovery request; the base calls
    # ``.execute()`` and unwraps ``{"items": [...]}`` (list) / the dict (get).
    def _list_request(self, *, project_id: str, parent: str | None, page_token: str | None = None, **kwargs):  # pragma: no cover - subclass responsibility
        # page_token is threaded by list() for nextPageToken pagination. Subclasses whose
        # discovery method supports it forward it (pageToken=page_token); those whose method
        # has no pageToken param accept and ignore it (single-page APIs).
        raise NotImplementedError("DiscoveryListResource subclasses must implement _list_request().")

    def _get_request(self, *, project_id: str, resource_id: str, **kwargs):  # pragma: no cover - subclass responsibility
        raise NotImplementedError("DiscoveryListResource subclasses must implement _get_request().")

    def _normalize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return row

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {}

    def list(self, *, project_id: str | None = None, location: str | None = None, parent: str | None = None, action_dict=None, **kwargs):
        """List resources via the discovery client, record the list permission, return rows.

        Returns the list of row dicts, the sentinel ``"Not Enabled"`` when the API
        is disabled, or ``None``/``[]`` on a denied/error response -- whatever
        ``handle_discovery_error`` yields.
        """
        project_id = project_id or self._fallback_project()
        resource_label = str(kwargs.get("instance") or parent or "")
        try:
            # Drain nextPageToken -- a single .execute() only returns the first page, so a
            # project whose list spans multiple pages (e.g. sqladmin instances.list) would
            # silently drop everything past page 1. Subclasses whose API has no pageToken
            # accept+ignore page_token, so their response carries no nextPageToken and the
            # loop exits after one page.
            rows: list[dict[str, Any]] = []
            page_token = None
            while True:
                response = self._list_request(project_id=project_id, parent=parent, page_token=page_token, **kwargs).execute()
                if not isinstance(response, dict):
                    break
                rows.extend(self._normalize_row(item) for item in response.get("items", []) if isinstance(item, dict))
                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            if self.LIST_PERMISSION:
                if self.LIST_PROJECT_SCOPE:
                    record_permissions(action_dict, permissions=self.LIST_PERMISSION,
                                       scope_key="project_permissions", scope_label=project_id)
                else:
                    record_permissions(action_dict, permissions=self.LIST_PERMISSION, project_id=project_id,
                                       resource_type=self.ACTION_RESOURCE_TYPE, resource_label=resource_label)
            return rows
        except Exception as exc:
            return handle_discovery_error(self.session, self.LIST_API_NAME or self.LIST_PERMISSION,
                                          resource_label or project_id, exc, service_label=self.SERVICE_LABEL)

    def get(self, *, resource_id: str, project_id: str | None = None, action_dict=None, **kwargs):
        """Fetch one resource via the discovery client; record GET_PERMISSION evidence."""
        if not resource_id:
            return None
        project_id = project_id or self._fallback_project()
        try:
            response = self._get_request(project_id=project_id, resource_id=resource_id, **kwargs).execute()
            if not isinstance(response, dict):
                return None
            row = self._normalize_row(response)
            if self.GET_PERMISSION:
                record_permissions(action_dict, permissions=self.GET_PERMISSION, project_id=project_id,
                                   resource_type=self.ACTION_RESOURCE_TYPE, resource_label=resource_id)
            return row
        except Exception as exc:
            result = handle_discovery_error(self.session, self.GET_API_NAME or self.GET_PERMISSION,
                                            resource_id, exc, service_label=self.SERVICE_LABEL)
            return result if isinstance(result, dict) else None

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **extra_defaults: Any) -> None:
        """Upsert rows into TABLE_NAME (workspace-scoped). DB write -- MAIN THREAD ONLY.

        All rows persist in ONE transaction (a single fsync for the batch).
        """
        with self.session.batched_writes():
            for row in rows or []:
                defaults: dict[str, Any] = {"project_id": project_id, **extra_defaults}
                if "location" in self.COLUMNS and "location" not in defaults:
                    name = str(row.get("name", "")).strip()
                    defaults["location"] = location if location and location != "-" else extract_location_from_resource_name(name)
                save_to_table(self.session, self.TABLE_NAME, row, defaults=defaults, extra_builder=self._save_extra_builder)

    def _save_extra_builder(self, _obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
        extra = dict(self._extra_save_fields(raw))
        if self.ID_FIELD and self.ID_FIELD not in extra:
            extra[self.ID_FIELD] = extract_path_tail(raw.get("name", ""))
        return extra
