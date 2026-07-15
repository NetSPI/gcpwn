from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from gcpwn.core.utils.iam_simplifier import create_simplified_hierarchy_permissions
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    is_convenience_member,
    OpenGraphBuilder,
    principal_node_id,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import canonical_scope_type_for_bindings


@dataclass
class OpenGraphBuildOptions:
    include_all: bool = False
    expand_inheritance: bool = False
    conditional_evaluation: bool = False
    deny_policies: bool = False
    debug: bool = False
    # cross_project=True disables same-project partitioning for 2-hop combo rules.
    # cross_project_sa_projects: empty frozenset = allow ALL SA projects cross-project;
    # non-empty = only SA home-projects listed here (where iam.disableCrossProjectServiceAccountUsage
    # has been disabled).  cross_project=False ignores the set entirely.
    cross_project: bool = False
    cross_project_sa_projects: "frozenset[str]" = frozenset()


def _build_hierarchy_data(
    hierarchy_rows: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    children_by_parent: dict[str, list[str]] = defaultdict(list)
    scope_type_by_name: dict[str, str] = {}
    scope_display_by_name: dict[str, str] = {}
    project_id_by_scope_name: dict[str, str] = {}
    parent_by_name: dict[str, str] = {}
    known_project_ids: set[str] = set()

    for row in hierarchy_rows or []:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        scope_type_by_name[name] = canonical_scope_type_for_bindings(str(row.get("type") or ""), name)
        scope_display_by_name[name] = str(row.get("display_name") or "").strip()
        project_id = str(row.get("project_id") or "").strip()
        if project_id:
            project_id_by_scope_name[name] = project_id
            known_project_ids.add(project_id)
        parent = str(row.get("parent") or "").strip()
        if parent and parent not in {"N/A", "None"}:
            children_by_parent[parent].append(name)
            parent_by_name[name] = parent

    for parent_name in list(children_by_parent.keys()):
        children_by_parent[parent_name] = sorted(set(children_by_parent[parent_name]))

    return {
        "children_by_parent": dict(children_by_parent),
        "scope_type_by_name": scope_type_by_name,
        "scope_display_by_name": scope_display_by_name,
        "scope_project_by_name": project_id_by_scope_name,
        "parent_by_name": parent_by_name,
        "known_project_ids": known_project_ids,
    }

class OpenGraphBuildContext:
    """
    Shared in-memory context for staged OpenGraph builders.

    Builders should read inputs from `rows(...)`, write graph data through
    `builder`, and report compact per-step stats via `record_step(...)`.
    """

    def __init__(
        self,
        *,
        session,
        options: OpenGraphBuildOptions | None = None,
    ) -> None:
        self.session = session
        self.options = options or OpenGraphBuildOptions()
        self.builder = OpenGraphBuilder()
        self.step_stats: dict[str, dict[str, Any]] = {}
        self.artifacts: dict[str, Any] = {}
        self._rows_cache: dict[str, list[dict[str, Any]]] = {}
        self._service_table_names_cache: list[str] | None = None
        self._service_table_columns_cache: dict[str, list[str]] = {}
        # Hierarchy metadata cache used by IAM/resource builders.
        self._hierarchy_metadata: dict[str, Any] | None = None
        # Cached output of create_simplified_hierarchy_permissions(...),
        # keyed by {"base", "with_inferred"}.
        self._simplified_hierarchy_permissions_cache: dict[str, dict[str, Any]] = {}
        self._scope_resource_indexes_cache = None

    _ROW_TABLES = {
        "raw_allow_bindings": "iam_allow_policies",
        "iam_custom_roles": "iam_roles",
        "iam_service_accounts": "iam_service_accounts",
        "iam_sa_keys": "iam_sa_keys",
        "cloudcompute_instances": "cloudcompute_instances",
        "cloudfunctions_functions": "cloudfunctions_functions",
        "cloudrun_services": "cloudrun_services",
        "cloudrun_jobs": "cloudrun_jobs",
        # WIF tables feed stage-4 resource expansion (WIF_PROVIDER_IN_POOL /
        # GCP_FEDERATION_POSSIBLE / WIF EXISTS_IN_PROJECT). Without these mappings
        # context.rows() returns [] and those edges silently never emit.
        "workload_identity_pools": "workload_identity_pools",
        "workload_identity_providers": "workload_identity_providers",
        "workspace_users": "workspace_users",
        "workspace_groups": "workspace_groups",
        "hierarchy_rows": "abstract_tree_hierarchy",
        "group_memberships": "workspace_group_memberships",
        "workspace_admin_roles": "workspace_admin_roles",
        "workspace_role_assignments": "workspace_role_assignments",
        # IAM v2 Deny Policies -> the --deny-policies final filter (allow minus deny).
        "iam_deny_policies": "iam_deny_policies",
        # SA domain-wide-delegation grants -> DOMAIN_WIDE_DELEG edges (stage 1).
        "workspace_delegations": "workspace_delegations",
        # Group access/posting settings -> CAN_JOIN edges for self-join-open groups.
        "workspace_group_settings": "workspace_group_settings",
        # Drive file exposure -> CAN_READ edges for public / anyone-with-link files.
        "workspace_drive_files": "workspace_drive_files",
    }

    def _fetch_rows_for_key(self, key: str) -> list[dict[str, Any]]:
        table_name = self._ROW_TABLES.get(str(key or "").strip())
        if not table_name:
            return []
        values = self.session.get_data(table_name) or []
        return list(values) if isinstance(values, list) else []

    def rows(self, key: str) -> list[dict[str, Any]]:
        # Returns the CACHED list by reference (no per-call copy). All OpenGraph
        # callers treat rows() read-only; the golden pipeline test guards this.
        key_token = str(key or "").strip()
        if not key_token:
            return []
        cached = self._rows_cache.get(key_token)
        if cached is None:
            cached = self._fetch_rows_for_key(key_token)
            self._rows_cache[key_token] = cached
        return cached

    def service_table_names(self) -> list[str]:
        if self._service_table_names_cache is not None:
            return self._service_table_names_cache
        try:
            data_master = getattr(self.session, "data_master", None)
            cursor = getattr(data_master, "cursor", None)
            if cursor is None:
                self._service_table_names_cache = []
                return self._service_table_names_cache
            rows = cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            # The unified DB also holds control-plane tables (workspaces/session/
            # session_actions); they are not service resources -- keep them out of
            # the graph pipeline.
            control_plane = getattr(data_master, "_CONTROL_PLANE_TABLES", frozenset())
            names = [
                name
                for row in rows
                if row and (name := str(row[0] or "").strip()) and name not in control_plane
            ]
            self._service_table_names_cache = names
            return self._service_table_names_cache
        except Exception:
            self._service_table_names_cache = []
            return self._service_table_names_cache

    def service_table_columns(self, table_name: str) -> list[str]:
        token = str(table_name or "").strip()
        if not token:
            return []
        cached = self._service_table_columns_cache.get(token)
        if cached is not None:
            return cached
        try:
            cursor = getattr(getattr(self.session, "data_master", None), "cursor", None)
            if cursor is None:
                self._service_table_columns_cache[token] = []
                return self._service_table_columns_cache[token]
            rows = cursor.execute(f'PRAGMA table_info("{token}")').fetchall()
            columns = [str(row[1] or "").strip() for row in rows if len(row) > 1 and str(row[1] or "").strip()]
            self._service_table_columns_cache[token] = columns
            return columns
        except Exception:
            self._service_table_columns_cache[token] = []
            return self._service_table_columns_cache[token]

    def service_rows(self, table_name: str) -> list[dict[str, Any]]:
        token = str(table_name or "").strip()
        if not token:
            return []
        cache_key = f"service_table:{token}"
        cached = self._rows_cache.get(cache_key)
        if cached is None:
            try:
                values = self.session.get_data(token) or []
            except Exception:
                values = []
            cached = list(values) if isinstance(values, list) else []
            self._rows_cache[cache_key] = cached
        return cached

    def simplified_hierarchy_permissions(self, *, include_inferred_permissions: bool = False) -> dict[str, Any]:
        cache_key = "with_inferred" if include_inferred_permissions else "base"
        cached = self._simplified_hierarchy_permissions_cache.get(cache_key)
        if cached is None:
            cached = create_simplified_hierarchy_permissions(
                self.rows("raw_allow_bindings"),
                include_inheritance=bool(self.options.expand_inheritance),
                include_inferred_permissions=bool(include_inferred_permissions),
                hierarchy_data=self.hierarchy_data(),
                normalize_member=principal_node_id,
                is_convenience_member=is_convenience_member,
                session=self.session if include_inferred_permissions else None,
            )
            self._simplified_hierarchy_permissions_cache[cache_key] = cached
        return cached

    def hierarchy_data(self) -> dict[str, Any]:
        if self._hierarchy_metadata is None:
            self._hierarchy_metadata = _build_hierarchy_data(self.rows("hierarchy_rows"))
        return self._hierarchy_metadata

    def scope_resource_indexes(self):
        if self._scope_resource_indexes_cache is not None:
            return self._scope_resource_indexes_cache

        from gcpwn.modules.opengraph.utilities.stage_2_policy_bindings import (
            build_scope_and_resource_indexes,
        )

        simplified_base = self.simplified_hierarchy_permissions(include_inferred_permissions=False)
        self._scope_resource_indexes_cache = build_scope_and_resource_indexes(
            hierarchy_data=self.hierarchy_data(),
            flattened_member_rows=(simplified_base.get("flattened_member_rows") or []),
            cloudcompute_instances_rows=self.rows("cloudcompute_instances"),
            service_account_rows=self.rows("iam_service_accounts"),
        )
        return self._scope_resource_indexes_cache

    def counts(self) -> tuple[int, int]:
        return len(self.builder.node_map), len(self.builder.edge_map)

    def record_step(self, step_name: str, stats: dict[str, Any] | None = None) -> None:
        self.step_stats[str(step_name)] = dict(stats or {})

    def set_artifact(self, key: str, value: Any) -> None:
        self.artifacts[str(key)] = value

    def get_artifact(self, key: str, default: Any = None) -> Any:
        return self.artifacts.get(str(key), default)
