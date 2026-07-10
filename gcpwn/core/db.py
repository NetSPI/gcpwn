"""SQLite persistence layer for gcpwn (the DataController).

Owns ONE on-disk database, ``databases/gcpwn.db``, holding three logical groups
of tables in a single file so foreign keys can enforce integrity across them:

  * workspaces      -- one row per workspace (name, project list, config blob).
                       The parent table: everything else is keyed to it.
  * session / session_actions -- per-credential session rows + the
    permission/evidence trees.
  * per-service tables -- enumeration output (one table per service resource
    type, e.g. cloudstorage_buckets, opengraph_nodes/edges).

Every session/service table declares ``FOREIGN KEY (workspace_id) REFERENCES
workspaces(id) ON DELETE CASCADE`` (with ``PRAGMA foreign_keys=ON``), so deleting
a workspace atomically removes all of its data and orphan rows (a workspace_id
with no parent) can never be inserted. This is why the three groups share one
file -- SQLite foreign keys cannot span separate database files.

Threading invariant: a single DataController (and its SQLite connections) is
SHARED across the worker threads that fan out service enumeration. SQLite
connections are not safe to use concurrently, so connections are opened with
``check_same_thread=False`` and EVERY public DB method is wrapped with
``@_synchronized``, serializing all access through one process-wide re-entrant
lock. DB ops are microsecond-scale next to the GCP API calls the threads wait
on, so this serialization is effectively free. Module workers (parallel_map /
ThreadPoolExecutor) must still only do network/CPU work and RETURN results;
funnel writes back through ``session.insert_*`` on the main thread.

Workspace scoping: every service/action table carries a ``workspace_id``;
queries here filter on it so workspaces never see each other's data.

Permission model: permissions are stored as EVIDENCE with provenance, not
booleans. ``session_actions`` keeps per-scope/per-resource permission trees
plus a parallel provenance tree tagging each permission with how it was learned
(``direct_api`` vs ``test_iam_permissions``). See action_schema.py and the
``_merge_action_*`` / ``_build_provenance_tree`` helpers below.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sqlite3
import threading
import traceback
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.action_schema import (
    ACTION_COLUMNS,
    ACTION_EVIDENCE_DIRECT_API,
    ACTION_PROVENANCE_COLUMN,
    ACTION_SCOPE_COLUMNS,
    ACTION_SCOPE_KEYS,
)
from gcpwn.core.config import WorkspaceConfig
from gcpwn.core.utils.module_helpers import load_mapping_data


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    """Apply gcpwn's standard SQLite PRAGMAs (WAL, NORMAL sync, mem temp, busy timeout).

    WAL + a 5s busy_timeout let the shared connection tolerate brief contention;
    foreign_keys=ON enforces the few FK relationships. Run once per connection.
    """
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA temp_store=MEMORY;")
        cursor.execute("PRAGMA cache_size=-20000;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
    finally:
        cursor.close()


@lru_cache(maxsize=1)
def _load_service_tables() -> list[dict[str, Any]]:
    """All service-table specs (table_name/columns/primary_keys) from database_info.json.

    The file is a flat ``{"tables": [...]}`` document (one unified service DB); returns
    the table list, or [] when absent/malformed.
    """
    payload = load_mapping_data("database_info.json", kind="json") or {}
    tables = payload.get("tables")
    return list(tables) if isinstance(tables, list) else []


def _decode_json_blob(blob: Any, default: Any) -> Any:
    if blob is None:
        return default
    if isinstance(blob, (dict, list)):
        return blob
    text = str(blob).strip()
    if not text:
        return default
    return json.loads(text)


def _decode_python_list(blob: Any) -> list[str]:
    """Parse a stored ``repr(list)`` string back into a list of strings.

    Workspace project lists are persisted via _encode_python_list (a sorted
    repr), so decoding uses ast.literal_eval rather than JSON. Empty/blank -> [].
    """
    text = str(blob or "").strip()
    if not text:
        return []
    return list(ast.literal_eval(text))


def _encode_python_list(values: Iterable[str]) -> str:
    """Serialize an iterable to a sorted, de-duplicated ``repr(list)`` for storage.

    Round-trips with _decode_python_list. Sorting + dedup makes the stored blob
    stable regardless of insertion order; blank values are dropped.
    """
    return str(sorted({str(value) for value in values if str(value).strip()}))


def _synchronized(method):
    """Serialize a DataController method through the shared connection lock.

    gcpwn shares one DataController (and its SQLite connections) across the
    worker threads that fan out service enumeration. SQLite connections are not
    safe to use concurrently, so every public DB operation runs under a single
    re-entrant lock. DB ops are microsecond-scale next to the GCP API calls the
    threads are really waiting on, so this serialization is effectively free.
    """

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


def _resolve_state_dir() -> Path:
    """Writable base directory for gcpwn's SQLite databases.

    Resolution order:
      1. ``$GCPWN_HOME`` if set (explicit override).
      2. A source checkout — the repo root (three parents up) that contains
         ``pyproject.toml`` and is writable — so a dev checkout keeps its
         gitignored ``databases/`` in place (unchanged behavior).
      3. Otherwise ``~/.gcpwn`` — the pip-installed case (``__file__`` under a
         read-only ``site-packages``) and the PyInstaller onefile case
         (``__file__`` under an ephemeral, read-only ``_MEIPASS`` temp dir),
         where writing next to the package would fail or be lost.
    """
    env = os.environ.get("GCPWN_HOME")
    if env:
        return Path(env).expanduser()
    repo_root = Path(__file__).resolve().parents[2]
    if (repo_root / "pyproject.toml").is_file() and os.access(repo_root, os.W_OK):
        return repo_root
    return Path.home() / ".gcpwn"


class DataController:
    """Single owner of gcpwn's unified SQLite database and all of its SQL.

    Instances share the class-level ``database_path`` and a single class-level
    re-entrant ``_lock``; every public method is ``@_synchronized`` so the shared
    ``self.conn`` (opened ``check_same_thread=False``) stays safe across
    enumeration worker threads. Despite that, this layer is effectively
    single-threaded for writes -- callers must not invoke get_data/insert_*
    from inside a ThreadPoolExecutor worker; collect results and write on the
    main thread (concurrent cursor use still corrupts state even under the lock
    for in-flight statements).

    Connection lifecycle: __init__ opens ONE connection (``self.conn`` /
    ``self.cursor``) to the unified file and eagerly builds the service schema
    (create_service_databases, cheap when the PRAGMA user_version fingerprint
    already matches).

    _SERVICE_INDEXES declares the (workspace_id, ...) covering indexes created
    for hot service tables; it also feeds the schema fingerprint so adding an
    index bumps the version and triggers a re-create pass.
    """

    # One physical SQLite file for everything (FK cascade needs one file). A single
    # process-wide lock keeps the shared connection safe across enumeration worker
    # threads; check_same_thread=False is set on connect.
    _lock = threading.RLock()
    _state_dir = _resolve_state_dir()
    database_path = str(_state_dir / "databases" / "gcpwn.db")
    _ACTION_PROVENANCE_COLUMN = ACTION_PROVENANCE_COLUMN
    _ACTION_SCOPE_KEYS = ACTION_SCOPE_KEYS
    _ACTION_SCOPE_COLUMNS = ACTION_SCOPE_COLUMNS
    # Control-plane tables that share the unified file but are NOT service data:
    # the service-wipe path must skip them so it can't delete creds/evidence.
    _CONTROL_PLANE_TABLES = frozenset({"workspaces", "session", "session_actions"})
    _SERVICE_INDEXES = {
        "abstract_tree_hierarchy": [
            ("ix_tree_workspace_name", ("workspace_id", "name")),
            ("ix_tree_workspace_parent", ("workspace_id", "parent")),
            ("ix_tree_workspace_type", ("workspace_id", "type")),
        ],
        "iam_allow_policies": [
            ("ix_allow_policies_workspace_type", ("workspace_id", "resource_type")),
            ("ix_allow_policies_workspace_name", ("workspace_id", "resource_name")),
            ("ix_allow_policies_workspace_project", ("workspace_id", "project_id")),
        ],
        "iam_service_accounts": [
            ("ix_principals_workspace_email", ("workspace_id", "email")),
            ("ix_principals_workspace_type", ("workspace_id", "type")),
        ],
        "cloudstorage_buckets": [
            ("ix_buckets_workspace_name", ("workspace_id", "name")),
            ("ix_buckets_workspace_project", ("workspace_id", "project_id")),
        ],
        "cloudfunctions_functions": [
            ("ix_functions_workspace_name", ("workspace_id", "name")),
            ("ix_functions_workspace_project", ("workspace_id", "project_id")),
        ],
        "unauth_apikey_permissions": [
            ("ix_unauth_apikey_permissions_workspace_key", ("workspace_id", "key_fingerprint")),
            ("ix_unauth_apikey_permissions_workspace_status", ("workspace_id", "status")),
        ],
        "unauth_apikey_gemini_models": [
            ("ix_unauth_apikey_gemini_models_workspace_key", ("workspace_id", "key_fingerprint")),
            ("ix_unauth_apikey_gemini_models_workspace_model", ("workspace_id", "model")),
        ],
        "unauth_apikey_vertex_models": [
            ("ix_unauth_apikey_vertex_models_workspace_key", ("workspace_id", "key_fingerprint")),
            ("ix_unauth_apikey_vertex_models_workspace_model", ("workspace_id", "model")),
        ],
        "cloudcompute_instances": [
            ("ix_instances_workspace_name", ("workspace_id", "name")),
            ("ix_instances_workspace_project", ("workspace_id", "project_id")),
        ],
        "secretsmanager_secrets": [
            ("ix_secrets_workspace_name", ("workspace_id", "name")),
            ("ix_secrets_workspace_project", ("workspace_id", "project_id")),
        ],
        "opengraph_nodes": [
            ("ix_opengraph_nodes_workspace_node", ("workspace_id", "node_id")),
            ("ix_opengraph_nodes_workspace_type", ("workspace_id", "node_type")),
        ],
        "opengraph_edges": [
            ("ix_opengraph_edges_workspace_source", ("workspace_id", "source_id")),
            ("ix_opengraph_edges_workspace_dest", ("workspace_id", "destination_id")),
            ("ix_opengraph_edges_workspace_type", ("workspace_id", "edge_type")),
        ],
        "opengraph_ui_config": [
            ("ix_opengraph_ui_config_workspace_token_id", ("workspace_id", "custom_nodes_token_id")),
        ],
    }

    def __init__(self):
        os.makedirs(self._state_dir / "databases", exist_ok=True)

        # One connection to the unified file, used by every table group.
        self.conn = self._connect_database(self.database_path)
        self.cursor = self.conn.cursor()
        self._service_primary_key_cache: dict[str, list[str]] = {}

        # Build the service schema up front (cheap no-op when the fingerprint matches);
        # the connection is already non-None, so nothing else would trigger it.
        self.create_service_databases()

    def _connect_database(self, path: str) -> sqlite3.Connection:
        return self._connect_database_for_path(path)

    def _ensure_service_database(self) -> None:
        """Ensure the service schema exists; raise if the connection is unusable.

        __init__ builds the schema eagerly, so this is normally a fast guard. Tests
        that construct via ``__new__`` set ``self.conn`` themselves; if it is
        missing we build the schema once.
        """
        if self.conn is None or self.cursor is None:
            self.create_service_databases()
        if self.conn is None or self.cursor is None:
            raise RuntimeError("Service database has not been initialized.")

    def _run(
        self,
        cursor: sqlite3.Cursor,
        query: str,
        params: Iterable[Any] = (),
        *,
        fetch: str | None = None,
    ) -> sqlite3.Cursor | sqlite3.Row | list[sqlite3.Row] | Any:
        """Execute parameterized SQL on a cursor and shape the result by ``fetch``.

        Always binds ``params`` as a tuple (use ? placeholders -- prefer this over
        f-string interpolation of caller data). fetch: "one"/"all"/"scalar" return
        the row / rows / first column of first row; None returns the live cursor.
        """
        cursor.execute(query, tuple(params))
        if fetch == "one":
            return cursor.fetchone()
        if fetch == "all":
            return cursor.fetchall()
        if fetch == "scalar":
            row = cursor.fetchone()
            return None if row is None else row[0]
        return cursor

    def _select_rows(
        self,
        cursor: sqlite3.Cursor,
        table_name: str,
        *,
        conditions: str | None,
        columns: str | list[str] = "*",
        params: Iterable[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Run a SELECT and return rows as plain dicts; swallow SQLite errors -> [].

        ``conditions`` is a raw WHERE string (sans WHERE) with ? placeholders
        bound from ``params`` -- callers must not interpolate untrusted values
        into it. Returns [] (not None) on any sqlite3.Error so callers can iterate.
        """
        try:
            sql_query = f'SELECT {self._columns_clause(columns)} FROM "{table_name}"'
            if conditions:
                sql_query += " WHERE " + conditions
            return [dict(row) for row in self._run(cursor, sql_query, params or (), fetch="all")]
        except sqlite3.Error as exc:
            print("SQLite error:", exc)
            return []

    def _where_clause(self, columns: Iterable[str]) -> str:
        return " AND ".join(f'"{column}" = ?' for column in columns)

    def _columns_clause(self, columns: str | Iterable[str]) -> str:
        """Build a quoted SELECT column list ("*", one quoted name, or a comma-joined set)."""
        if columns == "*":
            return "*"
        if isinstance(columns, str):
            return f'"{columns}"'
        return ", ".join(f'"{column}"' for column in columns)

    def _select_one(
        self,
        cursor: sqlite3.Cursor,
        table_name: str,
        where: dict[str, Any],
        columns: str | Iterable[str] = "*",
    ) -> sqlite3.Row | None:
        query = f'SELECT {self._columns_clause(columns)} FROM "{table_name}" WHERE {self._where_clause(where.keys())}'
        return self._run(cursor, query, where.values(), fetch="one")

    def _update_table(
        self,
        conn: sqlite3.Connection,
        cursor: sqlite3.Cursor,
        table_name: str,
        updates: dict[str, Any],
        where: dict[str, Any],
    ) -> None:
        assignments = ", ".join(f'"{column}" = ?' for column in updates)
        where_clause = self._where_clause(where.keys())
        params = [*updates.values(), *where.values()]
        self._run(cursor, f'UPDATE "{table_name}" SET {assignments} WHERE {where_clause}', params)
        conn.commit()

    def _insert_row(
        self,
        cursor: sqlite3.Cursor,
        table_name: str,
        payload: dict[str, Any],
        *,
        replace: bool = False,
    ) -> None:
        columns = list(payload.keys())
        quoted_columns = ", ".join(f'"{column}"' for column in columns)
        placeholders = ", ".join("?" for _ in columns)
        insert_mode = "INSERT OR REPLACE" if replace else "INSERT"
        self._run(
            cursor,
            f'{insert_mode} INTO "{table_name}" ({quoted_columns}) VALUES ({placeholders})',
            [payload[column] for column in columns],
        )

    def _create_service_table(
        self,
        cursor: sqlite3.Cursor,
        table_name: str,
        columns: list[str],
        primary_key_columns: list[str],
    ) -> None:
        columns_definition = ", ".join(f'"{column}" TEXT NULL' for column in columns)
        primary_keys_definition = ", ".join(f'"{column}"' for column in primary_key_columns)
        # Every service row belongs to a workspace: the FK cascades deletes from the
        # parent and blocks orphan rows (a workspace_id with no workspaces parent).
        self._run(
            cursor,
            f'''
            CREATE TABLE IF NOT EXISTS "{table_name}" (
                {columns_definition},
                PRIMARY KEY ({primary_keys_definition}),
                FOREIGN KEY ("workspace_id") REFERENCES "workspaces" ("id") ON DELETE CASCADE
            )
            ''',
        )

    def _ensure_workspace_scope_index(
        self, cursor: sqlite3.Cursor, table_name: str, original_primary_keys: list[str]
    ) -> None:
        """Create the baseline ``(workspace_id, <pk...>)`` index every service table needs.

        Every service read is workspace-scoped -- session.get_data forces
        workspace_id into the WHERE -- but workspace_id is appended LAST in each
        composite PK, so the implicit PK index can't seek on it and reads fall back
        to a full table SCAN. This mirrors the PK with workspace_id FIRST, turning
        those scans into index seeks across all 170+ tables with no table rebuild
        (pure additive index). The hand-tuned _SERVICE_INDEXES adds extra covering
        indexes on hot NON-prefix columns (e.g. name/type) on top of this.
        """
        scope_columns = ["workspace_id", *original_primary_keys]
        joined_columns = ", ".join(f'"{column}"' for column in scope_columns)
        self._run(
            cursor,
            f'CREATE INDEX IF NOT EXISTS "ix_ws__{table_name}" ON "{table_name}" ({joined_columns})',
        )

    def _ensure_service_indexes(self, cursor: sqlite3.Cursor) -> None:
        for table_name, index_specs in self._SERVICE_INDEXES.items():
            for index_name, columns in index_specs:
                joined_columns = ", ".join(f'"{column}"' for column in columns)
                self._run(
                    cursor,
                    f'CREATE INDEX IF NOT EXISTS "{index_name}" ON "{table_name}" ({joined_columns})',
                )

    def _ensure_service_table_columns(
        self,
        cursor: sqlite3.Cursor,
        table_name: str,
        expected_columns: Iterable[str],
    ) -> None:
        existing_rows = self._run(cursor, f'PRAGMA table_info("{table_name}")', fetch="all") or []
        existing_columns = {
            str(row[1]).strip()
            for row in existing_rows
            if row and len(row) > 1 and str(row[1]).strip()
        }
        for column in expected_columns:
            normalized = str(column or "").strip()
            if not normalized or normalized in existing_columns:
                continue
            self._run(cursor, f'ALTER TABLE "{table_name}" ADD COLUMN "{normalized}" TEXT')
            existing_columns.add(normalized)

    def _service_primary_keys(self, table_name: str) -> list[str]:
        self._ensure_service_database()
        if table_name not in self._service_primary_key_cache:
            columns = self._run(self.cursor, f'PRAGMA table_info("{table_name}")', fetch="all")
            self._service_primary_key_cache[table_name] = [column[1] for column in columns if column[5]]
        return self._service_primary_key_cache[table_name]

    def _upsert_service_row(
        self,
        table_name: str,
        payload: dict[str, Any],
        *,
        dont_change: Iterable[str] = (),
    ) -> None:
        """Insert-or-update a service row keyed on its declared PRIMARY KEY columns.

        Uses INSERT ... ON CONFLICT(pk) DO UPDATE, refreshing all non-PK columns
        from the incoming row EXCEPT those in ``dont_change`` (preserved across
        re-enumeration, e.g. first-seen / manually-set fields). Tables with no
        primary key fall back to a plain INSERT.
        """
        self._ensure_service_database()
        columns = list(payload.keys())
        quoted_columns = ", ".join(f'"{column}"' for column in columns)
        placeholders = ", ".join("?" for _ in columns)
        primary_keys = self._service_primary_keys(table_name)

        if not primary_keys:
            self._insert_row(self.cursor, table_name, payload)
            return

        immutable_columns = set(dont_change)
        update_columns = [
            column for column in columns
            if column not in immutable_columns and column not in primary_keys
        ]
        conflict_clause = "DO NOTHING"
        if update_columns:
            assignments = ", ".join(f'"{column}" = excluded."{column}"' for column in update_columns)
            conflict_clause = f"DO UPDATE SET {assignments}"

        quoted_primary_keys = ", ".join(f'"{column}"' for column in primary_keys)
        self._run(
            self.cursor,
            f'''
            INSERT INTO "{table_name}" ({quoted_columns})
            VALUES ({placeholders})
            ON CONFLICT ({quoted_primary_keys}) {conflict_clause}
            ''',
            [payload[column] for column in columns],
        )

    def _decode_action_row(self, row: sqlite3.Row, *, include_provenance: bool = False) -> dict[str, Any]:
        """Decode a session_actions row's JSON-blob columns into nested dicts.

        Each ACTION_COLUMNS column is a JSON blob holding a permission tree;
        missing/empty blobs decode to {}. With include_provenance, also decodes
        the parallel provenance column (permission -> [evidence_type] tags).
        """
        payload = {"credname": row["credname"]}
        for column_name in ACTION_COLUMNS:
            payload[column_name] = _decode_json_blob(row[column_name], {})
        if include_provenance:
            payload[self._ACTION_PROVENANCE_COLUMN] = _decode_json_blob(
                row[self._ACTION_PROVENANCE_COLUMN],
                {},
            )
        return payload

    def _merge_permission_tree(
        self,
        current_permissions: dict[str, Any],
        new_permissions: dict[str, Any],
        *,
        leaf_depth: int,
    ) -> tuple[dict[str, Any], bool]:
        """Recursively union two nested permission trees, reporting whether it changed.

        Walks ``leaf_depth`` levels of nested dicts; at depth 1 the values are
        lists of permission strings that get set-unioned and sorted. Returns
        (merged_tree, changed) where ``changed`` is True iff the merge added
        anything to ``current_permissions`` -- callers skip the DB write when
        nothing changed, so the flag is load-bearing, not cosmetic.

        Shape contract: resource permission trees are 3-deep
        (project_id -> resource_type -> resource_name -> [permissions], i.e.
        leaf_depth=3), while per-scope columns are 1-deep (scope -> [permissions]).
        Provenance trees are merged at leaf_depth=2 (column -> scope -> permission).
        """
        current_permissions = current_permissions or {}
        new_permissions = new_permissions or {}
        changed = False
        merged: dict[str, Any] = {}

        for name in set(current_permissions) | set(new_permissions):
            current_value = current_permissions.get(name)
            new_value = new_permissions.get(name)

            if leaf_depth == 1:
                merged_values = sorted(set(current_value or []) | set(new_value or []))
                merged[name] = merged_values
                if merged_values != sorted(set(current_value or [])):
                    changed = True
                continue

            merged_value, child_changed = self._merge_permission_tree(
                current_value if isinstance(current_value, dict) else {},
                new_value if isinstance(new_value, dict) else {},
                leaf_depth=leaf_depth - 1,
            )
            merged[name] = merged_value
            changed = changed or child_changed

        return merged, changed

    @staticmethod
    def _row_value(row: sqlite3.Row | None, target_column: str):
        """A stored column's value, or None if the row is empty/missing the column."""
        if not row:
            return None
        try:
            return row[target_column]
        except Exception:
            return None

    def _merge_action_updates(
        self,
        current_row: sqlite3.Row | None,
        permission_record: dict[str, Any],
        column_name: str | None,
    ) -> dict[str, Any]:
        """Compute the per-column permission-tree updates for one insert_actions call.

        For each (scope/resource) spec from _iter_action_specs, merges the
        incoming permissions into the current column blob and records the result
        only if it changed. Returns {target_column: merged_tree} for the columns
        that actually grew -- columns absent from the dict are left untouched.
        """
        updates: dict[str, Any] = {}
        for _permission_key, target_column, leaf_depth, incoming_permissions in self._iter_action_specs(
            permission_record,
            column_name,
        ):
            merged_permissions, changed = self._merge_permission_tree(
                _decode_json_blob(self._row_value(current_row, target_column), {}),
                incoming_permissions,
                leaf_depth=leaf_depth,
            )
            if changed:
                updates[target_column] = merged_permissions
        return updates

    def _build_provenance_tree(
        self,
        incoming_permissions: dict[str, Any],
        *,
        leaf_depth: int,
        evidence_type: str,
    ) -> dict[str, dict[str, list[str]]]:
        """Flatten an incoming permission tree into a scope -> {permission: [evidence]} map.

        Collects the permission names visible at this spec's depth (list leaves at
        leaf_depth==1, dict keys otherwise) and tags each with ``evidence_type``
        (e.g. direct_api vs test_iam_permissions). This is the provenance record
        that _merge_action_provenance later unions in, so permissions are tracked
        as evidence with a source rather than as booleans.
        """
        if not isinstance(incoming_permissions, dict):
            return {}

        provenance_tree: dict[str, dict[str, list[str]]] = {}
        for scope_name, scope_permissions in incoming_permissions.items():
            if leaf_depth == 1:
                permission_names = sorted(
                    {
                        str(permission).strip()
                        for permission in (scope_permissions or [])
                        if str(permission).strip()
                    }
                )
            else:
                permission_names = sorted(
                    {
                        str(permission_name).strip()
                        for permission_name in (
                            scope_permissions.keys() if isinstance(scope_permissions, dict) else []
                        )
                        if str(permission_name).strip()
                    }
                )
            if permission_names:
                provenance_tree[str(scope_name)] = {
                    permission_name: [evidence_type] for permission_name in permission_names
                }
        return provenance_tree

    def _iter_action_specs(
        self,
        permission_record: dict[str, Any],
        column_name: str | None,
    ) -> list[tuple[str | None, str, int, dict[str, Any]]]:
        """Decompose a permission_record into (key, column, leaf_depth, subtree) specs.

        Yields one spec per scope column (leaf_depth=1, e.g. org/folder/project
        scope permissions pulled from the record by scope key) plus, when a
        ``column_name`` is given, one spec for the resource-level column holding
        everything that is NOT a scope key (leaf_depth=3:
        project -> resource_type -> resource_name -> [permissions]). The leaf_depth
        per spec is what drives the recursion depth in the merge/provenance helpers.
        """
        specs = [
            (scope_key, scope_column, 1, permission_record.get(scope_key, {}))
            for scope_key, scope_column in self._ACTION_SCOPE_COLUMNS
        ]
        if column_name:
            resource_permissions = {
                key: value for key, value in permission_record.items() if key not in self._ACTION_SCOPE_KEYS
            }
            specs.append((None, column_name, 3, resource_permissions))
        return specs

    def _merge_action_provenance(
        self,
        current_row: sqlite3.Row | None,
        permission_record: dict[str, Any],
        column_name: str | None,
        *,
        evidence_type: str,
    ) -> tuple[dict[str, Any], bool]:
        """Merge new evidence tags into the credential's provenance tree.

        Builds an incoming provenance tree per spec (tagged with ``evidence_type``)
        and unions it into the stored provenance under each target column, keyed
        column -> scope -> permission -> [evidence_types]. Returns
        (merged_provenance, changed); ``changed`` gates the DB write in
        insert_actions so re-seeing the same evidence is a no-op.
        """
        current_provenance = _decode_json_blob(
            self._row_value(current_row, self._ACTION_PROVENANCE_COLUMN),
            {},
        )
        if not isinstance(current_provenance, dict):
            current_provenance = {}

        merged_provenance = dict(current_provenance)
        changed = False
        for _permission_key, target_column, leaf_depth, incoming_permissions in self._iter_action_specs(
            permission_record,
            column_name,
        ):
            incoming_provenance = self._build_provenance_tree(
                incoming_permissions,
                leaf_depth=leaf_depth,
                evidence_type=evidence_type,
            )
            if not incoming_provenance:
                continue
            merged_column, column_changed = self._merge_permission_tree(
                current_provenance.get(target_column, {}) if isinstance(current_provenance.get(target_column, {}), dict) else {},
                incoming_provenance,
                leaf_depth=2,
            )
            if column_changed:
                merged_provenance[target_column] = merged_column
                changed = True

        return merged_provenance, changed

    def _ensure_session_actions_row(self, workspace_id: int, credname: str) -> None:
        self._run(
            self.cursor,
            'INSERT OR IGNORE INTO "session_actions" (workspace_id, credname) VALUES (?, ?)',
            (workspace_id, credname),
        )

    def close(self) -> None:
        # One shared connection for the whole file; close cursor then connection.
        for handle in (getattr(self, "cursor", None), getattr(self, "conn", None)):
            if handle is None:
                continue
            try:
                handle.close()
            except Exception:
                pass

    def __enter__(self) -> "DataController":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @classmethod
    def create_initial_workspace_session_database(cls) -> int | None:
        """Create (or migrate) the workspaces and sessions databases idempotently.

        Run at startup before any DataController instance is used. Besides the
        base tables it performs a lightweight migration: any newly-added
        ACTION_COLUMNS / provenance column missing from an existing
        session_actions table are ALTERed in (existing rows get NULLs). Returns 1
        on success, None on failure (prints the error -- does not raise).
        """
        try:
            cls._state_dir.joinpath("databases").mkdir(parents=True, exist_ok=True)

            # workspaces (parent) + session/session_actions live in the one unified
            # file so their FKs can reference it. Create the parent first.
            with sqlite3.connect(cls.database_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS workspaces
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, global_project_list TEXT, data TEXT, workspace_config TEXT)
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS session
                    (workspace_id INTEGER, credname TEXT, credtype TEXT, email TEXT, default_project TEXT, scopes TEXT, session_creds TEXT,
                     PRIMARY KEY (workspace_id, credname),
                     FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE)
                    """
                )
                resource_columns = ", ".join(f"{column_name} TEXT" for column_name in ACTION_COLUMNS)
                conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS session_actions
                    (
                        workspace_id INTEGER, credname TEXT,
                        {resource_columns},
                        {ACTION_PROVENANCE_COLUMN} TEXT,
                        PRIMARY KEY (workspace_id, credname),
                        FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
                    )
                    """
                )
                # Lightweight schema migration: add any new ACTION_COLUMNS to existing session_actions table.
                existing = {
                    row[1]
                    for row in conn.execute('PRAGMA table_info("session_actions")').fetchall()
                }
                expected = {"workspace_id", "credname", *ACTION_COLUMNS, ACTION_PROVENANCE_COLUMN}
                missing = sorted(expected - existing)
                for column in missing:
                    if column in {"workspace_id", "credname"}:
                        continue
                    conn.execute(f'ALTER TABLE "session_actions" ADD COLUMN "{column}" TEXT')
                conn.commit()
            return 1
        except Exception as exc:
            print("[X] Failed in create_initial_workspace_session_database for following error")
            print(str(exc))
            return None

    @_synchronized
    def get_workspace(
        self,
        workspace_id: int,
        *,
        columns: str | list[str] = "*",
    ) -> dict[str, Any] | list[Any] | Any | None:
        try:
            row = self._select_one(self.cursor, "workspaces", {"id": workspace_id}, columns)
            if row is None:
                return None
            if columns == "*":
                return dict(row)
            if isinstance(columns, str):
                return row[0]
            return dict(row)
        except Exception as exc:
            print("[X] Failed in get_workspace for following error")
            print(str(exc))
            return None

    @_synchronized
    def update_workspace(self, workspace_id: int, updates: dict[str, Any]) -> bool:
        try:
            if not updates:
                return False
            self._update_table(
                self.conn,
                self.cursor,
                "workspaces",
                updates,
                {"id": workspace_id},
            )
            return True
        except Exception as exc:
            print("[X] Failed in update_workspace for the following error")
            print(str(exc))
            return False

    @_synchronized
    def insert_workspace(self, name: str) -> int | None:
        try:
            workspace_config = WorkspaceConfig()
            self._run(
                self.cursor,
                "INSERT INTO workspaces (name, workspace_config) VALUES (?, ?)",
                (name, workspace_config.to_json_string()),
            )
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as exc:
            print("[X] Failed to insert workspace due to database error")
            print(str(exc))
            return None
        except Exception as exc:
            print("[X] Failed to insert workspace due to an unexpected error")
            print(str(exc))
            return None

    @_synchronized
    def fetch_all_workspace_names(self) -> list[str] | None:
        try:
            rows = self._run(self.cursor, "SELECT name FROM workspaces", fetch="all")
            return [row[0] for row in rows]
        except Exception as exc:
            print("[X] Failed in fetch_all_workspaces for following error")
            print(str(exc))
            return None

    @_synchronized
    def get_workspaces(self) -> list[sqlite3.Row]:
        if not Path(self.database_path).exists():
            return []
        return self._run(self.cursor, "SELECT id, name FROM workspaces", fetch="all")

    @_synchronized
    def delete_workspace(self, workspace_id: int) -> int:
        """Delete a workspace and, via ON DELETE CASCADE, all of its data.

        Because session/session_actions and every service table declare a
        ``workspaces(id)`` FK with ON DELETE CASCADE (and foreign_keys=ON), a single
        DELETE here atomically removes the workspace's credentials, action evidence,
        and all enumerated service/opengraph rows -- no orphans, no manual per-table
        cleanup. Returns the number of workspace rows deleted (0 or 1).
        """
        self._ensure_service_database()
        self._run(self.cursor, "DELETE FROM workspaces WHERE id = ?", (int(workspace_id),))
        deleted = self.cursor.rowcount if isinstance(self.cursor.rowcount, int) and self.cursor.rowcount > 0 else 0
        self.conn.commit()
        return deleted

    @_synchronized
    def sync_workspace_projects(
        self,
        workspace_id: int,
        *,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> list[str] | None:
        """Add/remove projects in a workspace's global project list, return the new sorted set.

        Reads the stored repr-encoded list, applies ``add``/``remove`` as set ops,
        and writes it back. Returns the resulting sorted list, or None on failure.
        """
        try:
            project_blob = self.get_workspace(workspace_id, columns="global_project_list")
            current_projects = set(_decode_python_list(project_blob) if project_blob else [])
            if add:
                current_projects.update(add)
            if remove:
                current_projects.difference_update(remove)
            if not self.update_workspace(
                workspace_id,
                {"global_project_list": _encode_python_list(current_projects)},
            ):
                return None
            return sorted(current_projects)
        except Exception as exc:
            print("[X] Failed in sync_workspace_projects for following error")
            print(str(exc))
            return None

    @_synchronized
    def get_credential(self, workspace_id: int, credname: str) -> dict[str, Any] | None:
        try:
            row = self._select_one(
                self.cursor,
                "session",
                {"workspace_id": workspace_id, "credname": credname},
            )
            return dict(row) if row else None
        except Exception as exc:
            print("[X] Failed in get_credential for following error")
            print(str(exc))
            return None

    @_synchronized
    def insert_creds(
        self,
        workspace_id: int,
        credname: str,
        credtype: str,
        default_project: str,
        session_creds: str,
        email: str | None = None,
        scopes: str | None = None,
    ) -> int | None:
        """Insert-or-replace a credential row, also registering its default project.

        ``email``/``scopes`` are only added to the payload when provided. Note this
        uses INSERT OR REPLACE on the (workspace_id, credname) PK, so it rewrites
        the whole row -- columns not in the payload revert to their defaults.
        Registers default_project into the workspace project list as a side
        effect. Returns 1 / None.
        """
        try:
            if default_project:
                self.sync_workspace_projects(workspace_id, add=[default_project])

            payload: dict[str, Any] = {
                "workspace_id": workspace_id,
                "credname": credname,
                "credtype": credtype,
                "default_project": default_project,
                "session_creds": session_creds,
            }
            if email is not None:
                payload["email"] = email
            if scopes is not None:
                payload["scopes"] = scopes
            self._insert_row(self.cursor, "session", payload, replace=True)
            self.conn.commit()
            return 1
        except Exception as exc:
            print("[X] Failed in insert_creds for following error")
            print(str(exc))
            return None

    @_synchronized
    def update_credential(
        self,
        workspace_id: int,
        credname: str,
        updates: dict[str, Any],
    ) -> int | None:
        try:
            if not updates:
                return None

            self._update_table(
                self.conn,
                self.cursor,
                "session",
                updates,
                {"workspace_id": workspace_id, "credname": credname},
            )
            return 1
        except sqlite3.Error as exc:
            print(f"Error updating credentials: {exc}")
            return None
        except Exception as exc:
            print("[X] Failed in update_credential for following error")
            print(str(exc))
            return None

    @_synchronized
    def list_creds(self, workspace_id: int) -> list[sqlite3.Row] | None:
        try:
            return self._run(
                self.cursor,
                "SELECT credname, credtype, email FROM session WHERE workspace_id = ?",
                (workspace_id,),
                fetch="all",
            )
        except Exception as exc:
            print("[X] Failed in list_creds for following error")
            print(str(exc))
            return None

    @_synchronized
    def delete_service_rows(self, table_name: str, *, where: dict[str, Any]) -> int:
        """Delete service rows matching ``where`` (a {column: value} dict, bound as
        parameters). Callers must include workspace_id in ``where`` to stay
        workspace-scoped (session.delete_data does this). Returns rows deleted; 0 on
        empty ``where`` or SQLite error (never raises)."""
        if not where:
            return 0
        self._ensure_service_database()
        clause = self._where_clause(where.keys())
        try:
            self._run(self.cursor, f'DELETE FROM "{table_name}" WHERE {clause}', list(where.values()))
            deleted = self.cursor.rowcount if isinstance(self.cursor.rowcount, int) and self.cursor.rowcount > 0 else 0
            self.conn.commit()
            return deleted
        except sqlite3.Error as exc:
            print("SQLite error:", exc)
            return 0

    @_synchronized
    def select_rows(
        self,
        table_name: str,
        *,
        db: str = "service",
        conditions: str | None = None,
        columns: str | list[str] = "*",
        params: Iterable[Any] | None = None,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Public SELECT helper -- pick a database by ``db`` and return rows as dicts.

        ``db`` is one of "service" (default), "workspace", "session" -- validated
        for API compatibility but all resolve to the one shared connection. ``where``
        is the SAFE path: a {column: value} dict bound as parameters and AND-ed onto any raw
        ``conditions`` string. Prefer ``where`` (and remember service tables are
        workspace-scoped -- pass workspace_id) over interpolating into conditions.
        """
        target = str(db or "service").strip().lower()
        if target not in ("workspace", "session", "service"):
            raise ValueError(f"Unknown database selector: {db}")
        # All groups live in one file now; the selector is validated for API
        # compatibility but every target uses the single shared cursor.
        self._ensure_service_database()
        cursor = self.cursor

        query_conditions = conditions
        query_params = list(params or ())
        if where:
            scoped_condition = self._where_clause(where.keys())
            query_conditions = f"{query_conditions} AND {scoped_condition}" if query_conditions else scoped_condition
            query_params.extend(where.values())

        return self._select_rows(
            cursor,
            table_name,
            conditions=query_conditions,
            columns=columns,
            params=query_params,
        )

    @_synchronized
    def execute_sql(
        self,
        query: str,
        *,
        db: str = "service",
        fetch_limit: int = 200,
    ) -> dict[str, Any]:
        """Run a raw SQL string against the chosen DB (interactive/REPL escape hatch).

        ``db`` is kept as a response label ("metadata" maps to "session"); all
        targets share the one connection. Read queries
        (select/pragma/with) are capped at ``fetch_limit`` rows and returned under
        "rows"; writes are committed and report "rows_affected". This executes
        UNPARAMETERIZED user SQL by design (REPL power-user feature) -- do not use
        it as a programmatic query path for untrusted input. Returns a result dict.
        """
        sql = str(query or "").strip()
        if not sql:
            raise ValueError("Missing SQL query.")

        target = str(db or "service").strip().lower()
        if target == "metadata":
            target = "session"
        if target not in ("workspace", "session", "service"):
            raise ValueError(f"Unknown database selector: {db}")

        # All three groups now live in one file; the selector only labels the
        # response. _ensure_service_database keeps __new__-constructed instances safe.
        self._ensure_service_database()
        conn = self.conn
        cursor = self.cursor
        db_path = self.database_path

        query_prefix = sql.lstrip().lower()
        is_read_query = query_prefix.startswith(("select", "pragma", "with"))

        cursor.execute(sql)
        if is_read_query:
            rows = [dict(row) for row in cursor.fetchmany(max(1, int(fetch_limit or 200)))]
            return {
                "db": target,
                "db_path": db_path,
                "read_query": True,
                "rows": rows,
                "rows_affected": None,
            }

        conn.commit()
        return {
            "db": target,
            "db_path": db_path,
            "read_query": False,
            "rows": [],
            "rows_affected": cursor.rowcount,
        }

    @staticmethod
    def _connect_database_for_path(path: str | Path) -> sqlite3.Connection:
        # check_same_thread=False: connections are shared across enumeration worker
        # threads; concurrent access is serialized by _synchronized.
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _apply_pragmas(conn)
        return conn

    @classmethod
    def iter_sqlite_tables_from_paths(
        cls,
        db_paths: Iterable[str],
    ) -> Iterable[tuple[dict[str, Any], list[dict[str, Any]]]]:
        """Yield (table-metadata, rows) for every user table across arbitrary SQLite files.

        Opens each existing path read-only-ish on its own short-lived connection
        (independent of this instance's connections), skips sqlite_* internal
        tables AND the control-plane tables (workspaces/session/session_actions --
        the session table holds serialized credentials, which must never land in a
        data export), and emits all rows per table. Used to dump/export DBs
        generically; non-existent paths are silently skipped.
        """
        for raw_path in db_paths or ():
            db_path = Path(str(raw_path or "")).expanduser()
            if not db_path.exists():
                continue

            conn = cls._connect_database_for_path(db_path)
            cursor = conn.cursor()
            try:
                tables = cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
                for row in tables:
                    table_name = str(row["name"])
                    if table_name in cls._CONTROL_PLANE_TABLES:
                        continue
                    columns = [
                        str(info["name"])
                        for info in cursor.execute(f'PRAGMA table_info("{table_name}")').fetchall()
                    ]
                    records = [dict(item) for item in cursor.execute(f'SELECT * FROM "{table_name}"').fetchall()]
                    yield (
                        {
                            "db_name": db_path.stem,
                            "db_path": str(db_path),
                            "table_name": table_name,
                            "columns": columns,
                        },
                        records,
                    )
            finally:
                cursor.close()
                conn.close()

    @_synchronized
    def get_actions(
        self,
        workspace_id: int,
        credname: str | None = None,
        *,
        include_provenance: bool = False,
    ) -> list[dict[str, Any]]:
        """Fetch decoded permission trees for a workspace's credentials.

        Returns one dict per session_actions row (optionally filtered to a single
        ``credname``), each with JSON blobs decoded into nested permission dicts;
        include_provenance adds the evidence-tag tree. Returns [] on error.
        """
        try:
            action_columns = ", ".join(f'"{column_name}"' for column_name in ACTION_COLUMNS)
            extra_columns = f', "{self._ACTION_PROVENANCE_COLUMN}"' if include_provenance else ""
            query = f'SELECT credname, {action_columns}{extra_columns} FROM session_actions WHERE workspace_id = ?'
            params: list[Any] = [workspace_id]
            if credname:
                query += " AND credname = ?"
                params.append(credname)
            return [
                self._decode_action_row(row, include_provenance=include_provenance)
                for row in self._run(self.cursor, query, params, fetch="all")
            ]
        except Exception as exc:
            print("Error:", exc)
            return []

    def _service_schema_version(self, database_info: dict[str, Any]) -> int:
        """Stable 28-bit schema fingerprint for a service DB spec.

        Hashes the table definitions plus the shared index specs so any schema
        change bumps the version (fits PRAGMA user_version's signed 32-bit range).
        """
        blob = json.dumps(
            {
                "tables": database_info.get("tables", []),
                "indexes": self._SERVICE_INDEXES,
                # Bump when the auto-generated index scheme below changes so existing
                # on-disk DBs re-run the (additive) index pass.
                "auto_ws_index": 1,
            },
            sort_keys=True,
            ensure_ascii=False,
            default=list,
        )
        return int(hashlib.sha1(blob.encode("utf-8")).hexdigest()[:7], 16)

    @_synchronized
    def create_service_databases(self) -> int | None:
        """Build/migrate the service tables in the unified DB from database_info.json.

        The combined schema is fingerprinted via _service_schema_version and stored
        in PRAGMA user_version; the expensive CREATE/ALTER/INDEX pass is skipped
        when the on-disk version already matches, and runs (adding new
        columns/indexes) whenever tables or _SERVICE_INDEXES change. Every service
        table gets an implicit ``workspace_id`` column + composite PK + a
        ``workspaces(id)`` FK (ON DELETE CASCADE) so rows are workspace-scoped and
        cannot orphan. Runs on the shared connection. Returns 1, or None if there
        are no specs / on error.
        """
        try:
            all_tables = _load_service_tables()
            if not all_tables:
                return None

            cursor = self.cursor

            # Skip the full CREATE/ALTER/INDEX pass when the on-disk schema already
            # matches. The version is derived from the table + index definitions, so
            # it auto-bumps (and the DDL re-runs) whenever they change.
            expected_version = self._service_schema_version({"tables": all_tables})
            current_version = int(self._run(cursor, "PRAGMA user_version", fetch="scalar") or 0)
            if current_version != expected_version:
                for table in all_tables:
                    columns = [*table["columns"], "workspace_id"]
                    primary_keys = [*table["primary_keys"], "workspace_id"]
                    self._create_service_table(cursor, table["table_name"], columns, primary_keys)
                    self._ensure_service_table_columns(cursor, table["table_name"], columns)
                    self._ensure_workspace_scope_index(cursor, table["table_name"], table["primary_keys"])
                self._ensure_service_indexes(cursor)
                self._run(cursor, f"PRAGMA user_version = {expected_version}")
                self.conn.commit()

            self._service_primary_key_cache.clear()
            return 1
        except Exception as exc:
            print("[X] Failed in create_service_databases for following error")
            print(str(exc))
            return None

    @_synchronized
    def plan_service_wipe(self, workspace_id: int, *, all_workspaces: bool = False) -> dict[str, Any]:
        """Dry-run a service-data wipe: enumerate tables and count deletable rows.

        Counts rows scoped to ``workspace_id`` (or every row when all_workspaces).
        Tables lacking a workspace_id column are flagged as non-deletable in
        per-workspace mode. Returns a plan dict (plans / candidate_tables /
        non_workspace_tables / tables_with_rows / total_rows) that wipe_service_rows
        consumes -- read-only, performs no deletes.
        """
        self._ensure_service_database()
        cursor = self.cursor
        target_ws = int(workspace_id)

        table_rows = self._run(
            cursor,
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            fetch="all",
        ) or []
        # The unified file also holds the control-plane tables (workspaces/session/
        # session_actions). They share the file only so FKs can reference workspaces;
        # a *service* wipe must never touch credentials or action evidence.
        table_names = [
            str(row[0])
            for row in table_rows
            if row and row[0] and str(row[0]) not in self._CONTROL_PLANE_TABLES
        ]
        if not table_names:
            return {
                "db_path": self.database_path,
                "scope_label": ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"),
                "plans": [],
                "candidate_tables": [],
                "non_workspace_tables": [],
                "tables_with_rows": [],
                "total_rows": 0,
            }

        plans: list[dict[str, Any]] = []
        total_rows = 0
        for table_name in table_names:
            pragma_rows = self._run(cursor, f'PRAGMA table_info("{table_name}")', fetch="all") or []
            columns = [str(column[1]) for column in pragma_rows if len(column) > 1]
            has_workspace_id = "workspace_id" in columns

            if not has_workspace_id:
                plans.append(
                    {
                        "table_name": table_name,
                        "has_workspace_id": False,
                        "row_count": 0,
                    }
                )
                continue

            if all_workspaces:
                row = self._run(cursor, f'SELECT COUNT(1) FROM "{table_name}"', fetch="one")
            else:
                row = self._run(cursor, f'SELECT COUNT(1) FROM "{table_name}" WHERE "workspace_id" = ?', (target_ws,), fetch="one")
            count = int(row[0]) if row and len(row) > 0 else 0
            count = max(count, 0)
            total_rows += count
            plans.append(
                {
                    "table_name": table_name,
                    "has_workspace_id": True,
                    "row_count": count,
                }
            )

        candidate_tables = [entry for entry in plans if bool(entry.get("has_workspace_id"))]
        non_workspace_tables = [str(entry.get("table_name") or "") for entry in plans if not bool(entry.get("has_workspace_id"))]
        tables_with_rows = [entry for entry in candidate_tables if int(entry.get("row_count") or 0) > 0]

        return {
            "db_path": self.database_path,
            "scope_label": ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"),
            "plans": plans,
            "candidate_tables": candidate_tables,
            "non_workspace_tables": non_workspace_tables,
            "tables_with_rows": tables_with_rows,
            "total_rows": total_rows,
        }

    @_synchronized
    def wipe_service_rows(
        self,
        workspace_id: int,
        *,
        all_workspaces: bool = False,
        planned_tables_with_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Delete service rows for one workspace (or all), in a single rolled-back-on-error txn.

        Operates on ``planned_tables_with_rows`` from plan_service_wipe, or
        re-plans if none given. Deletes are scoped by workspace_id unless
        all_workspaces. All deletes commit together; any error rolls back the
        whole batch and re-raises. Returns {deleted_rows, deleted_tables}.
        """
        self._ensure_service_database()
        cursor = self.cursor
        target_ws = int(workspace_id)

        tables_with_rows = list(planned_tables_with_rows or [])
        if not tables_with_rows:
            plan = self.plan_service_wipe(target_ws, all_workspaces=all_workspaces)
            tables_with_rows = list(plan.get("tables_with_rows") or [])

        deleted_total = 0
        deleted_tables = 0
        try:
            for entry in tables_with_rows:
                table_name = str(entry.get("table_name") or "").strip()
                if not table_name:
                    continue
                if all_workspaces:
                    self._run(cursor, f'DELETE FROM "{table_name}"')
                else:
                    self._run(cursor, f'DELETE FROM "{table_name}" WHERE "workspace_id" = ?', (target_ws,))

                rowcount = cursor.rowcount if isinstance(cursor.rowcount, int) and cursor.rowcount >= 0 else int(entry.get("row_count") or 0)
                deleted_total += max(rowcount, 0)
                deleted_tables += 1

            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return {
            "deleted_rows": deleted_total,
            "deleted_tables": deleted_tables,
        }

    @_synchronized
    def save_service_row(
        self,
        table_name: str,
        save_data: dict[str, Any] | None = None,
        *,
        only_if_missing: list[str] | None = None,
        dont_change: list[str] | None = None,
        replace_on: list[str] | None = None,
        update_data: dict[str, Any] | None = None,
    ) -> int | None:
        """Persist one service-table row with caller-selected write semantics.

        The primary write path modules use for enumeration output. Modes (checked
        in order): ``update_data`` -> plain UPDATE; ``only_if_missing`` -> insert
        only if no row matches those key columns (first-write-wins); ``replace_on``
        -> delete matching rows then insert (overwrite); otherwise upsert on the
        table's PK, preserving ``dont_change`` columns. Returns 1 / None.

        Threading: like all DataController methods this must be called on the main
        thread; enumeration workers return rows and the caller saves them here.
        """
        try:
            self._ensure_service_database()
            if update_data is not None:
                self._update_table(
                    self.conn,
                    self.cursor,
                    table_name,
                    update_data["data_to_insert"],
                    update_data["primary_keys_to_match"],
                )
                return 1

            if save_data is None:
                return None

            if only_if_missing:
                exists_query = f'SELECT 1 FROM "{table_name}" WHERE {self._where_clause(only_if_missing)} LIMIT 1'
                if self._run(
                    self.cursor,
                    exists_query,
                    [save_data[key] for key in only_if_missing],
                    fetch="one",
                ):
                    return 1
                self._insert_row(self.cursor, table_name, save_data)
            elif replace_on:
                delete_query = f'DELETE FROM "{table_name}" WHERE {self._where_clause(replace_on)}'
                self._run(self.cursor, delete_query, [save_data[column] for column in replace_on])
                self._insert_row(self.cursor, table_name, save_data)
            else:
                self._upsert_service_row(table_name, save_data, dont_change=dont_change or ())

            self.conn.commit()
            return 1
        except Exception as exc:
            print("[X] Failed to save row with the following error:")
            print(str(exc))
            return None

    @_synchronized
    def find_ancestors(self, asset_name: str, workspace_id: int) -> list[tuple[str, str]]:
        """Walk an asset up the resource hierarchy via a recursive CTE.

        Climbs the workspace-scoped ``abstract_tree_hierarchy`` from ``asset_name``
        following each node's ``parent`` until the synthetic root (parent == 'N/A').
        Excludes the asset itself. Returns [(type, name), ...] from nearest parent
        upward (e.g. project -> folder(s) -> organization), used for IAM
        inheritance resolution.
        """
        self._ensure_service_database()
        rows = self._run(
            self.cursor,
            """
            WITH RECURSIVE Ancestors AS (
                SELECT name, parent, type, workspace_id
                FROM "abstract_tree_hierarchy"
                WHERE name = ? AND workspace_id = ?

                UNION ALL

                SELECT t.name, t.parent, t.type, t.workspace_id
                FROM "abstract_tree_hierarchy" t
                JOIN Ancestors a ON t.name = a.parent
                WHERE t.workspace_id = ?
            )
            SELECT type, name FROM Ancestors
            WHERE parent != 'N/A' AND name != ?
            """,
            (asset_name, workspace_id, workspace_id, asset_name),
            fetch="all",
        )
        return [(row[0], row[1]) for row in rows]

    @_synchronized
    def insert_actions(
        self,
        workspace_id: int,
        credname: str,
        permission_record: dict[str, Any],
        column_name: str | None = None,
        evidence_type: str = ACTION_EVIDENCE_DIRECT_API,
    ) -> bool:
        """Merge discovered permissions (and their provenance) into a credential's action row.

        The public entry point for recording what a credential can do. Decomposes
        ``permission_record`` into scope columns (org/folder/project) and, if
        ``column_name`` is given, a 3-deep resource permission tree
        (project -> resource_type -> resource_name -> [permissions]) for that
        service column. Permissions are unioned in (never removed) and tagged with
        ``evidence_type`` provenance -- ACTION_EVIDENCE_DIRECT_API for permissions
        observed by a successful API call vs the test_iam_permissions value for
        testIamPermissions probes -- so this stores evidence, not booleans.

        Writes only when the merge actually changed something (re-running enum is
        idempotent). Main-thread only. Returns True on success/no-op, False on error.
        """
        try:
            columns = [column_name for _, column_name in self._ACTION_SCOPE_COLUMNS]
            if column_name:
                columns.insert(0, column_name)

            row = self._select_one(
                self.cursor,
                "session_actions",
                {"workspace_id": workspace_id, "credname": credname},
                ["credname", *columns, self._ACTION_PROVENANCE_COLUMN],
            )

            updates = self._merge_action_updates(row, permission_record, column_name)
            merged_provenance, provenance_changed = self._merge_action_provenance(
                row,
                permission_record,
                column_name,
                evidence_type=evidence_type,
            )
            if provenance_changed:
                updates[self._ACTION_PROVENANCE_COLUMN] = merged_provenance

            if not updates:
                return True

            self._ensure_session_actions_row(workspace_id, credname)
            self._update_table(
                self.conn,
                self.cursor,
                "session_actions",
                {column: json.dumps(value) for column, value in updates.items()},
                {"workspace_id": workspace_id, "credname": credname},
            )
            return True
        except Exception:
            print(traceback.format_exc())
            return False
