from __future__ import annotations

import ast
import json
import os
import sqlite3
import traceback
from functools import lru_cache
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
def _load_database_specs() -> list[dict[str, Any]]:
    payload = load_mapping_data("database_info.json", kind="json") or {}
    specs = payload.get("databases")
    return list(specs) if isinstance(specs, list) else []


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
    text = str(blob or "").strip()
    if not text:
        return []
    return list(ast.literal_eval(text))


def _encode_python_list(values: Iterable[str]) -> str:
    return str(sorted({str(value) for value in values if str(value).strip()}))


class DataController:
    _repo_root = Path(__file__).resolve().parents[2]
    workspace_database = str(_repo_root / "databases" / "workspaces.db")
    session_database = str(_repo_root / "databases" / "sessions.db")
    service_database = str(_repo_root / "databases" / "service_info.db")
    _ACTION_PROVENANCE_COLUMN = ACTION_PROVENANCE_COLUMN
    _ACTION_SCOPE_KEYS = ACTION_SCOPE_KEYS
    _ACTION_SCOPE_COLUMNS = ACTION_SCOPE_COLUMNS
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
        os.makedirs(self._repo_root / "databases", exist_ok=True)

        self.workspace_conn = self._connect_database(self.workspace_database)
        self.workspace_cursor = self.workspace_conn.cursor()

        self.session_conn = self._connect_database(self.session_database)
        self.session_cursor = self.session_conn.cursor()

        self.service_conn: sqlite3.Connection | None = None
        self.service_cursor: sqlite3.Cursor | None = None
        self._service_primary_key_cache: dict[str, list[str]] = {}

    def _connect_database(self, path: str) -> sqlite3.Connection:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        _apply_pragmas(conn)
        return conn

    def _ensure_service_database(self) -> None:
        if self.service_conn is None or self.service_cursor is None:
            self.create_service_databases()
        if self.service_conn is None or self.service_cursor is None:
            raise RuntimeError("Service database has not been initialized.")

    def _run(
        self,
        cursor: sqlite3.Cursor,
        query: str,
        params: Iterable[Any] = (),
        *,
        fetch: str | None = None,
    ) -> sqlite3.Cursor | sqlite3.Row | list[sqlite3.Row] | Any:
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
        try:
            if columns == "*":
                selected_columns = "*"
            elif isinstance(columns, str):
                selected_columns = f'"{columns}"'
            else:
                selected_columns = ", ".join(columns)
            sql_query = f'SELECT {selected_columns} FROM "{table_name}"'
            if conditions:
                sql_query += " WHERE " + conditions
            return [dict(row) for row in self._run(cursor, sql_query, params or (), fetch="all")]
        except sqlite3.Error as exc:
            print("SQLite error:", exc)
            return []

    def _where_clause(self, columns: Iterable[str]) -> str:
        return " AND ".join(f'"{column}" = ?' for column in columns)

    def _select_one(
        self,
        cursor: sqlite3.Cursor,
        table_name: str,
        where: dict[str, Any],
        columns: str | Iterable[str] = "*",
    ) -> sqlite3.Row | None:
        if columns == "*":
            selected_columns = "*"
        elif isinstance(columns, str):
            selected_columns = f'"{columns}"'
        else:
            selected_columns = ", ".join(f'"{column}"' for column in columns)
        query = f'SELECT {selected_columns} FROM "{table_name}" WHERE {self._where_clause(where.keys())}'
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
        self._run(
            cursor,
            f'''
            CREATE TABLE IF NOT EXISTS "{table_name}" (
                {columns_definition},
                PRIMARY KEY ({primary_keys_definition})
            )
            ''',
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
            columns = self._run(self.service_cursor, f'PRAGMA table_info("{table_name}")', fetch="all")
            self._service_primary_key_cache[table_name] = [column[1] for column in columns if column[5]]
        return self._service_primary_key_cache[table_name]

    def _upsert_service_row(
        self,
        table_name: str,
        payload: dict[str, Any],
        *,
        dont_change: Iterable[str] = (),
    ) -> None:
        self._ensure_service_database()
        columns = list(payload.keys())
        quoted_columns = ", ".join(f'"{column}"' for column in columns)
        placeholders = ", ".join("?" for _ in columns)
        primary_keys = self._service_primary_keys(table_name)

        if not primary_keys:
            self._insert_row(self.service_cursor, table_name, payload)
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
            self.service_cursor,
            f'''
            INSERT INTO "{table_name}" ({quoted_columns})
            VALUES ({placeholders})
            ON CONFLICT ({quoted_primary_keys}) {conflict_clause}
            ''',
            [payload[column] for column in columns],
        )

    def _decode_action_row(self, row: sqlite3.Row, *, include_provenance: bool = False) -> dict[str, Any]:
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

    def _merge_action_updates(
        self,
        current_row: sqlite3.Row | None,
        permission_record: dict[str, Any],
        column_name: str | None,
    ) -> dict[str, Any]:
        def _row_value(row: sqlite3.Row | None, target_column: str):
            if not row:
                return None
            try:
                return row[target_column]
            except Exception:
                return None

        updates: dict[str, Any] = {}
        for _permission_key, target_column, leaf_depth, incoming_permissions in self._iter_action_specs(
            permission_record,
            column_name,
        ):
            merged_permissions, changed = self._merge_permission_tree(
                _decode_json_blob(_row_value(current_row, target_column), {}),
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
        def _row_value(row: sqlite3.Row | None, target_column: str):
            if not row:
                return None
            try:
                return row[target_column]
            except Exception:
                return None

        current_provenance = _decode_json_blob(
            _row_value(current_row, self._ACTION_PROVENANCE_COLUMN),
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
            self.session_cursor,
            'INSERT OR IGNORE INTO "session_actions" (workspace_id, credname) VALUES (?, ?)',
            (workspace_id, credname),
        )

    def close(self) -> None:
        for cursor in (self.workspace_cursor, self.session_cursor, self.service_cursor):
            if cursor is None:
                continue
            try:
                cursor.close()
            except Exception:
                pass

        for conn in (self.workspace_conn, self.session_conn, self.service_conn):
            if conn is None:
                continue
            try:
                conn.close()
            except Exception:
                pass

    def __enter__(self) -> "DataController":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @classmethod
    def create_initial_workspace_session_database(cls) -> int | None:
        try:
            cls._repo_root.joinpath("databases").mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(cls.workspace_database) as workspace_conn:
                workspace_conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS workspaces
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, global_project_list TEXT, data TEXT, workspace_config TEXT)
                    """
                )
                workspace_conn.commit()

            with sqlite3.connect(cls.session_database) as session_conn:
                session_conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS session
                    (workspace_id INTEGER, credname TEXT, credtype TEXT, email TEXT, default_project TEXT, scopes TEXT, session_creds TEXT, PRIMARY KEY (workspace_id, credname))
                    """
                )
                resource_columns = ", ".join(f"{column_name} TEXT" for column_name in ACTION_COLUMNS)
                session_conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS session_actions
                    (
                        workspace_id INTEGER, credname TEXT,
                        {resource_columns},
                        {ACTION_PROVENANCE_COLUMN} TEXT,
                        PRIMARY KEY (workspace_id, credname)
                    )
                    """
                )
                # Lightweight schema migration: add any new ACTION_COLUMNS to existing session_actions table.
                existing = {
                    row[1]
                    for row in session_conn.execute('PRAGMA table_info("session_actions")').fetchall()
                }
                expected = {"workspace_id", "credname", *ACTION_COLUMNS, ACTION_PROVENANCE_COLUMN}
                missing = sorted(expected - existing)
                for column in missing:
                    if column in {"workspace_id", "credname"}:
                        continue
                    session_conn.execute(f'ALTER TABLE "session_actions" ADD COLUMN "{column}" TEXT')
                session_conn.commit()
            return 1
        except Exception as exc:
            print("[X] Failed in create_initial_workspace_session_database for following error")
            print(str(exc))
            return None

    def get_workspace(
        self,
        workspace_id: int,
        *,
        columns: str | list[str] = "*",
    ) -> dict[str, Any] | list[Any] | Any | None:
        try:
            row = self._select_one(self.workspace_cursor, "workspaces", {"id": workspace_id}, columns)
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

    def update_workspace(self, workspace_id: int, updates: dict[str, Any]) -> bool:
        try:
            if not updates:
                return False
            self._update_table(
                self.workspace_conn,
                self.workspace_cursor,
                "workspaces",
                updates,
                {"id": workspace_id},
            )
            return True
        except Exception as exc:
            print("[X] Failed in update_workspace for the following error")
            print(str(exc))
            return False

    def insert_workspace(self, name: str) -> int | None:
        try:
            workspace_config = WorkspaceConfig()
            self._run(
                self.workspace_cursor,
                "INSERT INTO workspaces (name, workspace_config) VALUES (?, ?)",
                (name, workspace_config.to_json_string()),
            )
            self.workspace_conn.commit()
            return self.workspace_cursor.lastrowid
        except sqlite3.Error as exc:
            print("[X] Failed to insert workspace due to database error")
            print(str(exc))
            return None
        except Exception as exc:
            print("[X] Failed to insert workspace due to an unexpected error")
            print(str(exc))
            return None

    def fetch_all_workspace_names(self) -> list[str] | None:
        try:
            rows = self._run(self.workspace_cursor, "SELECT name FROM workspaces", fetch="all")
            return [row[0] for row in rows]
        except Exception as exc:
            print("[X] Failed in fetch_all_workspaces for following error")
            print(str(exc))
            return None

    def get_workspaces(self) -> list[sqlite3.Row]:
        if not Path(self.workspace_database).exists():
            return []
        return self._run(self.workspace_cursor, "SELECT id, name FROM workspaces", fetch="all")

    def sync_workspace_projects(
        self,
        workspace_id: int,
        *,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> list[str] | None:
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

    def get_credential(self, workspace_id: int, credname: str) -> dict[str, Any] | None:
        try:
            row = self._select_one(
                self.session_cursor,
                "session",
                {"workspace_id": workspace_id, "credname": credname},
            )
            return dict(row) if row else None
        except Exception as exc:
            print("[X] Failed in get_credential for following error")
            print(str(exc))
            return None

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
            self._insert_row(self.session_cursor, "session", payload, replace=True)
            self.session_conn.commit()
            return 1
        except Exception as exc:
            print("[X] Failed in insert_creds for following error")
            print(str(exc))
            return None

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
                self.session_conn,
                self.session_cursor,
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

    def list_creds(self, workspace_id: int) -> list[sqlite3.Row] | None:
        try:
            return self._run(
                self.session_cursor,
                "SELECT credname, credtype, email FROM session WHERE workspace_id = ?",
                (workspace_id,),
                fetch="all",
            )
        except Exception as exc:
            print("[X] Failed in list_creds for following error")
            print(str(exc))
            return None

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
        target = str(db or "service").strip().lower()
        if target == "workspace":
            cursor = self.workspace_cursor
        elif target == "session":
            cursor = self.session_cursor
        elif target == "service":
            self._ensure_service_database()
            cursor = self.service_cursor
        else:
            raise ValueError(f"Unknown database selector: {db}")

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

    def execute_sql(
        self,
        query: str,
        *,
        db: str = "service",
        fetch_limit: int = 200,
    ) -> dict[str, Any]:
        sql = str(query or "").strip()
        if not sql:
            raise ValueError("Missing SQL query.")

        target = str(db or "service").strip().lower()
        if target == "metadata":
            target = "session"

        if target == "workspace":
            conn = self.workspace_conn
            cursor = self.workspace_cursor
            db_path = self.workspace_database
        elif target == "session":
            conn = self.session_conn
            cursor = self.session_cursor
            db_path = self.session_database
        elif target == "service":
            self._ensure_service_database()
            conn = self.service_conn
            cursor = self.service_cursor
            db_path = self.service_database
        else:
            raise ValueError(f"Unknown database selector: {db}")

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
    def _connect_database_for_path(path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        _apply_pragmas(conn)
        return conn

    @classmethod
    def iter_sqlite_tables_from_paths(
        cls,
        db_paths: Iterable[str],
    ) -> Iterable[tuple[dict[str, Any], list[dict[str, Any]]]]:
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

    def get_actions(
        self,
        workspace_id: int,
        credname: str | None = None,
        *,
        include_provenance: bool = False,
    ) -> list[dict[str, Any]]:
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
                for row in self._run(self.session_cursor, query, params, fetch="all")
            ]
        except Exception as exc:
            print("Error:", exc)
            return []

    def create_service_databases(self) -> int | None:
        try:
            database_specs = _load_database_specs()
            if not database_specs:
                return None

            for database_info in database_specs:
                database_path = self._repo_root / "databases" / f'{database_info["database_name"]}.db'
                conn = self._connect_database(str(database_path))
                cursor = conn.cursor()
                try:
                    for table in database_info["tables"]:
                        columns = [*table["columns"], "workspace_id"]
                        primary_keys = [*table["primary_keys"], "workspace_id"]
                        self._create_service_table(cursor, table["table_name"], columns, primary_keys)
                        self._ensure_service_table_columns(cursor, table["table_name"], columns)
                    self._ensure_service_indexes(cursor)
                    conn.commit()
                finally:
                    cursor.close()
                    conn.close()

            if self.service_cursor is not None:
                self.service_cursor.close()
            if self.service_conn is not None:
                self.service_conn.close()

            self.service_conn = self._connect_database(self.service_database)
            self.service_cursor = self.service_conn.cursor()
            self._service_primary_key_cache.clear()
            return 1
        except Exception as exc:
            print("[X] Failed in create_service_databases for following error")
            print(str(exc))
            return None

    def plan_service_wipe(self, workspace_id: int, *, all_workspaces: bool = False) -> dict[str, Any]:
        self._ensure_service_database()
        cursor = self.service_cursor
        target_ws = int(workspace_id)

        table_rows = self._run(
            cursor,
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            fetch="all",
        ) or []
        table_names = [str(row[0]) for row in table_rows if row and row[0]]
        if not table_names:
            return {
                "db_path": self.service_database,
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
            "db_path": self.service_database,
            "scope_label": ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"),
            "plans": plans,
            "candidate_tables": candidate_tables,
            "non_workspace_tables": non_workspace_tables,
            "tables_with_rows": tables_with_rows,
            "total_rows": total_rows,
        }

    def wipe_service_rows(
        self,
        workspace_id: int,
        *,
        all_workspaces: bool = False,
        planned_tables_with_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._ensure_service_database()
        cursor = self.service_cursor
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

            self.service_conn.commit()
        except Exception:
            self.service_conn.rollback()
            raise

        return {
            "deleted_rows": deleted_total,
            "deleted_tables": deleted_tables,
        }

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
        try:
            self._ensure_service_database()
            if update_data is not None:
                self._update_table(
                    self.service_conn,
                    self.service_cursor,
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
                    self.service_cursor,
                    exists_query,
                    [save_data[key] for key in only_if_missing],
                    fetch="one",
                ):
                    return 1
                self._insert_row(self.service_cursor, table_name, save_data)
            elif replace_on:
                delete_query = f'DELETE FROM "{table_name}" WHERE {self._where_clause(replace_on)}'
                self._run(self.service_cursor, delete_query, [save_data[column] for column in replace_on])
                self._insert_row(self.service_cursor, table_name, save_data)
            else:
                self._upsert_service_row(table_name, save_data, dont_change=dont_change or ())

            self.service_conn.commit()
            return 1
        except Exception as exc:
            print("[X] Failed to save row with the following error:")
            print(str(exc))
            return None

    def find_ancestors(self, asset_name: str, workspace_id: int) -> list[tuple[str, str]]:
        self._ensure_service_database()
        rows = self._run(
            self.service_cursor,
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

    def insert_actions(
        self,
        workspace_id: int,
        credname: str,
        permission_record: dict[str, Any],
        column_name: str | None = None,
        evidence_type: str = ACTION_EVIDENCE_DIRECT_API,
    ) -> bool:
        try:
            columns = [column_name for _, column_name in self._ACTION_SCOPE_COLUMNS]
            if column_name:
                columns.insert(0, column_name)

            row = self._select_one(
                self.session_cursor,
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
                self.session_conn,
                self.session_cursor,
                "session_actions",
                {column: json.dumps(value) for column, value in updates.items()},
                {"workspace_id": workspace_id, "credname": credname},
            )
            return True
        except Exception:
            print(traceback.format_exc())
            return False
