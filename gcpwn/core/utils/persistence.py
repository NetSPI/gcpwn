"""Universal API-response -> SQLite persistence (``save_to_table``).

The point is to keep per-module code tiny: a module hands a raw GCP API object
(or an iterable of them) straight to ``save_to_table`` and this module reshapes
it to match the table schema declared in ``mappings/database_info.json``. The
reshaping runs as a fixed pipeline of passes (normalize keys -> expand nested
reference ids -> flatten top-level scalar dicts -> apply aliases), then filters
to known columns, JSON-encodes complex values, fills ``raw_json``, and finally
writes via ``session.insert_data`` (main thread only -- see DataController).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Callable, Iterable

from gcpwn.core.utils.module_helpers import load_mapping_data
from gcpwn.core.utils.serialization import resource_to_dict


_CAMEL_SPLIT_1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_SPLIT_2 = re.compile(r"([a-z0-9])([A-Z])")
_EMPTY_VALUES = (None, "", [], {})
_COMMON_ALIASES = {
    "created": ("creation_time", "creationtime"),
    "modified": ("last_modified_time", "lastmodifiedtime"),
    "expires": ("expiration_time", "expirationtime"),
    "retention_policy_locked": ("retention_policy_is_locked",),
    "schema_json": ("schema",),
    "access_entries": ("access",),
    "partitioning_type": ("time_partitioning_type",),
}
_SERVICE_TABLES = (load_mapping_data("database_info.json", kind="json") or {}).get("tables", [])


def to_snake_key(name: str) -> str:
    """Convert a single key to snake_case (camelCase/kebab-case -> snake_case)."""
    token = str(name or "").strip()
    if not token:
        return ""
    token = token.replace("-", "_")
    token = _CAMEL_SPLIT_1.sub(r"\1_\2", token)
    token = _CAMEL_SPLIT_2.sub(r"\1_\2", token)
    return token.lower()


def _normalize_keys(value: Any) -> Any:
    """Recursively snake_case every dict key in a nested structure (in lists too).

    Keys that normalize to empty are dropped. Non-dict/list values pass through
    unchanged. First pass of the save_to_table pipeline so the schema's snake_case
    column names match regardless of whether the API returned camelCase.
    """
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


def _has_value(value: Any) -> bool:
    return value not in _EMPTY_VALUES


def _encode_value(value: Any) -> Any:
    """JSON-encode dict/list/tuple values for storage; leave scalars as-is.

    Uses ``sort_keys=True`` and ``default=str`` so encoding is deterministic and
    never blows up on non-serializable values (datetimes, bytes-ish objects)."""
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if isinstance(value, (dict, list, tuple))
        else value
    )


def _expand_reference_ids(payload: dict[str, Any]) -> dict[str, Any]:
    """Hoist BigQuery ``*_reference`` nested ids (project/dataset/table) to top level.

    BigQuery wraps identifiers in ``dataset_reference``/``table_reference`` objects;
    this lifts ``project_id``/``dataset_id``/``table_id`` out so they land in their
    own columns. Only fills a target if it is currently empty (won't clobber)."""
    payload = dict(payload or {})
    for key in ("dataset_reference", "table_reference"):
        ref = payload.get(key)
        if not isinstance(ref, dict):
            continue
        for ref_key in ("project_id", "dataset_id", "table_id"):
            if ref_key in ref and not _has_value(payload.get(ref_key)) and _has_value(ref.get(ref_key)):
                payload[ref_key] = ref.get(ref_key)
    return payload


def _apply_common_aliases(payload: dict[str, Any], *, columns: set[str]) -> dict[str, Any]:
    """Fill an expected column from a known synonym key when the column is empty.

    Bridges naming differences across APIs (e.g. ``created`` <- ``creation_time``,
    ``access_entries`` <- ``access``) per ``_COMMON_ALIASES``. Only targets columns
    that actually exist in this table and are currently empty; first matching alias
    wins."""
    payload = dict(payload or {})
    for target_key, aliases in _COMMON_ALIASES.items():
        if target_key not in columns or _has_value(payload.get(target_key)):
            continue
        for alias in aliases:
            value = payload.get(alias)
            if _has_value(value):
                payload[target_key] = value
                break
    return payload


def _flatten_top_level_scalars(payload: dict[str, Any]) -> dict[str, Any]:
    """Expose scalar fields of one-level-nested dicts as ``<parent>_<child>`` keys.

    e.g. ``{"reference": {"project_id": "p"}}`` also yields ``reference_project_id``.
    Only scalar children are flattened (nested dict children are left for ``raw_json``
    / explicit handling). The original nested dict is preserved alongside."""
    payload = dict(payload or {})
    for key, value in list(payload.items()):
        if not isinstance(value, dict):
            continue
        for child_key, child_value in value.items():
            if isinstance(child_value, dict):
                continue
            payload[f"{key}_{child_key}"] = child_value
    return payload


@lru_cache(maxsize=256)
def _table_spec(table_name: str) -> tuple[list[str], list[str]]:
    """Look up ``(columns, primary_keys)`` for a table from database_info.json.

    Returns ``([], [])`` for unknown tables -- ``save_to_table`` treats that as a
    no-op. Cached since the spec is static for the process lifetime."""
    wanted = str(table_name or "").strip()
    if not wanted:
        return ([], [])
    for table in _SERVICE_TABLES:
        if str(table.get("table_name")) == wanted:
            return (list(table.get("columns", [])), list(table.get("primary_keys", [])))
    return ([], [])


def save_to_table(
    session,
    table_name: str,
    response: Any,
    *,
    defaults: dict[str, Any] | None = None,
    extras: dict[str, Any] | None = None,
    extra_builder: Callable[[Any, dict[str, Any]], dict[str, Any]] | None = None,
    only_if_new_columns: list[str] | None = None,
    dont_change: list[str] | None = None,
    if_column_matches: list[str] | None = None,
) -> None:
    """
    Universal persistence helper.

    Goal: keep per-module code tiny by passing API responses directly.

    Typical usage:
      - Save a single API object/dict:
        `save_to_table(session, "pubsub_topics", topic, defaults={"project_id": project_id})`
      - Save an iterator/list of API objects:
        `save_to_table(session, "pubsub_topics", topics_iterable, extra_builder=...)`

    `save_to_table()`:
      - normalizes keys (`camelCase`/`kebab-case` → `snake_case`)
      - filters to columns defined in `mappings/database_info.json`
      - auto-fills `raw_json` when the table has it
      - skips rows missing required primary keys
    """

    if response is None:
        return

    columns, required_keys = _table_spec(table_name)
    if not columns:
        return

    if isinstance(response, (dict, str, bytes)) or any(
        hasattr(response, attr) for attr in ("_pb", "to_api_repr", "to_dict")
    ):
        objects: Iterable[Any] = [response]
    else:
        try:
            iter(response)  # type: ignore[arg-type]
            objects = response
        except TypeError:
            objects = [response]

    column_set = set(columns)
    base_defaults = dict(defaults or {})
    base_extras = dict(extras or {})

    for obj in objects or []:
        raw = _apply_common_aliases(
            _flatten_top_level_scalars(_expand_reference_ids(_normalize_keys(resource_to_dict(obj)))),
            columns=column_set,
        )
        save_data = {
            key: _encode_value(raw[key])
            for key in columns
            if _has_value(raw.get(key))
        }

        for key, value in base_defaults.items():
            if _has_value(value) and key not in save_data:
                save_data[key] = _encode_value(value)
        for key, value in base_extras.items():
            if _has_value(value):
                save_data[key] = _encode_value(value)
        if callable(extra_builder):
            for key, value in (extra_builder(obj, raw) or {}).items():
                if _has_value(value):
                    save_data[key] = _encode_value(value)

        if "raw_json" in column_set and "raw_json" not in save_data:
            save_data["raw_json"] = _encode_value(raw) if raw else ""

        if any(not _has_value(save_data.get(key)) for key in required_keys):
            continue

        session.insert_data(
            table_name,
            save_data,
            only_if_new_columns=only_if_new_columns,
            dont_change=dont_change,
            if_column_matches=if_column_matches,
        )
