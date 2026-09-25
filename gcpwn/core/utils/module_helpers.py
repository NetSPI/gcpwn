from __future__ import annotations

import ast
import json
import logging
import sqlite3
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Literal


_SERVICE_TYPE_ALIASES = {
    "abstract": "resourcemanager",
    "resource": "resourcemanager",
    "gw": "googleworkspace",
    "member": "iam",
}
_RESOURCE_NAME_KEYS = (
    "display_name",
    "friendly_name",
    "resource_name",
    "bucket_name",
    "dataset_id",
    "table_id",
    "instance",
    "email",
    "service_account_email",
    "member",
    "name",
    "id",
    "unique_id",
    "access_id",
)
_RESOURCE_IDENTIFIER_KEYS = (
    "id",
    "resource_name",
    "name",
    "full_table_id",
    "full_dataset_id",
    "unique_id",
    "email",
    "service_account_email",
    "access_id",
    "bucket_name",
    "dataset_id",
    "table_id",
    "instance",
)
_STATE_KEYS = ("state", "lifecycle_state", "status")


def _load_data(path: str | Path, *, kind: Literal["json"] | None = None) -> Any:
    file_path = Path(path)
    data_kind = kind or {
        ".json": "json",
    }.get(file_path.suffix.lower())

    if data_kind == "json":
        with file_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    raise ValueError(f"Unsupported data file type for {file_path}. Provide kind='json'.")


# Mapping files (module registry, IAM/escalation maps) are static config read many
# times per run. Cache the parsed result; callers treat the returned object as
# read-only (they .get() and copy rows before mutating). Cleared automatically on
# process exit; call load_mapping_data.cache_clear() if a mapping file is rewritten.
@lru_cache(maxsize=None)
def load_mapping_data(*parts: str, kind: Literal["json"] | None = None) -> Any:
    traversable = resources.files("gcpwn.mappings").joinpath(*parts)
    # Use the Traversable .open() API instead of Path() — avoids failures when the
    # package is installed as a wheel where namespace-package resources return
    # MultiplexedPath objects that do not implement __fspath__.
    name = str(traversable)
    suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name.rsplit("/", 1)[-1] else ""
    data_kind = kind or {".json": "json"}.get(suffix)
    if data_kind == "json":
        with traversable.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    raise ValueError(f"Unsupported data file type for {traversable}. Provide kind='json'.")


def module_data_file(anchor_file: str, *parts: str) -> Path:
    return Path(anchor_file).resolve().parent.joinpath(*parts)


def read_lines(path: str | Path) -> list[str]:
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def iter_module_rows(payload: Any) -> list[dict[str, Any]]:
    """Flatten module_mappings.json into per-module dict rows across both schema shapes.

    Supports the flat ``{"modules": [...]}`` form and the nested
    ``{"services": [{"service": ..., "categories": {cat: [...]}}]}`` form. In the nested
    form each row is tagged with ``service`` and ``module_category`` (stripped, ``""`` when
    absent); callers layer their own display defaults / field selection on top. The single
    home for parsing the module-registry schema (shared by the CLI dispatch and the REPL).
    """
    if not isinstance(payload, dict):
        return []
    flat_rows = payload.get("modules")
    if isinstance(flat_rows, list):
        return [dict(row) for row in flat_rows if isinstance(row, dict)]

    rows: list[dict[str, Any]] = []
    for service_entry in payload.get("services") or []:
        if not isinstance(service_entry, dict):
            continue
        service_name = str(service_entry.get("service") or "").strip()
        categories = service_entry.get("categories") or {}
        if not isinstance(categories, dict):
            continue
        for category, modules in categories.items():
            if not isinstance(modules, list):
                continue
            category_name = str(category or "").strip()
            for module in modules:
                if not isinstance(module, dict):
                    continue
                row = dict(module)
                row.setdefault("module_category", category_name)
                row.setdefault("service", service_name)
                rows.append(row)
    return rows


def normalize_service_account_resource_name(sa_value, default_project="-"):
    if not sa_value:
        return None

    candidate = str(sa_value).strip()
    if candidate.startswith("projects/") and "/serviceAccounts/" in candidate:
        return candidate
    if candidate.startswith("serviceAccount:"):
        candidate = candidate.split(":", 1)[1]
    if "@" in candidate:
        return f"projects/{default_project}/serviceAccounts/{candidate}"
    return candidate


def extract_service_account_email(sa_value):
    normalized = normalize_service_account_resource_name(sa_value)
    if not normalized:
        return None
    return normalized.split("/serviceAccounts/", 1)[-1]


def extract_service_account_project(sa_value):
    normalized = normalize_service_account_resource_name(sa_value)
    if not normalized or not normalized.startswith("projects/"):
        return None
    parts = normalized.split("/")
    if len(parts) < 2:
        return None
    return parts[1]


def resolve_regions_args(session, args, *, default_region: str = "-") -> list[str]:
    if getattr(args, "regions_list", None):
        return [region.strip() for region in str(args.regions_list).split(",") if region.strip()]
    if getattr(args, "regions_file", None):
        return read_lines(args.regions_file)
    if getattr(args, "all_regions", False):
        return [default_region]
    preferred = getattr(getattr(session, "workspace_config", None), "preferred_regions", None)
    if preferred:
        return [str(region).strip() for region in preferred if str(region).strip()]
    return [default_region]


@lru_cache(maxsize=1)
def load_service_locations() -> dict[str, list[str]]:
    """Parse the consolidated mappings/service_locations.txt into {service: [locations]}.

    Sections are headed by ``[<service>]``; blank lines and ``#`` comments are
    ignored. Replaces the per-module ``utilities/data/locations.txt`` files."""
    text = resources.files("gcpwn.mappings").joinpath("service_locations.txt").read_text(encoding="utf-8")
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def static_locations(service: str) -> list[str]:
    """The hardcoded fallback locations for ``service`` from the consolidated file."""
    return list(load_service_locations().get(str(service or "").strip().lower(), []))


def discover_service_locations(credentials, api_name: str, api_version: str, project_id: str) -> list[str]:
    """Live ``<service>.projects.locations.list`` lookup. Returns the location IDs,
    or [] on any failure (caller falls back to the static list)."""
    project = str(project_id or "").strip()
    if not (credentials and api_name and api_version and project):
        return []
    try:
        # Lazy import avoids a module-load cycle with service_runtime.
        from gcpwn.core.utils.service_runtime import build_discovery_service

        service = build_discovery_service(credentials, api_name, api_version)
        response = service.projects().locations().list(name=f"projects/{project}").execute()
        return [
            str(location.get("locationId")).strip()
            for location in (response.get("locations") or [])
            if str(location.get("locationId") or "").strip()
        ]
    except Exception:
        return []


def resolve_regions_from_module_data(
    session,
    args,
    *,
    service: str | None = None,
    discovery: tuple[str, str] | None = None,
    module_file: str | None = None,
    locations_filename: str = "locations.txt",
    default_region: str = "-",
) -> list[str]:
    """Resolve the regions/locations a region-scoped enum module fans out over.

    Precedence: explicit ``--regions-list`` / ``--regions-file`` win, then the
    workspace's preferred_regions. Otherwise (default, or ``--all-regions``) the
    module's full location set is used -- discovered LIVE from the service's
    ``projects.locations.list`` API when ``discovery`` is given, falling back to
    the consolidated static list (``service``) or a legacy per-module file."""

    def _static() -> list[str]:
        if service:
            return static_locations(service)
        if module_file:
            return read_lines(module_data_file(module_file, "data", locations_filename))
        return []

    def _known() -> list[str]:
        if discovery is not None:
            discovered = discover_service_locations(
                getattr(session, "credentials", None),
                discovery[0],
                discovery[1],
                getattr(session, "project_id", "") or "",
            )
            if discovered:
                return discovered
        return _static()

    if getattr(args, "regions_list", None):
        return [region.strip() for region in str(args.regions_list).split(",") if region.strip()]
    if getattr(args, "regions_file", None):
        return read_lines(args.regions_file)
    if getattr(args, "all_regions", False):
        return _known() or [default_region]

    preferred = getattr(getattr(session, "workspace_config", None), "preferred_regions", None)
    if preferred:
        return [str(region).strip() for region in preferred if str(region).strip()]

    return _known() or [default_region]


def region_resolver_for(service, discovery=None):
    """A run_components region_resolver bound to a service (+optional discovery tuple)."""
    def _resolve(session, args):
        return resolve_regions_from_module_data(session, args, service=service, discovery=discovery)
    return _resolve


def split_path_tokens(value: Any, *, separator: str = "/", drop_empty: bool = True) -> list[str]:
    """Split a resource path into stripped tokens (the basis of the extract_* helpers)."""
    text = str(value or "").strip()
    if not text:
        return []
    parts = [part.strip() for part in text.split(separator)]
    if drop_empty:
        return [part for part in parts if part]
    return parts


def extract_path_tail(value: Any, *, separator: str = "/", drop_empty: bool = True, default: str = "") -> str:
    """Return the last path segment (e.g. the short id from ``projects/p/.../name``)."""
    parts = split_path_tokens(value, separator=separator, drop_empty=drop_empty)
    if not parts:
        return str(default or "").strip()
    return str(parts[-1] or "").strip()


def extract_path_segment(resource_name: str, segment_name: str) -> str:
    """Return the value following ``segment_name`` in a GCP resource path.

    e.g. ``extract_path_segment("projects/p/locations/us", "projects")`` -> ``"p"``.
    Returns "" if the segment is absent or has no following token."""
    if not resource_name:
        return ""
    parts = split_path_tokens(resource_name, separator="/", drop_empty=True)
    for idx, token in enumerate(parts):
        if token == segment_name and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def extract_location_from_resource_name(resource_name: str, *, include_zones: bool = False) -> str:
    """Pull the region/location from a resource path; optionally fall back to ``zones/``."""
    location = extract_path_segment(resource_name, "locations")
    if location:
        return location
    if include_zones:
        return extract_path_segment(resource_name, "zones")
    return ""


def resource_name_from_value(row_or_name: Any, *field_names: str) -> str:
    """Extract a resource name from a str, a DB row dict, or an API object.

    Accepts a bare string (returned stripped), or looks up ``field_names`` (default
    ``("name",)``) first as dict keys then as attributes, returning the first
    non-empty hit. Lets callers pass either a raw name or the row/object holding it.
    """
    if isinstance(row_or_name, str):
        return str(row_or_name).strip()
    if isinstance(row_or_name, dict):
        for field_name in field_names or ("name",):
            value = row_or_name.get(field_name)
            if value not in (None, ""):
                return str(value).strip()
    for field_name in field_names or ("name",):
        value = getattr(row_or_name, field_name, None)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def name_from_input(
    value: str,
    *,
    project_id: str = "",
    template: tuple[str | int, ...],
    passthrough_prefixes: tuple[str, ...] = ("projects/",),
    separator: str = "/",
    error_message: str = "Invalid resource ID format.",
) -> str:
    """Expand a short user-supplied id into a full resource name via a template.

    If ``value`` already starts with a ``passthrough_prefixes`` entry (default
    ``projects/``) it is assumed full and returned as-is. Otherwise ``value`` is
    split on ``separator`` and zipped into ``template``: int entries index the
    split input parts, str entries are literals (``.format(project_id=...)``-aware).
    The number of input parts must equal ``max(int segments)+1`` or ``ValueError``
    is raised with ``error_message``. Returns the joined full resource name."""
    text = str(value or "").strip()
    if not text:
        return ""
    if any(text.startswith(prefix) for prefix in passthrough_prefixes):
        return text

    input_parts = [part.strip() for part in text.split(separator) if part.strip()]
    index_segments = [segment for segment in template if isinstance(segment, int)]
    required_parts = (max(index_segments) + 1) if index_segments else 0
    if len(input_parts) != required_parts:
        raise ValueError(error_message)

    output_parts: list[str] = []
    for segment in template:
        if isinstance(segment, int):
            output_parts.append(input_parts[segment])
        else:
            output_parts.append(str(segment).format(project_id=project_id))
    return separator.join(output_parts)


def extract_project_id_from_resource(row_or_name: Any, *, fallback_project: str = "", field_names: tuple[str, ...] = ("name",)) -> str:
    """Pull the project id from a resource's ``projects/<id>/...`` name, else fallback."""
    resource_name = resource_name_from_value(row_or_name, *field_names)
    return extract_path_segment(resource_name, "projects") or str(fallback_project or "").strip()


def normalize_bigquery_resource_id(resource_id: str) -> str:
    return str(resource_id or "").strip().replace(":", ".")


def split_bigquery_dataset_id(resource_id: str, *, fallback_project: str = "") -> tuple[str, str]:
    """Parse a dataset id into ``(project_id, dataset_id)`` from path or dotted form.

    Accepts both ``projects/<p>/datasets/<d>`` and ``<p>.<d>`` (BigQuery's
    ``project:dataset`` is normalized to dots first). If only a bare dataset is
    given, ``fallback_project`` is used as the project."""
    text = normalize_bigquery_resource_id(resource_id)
    if text.startswith("projects/") and "/datasets/" in text:
        project_id = extract_path_segment(text, "projects")
        dataset_id = extract_path_segment(text, "datasets")
        if project_id and dataset_id:
            return project_id, dataset_id
    project_id, dot, dataset_id = text.partition(".")
    if dot and project_id and dataset_id:
        return project_id, dataset_id
    return str(fallback_project or "").strip(), text


def _split_bigquery_child_id(
    resource_id: str,
    *,
    child_segment: str,
    fallback_project: str = "",
) -> tuple[str, str, str]:
    """Parse ``project.dataset.<child>`` (or its path form) into a 3-tuple.

    ``child_segment`` selects ``tables``/``routines``. Handles the full
    ``projects/.../datasets/.../<child>/...`` path and the dotted form; a 2-part
    dotted id uses ``fallback_project``. Returns ``(project, dataset, child)`` with
    empty middle/child fields if unparseable."""
    text = normalize_bigquery_resource_id(resource_id)
    if text.startswith("projects/") and "/datasets/" in text and f"/{child_segment}/" in text:
        project_id = extract_path_segment(text, "projects")
        dataset_id = extract_path_segment(text, "datasets")
        child_id = extract_path_segment(text, child_segment)
        if project_id and dataset_id and child_id:
            return project_id, dataset_id, child_id
    pieces = [part for part in text.split(".") if part]
    if len(pieces) == 3:
        return pieces[0], pieces[1], pieces[2]
    fallback = str(fallback_project or "").strip()
    if len(pieces) == 2 and fallback:
        return fallback, pieces[0], pieces[1]
    return fallback, "", text


def split_bigquery_table_id(resource_id: str, *, fallback_project: str = "") -> tuple[str, str, str]:
    return _split_bigquery_child_id(
        resource_id,
        child_segment="tables",
        fallback_project=fallback_project,
    )


def split_bigquery_routine_id(resource_id: str, *, fallback_project: str = "") -> tuple[str, str, str]:
    return _split_bigquery_child_id(
        resource_id,
        child_segment="routines",
        fallback_project=fallback_project,
    )


def bigquery_table_iam_resource_name(resource_id: str, *, fallback_project: str = "") -> str:
    project_id, dataset_id, table_id = split_bigquery_table_id(resource_id, fallback_project=fallback_project)
    if project_id and dataset_id and table_id:
        return f"projects/{project_id}/datasets/{dataset_id}/tables/{table_id}"
    return ""


def bigquery_routine_iam_resource_name(resource_id: str, *, fallback_project: str = "") -> str:
    project_id, dataset_id, routine_id = split_bigquery_routine_id(resource_id, fallback_project=fallback_project)
    if project_id and dataset_id and routine_id:
        return f"projects/{project_id}/datasets/{dataset_id}/routines/{routine_id}"
    return ""


def dedupe_strs(values: Iterable[str] | None) -> list[str]:
    """Strip, drop empties, and de-duplicate strings while preserving first-seen order."""
    output: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()


def parse_json_value(value: Any, *, default: Any = None) -> Any:
    """Decode a JSON string, passing through already-parsed dict/list, never raising.

    Returns ``default`` on None, empty, or invalid JSON. Convenient for columns that
    may hold either a JSON-encoded blob or an already-deserialized value."""
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    text = str(value).strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def normalize_str_set(values: Any) -> set[str]:
    """Coerce a value (or iterable of values) into a set of stripped, non-empty strings.

    A single non-iterable value is treated as a one-element collection (so a bare
    string is NOT iterated char-by-char). Empty/blank entries are dropped. This is
    the canonical "strip these into a set" helper -- prefer it over hand-rolled
    ``{str(v).strip() for v in vals if str(v).strip()}`` comprehensions.
    """
    candidates = values if isinstance(values, (list, tuple, set, frozenset)) else [values]
    return {token for value in candidates if (token := str(value or "").strip())}


def parse_string_list(
    value: Any,
    *,
    allow_json: bool = True,
    allow_python_literal: bool = True,
    fallback_to_single: bool = False,
) -> list[str]:
    """Coerce a value into a list of non-empty strings, tolerating many encodings.

    Already-iterable (set/tuple/list) values are stringified directly. A string is
    tried as JSON (if ``allow_json``) then as a Python literal (if
    ``allow_python_literal``) -- DB columns historically stored lists either way.
    If neither parses, returns ``[token]`` when ``fallback_to_single`` else ``[]``.
    """
    if value is None:
        return []
    if isinstance(value, (set, tuple, list)):
        return [str(item).strip() for item in value if str(item).strip()]

    token = str(value).strip()
    if not token:
        return []

    if allow_json:
        parsed = parse_json_value(token, default=None)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]

    if allow_python_literal:
        try:
            parsed_literal = ast.literal_eval(token)
            if isinstance(parsed_literal, (set, tuple, list)):
                return [str(item).strip() for item in parsed_literal if str(item).strip()]
        except Exception:
            pass

    return [token] if fallback_to_single else []


def collect_sqlite_export_bundle(
    *,
    db_paths: list[str],
    table_name: str | None,
) -> dict[str, Any]:
    """Collect rows from one or more SQLite databases into a flat export bundle.

    Args:
        db_paths: Paths to SQLite database files. Missing or non-SQLite files are skipped.
        table_name: When set, only rows from this table are included. When None, all tables.

    Returns:
        {"summary": {"tables": int, "rows": int}, "records": [{"table_name": str, ...}]}
    """
    records: list[dict[str, Any]] = []
    seen_tables: set[str] = set()

    for db_path in db_paths:
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
        except Exception:
            logging.debug("collect_sqlite_export_bundle: skipping %s (cannot open)", db_path)
            continue

        try:
            cursor = con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            table_names = [row[0] for row in cursor.fetchall()]
        except Exception:
            con.close()
            continue

        for tbl in table_names:
            if table_name is not None and tbl != table_name:
                continue
            try:
                rows = con.execute(f"SELECT * FROM \"{tbl}\"").fetchall()  # noqa: S608
            except Exception:
                continue
            seen_tables.add(tbl)
            for row in rows:
                rec = dict(row)
                rec["table_name"] = tbl
                records.append(rec)

        con.close()

    return {
        "summary": {"tables": len(seen_tables), "rows": len(records)},
        "records": records,
    }

