from __future__ import annotations

import ast
import csv
import json
import textwrap
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Literal
from xml.sax.saxutils import escape as xml_escape


UNIFORM_EXPORT_COLUMNS = [
    "table_name",
    "service_type",
    "resource_name",
    "resource_identifier",
    "scope_type",
    "scope_name",
    "scope_id",
    "state",
    "remaining_json",
]

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


def load_data(path: str | Path, *, kind: Literal["json"] | None = None) -> Any:
    file_path = Path(path)
    data_kind = kind or {
        ".json": "json",
    }.get(file_path.suffix.lower())

    if data_kind == "json":
        with file_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    raise ValueError(f"Unsupported data file type for {file_path}. Provide kind='json'.")


def load_mapping_data(*parts: str, kind: Literal["json"] | None = None) -> Any:
    return load_data(Path(resources.files("gcpwn.mappings").joinpath(*parts)), kind=kind)


def module_data_file(anchor_file: str, *parts: str) -> Path:
    return Path(anchor_file).resolve().parent.joinpath(*parts)


def read_lines(path: str | Path) -> list[str]:
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


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


def resolve_regions_from_module_data(
    session,
    args,
    *,
    module_file: str,
    locations_filename: str = "locations.txt",
    default_region: str = "-",
) -> list[str]:
    known_locations = read_lines(module_data_file(module_file, "data", locations_filename))

    if getattr(args, "regions_list", None):
        return [region.strip() for region in str(args.regions_list).split(",") if region.strip()]
    if getattr(args, "regions_file", None):
        return read_lines(args.regions_file)
    if getattr(args, "all_regions", False):
        return known_locations or [default_region]

    preferred = getattr(getattr(session, "workspace_config", None), "preferred_regions", None)
    if preferred:
        return [str(region).strip() for region in preferred if str(region).strip()]

    return known_locations or [default_region]


def split_path_tokens(value: Any, *, separator: str = "/", drop_empty: bool = True) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    parts = [part.strip() for part in text.split(separator)]
    if drop_empty:
        return [part for part in parts if part]
    return parts


def extract_path_tail(value: Any, *, separator: str = "/", drop_empty: bool = True, default: str = "") -> str:
    parts = split_path_tokens(value, separator=separator, drop_empty=drop_empty)
    if not parts:
        return str(default or "").strip()
    return str(parts[-1] or "").strip()


def extract_path_segment(resource_name: str, segment_name: str) -> str:
    if not resource_name:
        return ""
    parts = split_path_tokens(resource_name, separator="/", drop_empty=True)
    for idx, token in enumerate(parts):
        if token == segment_name and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def extract_location_from_resource_name(resource_name: str, *, include_zones: bool = False) -> str:
    location = extract_path_segment(resource_name, "locations")
    if location:
        return location
    if include_zones:
        return extract_path_segment(resource_name, "zones")
    return ""


def resource_name_from_value(row_or_name: Any, *field_names: str) -> str:
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
    resource_name = resource_name_from_value(row_or_name, *field_names)
    return extract_path_segment(resource_name, "projects") or str(fallback_project or "").strip()


def normalize_bigquery_resource_id(resource_id: str) -> str:
    return str(resource_id or "").strip().replace(":", ".")


def split_bigquery_dataset_id(resource_id: str, *, fallback_project: str = "") -> tuple[str, str]:
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


def parse_string_list(
    value: Any,
    *,
    allow_json: bool = True,
    allow_python_literal: bool = True,
    fallback_to_single: bool = False,
) -> list[str]:
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


def _short_resource_name(value: str) -> str:
    text = _stringify(value)
    if not text:
        return ""
    return extract_path_tail(text, separator="/", drop_empty=True, default=text)


def _sheet_title(base: str, used_titles: set[str]) -> str:
    stem = (
        str(base or "sheet")
        .replace("/", "_")
        .replace("\\", "_")
        .replace("[", "_")
        .replace("]", "_")
        .replace("*", "_")
        .replace("?", "_")
        .replace(":", "_")
    )[:31] or "sheet"
    title = stem
    suffix = 1
    while title in used_titles:
        token = f"_{suffix}"
        title = f"{stem[:31 - len(token)]}{token}"
        suffix += 1
    used_titles.add(title)
    return title


def _service_type(table_name: str) -> str:
    prefix = str(table_name or "").strip().split("_", 1)[0].lower()
    return _SERVICE_TYPE_ALIASES.get(prefix, prefix or "unknown")


def _resource_value(row: dict[str, Any], keys: Iterable[str], *, shorten_name: bool = False) -> tuple[str, str]:
    for key in keys:
        value = _stringify(row.get(key))
        if not value:
            continue
        if shorten_name and key == "name":
            value = _short_resource_name(value)
        return value, str(key)
    return "", ""


def _build_scope_context(loaded_tables: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> dict[str, Any]:
    tree_by_name: dict[str, dict[str, str]] = {}
    project_display_by_id: dict[str, str] = {}
    for ref, rows in loaded_tables:
        if str(ref.get("table_name") or "") != "abstract_tree_hierarchy":
            continue
        for row in rows:
            name = _stringify(row.get("name"))
            if not name:
                continue
            node = {
                "name": name,
                "type": _stringify(row.get("type")).lower(),
                "display_name": _stringify(row.get("display_name")),
                "project_id": _stringify(row.get("project_id")),
                "parent": _stringify(row.get("parent")),
                "state": _stringify(row.get("state")),
            }
            tree_by_name[name] = node
            if node["type"] == "project" and node["project_id"]:
                project_display_by_id[node["project_id"]] = node["display_name"] or node["project_id"]
    return {
        "tree_by_name": tree_by_name,
        "project_display_by_id": project_display_by_id,
    }


def _scope_from_tree_name(tree_by_name: dict[str, dict[str, str]], candidate: str) -> tuple[str, str, str]:
    current = _stringify(candidate)
    while current and current in tree_by_name:
        node = tree_by_name[current]
        node_type = node.get("type", "")
        normalized_type = {
            "organization": "org",
            "org": "org",
            "folder": "folder",
            "project": "project",
        }.get(node_type, "")
        if normalized_type:
            if normalized_type == "project":
                scope_id = node.get("project_id") or node.get("name") or current
                scope_name = node.get("display_name") or node.get("project_id") or scope_id
            else:
                scope_id = node.get("name") or current
                scope_name = node.get("display_name") or _short_resource_name(scope_id)
            return normalized_type, scope_name, scope_id
        current = _stringify(node.get("parent"))
    return "", "", ""


def _resolve_scope(
    *,
    row: dict[str, Any],
    table_name: str,
    scope_context: dict[str, Any],
) -> tuple[str, str, str]:
    tree_by_name = dict(scope_context.get("tree_by_name") or {})
    project_display_by_id = dict(scope_context.get("project_display_by_id") or {})

    if table_name == "abstract_tree_hierarchy":
        scope = _scope_from_tree_name(tree_by_name, _stringify(row.get("name")))
        if any(scope):
            return scope

    project_id = _stringify(row.get("project_id"))
    if project_id:
        return "project", project_display_by_id.get(project_id, project_id), project_id

    folder_id = _stringify(row.get("folder_id"))
    if folder_id:
        scope = _scope_from_tree_name(tree_by_name, folder_id)
        if any(scope):
            return scope
        return "folder", _short_resource_name(folder_id), folder_id

    org_id = _stringify(row.get("organization_id")) or _stringify(row.get("org_id"))
    if org_id:
        scope = _scope_from_tree_name(tree_by_name, org_id)
        if any(scope):
            return scope
        return "org", _short_resource_name(org_id), org_id

    for candidate_key in (
        "asset_name",
        "name",
        "resource_name",
        "parent",
        "folder_id",
        "organization_id",
        "org_id",
    ):
        scope = _scope_from_tree_name(tree_by_name, _stringify(row.get(candidate_key)))
        if any(scope):
            return scope

    return "", "", ""


def _row_state(row: dict[str, Any]) -> tuple[str, str]:
    for key in _STATE_KEYS:
        value = _stringify(row.get(key))
        if value:
            return value, key
    return "", ""


def _remaining_data(row: dict[str, Any], *, drop_keys: set[str]) -> dict[str, Any]:
    remaining: dict[str, Any] = {}
    for key, value in (row or {}).items():
        if str(key) in drop_keys:
            continue
        if value is None or isinstance(value, (str, int, float, bool)):
            normalized = value
        elif isinstance(value, bytes):
            normalized = value.decode("utf-8", errors="replace")
        elif isinstance(value, (dict, list, tuple)):
            normalized = json.dumps(value, ensure_ascii=False, sort_keys=False)
        else:
            normalized = str(value)

        if isinstance(normalized, str):
            token = normalized.strip()
            if token and token[0] in "[{":
                try:
                    normalized = json.loads(token)
                except Exception:
                    pass
        remaining[key] = normalized
    return remaining


def _flat_export_record(
    *,
    db_name: str,
    table_name: str,
    row: dict[str, Any],
    scope_context: dict[str, Any],
) -> dict[str, Any]:
    resource_name, resource_name_key = _resource_value(row, _RESOURCE_NAME_KEYS, shorten_name=True)
    resource_identifier, resource_identifier_key = _resource_value(row, _RESOURCE_IDENTIFIER_KEYS)
    scope_type, scope_name, scope_id = _resolve_scope(
        row=row,
        table_name=table_name,
        scope_context=scope_context,
    )
    state, state_key = _row_state(row)
    remaining_data = _remaining_data(
        row,
        drop_keys={
            resource_name_key,
            resource_identifier_key,
            state_key,
            "project_id",
            "folder_id",
            "organization_id",
            "org_id",
        },
    )
    return {
        "_db_name": db_name,
        "table_name": table_name,
        "service_type": _service_type(table_name),
        "resource_name": resource_name or _short_resource_name(resource_identifier),
        "resource_identifier": resource_identifier,
        "scope_type": scope_type,
        "scope_name": scope_name,
        "scope_id": scope_id,
        "state": state,
        "remaining_data": remaining_data,
        "remaining_json": json.dumps(remaining_data, ensure_ascii=False, sort_keys=True, default=str),
    }


def collect_sqlite_export_bundle(*, db_paths: list[str]) -> dict[str, Any]:
    from gcpwn.core.db import DataController

    loaded_tables = list(DataController.iter_sqlite_tables_from_paths(db_paths))
    refs = [ref for ref, _rows in loaded_tables]
    scope_context = _build_scope_context(loaded_tables)
    records: list[dict[str, Any]] = []

    for ref, rows in loaded_tables:
        db_name = _stringify(ref.get("db_name"))
        table_name = str(ref.get("table_name") or "")
        for row in rows:
            records.append(
                _flat_export_record(
                    db_name=db_name,
                    table_name=table_name,
                    row=row,
                    scope_context=scope_context,
                )
            )

    return {
        "refs": refs,
        "columns": list(UNIFORM_EXPORT_COLUMNS),
        "records": records,
        "summary": {
            "databases": len({_stringify(ref.get("db_name")) for ref in refs}),
            "tables": len(refs),
            "rows": len(records),
        },
    }


def _write_xlsx_sheet(worksheet, *, workbook, rows: list[dict[str, Any]]) -> None:
    header_format = workbook.add_format({"bold": True})
    wrap_format = workbook.add_format({"text_wrap": True, "valign": "top"})
    widths = {
        "table_name": 28,
        "service_type": 18,
        "resource_name": 34,
        "resource_identifier": 54,
        "scope_type": 16,
        "scope_name": 28,
        "scope_id": 32,
        "state": 16,
        "remaining_json": 120,
    }
    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(0, 0, max(len(rows), 1), len(UNIFORM_EXPORT_COLUMNS) - 1)
    for column_index, column_name in enumerate(UNIFORM_EXPORT_COLUMNS):
        worksheet.write(0, column_index, column_name, header_format)
        worksheet.set_column(
            column_index,
            column_index,
            widths.get(column_name, 24),
            wrap_format if column_name == "remaining_json" else None,
        )
    for row_index, row in enumerate(rows, start=1):
        for column_index, column_name in enumerate(UNIFORM_EXPORT_COLUMNS):
            worksheet.write(
                row_index,
                column_index,
                row.get(column_name, ""),
                wrap_format if column_name == "remaining_json" else None,
            )


def export_sqlite_dbs_to_csv_blob(*, db_paths: list[str], out_csv_path: str) -> dict[str, Any]:
    bundle = collect_sqlite_export_bundle(db_paths=db_paths)
    out_file = Path(out_csv_path).expanduser()
    if out_file.suffix.lower() != ".csv":
        out_file = out_file.with_suffix(".csv")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with out_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(UNIFORM_EXPORT_COLUMNS)
        for record in bundle["records"]:
            writer.writerow([record.get(column) for column in UNIFORM_EXPORT_COLUMNS])

    return {
        "ok": True,
        "csv_path": str(out_file),
        **bundle["summary"],
    }


def export_sqlite_dbs_to_json_blob(*, db_paths: list[str], out_json_path: str) -> dict[str, Any]:
    bundle = collect_sqlite_export_bundle(db_paths=db_paths)
    out_file = Path(out_json_path).expanduser()
    if out_file.suffix.lower() != ".json":
        out_file = out_file.with_suffix(".json")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "columns": [column for column in UNIFORM_EXPORT_COLUMNS if column != "remaining_json"] + ["remaining_data"],
        "records": [
            {key: value for key, value in record.items() if key != "remaining_json"}
            for record in bundle["records"]
        ],
        "summary": bundle["summary"],
    }
    out_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "json_path": str(out_file),
        **bundle["summary"],
    }


def export_sqlite_dbs_to_excel_blob(
    *,
    db_paths: list[str],
    out_xlsx_path: str,
    single_sheet: bool = True,
) -> dict[str, Any]:
    try:
        import xlsxwriter
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Excel export requires xlsxwriter. Install with `pip install gcpwn[excel]` "
            "or `pip install xlsxwriter==3.2.9`."
        ) from exc

    bundle = collect_sqlite_export_bundle(db_paths=db_paths)
    out_file = Path(out_xlsx_path).expanduser()
    if out_file.suffix.lower() != ".xlsx":
        out_file = out_file.with_suffix(".xlsx")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    workbook = xlsxwriter.Workbook(str(out_file))
    try:
        if single_sheet:
            worksheet = workbook.add_worksheet("all_resources")
            _write_xlsx_sheet(worksheet, workbook=workbook, rows=bundle["records"])
        else:
            used_titles: set[str] = set()
            for ref in bundle["refs"]:
                table_name = str(ref.get("table_name") or "")
                worksheet = workbook.add_worksheet(
                    _sheet_title(f'{ref.get("db_name", "")}_{table_name}', used_titles)
                )
                _write_xlsx_sheet(
                    worksheet,
                    workbook=workbook,
                    rows=[
                        record
                        for record in bundle["records"]
                        if record.get("_db_name") == _stringify(ref.get("db_name"))
                        and record.get("table_name") == table_name
                    ],
                )
    finally:
        workbook.close()

    return {
        "ok": True,
        "xlsx_path": str(out_file),
        **bundle["summary"],
        "format": "xlsx",
        "single_sheet": bool(single_sheet),
        "writer": "xlsxwriter",
    }


def _xml_safe_text(value: Any) -> str:
    text = str(value) if value is not None else ""
    text = "".join(ch for ch in text if (ord(ch) >= 32 or ch in "\t\n\r"))
    return xml_escape(text)


def _clean_hierarchy_label(*, display_name: str, resource_name: str, resource_type: str, project_id: str) -> str:
    base = display_name or _short_resource_name(resource_name) or project_id or "NAME_UNKNOWN"
    if len(base) > 36:
        base = f"{base[:33]}..."
    return base


def _build_hierarchy_tree_layout(rows: list[dict[str, Any]]) -> dict[str, Any]:
    raw_nodes: dict[str, dict[str, Any]] = {}
    children: dict[str, list[str]] = {}
    name_to_ids: dict[str, list[str]] = {}

    for index, row in enumerate(rows or []):
        resource_name = _stringify(row.get("name"))
        if not resource_name:
            continue
        project_id = _stringify(row.get("project_id"))
        resource_type = _stringify(row.get("type")).lower()
        parent_name = _stringify(row.get("parent"))
        if parent_name.upper() == "N/A":
            parent_name = ""

        node_id = f"{resource_name}::{project_id or '-'}::{index}"
        label = _clean_hierarchy_label(
            display_name=_stringify(row.get("display_name")),
            resource_name=resource_name,
            resource_type=resource_type,
            project_id=project_id,
        )
        raw_nodes[node_id] = {
            "id": node_id,
            "name": label,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "project_id": project_id,
            "parent_name": parent_name,
        }
        children.setdefault(node_id, [])
        name_to_ids.setdefault(resource_name, []).append(node_id)

    node_ids = sorted(raw_nodes.keys(), key=lambda item: (str(raw_nodes[item].get("name") or "").lower(), item))
    roots: list[str] = []

    for node_id in node_ids:
        node = raw_nodes[node_id]
        parent_name = _stringify(node.get("parent_name"))
        if not parent_name:
            roots.append(node_id)
            continue

        candidate_ids = list(name_to_ids.get(parent_name) or [])
        if not candidate_ids:
            roots.append(node_id)
            continue

        preferred_parent = ""
        project_id = _stringify(node.get("project_id"))
        if project_id:
            preferred_parent = next(
                (
                    parent_id
                    for parent_id in candidate_ids
                    if _stringify((raw_nodes.get(parent_id) or {}).get("project_id")) == project_id
                ),
                "",
            )
        if not preferred_parent:
            preferred_parent = candidate_ids[0]

        if preferred_parent and preferred_parent != node_id:
            children.setdefault(preferred_parent, []).append(node_id)
        else:
            roots.append(node_id)

    for parent_id in list(children.keys()):
        children[parent_id] = sorted(
            list(dict.fromkeys(children[parent_id])),
            key=lambda item: (str(raw_nodes.get(item, {}).get("name") or "").lower(), item),
        )

    roots = sorted(
        list(dict.fromkeys(roots)),
        key=lambda item: (str(raw_nodes.get(item, {}).get("name") or "").lower(), item),
    )
    if not roots and node_ids:
        roots = list(node_ids)

    depth: dict[str, int] = {}
    queue: list[str] = []
    for root_id in roots:
        depth[root_id] = 0
        queue.append(root_id)
    while queue:
        current = queue.pop(0)
        current_depth = int(depth.get(current, 0))
        for child in children.get(current, []):
            next_depth = current_depth + 1
            if child not in depth or next_depth < int(depth[child]):
                depth[child] = next_depth
                queue.append(child)
    for node_id in node_ids:
        depth.setdefault(node_id, 0)

    assigned_x: dict[str, float] = {}
    next_x = 0.0

    def _assign_x(node_id: str, stack: set[str]) -> float:
        nonlocal next_x
        if node_id in assigned_x:
            return assigned_x[node_id]
        if node_id in stack:
            value = next_x
            next_x += 1.0
            assigned_x[node_id] = value
            return value

        stack.add(node_id)
        child_x_values: list[float] = []
        for child in children.get(node_id, []):
            child_x_values.append(_assign_x(child, stack))
        stack.discard(node_id)

        if child_x_values:
            value = sum(child_x_values) / float(len(child_x_values))
        else:
            value = next_x
            next_x += 1.0
        assigned_x[node_id] = value
        return value

    for root_id in roots:
        _assign_x(root_id, set())
    for node_id in node_ids:
        if node_id not in assigned_x:
            _assign_x(node_id, set())

    nodes: dict[str, dict[str, Any]] = {}
    text_line_height = 17.5
    box_x_padding = 46.0
    org_box_x_padding_extra = 22.0
    box_y_padding = 36.0
    max_box_w = 220.0
    max_box_h = 88.0
    for node_id in node_ids:
        raw_node = raw_nodes[node_id]
        resource_type = str(raw_node.get("resource_type") or "").strip().lower()
        resource_name = str(raw_node.get("resource_name") or "")
        wrapped_name = textwrap.wrap(resource_name, width=34) or [resource_name]
        if wrapped_name:
            wrapped_name[0] = f"({wrapped_name[0]}"
            wrapped_name[-1] = f"{wrapped_name[-1]})"
        label_lines = [str(raw_node.get("name") or node_id)] + wrapped_name
        max_chars = max((len(line) for line in label_lines), default=12)
        line_count = max(1, len(label_lines))

        effective_x_padding = box_x_padding + (org_box_x_padding_extra if resource_type == "org" else 0.0)
        box_w = min(540.0, max(236.0, max_chars * 8.1 + effective_x_padding))
        box_h = min(240.0, max(92.0, line_count * text_line_height + box_y_padding))
        max_box_w = max(max_box_w, box_w)
        max_box_h = max(max_box_h, box_h)

        nodes[node_id] = {
            "id": node_id,
            "name": str(raw_node.get("name") or node_id),
            "resource_type": resource_type,
            "x_idx": float(assigned_x.get(node_id, 0.0)),
            "depth": int(depth.get(node_id, 0)),
            "box_w": float(box_w),
            "box_h": float(box_h),
            "label_lines": label_lines,
            "line_height": float(text_line_height),
        }

    x_spacing = max(320.0, max_box_w + 92.0)
    y_spacing = max(210.0, max_box_h + 86.0)
    min_x = min((nodes[node_id]["x_idx"] for node_id in node_ids), default=0.0)
    max_x = max((nodes[node_id]["x_idx"] for node_id in node_ids), default=0.0)
    max_depth = max((nodes[node_id]["depth"] for node_id in node_ids), default=0)
    pad = max(90.0, max(max_box_w, max_box_h) * 0.5 + 28.0)

    for node_id in node_ids:
        node = nodes[node_id]
        node["x"] = pad + (float(node["x_idx"]) - min_x) * x_spacing
        node["y"] = pad + float(int(node["depth"])) * y_spacing

    edges: list[tuple[str, str]] = []
    for parent_id in node_ids:
        for child_id in children.get(parent_id, []):
            if child_id in nodes and child_id != parent_id:
                edges.append((parent_id, child_id))

    width = int(max(980.0, (max_x - min_x) * x_spacing + pad * 2.0 + 1.0))
    height = int(max(700.0, float(max_depth) * y_spacing + pad * 2.0 + 1.0))

    return {
        "nodes": nodes,
        "node_order": node_ids,
        "edges": edges,
        "width": width,
        "height": height,
    }


def _render_hierarchy_tree_svg(layout: dict[str, Any], out_file: Path) -> None:
    nodes: dict[str, dict[str, Any]] = dict(layout.get("nodes") or {})
    node_order: list[str] = list(layout.get("node_order") or [])
    edges: list[tuple[str, str]] = list(layout.get("edges") or [])
    width = int(layout.get("width") or 800)
    height = int(layout.get("height") or 600)

    node_style_by_type = {
        "org": {"fill": "#163a54", "stroke": "#61d7ff"},
        "folder": {"fill": "#213d23", "stroke": "#9de06d"},
        "project": {"fill": "#4a2f1d", "stroke": "#ffbe73"},
    }
    default_node_style = {"fill": "#1a2036", "stroke": "#67f0e2"}
    legend_x = 18.0
    legend_y = 48.0
    legend_w = 252.0
    legend_h = 122.0

    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<defs>",
        '<linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
        '<stop offset="0%" stop-color="#0b1020" />',
        '<stop offset="100%" stop-color="#151b2f" />',
        "</linearGradient>",
        '<marker id="arrow" markerWidth="10" markerHeight="8" refX="10" refY="4" orient="auto" markerUnits="strokeWidth">',
        '<path d="M0,0 L10,4 L0,8 z" fill="#8ea0bf" />',
        "</marker>",
        '<filter id="shadow" x="-30%" y="-30%" width="160%" height="160%">',
        '<feDropShadow dx="0" dy="3" stdDeviation="3" flood-color="#000000" flood-opacity="0.42"/>',
        "</filter>",
        "</defs>",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="url(#bgGrad)" />',
        '<text x="{x}" y="34" text-anchor="middle" font-family="Segoe UI, DejaVu Sans, Arial, sans-serif" font-size="18" font-weight="700" fill="#dbe7ff">GCP Resource Hierarchy</text>'.format(
            x=width / 2
        ),
        f'<rect x="{legend_x:.2f}" y="{legend_y:.2f}" width="{legend_w:.2f}" height="{legend_h:.2f}" rx="12" fill="#0f1530" stroke="#7f8fb8" stroke-width="1.2" opacity="0.93" />',
        f'<text x="{legend_x + 14:.2f}" y="{legend_y + 22:.2f}" text-anchor="start" font-family="Segoe UI, DejaVu Sans, Arial, sans-serif" font-size="13" font-weight="700" fill="#dbe7ff">Legend</text>',
        f'<rect x="{legend_x + 14:.2f}" y="{legend_y + 35:.2f}" width="18" height="12" rx="3" fill="{node_style_by_type["org"]["fill"]}" stroke="{node_style_by_type["org"]["stroke"]}" stroke-width="1.2" />',
        f'<text x="{legend_x + 40:.2f}" y="{legend_y + 46:.2f}" text-anchor="start" font-family="Segoe UI, DejaVu Sans, Arial, sans-serif" font-size="12" fill="#f3f7ff">Organization</text>',
        f'<rect x="{legend_x + 14:.2f}" y="{legend_y + 60:.2f}" width="18" height="12" rx="3" fill="{node_style_by_type["folder"]["fill"]}" stroke="{node_style_by_type["folder"]["stroke"]}" stroke-width="1.2" />',
        f'<text x="{legend_x + 40:.2f}" y="{legend_y + 71:.2f}" text-anchor="start" font-family="Segoe UI, DejaVu Sans, Arial, sans-serif" font-size="12" fill="#f3f7ff">Folder</text>',
        f'<rect x="{legend_x + 14:.2f}" y="{legend_y + 85:.2f}" width="18" height="12" rx="3" fill="{node_style_by_type["project"]["fill"]}" stroke="{node_style_by_type["project"]["stroke"]}" stroke-width="1.2" />',
        f'<text x="{legend_x + 40:.2f}" y="{legend_y + 96:.2f}" text-anchor="start" font-family="Segoe UI, DejaVu Sans, Arial, sans-serif" font-size="12" fill="#f3f7ff">Project</text>',
        '<g id="viewport">',
    ]

    edge_lines: list[str] = []
    for src, dst in edges:
        source_node = nodes.get(src)
        dest_node = nodes.get(dst)
        if not source_node or not dest_node:
            continue
        x1 = float(source_node["x"])
        y1 = float(source_node["y"]) + float(source_node.get("box_h") or 80.0) * 0.5 + 1.0
        x2 = float(dest_node["x"])
        y2 = float(dest_node["y"]) - float(dest_node.get("box_h") or 80.0) * 0.5 - 1.8
        cy1 = y1 + max(16.0, (y2 - y1) * 0.32)
        cy2 = y2 - max(16.0, (y2 - y1) * 0.32)
        edge_lines.append(
            f'<path d="M {x1:.2f} {y1:.2f} C {x1:.2f} {cy1:.2f}, {x2:.2f} {cy2:.2f}, {x2:.2f} {y2:.2f}" '
            'fill="none" stroke="#8ea0bf" stroke-width="2" stroke-linecap="round" marker-end="url(#arrow)" opacity="0.9" />'
        )

    for node_id in node_order:
        node = nodes.get(node_id)
        if not node:
            continue
        x = float(node["x"])
        y = float(node["y"])
        width_px = float(node.get("box_w") or 220.0)
        height_px = float(node.get("box_h") or 84.0)
        resource_type = str(node.get("resource_type") or "").strip().lower()
        style = node_style_by_type.get(resource_type, default_node_style)
        fill = str(style["fill"])
        stroke = str(style["stroke"])

        lines.append(
            f'<rect x="{(x - width_px/2 + 1.4):.2f}" y="{(y - height_px/2 + 2.2):.2f}" width="{width_px:.2f}" height="{height_px:.2f}" rx="16" '
            'fill="#000000" opacity="0.28" />'
        )
        lines.append(
            f'<rect x="{(x - width_px/2):.2f}" y="{(y - height_px/2):.2f}" width="{width_px:.2f}" height="{height_px:.2f}" rx="16" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2.4" filter="url(#shadow)" />'
        )

        label_lines = list(node.get("label_lines") or [str(node.get("name") or node_id)])
        line_height = float(node.get("line_height") or 17.5)
        base_y = y - ((len(label_lines) - 1) * line_height) / 2.0
        for index, text in enumerate(label_lines):
            text_y = base_y + index * line_height
            safe_text = _xml_safe_text(text)
            font_size = 15 if index == 0 else 13
            font_weight = "700" if index == 0 else "500"
            font_color = "#ffffff" if index == 0 else "#f3f7ff"
            lines.append(
                f'<text x="{x:.2f}" y="{text_y:.2f}" text-anchor="middle" '
                'font-family="DejaVu Sans, Segoe UI, Arial, sans-serif" '
                f'font-size="{font_size}" font-weight="{font_weight}" fill="{font_color}" '
                'paint-order="stroke" stroke="#000000" stroke-width="1.25" stroke-linejoin="round">'
                f"{safe_text}</text>"
            )

    lines.extend(edge_lines)
    lines.append("</g>")
    lines.append("<style><![CDATA[")
    lines.append("svg { cursor: grab; user-select: none; }")
    lines.append("]]></style>")
    lines.append("<script><![CDATA[")
    lines.append("(function(){")
    lines.append("  var svg = document.documentElement;")
    lines.append("  var vp = document.getElementById('viewport');")
    lines.append("  if (!svg || !vp) return;")
    lines.append("  var scale = 1.0, tx = 0.0, ty = 0.0;")
    lines.append("  var dragging = false, sx = 0.0, sy = 0.0;")
    lines.append("  function apply(){ vp.setAttribute('transform', 'translate(' + tx + ' ' + ty + ') scale(' + scale + ')'); }")
    lines.append("  svg.addEventListener('wheel', function(e){")
    lines.append("    e.preventDefault();")
    lines.append("    var rect = svg.getBoundingClientRect();")
    lines.append("    var mx = e.clientX - rect.left;")
    lines.append("    var my = e.clientY - rect.top;")
    lines.append("    var factor = e.deltaY < 0 ? 1.1 : 0.9;")
    lines.append("    var ns = Math.max(0.28, Math.min(4.5, scale * factor));")
    lines.append("    var wx = (mx - tx) / scale;")
    lines.append("    var wy = (my - ty) / scale;")
    lines.append("    scale = ns;")
    lines.append("    tx = mx - wx * scale;")
    lines.append("    ty = my - wy * scale;")
    lines.append("    apply();")
    lines.append("  }, { passive: false });")
    lines.append("  svg.addEventListener('mousedown', function(e){")
    lines.append("    dragging = true;")
    lines.append("    sx = e.clientX - tx;")
    lines.append("    sy = e.clientY - ty;")
    lines.append("    svg.style.cursor = 'grabbing';")
    lines.append("  });")
    lines.append("  window.addEventListener('mousemove', function(e){")
    lines.append("    if (!dragging) return;")
    lines.append("    tx = e.clientX - sx;")
    lines.append("    ty = e.clientY - sy;")
    lines.append("    apply();")
    lines.append("  });")
    lines.append("  window.addEventListener('mouseup', function(){")
    lines.append("    dragging = false;")
    lines.append("    svg.style.cursor = 'grab';")
    lines.append("  });")
    lines.append("  svg.addEventListener('dblclick', function(){ scale = 1.0; tx = 0.0; ty = 0.0; apply(); });")
    lines.append("  apply();")
    lines.append("})();")
    lines.append("]]></script>")
    lines.append("</svg>")
    out_file.write_text("\n".join(lines), encoding="utf-8")


def export_hierarchy_tree_image(*, db_path: str, out_path: str, workspace_id: int | None = None) -> dict[str, Any]:
    db_file = Path(db_path).expanduser().resolve()
    if not db_file.exists():
        raise FileNotFoundError(f"SQLite DB not found: {db_file}")

    from gcpwn.core.db import DataController

    rows: list[dict[str, Any]] | None = None
    for ref, table_rows in DataController.iter_sqlite_tables_from_paths([str(db_file)]):
        if str(ref.get("table_name") or "") != "abstract_tree_hierarchy":
            continue
        rows = list(table_rows)
        if workspace_id is not None and rows and "workspace_id" in rows[0]:
            rows = [row for row in rows if str(row.get("workspace_id", "")).strip() == str(int(workspace_id))]
        rows.sort(
            key=lambda row: (
                str(row.get("type") or ""),
                str(row.get("display_name") or ""),
                str(row.get("name") or ""),
            )
        )
        break

    if rows is None:
        raise RuntimeError("abstract_tree_hierarchy table not found in service DB.")

    layout = _build_hierarchy_tree_layout(rows)
    if not list(layout.get("nodes") or []):
        layout = {
            "nodes": {
                "empty": {
                    "id": "empty",
                    "name": "(no hierarchy rows found)",
                    "resource_type": "unknown",
                    "x": 240.0,
                    "y": 180.0,
                    "x_idx": 0.0,
                    "depth": 0,
                    "box_w": 260.0,
                    "box_h": 84.0,
                    "label_lines": ["(no hierarchy rows found)"],
                    "line_height": 17.5,
                }
            },
            "node_order": ["empty"],
            "edges": [],
            "width": 480,
            "height": 360,
        }

    out_file = Path(out_path).expanduser()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    svg_file = out_file.with_suffix(".svg")
    _render_hierarchy_tree_svg(layout, svg_file)

    return {
        "ok": True,
        "format": "svg",
        "image_path": str(svg_file),
        "resources": len(rows),
        "nodes": len(layout.get("node_order") or []),
        "edges": len(layout.get("edges") or []),
        "renderer": "svg-interactive",
    }
