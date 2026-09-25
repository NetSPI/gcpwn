"""Contract: GcpListResource subclasses must align with database_info.json.

GcpListResource.save() injects two categories of keys into save_data without
column filtering -- both must be in the table schema or the SQLite INSERT fails:

  1. ID_FIELD -- the short path-tail column (e.g. "bucket_name", "job_id").
     The base save() always adds {self.ID_FIELD: extract_path_tail(name)}.

  2. _extra_save_fields() return dict keys -- extracted fields beyond what the
     raw API response provides (e.g. target_type, target_uri).

Neither is filtered through save_to_table's column-set guard (that guard only
covers keys taken from the normalized API response dict, not these injections).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULES_GCP = REPO_ROOT / "gcpwn" / "modules" / "gcp"
DB_INFO_PATH = REPO_ROOT / "gcpwn" / "mappings" / "database_info.json"


def _db_schemas() -> dict[str, set[str]]:
    data = json.loads(DB_INFO_PATH.read_text(encoding="utf-8"))
    return {t["table_name"]: set(t.get("columns", [])) for t in data.get("tables", [])}


def _base_names(class_node: ast.ClassDef) -> list[str]:
    names = []
    for base in class_node.bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
    return names


def _gcp_list_resource_descendants(tree: ast.Module) -> set[str]:
    """Return all class names that transitively extend GcpListResource in this file.

    Handles chains like _KmsResource(GcpListResource) → KmsCryptoKeysResource(_KmsResource)
    that the direct-base check misses.
    """
    gcp_derived: set[str] = {"GcpListResource"}
    # Iterate to a fixed point (handles chains of arbitrary depth).
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in gcp_derived:
                continue
            if any(b in gcp_derived for b in _base_names(node)):
                gcp_derived.add(node.name)
                changed = True
    return gcp_derived


def _class_const(class_node: ast.ClassDef, attr: str) -> str | None:
    for item in class_node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == attr
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, str)
            ):
                return item.value.value
    return None


def _extra_save_field_keys(class_node: ast.ClassDef) -> list[str]:
    """Extract string keys from the return dict of _extra_save_fields()."""
    keys: list[str] = []
    for item in class_node.body:
        if not isinstance(item, ast.FunctionDef) or item.name != "_extra_save_fields":
            continue
        for node in ast.walk(item):
            if not isinstance(node, ast.Return):
                continue
            val = node.value
            if not isinstance(val, ast.Dict):
                continue
            for k in val.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.append(k.value)
    return keys


def _collect_id_field_cases() -> list[tuple[str, str, str, str]]:
    """Return (table_name, class_name, id_field, file_rel) for GcpListResource subclasses.

    Includes indirect descendants (e.g. KmsCryptoKeysResource(_KmsResource) where
    _KmsResource(GcpListResource)) so chains of private base classes are not missed.
    """
    cases = []
    for py_file in sorted(MODULES_GCP.rglob("helpers.py")):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        file_rel = str(py_file.relative_to(REPO_ROOT))
        gcp_derived = _gcp_list_resource_descendants(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(b in gcp_derived for b in _base_names(node)):
                continue
            table_name = _class_const(node, "TABLE_NAME")
            id_field = _class_const(node, "ID_FIELD")
            if table_name and id_field:
                cases.append((table_name, node.name, id_field, file_rel))
    return cases


def _collect_extra_save_fields_cases() -> list[tuple[str, str, list[str], str]]:
    """Return (table_name, class_name, extra_keys, file_rel) for classes with _extra_save_fields.

    Includes indirect GcpListResource descendants so private-base-class chains are not missed.
    """
    cases = []
    for py_file in sorted(MODULES_GCP.rglob("helpers.py")):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        file_rel = str(py_file.relative_to(REPO_ROOT))
        gcp_derived = _gcp_list_resource_descendants(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            table_name = _class_const(node, "TABLE_NAME")
            if not table_name:
                continue
            # Only check GcpListResource descendants; non-derived classes may have
            # their own save() pipelines with different column rules.
            if not any(b in gcp_derived for b in _base_names(node)):
                continue
            extra_keys = _extra_save_field_keys(node)
            if extra_keys:
                cases.append((table_name, node.name, extra_keys, file_rel))
    return cases


_SCHEMAS = _db_schemas()
_ID_FIELD_CASES = _collect_id_field_cases()
_EXTRA_SAVE_CASES = _collect_extra_save_fields_cases()


@pytest.mark.parametrize(
    "table_name,class_name,id_field,file_rel",
    _ID_FIELD_CASES,
    ids=[f"{c}::ID_FIELD={f!r}" for _, c, f, _ in _ID_FIELD_CASES],
)
def test_id_field_in_schema(table_name: str, class_name: str, id_field: str, file_rel: str) -> None:
    """GcpListResource.ID_FIELD must be a column in database_info.json.

    The base save() always adds {self.ID_FIELD: extract_path_tail(name)} to save_data
    via extra_builder WITHOUT column filtering, so a missing column causes:
      sqlite3.OperationalError: table <T> has no column named <id_field>
    """
    schema = _SCHEMAS.get(table_name)
    if schema is None:
        pytest.skip(f"table {table_name!r} not in database_info.json (caught elsewhere)")

    assert id_field in schema, (
        f"{class_name} in {file_rel}: ID_FIELD={id_field!r} is not a column "
        f"in {table_name!r} in database_info.json.\n"
        "Add it as a column or correct the ID_FIELD declaration."
    )


@pytest.mark.parametrize(
    "table_name,class_name,extra_keys,file_rel",
    _EXTRA_SAVE_CASES,
    ids=[f"{c}::_extra_save_fields" for _, c, _, _ in _EXTRA_SAVE_CASES],
)
def test_extra_save_fields_keys_in_schema(
    table_name: str, class_name: str, extra_keys: list[str], file_rel: str
) -> None:
    """All _extra_save_fields() return dict keys must be in database_info.json.

    GcpListResource.save() spreads _extra_save_fields() into the extra_builder
    dict WITHOUT column filtering. Any key missing from the schema causes:
      sqlite3.OperationalError: table <T> has no column named <key>
    """
    schema = _SCHEMAS.get(table_name)
    if schema is None:
        pytest.skip(f"table {table_name!r} not in database_info.json (caught elsewhere)")

    missing = [k for k in extra_keys if k not in schema]
    assert not missing, (
        f"{class_name}._extra_save_fields() in {file_rel} returns key(s) "
        f"not in the DB schema for {table_name!r}: {missing}\n"
        "Add the missing column(s) to database_info.json."
    )
