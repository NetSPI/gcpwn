"""Contract: every key returned by an extra_builder lambda must be in database_info.json.

save_to_table applies extra_builder results WITHOUT filtering to the table's schema,
then passes them straight to insert_data which builds the SQL INSERT from payload.keys().
If any extra_builder key is not a column in the SQLite table the INSERT fails with:
  sqlite3.OperationalError: table <T> has no column named <key>

This test catches that by:
  1. Parsing every helpers.py in modules/gcp/ for class-scoped save_to_table calls
     that carry an extra_builder=lambda ... { dict literal } argument.
  2. Mapping the lambda dict keys to the enclosing class's TABLE_NAME.
  3. Asserting every key is present in that table's database_info.json schema.
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


def _extra_builder_keys_in_class(class_node: ast.ClassDef) -> list[str]:
    """Extract string keys from extra_builder=lambda(...): { ... } dict literals in a class."""
    keys: list[str] = []
    for node in ast.walk(class_node):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != "extra_builder":
                continue
            lam = kw.value
            if not isinstance(lam, ast.Lambda):
                continue
            body = lam.body
            if not isinstance(body, ast.Dict):
                continue
            for k in body.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.append(k.value)
    return keys


def _collect_cases() -> list[tuple[str, str, list[str], str]]:
    """Return list of (table_name, key, file_rel) tuples where key is NOT in the table schema.

    Returns ALL (table_name, file, extra_keys) triples for parametrize; the test
    itself checks each key against the schema.
    """
    cases: list[tuple[str, str, list[str], str]] = []
    for py_file in sorted(MODULES_GCP.rglob("helpers.py")):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        file_rel = str(py_file.relative_to(REPO_ROOT))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            table_name: str | None = None
            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                for target in item.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "TABLE_NAME"
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)
                    ):
                        table_name = item.value.value
            if not table_name:
                continue
            extra_keys = _extra_builder_keys_in_class(node)
            if extra_keys:
                cases.append((table_name, node.name, extra_keys, file_rel))
    return cases


_CASES = _collect_cases()
_SCHEMAS = _db_schemas()


@pytest.mark.parametrize(
    "table_name,class_name,extra_keys,file_rel",
    _CASES,
    ids=[f"{c}::{t}" for t, c, _, _ in _CASES],
)
def test_extra_builder_keys_in_schema(
    table_name: str, class_name: str, extra_keys: list[str], file_rel: str
) -> None:
    """All extra_builder dict keys for a class must be present in its table's DB schema.

    extra_builder results are injected into save_data WITHOUT column filtering,
    so any key absent from the schema causes a sqlite3.OperationalError at runtime.
    """
    schema = _SCHEMAS.get(table_name)
    if schema is None:
        # Separate contract (test_database_info_coverage) catches missing tables.
        pytest.skip(f"table {table_name!r} not in database_info.json (caught elsewhere)")

    missing = [k for k in extra_keys if k not in schema]
    assert not missing, (
        f"{class_name}.save() in {file_rel} has extra_builder that returns "
        f"key(s) not in the DB schema for {table_name!r}: {missing}\n"
        "Add the missing column(s) to database_info.json so the SQLite INSERT doesn't fail."
    )
