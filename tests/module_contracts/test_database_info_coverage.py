"""Contract: every TABLE_NAME used in module code must be in database_info.json["tables"].

save_to_table() silently returns without saving when a table is absent from
database_info.json — the enumeration runs and prints output but no rows land in
the DB. This contract catches that data-loss class of bug early.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULES_ROOT = REPO_ROOT / "gcpwn" / "modules"
DB_INFO = REPO_ROOT / "gcpwn" / "mappings" / "database_info.json"


def _collect_table_names() -> dict[str, str]:
    """Return {table_name: file_path} for every TABLE_NAME = "..." assignment in class bodies."""
    found: dict[str, str] = {}
    for py_file in MODULES_ROOT.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # Only class-body assignments so module-level TABLE_NAME constants
            # (e.g. in enum modules) don't fire false positives.
            if not isinstance(node, ast.ClassDef):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Assign):
                    continue
                for target in child.targets:
                    if not (isinstance(target, ast.Name) and target.id == "TABLE_NAME"):
                        continue
                    if isinstance(child.value, ast.Constant) and isinstance(child.value.value, str):
                        name = child.value.value
                        found[name] = str(py_file.relative_to(REPO_ROOT))
    return found


def _db_table_names() -> set[str]:
    data = json.loads(DB_INFO.read_text(encoding="utf-8"))
    return {t["table_name"] for t in data.get("tables", [])}


def test_all_table_names_present_in_database_info():
    used = _collect_table_names()
    defined = _db_table_names()
    missing = {name: path for name, path in used.items() if name not in defined}
    assert not missing, (
        f"{len(missing)} TABLE_NAME value(s) in module classes are missing from "
        f"database_info.json['tables'] — save_to_table silently discards all data "
        f"for these resources:\n"
        + "\n".join(f"  {name!r}  ({path})" for name, path in sorted(missing.items()))
    )
