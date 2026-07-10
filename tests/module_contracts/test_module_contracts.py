from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def _defines_run_module(tree: ast.Module) -> bool:
    """A module satisfies the run_module contract if it defines ``run_module`` at
    top level OR binds the name there via an import/assignment (the opengraph
    enumeration shims re-export ``run_module`` from a sibling module)."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "run_module":
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any((alias.asname or alias.name) == "run_module" for alias in node.names):
                return True
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "run_module" for target in node.targets):
                return True
    return False


def _module_files():
    files = []
    for path in sorted((REPO_ROOT / "gcpwn" / "modules").rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=str(path))
        if any(isinstance(node, ast.FunctionDef) and node.name == "run_module" for node in tree.body):
            files.append(path)
    return files


MODULE_FILES = _module_files()


@pytest.mark.parametrize("module_path", MODULE_FILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_module_argument_parser_has_no_invalid_output_format_kwarg(module_path: Path) -> None:
    tree = ast.parse(module_path.read_text(encoding="utf-8", errors="ignore"), filename=str(module_path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "ArgumentParser":
            continue
        invalid_kwarg = any(isinstance(kw, ast.keyword) and kw.arg == "output_format" for kw in (node.keywords or []))
        assert invalid_kwarg is False


def test_all_mapped_modules_exist() -> None:
    module_map_path = REPO_ROOT / "gcpwn" / "mappings" / "module_mappings.json"
    payload = json.loads(module_map_path.read_text(encoding="utf-8"))
    mapped_locations = []
    for service_entry in payload.get("services", []):
        if not isinstance(service_entry, dict):
            continue
        categories = service_entry.get("categories") or {}
        if not isinstance(categories, dict):
            continue
        for modules in categories.values():
            if not isinstance(modules, list):
                continue
            for module_info in modules:
                if not isinstance(module_info, dict):
                    continue
                location = str(module_info.get("location") or "").strip()
                if location:
                    mapped_locations.append(location)

    for location in mapped_locations:
        relative_path = Path(*location.split(".")).with_suffix(".py")
        module_file = REPO_ROOT / relative_path
        assert module_file.exists(), f"Missing module file for {location}"

        # Every mapped module must expose the run_module contract. Unauth/
        # passthrough modules are detected exactly as module_actions does and are
        # held to the same requirement (they still define run_module).
        tree = ast.parse(module_file.read_text(encoding="utf-8", errors="ignore"), filename=str(module_file))
        assert _defines_run_module(tree), f"Mapped module {location} does not define run_module"
