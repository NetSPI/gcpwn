"""Contract: every enum_*.py in gcp/workspace that defines run_module must be
registered in module_mappings.json.

A module that defines run_module but is absent from the registry is invisible to
the REPL (the user cannot discover or invoke it) and absent from enum_all unless
explicitly wired in. This test enforces that adding a new module and registering
it stay in sync.

Exclusions:
  - Shim modules that delegate run_module from a sub-module file are excluded
    because they're convenience entry-points (e.g. enum_dataflow.py delegates
    to enum_dataflow_core.py and enum_dataflow_datapipelines.py); enum_all
    references the shim, not the individual pieces.
  - The exclusion rule: a file whose run_module body calls run_module from
    another module in the same package (i.e. the body is entirely delegation),
    detected by checking for an import of run_module from a sibling path.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MAPPINGS_PATH = REPO_ROOT / "gcpwn" / "mappings" / "module_mappings.json"


def _registered_locations() -> set[str]:
    raw = json.loads(MAPPINGS_PATH.read_text(encoding="utf-8"))
    locs: set[str] = set()
    for svc in raw.get("services", []):
        if not isinstance(svc, dict):
            continue
        for cat_list in (svc.get("categories") or {}).values():
            if not isinstance(cat_list, list):
                continue
            for mod in cat_list:
                loc = (mod.get("location") or "").strip() if isinstance(mod, dict) else ""
                if loc:
                    locs.add(loc)
    return locs


def _is_delegation_shim(tree: ast.Module) -> bool:
    """Return True if this module's only job is to import run_module from siblings.

    A shim:
      - imports run_module (or a renamed alias) from another module and
      - defines its own run_module by calling those imports
      OR simply re-exports run_module via an import alias.

    Conservative check: if the module imports `run_module` as a name from any
    other module, it's a shim.  This covers both `from X import run_module as
    _run_X` and `from X import run_module`.
    """
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported_name = alias.asname or alias.name
                if imported_name == "run_module" or alias.name == "run_module":
                    return True
                # Also catches _run_core / _run_pipelines style
                if (alias.name or "").startswith("run_module") or (alias.asname or "").startswith("run_module"):
                    return True
    return False


def _enum_modules_with_run_module() -> list[tuple[str, Path]]:
    """Return (dot_path, file_path) for every non-shim enum module that defines run_module."""
    results = []
    search_roots = [
        REPO_ROOT / "gcpwn" / "modules" / "gcp",
        REPO_ROOT / "gcpwn" / "modules" / "workspace",
    ]
    for root in search_roots:
        for f in sorted(root.rglob("enum_*.py")):
            try:
                src = f.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(src, filename=str(f))
            except SyntaxError:
                continue

            has_run_module = any(
                isinstance(node, ast.FunctionDef) and node.name == "run_module"
                for node in tree.body
            )
            if not has_run_module:
                continue

            if _is_delegation_shim(tree):
                continue

            dot_path = ".".join(f.with_suffix("").relative_to(REPO_ROOT).parts)
            results.append((dot_path, f))
    return results


ENUM_MODULES = _enum_modules_with_run_module()
REGISTERED = _registered_locations()


@pytest.mark.parametrize(
    "dot_path,file_path",
    ENUM_MODULES,
    ids=[dot for dot, _ in ENUM_MODULES],
)
def test_enum_module_is_registered(dot_path: str, file_path: Path) -> None:
    """Every non-shim enum module must be registered in module_mappings.json.

    If this fails, add the module to module_mappings.json under its service.
    Use the dot-path shown above as the ``location`` field.
    """
    assert dot_path in REGISTERED, (
        f"{file_path.relative_to(REPO_ROOT)} defines run_module but is not registered "
        f"in module_mappings.json. Add it under its service with:\n"
        f'  "location": "{dot_path}"'
    )
