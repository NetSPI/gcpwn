"""Contract test: every ServiceSpec module path in enum_all must be importable.

enum_all._SERVICES references module paths (e.g.
``gcpwn.modules.gcp.foo.enumeration.enum_foo``) that are loaded at runtime via
importlib. If a module is renamed or split, the old path silently breaks and
the corresponding ``enum_all --foo`` gate raises ModuleNotFoundError.

This test uses AST to extract every ServiceSpec second argument (the module
path string), then checks that Python can resolve it in the installed package.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENUM_ALL = REPO_ROOT / "gcpwn" / "modules" / "everything" / "enumeration" / "enum_all.py"


def _extract_service_spec_modules() -> list[str]:
    """Parse enum_all.py with AST and return the second positional arg of every ServiceSpec() call."""
    tree = ast.parse(ENUM_ALL.read_text(encoding="utf-8"))
    modules = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)
        if name != "ServiceSpec" or len(node.args) < 2:
            continue
        arg = node.args[1]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            modules.append(arg.value)
    return sorted(set(modules))


SERVICE_SPEC_MODULES = _extract_service_spec_modules()


@pytest.mark.parametrize("module_path", SERVICE_SPEC_MODULES)
def test_service_spec_module_is_findable(module_path: str) -> None:
    """The module path must resolve to a real Python module (file must exist)."""
    spec = importlib.util.find_spec(module_path)
    assert spec is not None, (
        f"enum_all ServiceSpec references '{module_path}' but the module cannot be found. "
        "Did you rename or split this module without updating enum_all._SERVICES?"
    )
