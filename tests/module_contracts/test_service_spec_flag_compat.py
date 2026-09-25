"""Contract: ServiceSpec flags must be consistent with each module's argparser.

Each ServiceSpec controls what flags enum_all passes when invoking a sub-module:
  - get=True (default)  -> enum_all passes --get; the module must accept it
  - get=False           -> enum_all never passes --get; the module may reject it
  - iam=True            -> enum_all passes --iam when the user asks for it

If a module's argparser rejects --get but get=False is absent from its
ServiceSpec, enum_all will crash whenever the user runs with --get.

This test imports each service module (via its ServiceSpec path) and probes its
argparser directly -- the same argparser enum_all's built args flow through.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENUM_ALL = REPO_ROOT / "gcpwn" / "modules" / "everything" / "enumeration" / "enum_all.py"


def _extract_service_specs() -> list[dict[str, Any]]:
    """Parse enum_all.py and return a list of {module, get, iam} dicts."""
    tree = ast.parse(ENUM_ALL.read_text(encoding="utf-8"))
    specs = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)
        if name != "ServiceSpec" or len(node.args) < 2:
            continue
        arg = node.args[1]
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
            continue
        module_path = arg.value
        get_val = True   # default
        iam_val = False  # default
        for kw in node.keywords:
            if kw.arg == "get" and isinstance(kw.value, ast.Constant):
                get_val = kw.value.value
            if kw.arg == "iam" and isinstance(kw.value, ast.Constant):
                iam_val = kw.value.value
        specs.append({"module": module_path, "get": get_val, "iam": iam_val})
    return specs


SERVICE_SPECS = _extract_service_specs()

# Only test specs where the flag is True (those are the ones enum_all will
# actually pass to the sub-module). Shims without _parse_args are skipped.
GET_TRUE_SPECS = [s for s in SERVICE_SPECS if s["get"]]
IAM_TRUE_SPECS = [s for s in SERVICE_SPECS if s["iam"]]


def _probe_flag(module_path: str, flag: str) -> bool | None:
    """Return True if the module's _parse_args accepts flag, False if it rejects
    it, None if the module has no _parse_args (e.g. a shim)."""
    try:
        mod = importlib.import_module(module_path)
    except ModuleNotFoundError:
        pytest.skip(f"module {module_path!r} not importable")
    if not hasattr(mod, "_parse_args"):
        return None  # shim module — skip
    try:
        mod._parse_args([flag])
        return True
    except SystemExit:
        return False
    except TypeError:
        # _parse_args takes extra required args (non-standard signature); can't probe
        return None


@pytest.mark.parametrize("spec", GET_TRUE_SPECS, ids=[s["module"].split(".")[-1] for s in GET_TRUE_SPECS])
def test_get_true_module_accepts_get_flag(spec: dict) -> None:
    """A ServiceSpec with get=True (default) must have a module that accepts --get."""
    result = _probe_flag(spec["module"], "--get")
    if result is None:
        pytest.skip(f"{spec['module']!r} is a shim without _parse_args; skip flag probe")
    assert result, (
        f"ServiceSpec for {spec['module']!r} has get=True (default) but the module "
        f"rejects --get. Either add get=False to the ServiceSpec or add --get support "
        f"to the module."
    )


@pytest.mark.parametrize("spec", IAM_TRUE_SPECS, ids=[s["module"].split(".")[-1] for s in IAM_TRUE_SPECS])
def test_iam_true_module_accepts_iam_flag(spec: dict) -> None:
    """A ServiceSpec with iam=True must have a module that accepts --iam."""
    result = _probe_flag(spec["module"], "--iam")
    if result is None:
        pytest.skip(f"{spec['module']!r} is a shim without _parse_args; skip flag probe")
    assert result, (
        f"ServiceSpec for {spec['module']!r} has iam=True but the module rejects --iam."
    )
