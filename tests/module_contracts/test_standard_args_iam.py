"""Contract test: every parse_component_args call must include "iam" and "get" in standard_args.

enum_all passes --iam (when --iam is given) and --get (when --get is given) to
every sub-module whose ServiceSpec has iam=True / get=True respectively. A
parse_component_args call whose standard_args= tuple is missing either flag
causes argparse to raise SystemExit(2) when those flags arrive.

The fix is always to add the flag to standard_args — run_components already
silently no-ops --iam when supports_iam=False and --get when supports_get=False.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULES_ROOT = REPO_ROOT / "gcpwn" / "modules"


def _find_parse_component_args_calls(tree: ast.Module) -> list[ast.Call]:
    """Return every ast.Call node that is a parse_component_args() invocation."""
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (func.id if isinstance(func, ast.Name) else
                func.attr if isinstance(func, ast.Attribute) else None)
        if name == "parse_component_args":
            calls.append(node)
    return calls


def _standard_args_strings(call: ast.Call) -> list[str] | None:
    """Return the string literals in the standard_args= keyword of a call, or None if absent."""
    for kw in call.keywords:
        if kw.arg != "standard_args":
            continue
        val = kw.value
        if isinstance(val, ast.Tuple):
            return [elt.value for elt in val.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
        if isinstance(val, ast.Constant) and val.s is None:
            return []
    return None  # keyword not present


def _module_files_with_parse_component_args() -> list[Path]:
    result = []
    for path in sorted(MODULES_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "parse_component_args" not in text:
            continue
        result.append(path)
    return result


MODULE_FILES = _module_files_with_parse_component_args()


@pytest.mark.parametrize(
    "module_path",
    MODULE_FILES,
    ids=lambda p: p.relative_to(REPO_ROOT).as_posix(),
)
def test_parse_component_args_includes_iam_in_standard_args(module_path: Path) -> None:
    """Every parse_component_args call must register --iam via standard_args."""
    text = module_path.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(text, filename=str(module_path))
    calls = _find_parse_component_args_calls(tree)
    for call in calls:
        strings = _standard_args_strings(call)
        if strings is None:
            # No standard_args keyword at all — no --iam registered → violation.
            pytest.fail(
                f"{module_path.relative_to(REPO_ROOT)}: "
                "parse_component_args() called without standard_args= keyword; "
                'add standard_args=("iam", ...) so --iam is accepted.'
            )
        for required_flag in ("iam", "get"):
            assert required_flag in strings, (
                f"{module_path.relative_to(REPO_ROOT)}: "
                f'standard_args={strings!r} is missing "{required_flag}"; '
                f"passing --{required_flag} to this module will crash with SystemExit(2)."
            )
