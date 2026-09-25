"""Contract: every Component with supports_iam=True must have TEST_IAM_PERMISSIONS.

When run_components processes a Component with supports_iam=True and the user
passes --iam, it gates the IAM test on:

    getattr(resource, "TEST_IAM_PERMISSIONS", ())

If the resource class doesn't expose TEST_IAM_PERMISSIONS (or it's empty), the
IAM test silently no-ops for every resource row -- the user sees no error but
no permissions are tested.

The fix is either:
  - Add TEST_IAM_PERMISSIONS = permissions_with_prefixes("service.resource.")
    to the resource class, OR
  - Set supports_iam=False on the Component (if IAM testing is not yet supported).
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _collect_iam_components() -> list[dict[str, Any]]:
    """Return a flat list of {comp_key, cls, module} for every Component in every
    gcp/workspace enum module that has supports_iam=True."""
    sys.path.insert(0, str(REPO_ROOT))

    from gcpwn.core.utils.enum_framework import Component

    enum_files = sorted(set(
        list(REPO_ROOT.glob("gcpwn/modules/gcp/**/enum_*.py")) +
        list(REPO_ROOT.glob("gcpwn/modules/workspace/**/enum_*.py"))
    ))

    rows = []
    for f in enum_files:
        mod_path = ".".join(f.with_suffix("").relative_to(REPO_ROOT).parts)
        try:
            mod = importlib.import_module(mod_path)
        except Exception:
            continue

        components = getattr(mod, "COMPONENTS", None)
        if not components:
            continue

        for comp in components:
            if not isinstance(comp, Component):
                continue
            if not comp.supports_iam:
                continue
            rows.append({
                "comp_key": comp.key,
                "cls": comp.resource_cls,
                "module": mod_path,
            })
    return rows


COMPONENTS_WITH_IAM = _collect_iam_components()


def _cls_has_iam_permissions(cls: type) -> bool:
    """Return True if the class exposes a non-empty TEST_IAM_PERMISSIONS."""
    # Instantiate minimally to support @property implementations
    try:
        obj = object.__new__(cls)
    except TypeError:
        return False
    val = getattr(obj, "TEST_IAM_PERMISSIONS", None)
    if val is None:
        # Fall back to class-level attribute (covers plain class vars)
        val = getattr(cls, "TEST_IAM_PERMISSIONS", None)
    return bool(val)


@pytest.mark.parametrize(
    "row",
    COMPONENTS_WITH_IAM,
    ids=[f"{r['cls'].__name__}.{r['comp_key']}" for r in COMPONENTS_WITH_IAM],
)
def test_iam_support_compat(row: dict) -> None:
    """Component has supports_iam=True, so the resource class must have TEST_IAM_PERMISSIONS."""
    cls = row["cls"]
    assert _cls_has_iam_permissions(cls), (
        f"Component {row['comp_key']!r} ({cls.__name__}) in {row['module']!r} has "
        f"supports_iam=True but TEST_IAM_PERMISSIONS is missing or empty. "
        f"Either add TEST_IAM_PERMISSIONS = permissions_with_prefixes('service.resource.') "
        f"to the resource class, or set supports_iam=False on the Component."
    )
