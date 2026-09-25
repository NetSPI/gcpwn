"""Contract: every Component with supports_get=True must have a working get() path.

When run_components sees supports_get=True (the default) and the user passes
--get, it calls resource.get(resource_id=..., action_dict=...).

GcpListResource.get() delegates to _get_item(), which calls:
    getattr(self.client, self.GET_METHOD)(name=resource_id)

DiscoveryListResource.get() delegates to _get_request(), which raises
NotImplementedError if not overridden.

If the resource class uses a REST client (client=None) and never overrides
the appropriate hook, get() fails on every resource row.

A GcpListResource-backed Component with supports_get=True is safe if the class:
  1. Has a non-empty GET_METHOD (base _get_item calls the GAPIC method), OR
  2. Overrides _get_item() in its own class dict, OR
  3. Defines a custom get(self, *, resource_id, ...) in its own class dict.

A DiscoveryListResource-backed Component with supports_get=True is safe if:
  1. The class overrides _get_request() in its own class dict, OR
  2. Defines a custom get(self, *, resource_id, ...) in its own class dict.

A Component with supports_get=False is always safe (get() is never called).
"""
from __future__ import annotations

import importlib
import inspect
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _collect_components() -> list[dict[str, Any]]:
    """Return a flat list of {comp_key, cls, module, base} for every Component in every
    gcp/workspace enum module that has supports_get=True."""
    sys.path.insert(0, str(REPO_ROOT))

    from gcpwn.core.resource import DiscoveryListResource, GcpListResource
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
            if not comp.supports_get:
                continue
            cls = comp.resource_cls
            if not isinstance(cls, type):
                continue
            if issubclass(cls, GcpListResource):
                base = "gapic"
            elif issubclass(cls, DiscoveryListResource):
                base = "discovery"
            else:
                continue
            rows.append({
                "comp_key": comp.key,
                "cls": cls,
                "module": mod_path,
                "base": base,
            })
    return rows


COMPONENTS_WITH_GET = _collect_components()


def _cls_has_working_get(cls: type, base: str) -> bool:
    """Return True if the class can safely handle get(resource_id=...)."""
    # Custom get() with resource_id= always works for both base classes
    if "get" in cls.__dict__:
        sig = inspect.signature(cls.__dict__["get"])
        if "resource_id" in sig.parameters:
            return True

    if base == "gapic":
        # Non-empty GET_METHOD -> base _get_item calls getattr(client, GET_METHOD)(name=...)
        if getattr(cls, "GET_METHOD", ""):
            return True
        # Class overrides _get_item in its own __dict__
        if "_get_item" in cls.__dict__:
            return True

    elif base == "discovery":
        # DiscoveryListResource.get() calls _get_request(); must be overridden
        if "_get_request" in cls.__dict__:
            return True

    return False


@pytest.mark.parametrize(
    "row",
    COMPONENTS_WITH_GET,
    ids=[f"{r['cls'].__name__}.{r['comp_key']}" for r in COMPONENTS_WITH_GET],
)
def test_get_support_compat(row: dict) -> None:
    """Component has supports_get=True, so the resource class must support get(resource_id=)."""
    cls = row["cls"]
    base = row["base"]
    assert _cls_has_working_get(cls, base), (
        f"Component {row['comp_key']!r} ({cls.__name__}, {base}) in {row['module']!r} has "
        f"supports_get=True (default) but no working get() path. "
        f"For {base!r} resources: either set supports_get=False, or implement the "
        f"required hook (_get_item/_get_request or GET_METHOD for gapic)."
    )
