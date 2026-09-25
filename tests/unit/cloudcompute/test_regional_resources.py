"""Regression tests for compute regional resource enumeration.

Bug: region_disks, region_instant_snapshots, and resource_policies used
`explicit_region_scope and regions` as the condition to fan out per-region.
Because `explicit_region_scope` is only True when the user explicitly passes
--all-regions / --regions-list / --regions-file, the per-region path was dead
in normal invocations. The fallback called `.list(project_id=...)` without a
region; those three resources have no `aggregated_list`, so they silently
returned [].

Fix: the condition is now `if regions else ...` — the per-region fan-out fires
whenever `regions` is non-empty (populated by `_resolve_regions` with
`require_all=True` for any selected regional component).
"""

from __future__ import annotations

import ast
from pathlib import Path

ENUM_FILE = Path(__file__).resolve().parents[3] / "gcpwn" / "modules" / "gcp" / "cloudcompute" / "enumeration" / "enum_cloudcompute_resources.py"

# The three resources that have no aggregated_list and need the per-region fan-out
AFFECTED_RESOURCES = (
    "region_disks_resource",
    "region_instant_snapshots_resource",
    "resource_policies_resource",
)


def _find_conditional_patterns(source: str, resource_name: str) -> list[str]:
    """Return all ternary `... if <cond> else <resource_name>.list(...)` patterns
    that contain `resource_name` in the else branch, capturing the condition."""
    # Walk AST to find IfExp nodes whose orelse is a Call whose func resolves to
    # `resource_name.list`.
    tree = ast.parse(source)
    conditions = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.IfExp):
            continue
        orelse = node.orelse
        if not isinstance(orelse, ast.Call):
            continue
        func = orelse.func
        if not (isinstance(func, ast.Attribute)
                and func.attr == "list"
                and isinstance(func.value, ast.Name)
                and func.value.id == resource_name):
            continue
        # Found: capture the condition as unparsed source
        conditions.append(ast.unparse(node.test))
    return conditions


def test_region_disks_condition_does_not_require_explicit_scope():
    source = ENUM_FILE.read_text()
    conds = _find_conditional_patterns(source, "region_disks_resource")
    assert conds, "No ternary with region_disks_resource in else-branch found"
    for cond in conds:
        assert "explicit_region_scope" not in cond, (
            f"region_disks uses 'explicit_region_scope' in its list condition: {cond!r}\n"
            "This silently returns [] on normal runs — condition must be just 'if regions'."
        )
        assert "regions" in cond, (
            f"region_disks condition {cond!r} doesn't gate on 'regions'; fan-out may not fire."
        )


def test_region_instant_snapshots_condition_does_not_require_explicit_scope():
    source = ENUM_FILE.read_text()
    conds = _find_conditional_patterns(source, "region_instant_snapshots_resource")
    assert conds, "No ternary with region_instant_snapshots_resource in else-branch found"
    for cond in conds:
        assert "explicit_region_scope" not in cond, (
            f"region_instant_snapshots uses 'explicit_region_scope': {cond!r}\n"
            "Fix: use 'if regions' so fan-out fires even without --all-regions."
        )


def test_resource_policies_condition_does_not_require_explicit_scope():
    source = ENUM_FILE.read_text()
    conds = _find_conditional_patterns(source, "resource_policies_resource")
    assert conds, "No ternary with resource_policies_resource in else-branch found"
    for cond in conds:
        assert "explicit_region_scope" not in cond, (
            f"resource_policies uses 'explicit_region_scope': {cond!r}\n"
            "Fix: use 'if regions' so fan-out fires even without --all-regions."
        )


def test_gapic_resource_list_without_region_returns_empty_for_no_aggregated_list():
    """Unit-level confirmation: a regional GAPIC resource with no aggregated_list
    silently returns [] when called without a region (the broken fallback path)."""
    from gcpwn.modules.gcp.cloudcompute.utilities.helpers import (
        CloudComputeGapicResource,
        CloudComputeGapicResourceSpec,
    )

    class _FakeSession:
        credentials = object()
        debug = False

    class _NoAggregatedListClient:
        """Simulates region_disks / region_instant_snapshots: no aggregated_list."""
        def list(self, request=None):
            return iter([{"name": "should-not-appear"}])
        # aggregated_list intentionally absent

    spec = CloudComputeGapicResourceSpec(
        component_key="region_disks",
        table_name="cloudcompute_region_disks",
        summary_columns=("name",),
        client_attr="RegionDisksClient",
        permission_prefix="compute.disks.",
        action_resource_type="region_disks",
        get_param_name="disk",
        location_scope="region",
    )

    res = object.__new__(CloudComputeGapicResource)
    res.session = _FakeSession()
    res.spec = spec
    res.client = _NoAggregatedListClient()
    res.TABLE_NAME = spec.table_name
    res.COLUMNS = list(spec.summary_columns)
    res.ACTION_RESOURCE_TYPE = spec.action_resource_type
    res.LIST_PERMISSION = "compute.disks.list"
    res.GET_PERMISSION = "compute.disks.get"
    res.TEST_IAM_API_NAME = "compute.disks.testIamPermissions"
    res.TEST_IAM_PERMISSIONS = ()
    res.SUPPORTS_GET = True
    res.SUPPORTS_IAM = True

    # Calling without region triggers the fallback that returns [] (no aggregated_list)
    rows = res.list(project_id="my-proj", action_dict=None)
    assert rows == [], (
        "Without region= and no aggregated_list, list() must return [] "
        "(this is why the per-region fan-out is required for region_disks etc.)"
    )
