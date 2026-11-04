"""Regression test for compute regional resource enumeration.

Region-scoped resources (region_disks, region_instant_snapshots, resource_policies)
have no aggregated_list, so calling .list() without a region silently returns [].
The per-region fan-out must fire whenever a non-empty regions list is resolved,
not only when the user explicitly passes --all-regions.
"""

from __future__ import annotations


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
