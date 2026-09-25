"""Unit tests for CloudRunWorkerPoolsResource._extra_save_fields.

Covers the bug where automatic-scaling min_instance_count was always stored as 0
because the code checked the camelCase key (minInstanceCount) that is already
normalized to snake_case before _extra_save_fields receives the dict.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest


def _resource():
    from gcpwn.modules.gcp.cloudrun.utilities.helpers import CloudRunWorkerPoolsResource

    session = SimpleNamespace(credentials=None, project_id="proj")
    r = CloudRunWorkerPoolsResource.__new__(CloudRunWorkerPoolsResource)
    r.session = session
    return r


@pytest.mark.parametrize(
    "raw,expected_min,expected_sa",
    [
        # Automatic scaling path: min_instance_count on the scaling dict (snake_case)
        (
            {
                "template": {"service_account": "sa@project.iam.gserviceaccount.com"},
                "scaling": {"min_instance_count": 3, "max_instance_count": 10},
            },
            3,
            "sa@project.iam.gserviceaccount.com",
        ),
        # Manual scaling path: manual_instance_count on the scaling dict
        (
            {
                "template": {"service_account": "manual-sa@project.iam.gserviceaccount.com"},
                "scaling": {"manual_instance_count": 5},
            },
            5,
            "manual-sa@project.iam.gserviceaccount.com",
        ),
        # No scaling configured → 0
        (
            {
                "template": {"service_account": "sa@project.iam.gserviceaccount.com"},
                "scaling": {},
            },
            0,
            "sa@project.iam.gserviceaccount.com",
        ),
        # No template → empty service account
        (
            {
                "scaling": {"min_instance_count": 2},
            },
            2,
            "",
        ),
        # camelCase keys (pre-normalization form) must NOT appear in the normalized raw
        # dict, so the code must not rely on them.
        (
            {
                "template": {"service_account": "ok@project.iam.gserviceaccount.com"},
                # Deliberately only snake_case (as save_to_table normalizes before calling)
                "scaling": {"min_instance_count": 7},
            },
            7,
            "ok@project.iam.gserviceaccount.com",
        ),
    ],
    ids=[
        "auto_scaling",
        "manual_scaling",
        "empty_scaling",
        "no_template",
        "snake_case_only",
    ],
)
def test_worker_pool_extra_save_fields(raw, expected_min, expected_sa):
    r = _resource()
    result = r._extra_save_fields(raw)
    assert result["min_instance_count"] == expected_min, (
        f"Expected min_instance_count={expected_min!r}, got {result['min_instance_count']!r}"
    )
    assert result["service_account"] == expected_sa, (
        f"Expected service_account={expected_sa!r}, got {result['service_account']!r}"
    )
