"""Unit tests for StorageTransferJobsResource.save() signature.

run_components always calls save(batch, project_id=..., location=...) for
PROJECT-scope components. The original signature was missing `location` which
would cause a TypeError at runtime. This test ensures the method accepts
`location` as a keyword argument.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _resource():
    from gcpwn.modules.gcp.storagetransfer.utilities.helpers import StorageTransferJobsResource

    session = SimpleNamespace(credentials=None, project_id="proj")
    r = StorageTransferJobsResource.__new__(StorageTransferJobsResource)
    r.session = session
    return r


def test_save_accepts_location_kwarg():
    """save() must not raise when called with location=... (as run_components does)."""
    r = _resource()
    row = {"name": "transferJobs/test-job", "status": "ENABLED", "project_id": "proj"}

    with patch("gcpwn.modules.gcp.storagetransfer.utilities.helpers.save_to_table") as mock_save:
        r.save([row], project_id="proj", location="global")
        mock_save.assert_called_once()


def test_save_location_kwarg_is_ignored():
    """location kwarg is accepted but does not affect the saved row."""
    r = _resource()
    row = {"name": "transferJobs/test-job", "status": "ENABLED"}

    with patch("gcpwn.modules.gcp.storagetransfer.utilities.helpers.save_to_table") as mock_save:
        r.save([row], project_id="proj", location="us-central1")
        args, kwargs = mock_save.call_args
        # The table name should be present, not any location injection
        assert args[1] == "storagetransfer_transferjobs"


def test_save_without_location_still_works():
    """save() must also work when location is omitted (backward compatibility)."""
    r = _resource()
    row = {"name": "transferJobs/test-job", "status": "ENABLED"}

    with patch("gcpwn.modules.gcp.storagetransfer.utilities.helpers.save_to_table") as mock_save:
        r.save([row], project_id="proj")
        mock_save.assert_called_once()


def test_save_extra_kwargs_ignored():
    """**_ absorbs any unexpected keyword arguments without raising."""
    r = _resource()
    row = {"name": "transferJobs/test-job", "status": "ENABLED"}

    with patch("gcpwn.modules.gcp.storagetransfer.utilities.helpers.save_to_table") as mock_save:
        r.save([row], project_id="proj", location="global", unknown_future_param="x")
        mock_save.assert_called_once()
