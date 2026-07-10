"""Unit coverage for the config-driven GAPIC compute base that replaced 17
hand-written enumeration classes.

We never build a real ``compute_v1`` client: ``CloudComputeGapicResource`` is
constructed with ``object.__new__`` to bypass the client-building ``__init__``,
then we set ``.session``/``.spec``/``.client`` (a fake exposing ``list``/``get``)
and the derived attrs the methods read. This keeps the tests offline and
deterministic while still exercising the real list/get/reference_from_row logic
and the request-shaping that branches on ``location_scope``.
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from gcpwn.modules.gcp.cloudcompute.utilities.helpers import (
    CLOUDCOMPUTE_GAPIC_RESOURCE_SPECS,
    CloudComputeGapicResource,
    CloudComputeGapicResourceSpec,
)


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #
class _FakeSession:
    """Bare session stand-in; the base only touches ``.credentials`` in
    ``__init__`` (which we skip) so nothing here is exercised by the methods."""

    credentials = object()
    debug = False


class _RecordingClient:
    """Fake GAPIC client. ``list``/``get`` record the request dict they were
    called with and return canned rows, so we can assert request-shaping."""

    def __init__(self, list_rows=None, get_row=None):
        self._list_rows = list(list_rows or [])
        self._get_row = get_row
        self.list_requests: list[dict] = []
        self.get_requests: list[dict] = []

    def list(self, request=None):
        self.list_requests.append(dict(request or {}))
        # GAPIC list pagers are iterable; return an iterator so the base's
        # ``list(self.client.list(...))`` materializes it.
        return iter(self._list_rows)

    def get(self, request=None):
        self.get_requests.append(dict(request or {}))
        return self._get_row


def _make_action_accumulators() -> dict:
    """A defaultdict tree mirroring the action_dict shape modules build."""
    return defaultdict(lambda: defaultdict(lambda: defaultdict(set)))


def _spec(scope: str = "global", *, get_param_name: str | None = "thing"):
    return CloudComputeGapicResourceSpec(
        component_key="widgets",
        table_name="cloudcompute_widgets",
        summary_columns=("name",),
        client_attr="WidgetsClient",
        permission_prefix="compute.widgets.",
        action_resource_type="widgets",
        get_param_name=get_param_name,
        location_scope=scope,
    )


def _make_resource(
    spec: CloudComputeGapicResourceSpec,
    *,
    client: _RecordingClient | None = None,
) -> CloudComputeGapicResource:
    """Build the resource without invoking the client-building __init__."""
    res = object.__new__(CloudComputeGapicResource)
    res.session = _FakeSession()
    res.spec = spec
    res.client = client if client is not None else _RecordingClient()
    res.TABLE_NAME = spec.table_name
    res.COLUMNS = list(spec.summary_columns)
    res.ACTION_RESOURCE_TYPE = spec.action_resource_type
    res.LIST_PERMISSION = spec.permission_prefix + "list"
    res.GET_PERMISSION = spec.permission_prefix + "get"
    res.TEST_IAM_API_NAME = spec.permission_prefix + "testIamPermissions"
    res.TEST_IAM_PERMISSIONS = spec.test_iam_permissions or ()
    res.SUPPORTS_GET = bool(spec.get_param_name)
    res.SUPPORTS_IAM = True
    return res


# --------------------------------------------------------------------------- #
# list() -- request shaping per location_scope
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "scope, location_kwargs, list_rows, expected_request",
    [
        # global scope builds a project-only request (also covers the folded
        # "runs even without region or zone" case -- same input, no new branch).
        ("global", {}, [{"name": "a"}, {"name": "b"}], {"project": "proj-1"}),
        # region scope adds the region.
        ("region", {"region": "us-central1"}, [{"name": "r"}], {"project": "proj-1", "region": "us-central1"}),
        # zone scope adds the zone.
        ("zone", {"zone": "us-central1-a"}, [{"name": "z"}], {"project": "proj-1", "zone": "us-central1-a"}),
    ],
    ids=["global", "region", "zone"],
)
def test_list_request_shaping_per_scope(scope, location_kwargs, list_rows, expected_request):
    client = _RecordingClient(list_rows=list_rows)
    res = _make_resource(_spec(scope), client=client)

    rows = res.list(project_id="proj-1", action_dict=None, **location_kwargs)

    assert rows == list_rows
    assert client.list_requests == [expected_request]


def test_list_region_scope_does_not_leak_zone_param():
    client = _RecordingClient(list_rows=[])
    res = _make_resource(_spec("region"), client=client)

    res.list(project_id="proj-1", region="us-east1", zone="us-east1-b", action_dict=None)

    # region scope only ever sets "region", never "zone"
    assert client.list_requests == [{"project": "proj-1", "region": "us-east1"}]


# --------------------------------------------------------------------------- #
# list() -- empty short-circuit when scoped but no location supplied
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "scope, none_kwarg",
    [
        ("region", {"region": None}),
        ("zone", {"zone": None}),
    ],
    ids=["region_none", "zone_none"],
)
def test_list_scoped_returns_empty_when_location_none(scope, none_kwarg):
    client = _RecordingClient(list_rows=[{"name": "should-not-appear"}])
    res = _make_resource(_spec(scope), client=client)

    rows = res.list(project_id="proj-1", action_dict=None, **none_kwarg)

    assert rows == []
    # client.list must not have been called -- short-circuit before the API hop.
    assert client.list_requests == []


# --------------------------------------------------------------------------- #
# list() -- permission recording
# --------------------------------------------------------------------------- #
def test_list_records_list_permission_on_success():
    client = _RecordingClient(list_rows=[{"name": "a"}])
    res = _make_resource(_spec("global"), client=client)
    action_dict = _make_action_accumulators()

    res.list(project_id="proj-1", action_dict=action_dict)

    assert "compute.widgets.list" in action_dict["project_permissions"]["proj-1"]


def test_list_does_not_record_when_short_circuited():
    res = _make_resource(_spec("region"), client=_RecordingClient(list_rows=[]))
    action_dict = _make_action_accumulators()

    res.list(project_id="proj-1", region=None, action_dict=action_dict)

    # Nothing recorded -- the defaultdict tree stays empty of real entries.
    assert "proj-1" not in action_dict.get("project_permissions", {})


def test_list_accepts_none_action_dict():
    client = _RecordingClient(list_rows=[{"name": "a"}])
    res = _make_resource(_spec("global"), client=client)

    # record_permissions tolerates action_dict=None; list must not raise.
    assert res.list(project_id="proj-1", action_dict=None) == [{"name": "a"}]


# --------------------------------------------------------------------------- #
# get() -- request shaping + SUPPORTS_GET gating
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "scope, location_kwargs, expected_request",
    [
        ("global", {}, {"project": "proj-1", "widget": "w1"}),
        ("region", {"region": "us-central1"}, {"project": "proj-1", "region": "us-central1", "widget": "w1"}),
        ("zone", {"zone": "us-central1-a"}, {"project": "proj-1", "zone": "us-central1-a", "widget": "w1"}),
    ],
    ids=["global", "region", "zone"],
)
def test_get_request_shaping_per_scope(scope, location_kwargs, expected_request):
    client = _RecordingClient(get_row={"name": "w1"})
    res = _make_resource(_spec(scope, get_param_name="widget"), client=client)

    row = res.get(project_id="proj-1", resource_id="w1", action_dict=None, **location_kwargs)

    assert row == {"name": "w1"}
    assert client.get_requests == [expected_request]


def test_get_records_get_permission_in_action_dict():
    # get records GET_PERMISSION under the resource_type tree, keyed by label.
    client = _RecordingClient(get_row={"name": "w1"})
    res = _make_resource(_spec("global", get_param_name="widget"), client=client)
    action_dict = _make_action_accumulators()

    res.get(project_id="proj-1", resource_id="w1", action_dict=action_dict)

    assert "w1" in action_dict["proj-1"]["compute.widgets.get"]["widgets"]


def test_get_returns_none_when_not_supported():
    # get_param_name=None => SUPPORTS_GET False => get() is a no-op returning None.
    client = _RecordingClient(get_row={"name": "w1"})
    res = _make_resource(_spec("global", get_param_name=None), client=client)

    assert res.get(project_id="proj-1", resource_id="w1", action_dict=None) is None
    # The client must never be hit when get is unsupported.
    assert client.get_requests == []


# --------------------------------------------------------------------------- #
# reference_from_row()
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "scope, row, expected_ref",
    [
        ("global", {"name": "widget-a"}, {"resource_id": "widget-a"}),
        ("region", {"name": "widget-a", "region": "us-central1"}, {"resource_id": "widget-a", "region": "us-central1"}),
        ("zone", {"name": "widget-a", "zone": "us-central1-a"}, {"resource_id": "widget-a", "zone": "us-central1-a"}),
    ],
    ids=["global", "region", "zone"],
)
def test_reference_from_row_per_scope(scope, row, expected_ref):
    res = _make_resource(_spec(scope))
    assert res.reference_from_row(row) == expected_ref


def test_reference_from_row_region_from_self_link_path():
    # When "region" is a full URL/path, it is normalized to the tail segment.
    res = _make_resource(_spec("region"))
    ref = res.reference_from_row(
        {"name": "w", "region": "https://x/projects/p/regions/europe-west1"}
    )
    assert ref == {"resource_id": "w", "region": "europe-west1"}


def test_reference_from_row_missing_name_yields_empty_resource_id():
    res = _make_resource(_spec("global"))
    ref = res.reference_from_row({})
    assert ref == {"resource_id": ""}


# --------------------------------------------------------------------------- #
# CLOUDCOMPUTE_GAPIC_RESOURCE_SPECS registry
# --------------------------------------------------------------------------- #
def test_registry_has_seventeen_specs():
    assert len(CLOUDCOMPUTE_GAPIC_RESOURCE_SPECS) == 17


def test_registry_scope_distribution():
    scopes = [s.location_scope for s in CLOUDCOMPUTE_GAPIC_RESOURCE_SPECS.values()]
    assert scopes.count("global") == 7
    assert scopes.count("region") == 6
    assert scopes.count("zone") == 4


@pytest.mark.parametrize(
    "key, scope",
    [
        ("backend_buckets", "global"),   # representative global
        ("node_templates", "region"),    # representative region
        ("node_groups", "zone"),         # representative zone
    ],
)
def test_registry_representative_scope_trio(key, scope):
    spec = CLOUDCOMPUTE_GAPIC_RESOURCE_SPECS[key]
    assert spec.location_scope == scope
    # component_key in the registry should match the dict key.
    assert spec.component_key == key


def test_registry_every_value_is_a_spec_with_consistent_key():
    for key, spec in CLOUDCOMPUTE_GAPIC_RESOURCE_SPECS.items():
        assert isinstance(spec, CloudComputeGapicResourceSpec)
        assert spec.component_key == key
        assert spec.table_name.startswith("cloudcompute_")
        assert spec.permission_prefix.startswith("compute.")
        assert spec.location_scope in {"global", "region", "zone"}
