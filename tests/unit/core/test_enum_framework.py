"""Unit coverage for ``gcpwn.core.utils.enum_framework`` -- the declarative
enumeration runner that 25+ ``enum_<service>`` modules depend on.

The runner is driven with a fake session (records ``get_data``/``insert_actions``
and exposes ``project_id``) and fake resource classes whose ``list``/``get``/
``test_iam_permissions``/``save`` return/record plain dict rows keyed by
``name``. No GCP client, credential, or network is ever touched: the resource
classes are constructed straight from the session and never reach Google.

Each test exercises one runner contract:
  * resolve_selected_components: nothing selected -> all; one selected -> only it
  * REGION / PROJECT / NESTED scope plumbing (locations, parents)
  * NESTED parent fallback to the DB cache when the parent isn't selected
  * NESTED parent resolution from MANUAL parent names (with/without an
    enumerated row to keep parent_filter fields)
  * parent_filter, enrich_fn, persist=False, summarize=False
  * credname_override threaded to insert_actions
  * supports_get / supports_iam gating, manual --X-ids name lists
  * the "No <title> found" vs print_missing_dependency messaging
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from gcpwn.core.utils import enum_framework as ef
from gcpwn.core.utils.enum_framework import NESTED, PROJECT, REGION, Component, run_components


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeSession:
    """Records the data API surface the runner touches."""

    def __init__(self, project_id="proj-1", cache=None):
        self.project_id = project_id
        # cache maps TABLE_NAME -> list[dict] returned by get_data
        self._cache = dict(cache or {})
        self.get_data_calls: list[dict] = []
        self.insert_actions_calls: list[dict] = []

    def get_data(self, table, columns="*", conditions=None, *, where=None, params=None):
        self.get_data_calls.append(
            {"table": table, "columns": columns, "conditions": conditions,
             "where": dict(where) if where else None, "params": tuple(params or ())}
        )
        return list(self._cache.get(table, []))

    def insert_actions(self, action_dict, project_id, *, column_name=None,
                       evidence_type=None, credname_override=None):
        self.insert_actions_calls.append(
            {"project_id": project_id, "column_name": column_name,
             "evidence_type": evidence_type, "credname_override": credname_override}
        )


def make_resource_cls(
    *,
    table_name="fake_table",
    columns=("location", "name"),
    test_iam=("perm.get",),
    list_returns=None,
    get_returns=None,
):
    """Build a fake resource class. ``list_returns`` / ``get_returns`` may be a
    dict keyed by location/parent/name, or a flat list returned for every key."""

    class FakeResource:
        TABLE_NAME = table_name
        COLUMNS = list(columns)
        TEST_IAM_PERMISSIONS = tuple(test_iam)

        instances: list = []

        def __init__(self, session):
            self.session = session
            self.list_calls: list[dict] = []
            self.get_calls: list[dict] = []
            self.iam_calls: list[str] = []
            self.save_calls: list[dict] = []
            FakeResource.instances.append(self)

        def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **extra):
            self.list_calls.append(
                {"project_id": project_id, "location": location, "parent": parent, "extra": dict(extra)}
            )
            if list_returns is None:
                return []
            if isinstance(list_returns, dict):
                key = parent if parent is not None else location
                return list(list_returns.get(key, []))
            return list(list_returns)

        def get(self, *, resource_id=None, action_dict=None, **extra):
            self.get_calls.append({"resource_id": resource_id, "extra": dict(extra)})
            if get_returns is None:
                # default: echo a hydrated row carrying its own name
                return {"name": resource_id, "hydrated": True}
            if isinstance(get_returns, dict):
                return get_returns.get(resource_id)
            return dict(get_returns)

        def test_iam_permissions(self, *, resource_id=None, action_dict=None):
            self.iam_calls.append(resource_id)
            # populate the accumulator so flush_actions -> insert_actions fires
            if action_dict is not None:
                action_dict[resource_id]["perm.get"]["allow"].add("ok")

        def save(self, rows, *, project_id=None, location=None, **kwargs):
            self.save_calls.append(
                {"rows": list(rows), "project_id": project_id, "location": location, "kwargs": dict(kwargs)}
            )

    return FakeResource


def make_args(**overrides):
    base = dict(get=False, iam=False, threads=1)
    base.update(overrides)
    return SimpleNamespace(**base)


def loc_name(location, ident):
    return f"projects/proj-1/locations/{location}/things/{ident}"


# --------------------------------------------------------------------------- #
# resolve_selected_components plumbing
# --------------------------------------------------------------------------- #
def test_no_component_flag_selects_all_components():
    a_cls = make_resource_cls(table_name="a", list_returns=[{"name": loc_name("global", "a1")}])
    b_cls = make_resource_cls(table_name="b", list_returns=[{"name": loc_name("global", "b1")}])
    comps = [
        Component(key="a", resource_cls=a_cls, title="A", primary_resource="a", scope=PROJECT),
        Component(key="b", resource_cls=b_cls, title="B", primary_resource="b", scope=PROJECT),
    ]
    session = FakeSession()
    out = run_components(session, make_args(), components=comps, column_name="col")
    assert set(out) == {"a", "b"}
    assert a_cls.instances[0].list_calls and b_cls.instances[0].list_calls


def test_one_component_flag_selects_only_that_component():
    a_cls = make_resource_cls(table_name="a", list_returns=[{"name": loc_name("global", "a1")}])
    b_cls = make_resource_cls(table_name="b", list_returns=[{"name": loc_name("global", "b1")}])
    comps = [
        Component(key="a", resource_cls=a_cls, title="A", primary_resource="a", scope=PROJECT),
        Component(key="b", resource_cls=b_cls, title="B", primary_resource="b", scope=PROJECT),
    ]
    session = FakeSession()
    out = run_components(session, make_args(a=True), components=comps, column_name="col")
    # only "a" ran; "b" not even keyed into discovered
    assert set(out) == {"a"}
    assert a_cls.instances[0].list_calls
    assert b_cls.instances[0].list_calls == []


# --------------------------------------------------------------------------- #
# Scope plumbing: REGION / PROJECT / NESTED
# --------------------------------------------------------------------------- #
def test_region_scope_fans_out_over_region_resolver():
    rows = {
        "us-central1": [{"name": loc_name("us-central1", "x")}],
        "europe-west1": [{"name": loc_name("europe-west1", "y")}],
    }
    cls = make_resource_cls(list_returns=rows)
    comp = Component(key="r", resource_cls=cls, title="Regional", primary_resource="thing", scope=REGION)
    session = FakeSession()

    seen_args = {}

    def resolver(sess, args):
        seen_args["called"] = True
        return ["us-central1", "europe-west1"]

    out = run_components(session, make_args(), components=[comp], column_name="col",
                         region_resolver=resolver)
    assert seen_args.get("called")
    inst = cls.instances[0]
    listed_locations = {c["location"] for c in inst.list_calls}
    assert listed_locations == {"us-central1", "europe-west1"}
    # both regions saved with their own location
    saved_locs = {s["location"] for s in inst.save_calls}
    assert saved_locs == {"us-central1", "europe-west1"}
    assert len(out["r"]) == 2


def test_region_scope_fixed_locations_skip_resolver():
    cls = make_resource_cls(list_returns={"asia-east1": [{"name": loc_name("asia-east1", "z")}]})
    comp = Component(key="r", resource_cls=cls, title="Regional", primary_resource="thing",
                     scope=REGION, locations=["asia-east1"])
    session = FakeSession()

    def resolver(sess, args):  # pragma: no cover - must not be called
        raise AssertionError("region_resolver must not run when locations are fixed")

    run_components(session, make_args(), components=[comp], column_name="col", region_resolver=resolver)
    assert [c["location"] for c in cls.instances[0].list_calls] == ["asia-east1"]


def test_region_scope_without_resolver_or_locations_defaults_to_global():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "g")}]})
    comp = Component(key="r", resource_cls=cls, title="Regional", primary_resource="thing", scope=REGION)
    session = FakeSession()
    run_components(session, make_args(), components=[comp], column_name="col")
    assert [c["location"] for c in cls.instances[0].list_calls] == ["global"]


def test_project_scope_lists_global_with_project_id():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "p")}]})
    comp = Component(key="p", resource_cls=cls, title="ProjThing", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    run_components(session, make_args(), components=[comp], column_name="col")
    call = cls.instances[0].list_calls[0]
    assert call["location"] == "global"
    assert call["project_id"] == "proj-1"


def test_nested_scope_lists_under_each_discovered_parent():
    parent_rows = [{"name": "parents/p1"}, {"name": "parents/p2"}]
    parent_cls = make_resource_cls(table_name="parents", list_returns={"global": parent_rows})
    child_cls = make_resource_cls(
        table_name="children",
        list_returns={"parents/p1": [{"name": "parents/p1/children/c1"}],
                      "parents/p2": [{"name": "parents/p2/children/c2"}]},
    )
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT)
    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent",
                      save_parent_kwarg="parent_name")
    session = FakeSession()
    out = run_components(session, make_args(), components=[parent, child], column_name="col")
    child_inst = child_cls.instances[0]
    parents_listed = {c["parent"] for c in child_inst.list_calls}
    assert parents_listed == {"parents/p1", "parents/p2"}
    # save carries the parent name via save_parent_kwarg
    assert all("parent_name" in s["kwargs"] for s in child_inst.save_calls)
    assert {s["kwargs"]["parent_name"] for s in child_inst.save_calls} == {"parents/p1", "parents/p2"}
    assert len(out["child"]) == 2


# --------------------------------------------------------------------------- #
# NESTED parent fallback to the DB cache (parent not selected this run)
# --------------------------------------------------------------------------- #
def test_nested_parent_falls_back_to_db_cache_when_parent_not_selected():
    parent_cls = make_resource_cls(table_name="parents_tbl")
    child_cls = make_resource_cls(
        table_name="children",
        list_returns={"parents/cached": [{"name": "parents/cached/children/cc"}]},
    )
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT)
    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent")
    # Only the child is selected; parent rows come from the cache.
    session = FakeSession(cache={"parents_tbl": [{"name": "parents/cached"}]})
    out = run_components(session, make_args(child=True), components=[parent, child], column_name="col")
    # cache was consulted for the parent table
    assert any(c["table"] == "parents_tbl" for c in session.get_data_calls)
    assert [c["parent"] for c in child_cls.instances[0].list_calls] == ["parents/cached"]
    assert len(out["child"]) == 1


def test_nested_parent_filter_pulls_filter_columns_from_cache():
    parent_cls = make_resource_cls(table_name="parents_tbl", columns=("name", "kind"))
    child_cls = make_resource_cls(table_name="children", list_returns={"parents/keep": [{"name": "x"}]})
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT)
    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent",
                      parent_filter=lambda row: row.get("kind") == "good")
    session = FakeSession(cache={"parents_tbl": [
        {"name": "parents/keep", "kind": "good"},
        {"name": "parents/drop", "kind": "bad"},
    ]})
    run_components(session, make_args(child=True), components=[parent, child], column_name="col")
    # cache fetch requested the filter column too
    cache_call = next(c for c in session.get_data_calls if c["table"] == "parents_tbl")
    assert "kind" in cache_call["columns"]
    # only the matching parent was listed under
    assert [c["parent"] for c in child_cls.instances[0].list_calls] == ["parents/keep"]


# --------------------------------------------------------------------------- #
# NESTED parent resolution from MANUAL parent names (recent feature)
# --------------------------------------------------------------------------- #
def test_nested_manual_parent_names_nest_without_get():
    """Parent targeted by manual --parent-ids must nest even though the parent
    was never hydrated (no --get). Synthesizes a name-only parent."""
    parent_cls = make_resource_cls(table_name="parents_tbl")
    child_cls = make_resource_cls(
        table_name="children",
        list_returns={"parents/manual": [{"name": "parents/manual/children/m"}]},
    )
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT,
                       manual_id_arg="parent_ids")
    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent")
    session = FakeSession()
    # manual parent names supplied, no --get; child explicitly selected too
    args = make_args(child=True, parent_ids="parents/manual", parent_ids_file=None)
    out = run_components(session, args, components=[parent, child], column_name="col")
    assert [c["parent"] for c in child_cls.instances[0].list_calls] == ["parents/manual"]
    assert len(out["child"]) == 1
    # cache must NOT be consulted for the parent when manual names are present
    assert not any(c["table"] == "parents_tbl" for c in session.get_data_calls)


def test_nested_manual_parent_prefers_enumerated_row_to_keep_filter_fields():
    """When the parent was both hydrated this run (carrying fields, via manual
    --parent-ids + --get) AND named manually, the runner must reuse the
    enumerated/hydrated row so parent_filter still sees its fields, not a bare
    name-only stub."""
    # parent get() returns a row carrying the filter field "kind"
    parent_cls = make_resource_cls(
        table_name="parents_tbl", columns=("name", "kind"),
        get_returns={"parents/m": {"name": "parents/m", "kind": "good"}},
    )
    child_cls = make_resource_cls(table_name="children",
                                  list_returns={"parents/m": [{"name": "c"}]})
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT,
                       manual_id_arg="parent_ids")
    seen_filter_rows: list[dict] = []

    def _filter(row):
        seen_filter_rows.append(dict(row))
        return row.get("kind") == "good"

    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent",
                      parent_filter=_filter)
    session = FakeSession()
    # --get hydrates the manual parent into discovered with its "kind" field
    args = make_args(get=True, child=True, parent_ids="parents/m", parent_ids_file=None)
    out = run_components(session, args, components=[parent, child], column_name="col")
    # filter saw the hydrated row with its 'kind' field, so the parent passed
    assert any(r.get("kind") == "good" for r in seen_filter_rows)
    assert [c["parent"] for c in child_cls.instances[0].list_calls] == ["parents/m"]
    assert len(out["child"]) == 1


# --------------------------------------------------------------------------- #
# enrich_fn
# --------------------------------------------------------------------------- #
def test_enrich_fn_runs_before_save_and_can_replace_rows():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "orig")}]})
    captured = {}

    def enrich(rows, *, resource, args, api_actions):
        captured["count"] = len(rows)
        # replace the row entirely
        return [{"name": loc_name("global", "enriched"), "secret": "abc"}]

    comp = Component(key="e", resource_cls=cls, title="E", primary_resource="thing",
                     scope=PROJECT, enrich_fn=enrich)
    session = FakeSession()
    out = run_components(session, make_args(), components=[comp], column_name="col")
    assert captured["count"] == 1
    saved_rows = cls.instances[0].save_calls[0]["rows"]
    assert saved_rows[0]["secret"] == "abc"
    assert out["e"][0]["secret"] == "abc"


# --------------------------------------------------------------------------- #
# persist=False / summarize=False
# --------------------------------------------------------------------------- #
def test_persist_false_never_calls_save():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="np", resource_cls=cls, title="NoPersist", primary_resource="thing",
                     scope=PROJECT, persist=False)
    session = FakeSession()
    out = run_components(session, make_args(), components=[comp], column_name="col")
    assert cls.instances[0].save_calls == []
    # rows still returned even though not persisted
    assert len(out["np"]) == 1


def test_summarize_false_skips_summary_wrapup(monkeypatch):
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="ns", resource_cls=cls, title="NoSummary", primary_resource="thing",
                     scope=PROJECT, summarize=False)
    calls = []
    monkeypatch.setattr(ef.UtilityTools, "summary_wrapup",
                        staticmethod(lambda *a, **k: calls.append(a)))
    session = FakeSession()
    run_components(session, make_args(), components=[comp], column_name="col")
    assert calls == []


def test_summarize_true_calls_summary_wrapup_with_rows(monkeypatch):
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="s", resource_cls=cls, title="Summary", primary_resource="thing", scope=PROJECT)
    calls = []
    monkeypatch.setattr(ef.UtilityTools, "summary_wrapup",
                        staticmethod(lambda *a, **k: calls.append((a, k))))
    session = FakeSession()
    run_components(session, make_args(), components=[comp], column_name="col")
    assert len(calls) == 1
    args_passed, _ = calls[0]
    # (project_id, title, rows, columns, ...)
    assert args_passed[0] == "proj-1"
    assert args_passed[1] == "Summary"
    assert len(args_passed[2]) == 1


# --------------------------------------------------------------------------- #
# credname_override -> flush_actions -> insert_actions
# --------------------------------------------------------------------------- #
def test_credname_override_threaded_to_insert_actions():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="c", resource_cls=cls, title="C", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    run_components(session, make_args(iam=True), components=[comp], column_name="mycol",
                   credname_override="hmac-sa@x")
    assert session.insert_actions_calls, "iam testIamPermissions should record actions"
    for call in session.insert_actions_calls:
        assert call["credname_override"] == "hmac-sa@x"
        assert call["column_name"] == "mycol"


def test_no_actions_recorded_means_no_insert_actions():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="c", resource_cls=cls, title="C", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    # iam=False so test_iam_permissions never runs -> accumulators stay empty
    run_components(session, make_args(iam=False), components=[comp], column_name="col")
    assert session.insert_actions_calls == []


# --------------------------------------------------------------------------- #
# supports_get / supports_iam gating
# --------------------------------------------------------------------------- #
def test_supports_get_false_never_calls_get_even_with_get_flag():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="g", resource_cls=cls, title="G", primary_resource="thing",
                     scope=PROJECT, supports_get=False)
    session = FakeSession()
    run_components(session, make_args(get=True), components=[comp], column_name="col")
    assert cls.instances[0].get_calls == []


def test_get_flag_hydrates_when_supported():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="g", resource_cls=cls, title="G", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    out = run_components(session, make_args(get=True), components=[comp], column_name="col")
    assert [c["resource_id"] for c in cls.instances[0].get_calls] == [loc_name("global", "x")]
    assert out["g"][0].get("hydrated") is True


def test_supports_iam_false_never_calls_test_iam_and_prints_message(capsys):
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="i", resource_cls=cls, title="I", primary_resource="thing",
                     scope=PROJECT, supports_iam=False,
                     iam_unsupported_message="[*] IAM not supported here")
    session = FakeSession()
    run_components(session, make_args(iam=True), components=[comp], column_name="col")
    assert cls.instances[0].iam_calls == []
    assert "IAM not supported here" in capsys.readouterr().out


def test_iam_flag_calls_test_iam_when_supported():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]})
    comp = Component(key="i", resource_cls=cls, title="I", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    run_components(session, make_args(iam=True), components=[comp], column_name="col")
    assert cls.instances[0].iam_calls == [loc_name("global", "x")]


def test_iam_skipped_when_resource_has_no_test_iam_permissions():
    cls = make_resource_cls(list_returns={"global": [{"name": loc_name("global", "x")}]},
                            test_iam=())
    comp = Component(key="i", resource_cls=cls, title="I", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    run_components(session, make_args(iam=True), components=[comp], column_name="col")
    assert cls.instances[0].iam_calls == []
    assert session.insert_actions_calls == []


# --------------------------------------------------------------------------- #
# Manual name-list (--X-ids) handling
# --------------------------------------------------------------------------- #
def test_manual_ids_select_component_and_hydrate_with_get():
    target = "projects/proj-1/locations/global/things/manual1"
    cls = make_resource_cls(get_returns={target: {"name": target, "hydrated": True}})
    comp = Component(key="m", resource_cls=cls, title="M", primary_resource="thing",
                     scope=PROJECT, manual_id_arg="thing_ids")
    session = FakeSession()
    args = make_args(get=True, thing_ids=target, thing_ids_file=None)
    out = run_components(session, args, components=[comp], column_name="col")
    # manual ids imply selection + direct get(), not list()
    assert cls.instances[0].list_calls == []
    assert [c["resource_id"] for c in cls.instances[0].get_calls] == [target]
    assert out["m"][0]["hydrated"] is True
    assert cls.instances[0].save_calls  # persisted


def test_manual_ids_without_get_runs_iam_only_and_skips_summary(capsys):
    target = "projects/proj-1/locations/global/things/manual1"
    cls = make_resource_cls()
    comp = Component(key="m", resource_cls=cls, title="M", primary_resource="thing",
                     scope=PROJECT, manual_id_arg="thing_ids")
    session = FakeSession()
    args = make_args(iam=True, thing_ids=target, thing_ids_file=None)
    out = run_components(session, args, components=[comp], column_name="col")
    # no --get -> no hydrate, but IAM still targets the named resource
    assert cls.instances[0].get_calls == []
    assert cls.instances[0].iam_calls == [target]
    assert out["m"] == []
    assert "without --get; skipping summary" in capsys.readouterr().out


def test_manual_template_builds_full_resource_names():
    cls = make_resource_cls(get_returns={"projects/proj-1/things/t1": {"name": "projects/proj-1/things/t1"}})
    comp = Component(key="m", resource_cls=cls, title="M", primary_resource="thing", scope=PROJECT,
                     manual_id_arg="thing_ids",
                     manual_template=("projects", "{project_id}", "things", 0))
    session = FakeSession()
    args = make_args(get=True, thing_ids="t1", thing_ids_file=None)
    run_components(session, args, components=[comp], column_name="col")
    assert [c["resource_id"] for c in cls.instances[0].get_calls] == ["projects/proj-1/things/t1"]


def test_manual_template_invalid_token_aborts_run(capsys):
    cls = make_resource_cls()
    comp = Component(key="m", resource_cls=cls, title="M", primary_resource="thing", scope=PROJECT,
                     manual_id_arg="thing_ids",
                     manual_template=("projects", "{project_id}", "things", 0),
                     manual_error="bad thing id")
    session = FakeSession()
    # token with too many parts -> name_from_input raises ValueError -> run aborts
    args = make_args(get=True, thing_ids="a/b/c", thing_ids_file=None)
    out = run_components(session, args, components=[comp], column_name="col")
    assert out == {}
    assert "bad thing id" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Empty-result messaging: "No <title> found" vs print_missing_dependency
# --------------------------------------------------------------------------- #
def test_empty_list_prints_no_title_found(capsys):
    cls = make_resource_cls(list_returns={"global": []})
    comp = Component(key="e", resource_cls=cls, title="Widgets", primary_resource="widget", scope=PROJECT)
    session = FakeSession()
    out = run_components(session, make_args(), components=[comp], column_name="col")
    assert out["e"] == []
    assert "No Widgets found in project proj-1" in capsys.readouterr().out


def test_nested_enumerated_parent_with_no_rows_prints_no_title_found(capsys):
    parent_cls = make_resource_cls(table_name="parents_tbl", list_returns={"global": []})
    child_cls = make_resource_cls(table_name="children")
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT)
    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent")
    session = FakeSession()
    out = run_components(session, make_args(), components=[parent, child], column_name="col")
    # parent ran this invocation but found nothing -> "No Children found", not missing-dep
    captured = capsys.readouterr().out
    assert "No Children found in project proj-1" in captured
    assert "Skipping Children" not in captured
    assert out["child"] == []


def test_nested_unselected_parent_with_empty_cache_prints_missing_dependency(capsys):
    parent_cls = make_resource_cls(table_name="parents_tbl")
    child_cls = make_resource_cls(table_name="children")
    parent = Component(key="parent", resource_cls=parent_cls, title="Parents",
                       primary_resource="parent", scope=PROJECT)
    child = Component(key="child", resource_cls=child_cls, title="Children",
                      primary_resource="child", scope=NESTED, parent_key="parent",
                      dependency_label="Parents")
    session = FakeSession()  # empty cache
    out = run_components(session, make_args(child=True), components=[parent, child],
                         column_name="col", module_name="enum_demo")
    captured = capsys.readouterr().out
    assert "Skipping Children" in captured
    assert "No Children found" not in captured
    assert out["child"] == []


# --------------------------------------------------------------------------- #
# Resource construction failure short-circuits the whole run
# --------------------------------------------------------------------------- #
def test_resource_construction_runtime_error_returns_empty(capsys):
    class Boom:
        def __init__(self, session):
            raise RuntimeError("could not build client")

    comp = Component(key="b", resource_cls=Boom, title="B", primary_resource="thing", scope=PROJECT)
    session = FakeSession()
    out = run_components(session, make_args(), components=[comp], column_name="col")
    assert out == {}
    assert "could not build client" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# "Not Enabled" sentinel from list() yields no rows (and short-circuits regions)
# --------------------------------------------------------------------------- #
def test_not_enabled_listing_produces_no_rows():
    class DisabledResource:
        TABLE_NAME = "t"
        COLUMNS = ["location", "name"]
        TEST_IAM_PERMISSIONS = ("perm.get",)
        instances: list = []

        def __init__(self, session):
            self.session = session
            self.save_calls: list = []
            DisabledResource.instances.append(self)

        def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **extra):
            return "Not Enabled"

        def save(self, *a, **k):  # pragma: no cover - should never run
            raise AssertionError("save must not run for a disabled API")

    comp = Component(key="d", resource_cls=DisabledResource, title="D", primary_resource="thing",
                     scope=REGION, locations=["us-central1", "europe-west1"])
    session = FakeSession()
    out = run_components(session, make_args(), components=[comp], column_name="col")
    assert out["d"] == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
