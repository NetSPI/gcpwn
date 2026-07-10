"""Unit coverage for the shared enum helpers in ``gcpwn.core.utils.service_runtime``.

These exercise pure-logic helpers (argument parsing, component resolution, CSV
parsing, action accumulators/flush) and the light-mock progress/region fan-out
helpers. No real GCP client, network, or DB is touched: a fake session records
``insert_actions`` calls, and workers are plain Python callables.
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.utils import service_runtime as sr
from gcpwn.core.utils.action_recording import has_recorded_actions


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _RecordingSession:
    """Records every ``insert_actions`` call as (accumulator, project_id, kwargs)."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def insert_actions(self, action_dict, project_id, **kwargs):
        self.calls.append((action_dict, project_id, dict(kwargs)))


# --------------------------------------------------------------------------- #
# make_action_accumulators
# --------------------------------------------------------------------------- #
def test_make_action_accumulators_returns_triple_shape() -> None:
    scope, api, iam = sr.make_action_accumulators()

    assert set(scope.keys()) == {
        "project_permissions",
        "folder_permissions",
        "organization_permissions",
    }
    # project_permissions is a defaultdict(set); folder/org are plain dicts.
    assert isinstance(scope["project_permissions"], defaultdict)
    assert scope["project_permissions"].default_factory is set
    assert scope["folder_permissions"] == {}
    assert scope["organization_permissions"] == {}


def test_make_action_accumulators_api_iam_are_nested_defaultdicts() -> None:
    _scope, api, iam = sr.make_action_accumulators()
    # Auto-vivifying three levels deep, leaf is a set.
    api["proj"]["perm"]["rtype"].add("label")
    iam["proj"]["perm"]["rtype"].add("label")
    assert api["proj"]["perm"]["rtype"] == {"label"}
    assert iam["proj"]["perm"]["rtype"] == {"label"}


def test_make_action_accumulators_returns_fresh_objects() -> None:
    first = sr.make_action_accumulators()
    second = sr.make_action_accumulators()
    assert first[0] is not second[0]
    assert first[1] is not second[1]
    assert first[2] is not second[2]


def test_empty_accumulators_have_no_recorded_actions() -> None:
    scope, api, iam = sr.make_action_accumulators()
    assert not has_recorded_actions(scope)
    assert not has_recorded_actions(api)
    assert not has_recorded_actions(iam)


# --------------------------------------------------------------------------- #
# flush_actions
# --------------------------------------------------------------------------- #
def test_flush_actions_noop_when_all_empty() -> None:
    session = _RecordingSession()
    acc = sr.make_action_accumulators()
    sr.flush_actions(session, "proj-1", "myColumn", acc)
    assert session.calls == []


@pytest.mark.parametrize(
    "which, has_iam_evidence",
    [
        (0, False),  # scope accumulator -> NO testIamPermissions evidence
        (1, False),  # api (direct_api) accumulator -> NO evidence type
        (2, True),   # iam (test_iam_permissions) accumulator -> carries the evidence type
    ],
    ids=["scope", "api", "iam"],
)
def test_flush_actions_evidence_type_per_accumulator(which, has_iam_evidence) -> None:
    session = _RecordingSession()
    acc = sr.make_action_accumulators()  # (scope, api, iam)
    # Populate exactly the one accumulator under test (scope has a distinct shape).
    if which == 0:
        acc[0]["project_permissions"]["proj-1"].add("storage.buckets.list")
    else:
        acc[which]["proj-1"]["storage.buckets.get"]["bucket"].add("b1")

    sr.flush_actions(session, "proj-1", "storageActions", acc)

    assert len(session.calls) == 1
    action_dict, project_id, kwargs = session.calls[0]
    assert action_dict is acc[which]
    assert project_id == "proj-1"
    assert kwargs["column_name"] == "storageActions"
    assert kwargs["credname_override"] is None
    if has_iam_evidence:
        assert kwargs["evidence_type"] == ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
    else:
        assert "evidence_type" not in kwargs


def test_flush_actions_all_three_in_order_with_credname_override() -> None:
    session = _RecordingSession()
    scope, api, iam = sr.make_action_accumulators()
    scope["project_permissions"]["proj-1"].add("p1")
    api["proj-1"]["perm"]["rtype"].add("lbl")
    iam["proj-1"]["perm"]["rtype"].add("lbl")

    sr.flush_actions(
        session, "proj-1", "col", (scope, api, iam), credname_override="sa@x.iam"
    )

    assert len(session.calls) == 3
    recorded = [call[0] for call in session.calls]
    # scope, then api, then iam (verbatim order of the helper).
    assert recorded == [scope, api, iam]
    # credname_override threaded through to all three.
    assert all(call[2]["credname_override"] == "sa@x.iam" for call in session.calls)
    assert all(call[2]["column_name"] == "col" for call in session.calls)
    assert all(call[1] == "proj-1" for call in session.calls)
    # Only the iam (last) call carries the evidence type.
    assert "evidence_type" not in session.calls[0][2]
    assert "evidence_type" not in session.calls[1][2]
    assert session.calls[2][2]["evidence_type"] == ACTION_EVIDENCE_TEST_IAM_PERMISSIONS


def test_flush_actions_default_credname_override_is_none() -> None:
    session = _RecordingSession()
    scope, api, iam = sr.make_action_accumulators()
    scope["organization_permissions"]["orgs/1"] = {"x"}

    sr.flush_actions(session, None, "col", (scope, api, iam))

    assert len(session.calls) == 1
    assert session.calls[0][2]["credname_override"] is None
    assert session.calls[0][1] is None


# --------------------------------------------------------------------------- #
# resolve_selected_components
# --------------------------------------------------------------------------- #
def _ns(**kwargs):
    import argparse

    return argparse.Namespace(**kwargs)


@pytest.mark.parametrize(
    "attrs, keys, expected",
    [
        # none selected -> all True
        ({"buckets": False, "objects": False, "hmac": False}, ["buckets", "objects", "hmac"],
         {"buckets": True, "objects": True, "hmac": True}),
        # some selected -> only those
        ({"buckets": True, "objects": False, "hmac": False}, ["buckets", "objects", "hmac"],
         {"buckets": True, "objects": False, "hmac": False}),
        # all selected -> all True
        ({"a": True, "b": True}, ["a", "b"], {"a": True, "b": True}),
        # key absent from namespace -> getattr default False -> none selected -> all True
        ({"a": False}, ["a", "missing"], {"a": True, "missing": True}),
        # empty / None keys -> empty
        ({}, [], {}),
        ({}, None, {}),
    ],
    ids=["none-selected", "some-selected", "all-selected", "missing-attr", "empty-keys", "none-keys"],
)
def test_resolve_selected_components(attrs, keys, expected) -> None:
    assert sr.resolve_selected_components(_ns(**attrs), keys) == expected


# --------------------------------------------------------------------------- #
# parse_component_args / add_standard_arguments
# --------------------------------------------------------------------------- #
def test_add_standard_arguments_known_specs() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    sr.add_standard_arguments(parser, ["iam", "get", "debug", "threads"])
    args = parser.parse_args(["--iam", "--get", "--debug"])
    assert args.iam is True
    assert args.get is True
    assert args.debug is True
    assert args.threads == 4  # default


def test_add_standard_arguments_debug_short_flag() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    sr.add_standard_arguments(parser, ["debug"])
    assert parser.parse_args(["-v"]).debug is True


def test_add_standard_arguments_unknown_raises() -> None:
    import argparse

    with pytest.raises(ValueError, match="Unknown standard argument"):
        sr.add_standard_arguments(argparse.ArgumentParser(), ["bogus"])


def test_add_standard_arguments_override_flags_and_help() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    sr.add_standard_arguments(
        parser,
        ["threads"],
        overrides={"threads": {"flags": ("--workers",), "default": 9}},
    )
    # Overriding flags to --workers makes the dest "workers" (argparse derives
    # dest from the first long flag); the default override still applies.
    assert parser.parse_args([]).workers == 9
    assert parser.parse_args(["--workers", "3"]).workers == 3


def test_parse_component_args_flags_and_dest_underscore() -> None:
    components = [
        ("buckets", "List buckets"),
        ("hmac_keys", "List HMAC keys"),
    ]
    args = sr.parse_component_args(
        ["--buckets", "--hmac-keys", "--iam"],
        description="storage enum",
        components=components,
        standard_args=["iam"],
    )
    assert args.buckets is True
    # dashed flag maps back to underscore dest.
    assert args.hmac_keys is True
    assert args.iam is True
    # threads always injected even without being requested.
    assert args.threads == 4


def test_parse_component_args_defaults_all_false() -> None:
    args = sr.parse_component_args(
        [],
        description="d",
        components=[("a", "h"), ("b", "h")],
    )
    assert args.a is False
    assert args.b is False
    assert args.threads == 4


def test_parse_component_args_injects_threads_only_once() -> None:
    # Requesting "threads" as a standard arg must not collide with the auto-inject.
    args = sr.parse_component_args(
        ["--threads", "7"],
        description="d",
        components=[("a", "h")],
        standard_args=["threads"],
    )
    assert args.threads == 7


def test_parse_component_args_add_extra_args_callback() -> None:
    def add_extra(parser):
        parser.add_argument("--name", dest="name", default=None)

    args = sr.parse_component_args(
        ["--name", "foo"],
        description="d",
        components=[("a", "h")],
        add_extra_args=add_extra,
    )
    assert args.name == "foo"


def test_parse_component_args_disallows_abbrev() -> None:
    # allow_abbrev=False: a prefix of a flag is not accepted -> SystemExit.
    with pytest.raises(SystemExit):
        sr.parse_component_args(
            ["--buck"],
            description="d",
            components=[("buckets", "h")],
        )


# --------------------------------------------------------------------------- #
# parse_csv_arg / parse_csv_file_args
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value, expected",
    [
        ("a, b ,c", ["a", "b", "c"]),  # basic split + trimming
        ("", []),  # empty string
        (None, []),  # None
        (" , ,, ", []),  # whitespace / empty segments dropped
        (123, ["123"]),  # non-string coerced via str()
    ],
    ids=["basic_and_trimming", "empty_string", "none", "all_whitespace", "non_string_coerced"],
)
def test_parse_csv_arg(value, expected) -> None:
    assert sr.parse_csv_arg(value) == expected


@pytest.mark.parametrize(
    "args, expected",
    [
        (("a,b,c",), ["a", "b", "c"]),  # inline only
        (("a,b,a,c,b",), ["a", "b", "c"]),  # dedup preserves order
        ((), []),  # no args at all
        ((None, None), []),  # explicit None inline + None file
    ],
    ids=["inline_only", "dedup_preserves_order", "no_args", "explicit_nones"],
)
def test_parse_csv_file_args_no_file(args, expected) -> None:
    assert sr.parse_csv_file_args(*args) == expected


def test_parse_csv_file_args_reads_file_and_skips_comments(tmp_path) -> None:
    path = tmp_path / "ids.txt"
    path.write_text("# comment\nx\n\ny, z\n# another\n")
    assert sr.parse_csv_file_args(file_path=str(path)) == ["x", "y", "z"]


def test_parse_csv_file_args_inline_then_file_dedup_across_sources(tmp_path) -> None:
    path = tmp_path / "ids.txt"
    path.write_text("b\nc\n")
    # inline entries come first, then file entries; duplicates suppressed.
    assert sr.parse_csv_file_args("a,b", file_path=str(path)) == ["a", "b", "c"]


# --------------------------------------------------------------------------- #
# process_with_progress
# --------------------------------------------------------------------------- #
def test_process_with_progress_maps_all(monkeypatch) -> None:
    # Force non-TTY so no counter is rendered (deterministic).
    monkeypatch.setattr(sr.sys.stdout, "isatty", lambda: False, raising=False)
    results = sr.process_with_progress([1, 2, 3], lambda x: x * 10)
    assert results == [10, 20, 30]


def test_process_with_progress_empty() -> None:
    assert sr.process_with_progress([], lambda x: x) == []


def test_process_with_progress_consumes_iterator() -> None:
    results = sr.process_with_progress(iter(["a", "b"]), str.upper)
    assert results == ["A", "B"]


def test_process_with_progress_keyboardinterrupt_returns_partial(capsys) -> None:
    calls = []

    def fn(item):
        calls.append(item)
        if item == 3:
            raise KeyboardInterrupt
        return item

    results = sr.process_with_progress([1, 2, 3, 4, 5], fn, label="things")
    # 1 and 2 completed; 3 raised before appending; rest skipped.
    assert results == [1, 2]
    assert calls == [1, 2, 3]
    out = capsys.readouterr().out
    assert "Interrupted while reviewing things at 2/5" in out


def test_process_with_progress_shows_counter_on_tty(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sr.sys.stdout, "isatty", lambda: True, raising=False)
    # min_show small enough to trigger the in-place counter.
    results = sr.process_with_progress(
        [1, 2, 3], lambda x: x, label="rows", min_show=2
    )
    assert results == [1, 2, 3]
    out = capsys.readouterr().out
    assert "reviewed 3/3" in out


# --------------------------------------------------------------------------- #
# map_regions_with_disabled_short_circuit
# --------------------------------------------------------------------------- #
def test_map_regions_empty_returns_empty() -> None:
    assert sr.map_regions_with_disabled_short_circuit([], lambda r: r) == []
    assert sr.map_regions_with_disabled_short_circuit(None, lambda r: r) == []


def test_map_regions_blank_regions_filtered_out() -> None:
    # All-whitespace regions are stripped, leaving nothing.
    assert sr.map_regions_with_disabled_short_circuit(["", "  ", None], lambda r: r) == []


def test_map_regions_runs_all_when_enabled() -> None:
    seen = []

    def worker(region):
        seen.append(region)
        return f"ok-{region}"

    out = sr.map_regions_with_disabled_short_circuit(
        ["us", "eu", "asia"], worker, show_progress=False
    )
    assert out == [("us", "ok-us"), ("eu", "ok-eu"), ("asia", "ok-asia")]
    assert set(seen) == {"us", "eu", "asia"}


def test_map_regions_short_circuits_on_not_enabled(capsys) -> None:
    seen = []

    def worker(region):
        seen.append(region)
        return "Not Enabled"

    out = sr.map_regions_with_disabled_short_circuit(
        ["us", "eu", "asia"], worker, progress_label="compute scan"
    )
    # Only the first region is probed; remaining regions skipped entirely.
    assert out == [("us", "Not Enabled")]
    assert seen == ["us"]
    msg = capsys.readouterr().out
    assert "API not enabled" in msg
    assert "us" in msg


def test_map_regions_single_region_enabled() -> None:
    out = sr.map_regions_with_disabled_short_circuit(["only"], lambda r: 7, show_progress=False)
    assert out == [("only", 7)]


def test_map_regions_strips_whitespace_in_region_names() -> None:
    out = sr.map_regions_with_disabled_short_circuit(
        [" us ", " eu "], lambda r: r, show_progress=False
    )
    # Region keys are stripped before the worker sees them.
    assert out == [("us", "us"), ("eu", "eu")]
