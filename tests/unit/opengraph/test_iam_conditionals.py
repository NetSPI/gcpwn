"""Tests for the conservative CEL-subset conditionals engine.

Covers: recognised resource.name/type predicates narrow; disjunctions resolve; &&, negation,
and unknown terms bail to unresolved (no narrowing -> no false negatives); time predicates are
recognised but non-narrowing; the engine is a no-op when disabled.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.iam_conditionals import StatementConditionalsEngine


def _opt(expr, enabled=True):
    options = StatementConditionalsEngine(enabled=enabled).evaluate_options({"expression": expr})
    assert len(options) == 1
    return options[0]


def test_startswith_narrows_prefix():
    o = _opt("resource.name.startsWith('projects/_/buckets/secret-')")
    assert o.unresolved is False
    assert o.narrowed_prefixes == ["projects/_/buckets/secret-"]


def test_endswith_and_equals_and_type():
    assert _opt("resource.name.endsWith('-prod')").narrowed_suffixes == ["-prod"]
    assert _opt("resource.name == 'projects/_/buckets/only'").narrowed_equals == ["projects/_/buckets/only"]
    o = _opt("resource.type == 'storage.googleapis.com/Bucket'")
    assert o.narrowed_resource_types == ["storage.googleapis.com/Bucket"]
    assert o.unresolved is False


def test_disjunction_of_recognised_predicates_resolves():
    o = _opt("resource.name.startsWith('a/') || resource.name.startsWith('b/')")
    assert o.unresolved is False
    assert o.narrowed_prefixes == ["a/", "b/"]


def test_conjunction_bails_to_unresolved():
    o = _opt("resource.name.startsWith('a/') && resource.type == 'x/Y'")
    assert o.unresolved is True
    assert o.narrowed_prefixes == [] and o.narrowed_resource_types == []


def test_unknown_term_bails_to_unresolved():
    o = _opt("request.auth.claims.email == 'x@y.com'")
    assert o.unresolved is True


def test_time_only_is_resolved_but_not_narrowing():
    o = _opt("request.time < timestamp('2030-01-01T00:00:00Z')")
    assert o.unresolved is False
    assert not (o.narrowed_prefixes or o.narrowed_suffixes or o.narrowed_equals)


def test_narrow_with_option_filters_by_prefix():
    eng = StatementConditionalsEngine(enabled=True)
    o = _opt("resource.name.startsWith('projects/_/buckets/keep-')")
    names = ["projects/_/buckets/keep-1", "projects/_/buckets/keep-2", "projects/_/buckets/drop-3"]
    out = eng.narrow_with_option(names, o)
    assert set(out) == {"projects/_/buckets/keep-1", "projects/_/buckets/keep-2"}


def test_narrow_with_option_equals_and_suffix():
    eng = StatementConditionalsEngine(enabled=True)
    names = ["a/only", "a/other", "a/thing-prod", "a/thing-dev"]
    assert eng.narrow_with_option(names, _opt("resource.name == 'a/only'")) == ["a/only"]
    assert eng.narrow_with_option(names, _opt("resource.name.endsWith('-prod')")) == ["a/thing-prod"]


def test_keeps_all_when_no_scope_matches():
    # A project-level grant conditioned on child (bucket) names: none of the binding's OWN
    # scopes match, so narrowing to empty would drop a real edge. Keep the originals instead.
    eng = StatementConditionalsEngine(enabled=True)
    o = _opt("resource.name.startsWith('projects/_/buckets/prod-')")
    names = ["projects/proj-a"]
    assert eng.narrow_with_option(names, o) == names


def test_unresolved_option_does_not_narrow():
    eng = StatementConditionalsEngine(enabled=True)
    o = _opt("resource.name.startsWith('a/') && foo()")  # unresolved
    names = ["a/1", "b/2"]
    assert eng.narrow_with_option(names, o) == names


def test_disabled_engine_is_passthrough():
    o = _opt("resource.name.startsWith('a/')", enabled=False)
    assert o.unresolved is False and o.narrowed_prefixes == []
