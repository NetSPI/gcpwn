"""Exhaustive unit coverage for ``gcpwn.core.utils.serialization``.

The functions here normalize the wildly heterogeneous shapes GCP client
libraries return (proto messages with ``_pb``, ``google-cloud-storage`` objects
that stash raw metadata in ``_properties``, plain ``to_dict``/``to_api_repr``
wrappers, raw dicts) into a single flat ``dict``. ``resource_to_dict`` is the
hot path and its ``_properties`` branch has regressed repeatedly -- the storage
Bucket/Blob case MUST come back FLAT, never nested under ``"_properties"``.

The ``_pb`` branch is exercised against a REAL protobuf message
(``FieldDescriptorProto``) so we actually prove ``preserving_proto_field_name``
is wired through (``type_name`` stays snake_case rather than collapsing to the
default camelCase ``typeName``).
"""

from __future__ import annotations

import pytest
from google.protobuf.descriptor_pb2 import FieldDescriptorProto

from gcpwn.core.utils.serialization import (
    field_from_row,
    hydrate_get_request_rows,
    resource_to_dict,
)

# ---------------------------------------------------------------------------
# Fakes -- one tailored shape per resource_to_dict branch.
# ---------------------------------------------------------------------------


class _PbWrapper:
    """Mimics a proto-backed client object: exposes a real proto via ``_pb``."""

    def __init__(self, pb) -> None:
        self._pb = pb
        # A decoy attribute that MUST be ignored because _pb wins.
        self.ignored = "should-not-appear"


class _ApiReprObj:
    def __init__(self, payload) -> None:
        self._payload = payload

    def to_api_repr(self):
        return self._payload


class _ToDictObj:
    def __init__(self, payload) -> None:
        self._payload = payload

    def to_dict(self):
        return self._payload


class _PropertiesObj:
    """The google-cloud-storage Bucket/Blob shape: raw metadata in ``_properties``."""

    def __init__(self, properties) -> None:
        self._properties = properties
        # Real storage objects also carry other vars; they must be ignored
        # in favor of the flat _properties payload.
        self.name = "set-via-attr-not-properties"


class _PlainObj:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


class _ApiReprRaises:
    def to_api_repr(self):
        raise RuntimeError("boom")


class _ToDictRaises:
    def to_dict(self):
        raise ValueError("boom")


def _field_proto() -> FieldDescriptorProto:
    """A real proto whose snake_case ``type_name`` proves preserve-field-name."""
    f = FieldDescriptorProto()
    f.name = "myfield"
    f.type_name = "SomeType"
    return f


# ---------------------------------------------------------------------------
# resource_to_dict -- dict input
# ---------------------------------------------------------------------------


def test_dict_input_returns_shallow_copy() -> None:
    src = {"a": 1, "b": {"nested": True}}
    out = resource_to_dict(src)
    assert out == src
    assert out is not src  # copied, not aliased


def test_dict_input_copy_is_shallow() -> None:
    inner = {"nested": True}
    src = {"a": inner}
    out = resource_to_dict(src)
    out["a"]["mutated"] = 1
    # Shallow copy: the inner dict is shared by reference.
    assert inner == {"nested": True, "mutated": 1}


def test_empty_dict_returns_empty_dict() -> None:
    out = resource_to_dict({})
    assert out == {}
    assert isinstance(out, dict)


# ---------------------------------------------------------------------------
# resource_to_dict -- _pb / MessageToDict branch (real proto)
# ---------------------------------------------------------------------------


def test_pb_branch_uses_message_to_dict_snake_case() -> None:
    wrapper = _PbWrapper(_field_proto())
    out = resource_to_dict(wrapper)
    # preserving_proto_field_name=True keeps snake_case.
    assert out == {"name": "myfield", "type_name": "SomeType"}
    assert "type_name" in out
    # NOT the default camelCase that MessageToDict produces without the flag.
    assert "typeName" not in out


def test_pb_branch_ignores_other_attributes() -> None:
    wrapper = _PbWrapper(_field_proto())
    out = resource_to_dict(wrapper)
    assert "ignored" not in out


def test_raw_protobuf_message_without_pb_wrapper() -> None:
    # A raw protobuf Message (no proto-plus `_pb`, e.g. google.iam.v1 Policy) must be
    # converted via MessageToDict, not fall through to dict(vars()) and leak Descriptors.
    raw = _field_proto()  # a real protobuf Message, passed directly
    assert not hasattr(raw, "_pb")
    out = resource_to_dict(raw)
    assert out == {"name": "myfield", "type_name": "SomeType"}
    assert "typeName" not in out  # preserving_proto_field_name=True


def test_pb_branch_wins_over_properties() -> None:
    # An object that has BOTH _pb and _properties must take the _pb path.
    wrapper = _PbWrapper(_field_proto())
    wrapper._properties = {"flat": "value"}
    out = resource_to_dict(wrapper)
    assert out == {"name": "myfield", "type_name": "SomeType"}
    assert "flat" not in out


# ---------------------------------------------------------------------------
# resource_to_dict -- to_api_repr branch
# ---------------------------------------------------------------------------


def test_to_api_repr_returns_its_dict() -> None:
    payload = {"kind": "storage#bucket", "id": "b1"}
    out = resource_to_dict(_ApiReprObj(payload))
    assert out == payload


def test_to_api_repr_raising_returns_empty() -> None:
    assert resource_to_dict(_ApiReprRaises()) == {}


def test_to_api_repr_wins_over_to_dict_and_properties() -> None:
    obj = _ApiReprObj({"from": "api_repr"})
    obj.to_dict = lambda: {"from": "to_dict"}  # type: ignore[attr-defined]
    obj._properties = {"from": "properties"}
    assert resource_to_dict(obj) == {"from": "api_repr"}


# ---------------------------------------------------------------------------
# resource_to_dict -- to_dict branch
# ---------------------------------------------------------------------------


def test_to_dict_returns_its_dict() -> None:
    payload = {"name": "svc", "state": "ACTIVE"}
    out = resource_to_dict(_ToDictObj(payload))
    assert out == payload


def test_to_dict_raising_returns_empty() -> None:
    assert resource_to_dict(_ToDictRaises()) == {}


def test_to_dict_wins_over_properties() -> None:
    obj = _ToDictObj({"from": "to_dict"})
    obj._properties = {"from": "properties"}
    assert resource_to_dict(obj) == {"from": "to_dict"}


# ---------------------------------------------------------------------------
# resource_to_dict -- _properties branch (THE recurring storage bug)
# ---------------------------------------------------------------------------


def test_properties_branch_returns_flat_top_level_keys() -> None:
    props = {"name": "mybucket", "location": "US", "storageClass": "STANDARD"}
    out = resource_to_dict(_PropertiesObj(props))
    # Top-level keys from _properties must be present...
    assert out["name"] == "mybucket"
    assert out["location"] == "US"
    assert out["storageClass"] == "STANDARD"
    # ...and the payload must NOT be nested under "_properties".
    assert "_properties" not in out


def test_properties_branch_is_a_copy_not_alias() -> None:
    props = {"name": "b"}
    obj = _PropertiesObj(props)
    out = resource_to_dict(obj)
    out["mutated"] = True
    assert props == {"name": "b"}  # original untouched


def test_properties_branch_ignores_instance_attrs() -> None:
    # The object's own ``name`` attr must lose to the _properties value.
    obj = _PropertiesObj({"name": "from-properties"})
    out = resource_to_dict(obj)
    assert out == {"name": "from-properties"}


def test_empty_properties_falls_through_to_vars() -> None:
    # _properties present but empty -> the `props and` guard fails, so we fall
    # through to dict(vars()), which yields the instance __dict__ (including the
    # empty _properties itself).
    obj = _PropertiesObj({})
    out = resource_to_dict(obj)
    assert out["name"] == "set-via-attr-not-properties"
    assert out["_properties"] == {}


def test_non_dict_properties_falls_through_to_vars() -> None:
    obj = _PlainObj(_properties=["not", "a", "dict"], other="x")
    out = resource_to_dict(obj)
    # Falls through to vars(); both attrs are present at top level.
    assert out["other"] == "x"
    assert out["_properties"] == ["not", "a", "dict"]


# ---------------------------------------------------------------------------
# resource_to_dict -- plain object via dict(vars())
# ---------------------------------------------------------------------------


def test_plain_object_uses_vars() -> None:
    obj = _PlainObj(alpha=1, beta="two")
    out = resource_to_dict(obj)
    assert out == {"alpha": 1, "beta": "two"}


def test_plain_object_copy_independent_of_instance() -> None:
    obj = _PlainObj(x=1)
    out = resource_to_dict(obj)
    out["x"] = 999
    assert obj.x == 1


# ---------------------------------------------------------------------------
# resource_to_dict -- graceful failure -> {}
# ---------------------------------------------------------------------------


class _Slotted:
    __slots__ = ("a",)


@pytest.mark.parametrize(
    "value",
    [
        # A bare object() has no __dict__, so dict(vars()) raises -> {}.
        object(),
        # __slots__ classes have no __dict__ -> vars() raises -> {}.
        _Slotted(),
        # None has no _pb/to_*/_properties and no __dict__ -> {}.
        None,
        # primitives -> {}.
        123,
        "a string",
        # to_api_repr returning a non-dict is defensively coerced to {}.
        _ApiReprObj(["not", "a", "dict"]),
        _ApiReprObj(None),
        _ApiReprObj("str"),
        # to_dict returning a non-dict is likewise coerced to {}.
        _ToDictObj([1, 2, 3]),
        _ToDictObj(42),
    ],
    ids=[
        "object_without_dict",
        "slots_object_without_set_attrs",
        "none_input",
        "primitive_int",
        "primitive_str",
        "api_repr_non_dict_list",
        "api_repr_non_dict_none",
        "api_repr_non_dict_str",
        "to_dict_non_dict_list",
        "to_dict_non_dict_int",
    ],
)
def test_resource_to_dict_returns_empty(value) -> None:
    assert resource_to_dict(value) == {}


# ---------------------------------------------------------------------------
# field_from_row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "row, payload, field_names, expected",
    [
        # str row short-circuits before any field lookup; stripped and returned.
        ("  hello  ", None, (), "hello"),
        # str row ignores field-name args (folded from ignores_field_names).
        ("  raw  ", None, ("name",), "raw"),
        # reads from explicit payload.
        (object(), {"name": "alice", "email": "a@b.c"}, ("name",), "alice"),
        # derives payload from row when payload is None.
        (_PlainObj(displayName="Bob"), None, ("displayName",), "Bob"),
        # first non-empty field wins.
        (object(), {"first": "", "second": "value"}, ("first", "second"), "value"),
        # skips None and empty values in payload.
        (object(), {"a": None, "b": "", "c": "found"}, ("a", "b", "c"), "found"),
        # falls back to attribute when field absent from payload.
        (_PlainObj(fallback="attr-value"), {}, ("fallback",), "attr-value"),
        # payload preferred over attribute.
        (_PlainObj(name="from-attr"), {"name": "from-payload"}, ("name",), "from-payload"),
        # attribute used when payload value is an empty string.
        (_PlainObj(name="attr-name"), {"name": ""}, ("name",), "attr-name"),
        # value is stringified and stripped.
        (object(), {"count": 42}, ("count",), "42"),
        # returns empty when nothing matches.
        (object(), {"x": ""}, ("x", "missing"), ""),
        # no field names -> empty.
        (object(), {"a": 1}, (), ""),
        # attribute None is skipped, next field used.
        (_PlainObj(a=None, b="present"), {}, ("a", "b"), "present"),
        # 0 is not in (None, "") so it counts as a real value.
        (object(), {"n": 0}, ("n",), "0"),
        # False is a real value too.
        (object(), {"flag": False}, ("flag",), "False"),
    ],
    ids=[
        "string_input_is_stripped",
        "string_input_ignores_field_names",
        "reads_from_explicit_payload",
        "derives_payload_from_row_when_none",
        "first_nonempty_field_wins",
        "skips_none_and_empty",
        "falls_back_to_attribute",
        "payload_preferred_over_attribute",
        "attribute_used_when_payload_empty_string",
        "value_is_stringified_and_stripped",
        "returns_empty_when_nothing_matches",
        "no_field_names_returns_empty",
        "attribute_none_skipped",
        "zero_value_is_returned",
        "false_value_is_returned",
    ],
)
def test_field_from_row(row, payload, field_names, expected) -> None:
    assert field_from_row(row, payload, *field_names) == expected


# ---------------------------------------------------------------------------
# hydrate_get_request_rows
# ---------------------------------------------------------------------------


def test_hydrate_none_rows_returns_empty_list() -> None:
    assert hydrate_get_request_rows(None, lambda _r, _p: None) == []


def test_hydrate_empty_rows_returns_empty_list() -> None:
    assert hydrate_get_request_rows([], lambda _r, _p: None) == []


def test_hydrate_uses_fetched_object_when_present() -> None:
    fetched = object()
    out = hydrate_get_request_rows([{"a": 1}], lambda _r, _p: fetched)
    assert out == [fetched]


def test_hydrate_fetcher_receives_row_and_payload() -> None:
    seen: list[tuple] = []

    def fetcher(row, payload):
        seen.append((row, payload))
        return "x"  # str -> ignored as a fetched object

    row = _PlainObj(name="n")
    hydrate_get_request_rows([row], fetcher)
    assert seen[0][0] is row
    assert seen[0][1] == {"name": "n"}  # resource_to_dict(row)


def test_hydrate_string_fetch_result_is_ignored() -> None:
    # A str return is NOT treated as a fetched object; we fall back to payload.
    out = hydrate_get_request_rows([{"k": "v"}], lambda _r, _p: "ignored-string")
    assert out == [{"k": "v"}]


def test_hydrate_falls_back_to_payload_when_fetch_none() -> None:
    out = hydrate_get_request_rows([{"k": "v"}], lambda _r, _p: None)
    assert out == [{"k": "v"}]


def test_hydrate_string_row_skipped_when_no_fetch() -> None:
    # A bare string row with no usable fetch result is dropped entirely.
    out = hydrate_get_request_rows(["just-a-string"], lambda _r, _p: None)
    assert out == []


def test_hydrate_string_row_can_still_be_hydrated_by_fetcher() -> None:
    fetched = {"resolved": True}
    out = hydrate_get_request_rows(["name-only"], lambda _r, _p: fetched)
    assert out == [fetched]


def test_hydrate_falls_back_to_row_when_payload_empty() -> None:
    # object() -> resource_to_dict gives {} (falsy) -> keep the raw row.
    row = object()
    out = hydrate_get_request_rows([row], lambda _r, _p: None)
    assert out == [row]


def test_hydrate_mixed_rows_preserve_order() -> None:
    fetched = {"id": "real"}
    rows = [{"a": 1}, "skip-me", _PlainObj(b=2)]

    def fetcher(row, _payload):
        if isinstance(row, _PlainObj):
            return fetched
        return None

    out = hydrate_get_request_rows(rows, fetcher)
    # dict row falls back to its payload; the string is dropped; the plain
    # object is replaced by the fetched dict.
    assert out == [{"a": 1}, fetched]
