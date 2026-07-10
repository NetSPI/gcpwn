"""Coerce heterogeneous GCP API response objects into plain dicts.

GCP client libraries return wildly different object shapes (proto-plus wrappers,
raw protobuf Messages, hand-rolled REST objects, google-cloud-storage blobs).
These helpers normalize all of them to dicts so persistence/serialization code
downstream can treat every response uniformly.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message


def resource_to_dict(value: Any) -> dict[str, Any]:
    """Best-effort convert any GCP API response object into a flat dict.

    Branch order matters and encodes precedence learned from real responses:
      1. dict -> shallow copy.
      2. proto-plus wrapper (has ``_pb``) -> MessageToDict on the inner message.
      3. raw protobuf Message (e.g. google.iam.v1 Policy, NOT a proto-plus
         wrapper) -> MessageToDict directly. Without this branch such objects
         fell through to ``dict(vars())`` and leaked protobuf Descriptors.
      4. ``to_api_repr()`` / ``to_dict()`` -> call it (google-cloud-* REST objs).
      5. ``_properties`` dict (google-cloud-storage et al. stash raw API metadata
         flat here) -> use it directly so callers get top-level fields instead of
         a nested ``{"_properties": {...}}``.
      6. ``dict(vars(value))`` -> last resort.

    ``preserving_proto_field_name=True`` keeps snake_case field names. Never
    raises: every fallible branch returns ``{}`` on failure.
    """
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "_pb"):
        return MessageToDict(value._pb, preserving_proto_field_name=True)  # type: ignore[attr-defined]
    if isinstance(value, Message):
        # Raw protobuf message (not a proto-plus wrapper) -- e.g. google.iam.v1 Policy.
        # Without this, such objects fell through to dict(vars()) and leaked Descriptors.
        return MessageToDict(value, preserving_proto_field_name=True)
    if hasattr(value, "to_api_repr") and callable(getattr(value, "to_api_repr")):
        try:
            payload = value.to_api_repr()
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        try:
            payload = value.to_dict()
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}
    # google-cloud-storage (and similar) objects hold the raw API metadata flat in
    # `_properties`; use it directly so callers get top-level fields instead of a
    # nested {"_properties": {...}} from dict(vars()). (Canonical fix -- previously
    # re-solved ad hoc per module.)
    props = getattr(value, "_properties", None)
    if isinstance(props, dict) and props:
        return dict(props)
    try:
        return dict(vars(value))
    except Exception:
        return {}


def field_from_row(row: Any, payload: dict[str, Any] | None = None, *field_names: str) -> str:
    """Pull the first non-empty value for ``field_names`` from a row/object.

    A plain string ``row`` is returned stripped. Otherwise checks the dict
    ``payload`` (resolved via ``resource_to_dict`` if not supplied) first, then the
    attribute on ``row``, for each candidate field in order. Returns "" if none hit.
    """
    if isinstance(row, str):
        return row.strip()
    source = payload if payload is not None else resource_to_dict(row)
    for field_name in field_names:
        value = source.get(field_name)
        if value not in (None, ""):
            return str(value).strip()
        attr = getattr(row, field_name, None)
        if attr not in (None, ""):
            return str(attr).strip()
    return ""


def hydrate_get_request_rows(
    rows: Iterable[Any] | None,
    fetcher: Callable[[Any, dict[str, Any]], Any | None],
) -> list[Any]:
    """Upgrade list-derived rows to detailed objects via a per-row GET, gracefully.

    For each row, calls ``fetcher(row, payload)`` (e.g. a ``get_x`` API call). If
    it returns a real object (not None and not a str sentinel/error), that detailed
    object is used; otherwise the original normalized ``payload`` dict is kept as a
    fallback so the row is never lost. Bare string rows with no fetch result are
    dropped (nothing useful to keep). ``payload`` is the ``resource_to_dict`` of the
    row, passed to the fetcher so it need not re-serialize.
    """
    detailed: list[Any] = []
    for row in rows or []:
        payload = resource_to_dict(row)
        fetched = fetcher(row, payload)
        if fetched is not None and not isinstance(fetched, str):
            detailed.append(fetched)
            continue
        if isinstance(row, str):
            continue
        detailed.append(payload if payload else row)
    return detailed
