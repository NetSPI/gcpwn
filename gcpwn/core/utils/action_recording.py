"""In-memory accumulators for discovered permissions before they are flushed to the DB.

These build the nested ``action_dict`` that a module later hands to
``session.insert_actions``. They are pure dict mutation (safe to call from worker
threads), unlike the DB write that consumes the result, which is main-thread only.
"""

from __future__ import annotations

from typing import Any, Iterable


def record_permissions(
    action_dict: dict[str, Any] | Any,
    *,
    permissions: str | Iterable[str] | None,
    scope_key: str | None = None,
    scope_label: str | None = None,
    project_id: str | None = None,
    resource_type: str | None = None,
    resource_label: str | None = None,
) -> None:
    """Accumulate discovered permission(s) into an in-memory action tree, two ways.

    Permissions are deduped/stripped first; nothing is recorded if empty.

    Two mutually-exclusive shapes depending on the kwargs supplied:
      - Scope form (``scope_key`` and/or ``scope_label`` given): records under
        ``action_dict[scope_key][scope_label]`` as a set of permissions (used for
        org/folder/project/workspace-level grants). Both tokens must be non-empty
        or it silently no-ops.
      - Resource form (``project_id`` + ``resource_type`` + ``resource_label``):
        records under ``action_dict[project_id][permission][resource_type]`` as a
        set of resource labels -- a per-permission inverted index of which
        resources the credential can act on. All three tokens required.

    Mutates ``action_dict`` in place; returns None. Pure dict work -- safe in a
    worker thread, but the eventual ``insert_actions`` flush is main-thread only.
    """
    normalized_permissions: list[str] = []
    seen_permissions: set[str] = set()
    if isinstance(permissions, str):
        token = permissions.strip()
        if token:
            normalized_permissions = [token]
    else:
        for permission in permissions or []:
            token = str(permission or "").strip()
            if not token or token in seen_permissions:
                continue
            seen_permissions.add(token)
            normalized_permissions.append(token)
    if not normalized_permissions or action_dict is None:
        return

    if scope_key is not None or scope_label is not None:
        scope_key_token = str(scope_key or "").strip()
        scope_label_token = str(scope_label or "").strip()
        if not scope_key_token or not scope_label_token:
            return
        action_dict.setdefault(scope_key_token, {}).setdefault(scope_label_token, set()).update(normalized_permissions)
        return

    project_token = str(project_id or "").strip()
    resource_type_token = str(resource_type or "").strip()
    resource_label_token = str(resource_label or "").strip()
    if not project_token or not resource_type_token or not resource_label_token:
        return
    project_actions = action_dict.setdefault(project_token, {})
    for permission in normalized_permissions:
        project_actions.setdefault(permission, {}).setdefault(resource_type_token, set()).add(resource_label_token)


def has_recorded_actions(action_dict: dict[str, Any] | Any) -> bool:
    """True if the action tree holds any non-empty leaf (avoids flushing empties).

    A top-level value counts only if it is a non-empty inner dict (or a truthy
    scalar); an empty ``{...: {}}`` reads as "nothing recorded". Lets callers skip
    an ``insert_actions`` call when enumeration found no permissions."""
    for value in (action_dict or {}).values():
        if isinstance(value, dict):
            if any(bool(item) for item in value.values()):
                return True
        elif value:
            return True
    return False
