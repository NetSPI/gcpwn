from __future__ import annotations

import json

import pytest

from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    BindingPlusScopeEntry,
)


class FakeSession:
    """Shared in-memory session for the OpenGraph fake-data tests.

    Only ``get_data`` is used by the in-memory graph build; ``get_actions`` /
    ``get_session_data`` feed the stage-3 inferred-permission evidence (empty
    unless a test passes ``actions=`` / ``session_rows=``).
    """

    def __init__(self, tables, *, actions=None, session_rows=None):
        self._tables = tables
        self._actions = actions or []
        self._session_rows = session_rows or []

    def get_data(self, table_name, columns="*", conditions=None, *, where=None, params=None):
        return [dict(row) for row in self._tables.get(str(table_name), [])]

    def get_actions(self):
        return [dict(action) for action in self._actions]

    def get_session_data(self, table=None, columns=None, **kwargs):
        return [dict(row) for row in self._session_rows]


def _policy(*bindings) -> str:
    """Build an ``iam_allow_policies.policy`` cell. Each binding is
    ``(role, members)`` or ``(role, members, condition)``."""
    out = []
    for binding in bindings:
        entry = {"role": binding[0], "members": list(binding[1])}
        if len(binding) > 2 and binding[2]:
            entry["condition"] = binding[2]
        out.append(entry)
    return json.dumps({"bindings": out})


def _edges(context) -> set[tuple[str, str, str]]:
    return {(e.source_id, e.edge_type, e.destination_id) for e in context.builder.edge_map.values()}


def _edge_kinds(context) -> set[str]:
    return {edge.edge_type for edge in context.builder.edge_map.values()}


def _node_types(context) -> dict[str, str]:
    return {node.node_id: node.node_type for node in context.builder.node_map.values()}


def make_binding_entry(
    *,
    role_name: str,
    permissions: set[str],
    binding_suffix: str | None = None,
) -> BindingPlusScopeEntry:
    """Shared ``BindingPlusScopeEntry`` factory for the opengraph tests.

    The combo-path tests need a per-binding ``binding_suffix`` (appended to the
    composite id as ``#<suffix>``); the permission-map tests use the plain
    composite id with no suffix. Every other field is byte-identical to the two
    previously-duplicated local factories, so output is unchanged.
    """
    if binding_suffix is None:
        binding_composite_id = f"iambinding:{role_name}@project:demo-project"
    else:
        binding_composite_id = f"iambinding:{role_name}@project:demo-project#{binding_suffix}"

    return BindingPlusScopeEntry(
        principal_id="user:alice@example.com",
        expanded_from_convenience_member="",
        binding_composite_id=binding_composite_id,
        role_name=role_name,
        permissions=frozenset(permissions),
        attached_scope_name="projects/demo-project",
        attached_scope_type="project",
        attached_scope_display="demo-project",
        source_scope_name="projects/demo-project",
        source_scope_type="project",
        source_scope_display="demo-project",
        effective_scope_name="projects/demo-project",
        effective_scope_type="project",
        effective_scope_display="demo-project",
        project_id="demo-project",
        inherited=False,
        source="unit_test",
        condition_expr_raw="",
        condition_hash="",
        condition_option_id="",
        condition_option_summary="",
        condition_services=frozenset(),
        condition_resource_types=frozenset(),
        condition_name_prefixes=frozenset(),
        condition_name_equals=frozenset(),
    )


@pytest.fixture
def binding_entry_factory():
    """Fixture form of :func:`make_binding_entry` for tests that prefer injection."""
    return make_binding_entry
