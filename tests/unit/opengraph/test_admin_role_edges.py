"""Stage-1 Workspace super-admin edge tests (CAN_IMPERSONATE / CAN_RESET_PASSWORD).

Locks the ADD-ONLY contract for the OpenGraph admin-role edges: with no super-admin
role data the graph is untouched (so every graph built before Workspace admin-role
enumeration is byte-identical); with super-admin data, each super-admin principal gets
impersonate + reset edges to every OTHER Workspace user (super-admin -> user -> GCP is
the attack path). Tests call the stage function directly against an OpenGraphBuilder.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphBuilder
from gcpwn.modules.opengraph.utilities.stage_1_principals import _add_admin_role_edges

_USERS = [
    {"email": "admin@corp.com", "user_id": "1"},
    {"email": "alice@corp.com", "user_id": "2"},
    {"email": "bob@corp.com", "user_id": "3"},
]
_ROLES = [
    {"role_id": "R1", "is_super_admin_role": "true"},
    {"role_id": "R2", "is_super_admin_role": "false"},
]
_ASSIGN_SUPER = [{"role_id": "R1", "assigned_to": "1"}]  # user_id 1 == admin@corp.com


def test_no_admin_data_adds_nothing():
    # The byte-stable guarantee: existing graphs (no admin-role data) are unchanged.
    b = OpenGraphBuilder()
    _add_admin_role_edges(b, admin_roles=[], role_assignments=[], workspace_users=_USERS)
    assert b.edge_map == {}
    assert b.node_map == {}


def test_roles_present_but_none_super_admin_adds_nothing():
    b = OpenGraphBuilder()
    _add_admin_role_edges(
        b,
        admin_roles=[{"role_id": "R2", "is_super_admin_role": "false"}],
        role_assignments=[{"role_id": "R2", "assigned_to": "1"}],
        workspace_users=_USERS,
    )
    assert b.edge_map == {}


def test_super_admin_gets_impersonate_and_reset_edges_to_every_other_user():
    b = OpenGraphBuilder()
    _add_admin_role_edges(b, admin_roles=_ROLES, role_assignments=_ASSIGN_SUPER, workspace_users=_USERS)
    # edge_map is keyed (source_id, edge_type, destination_id).
    admin = "user:admin@corp.com"
    for target in ("user:alice@corp.com", "user:bob@corp.com"):
        assert (admin, "CAN_IMPERSONATE", target) in b.edge_map
        assert (admin, "CAN_RESET_PASSWORD", target) in b.edge_map
    assert (admin, "CAN_IMPERSONATE", admin) not in b.edge_map  # no self-edge
    assert len(b.edge_map) == 4  # 2 other users x 2 edge kinds


def test_assignment_to_non_super_role_is_ignored():
    b = OpenGraphBuilder()
    _add_admin_role_edges(
        b, admin_roles=_ROLES, role_assignments=[{"role_id": "R2", "assigned_to": "1"}], workspace_users=_USERS
    )
    assert b.edge_map == {}


def test_assigned_to_email_fallback():
    # assignedTo can be an email-like value rather than a directory user id.
    b = OpenGraphBuilder()
    _add_admin_role_edges(
        b, admin_roles=_ROLES, role_assignments=[{"role_id": "R1", "assigned_to": "admin@corp.com"}], workspace_users=_USERS
    )
    assert ("user:admin@corp.com", "CAN_IMPERSONATE", "user:alice@corp.com") in b.edge_map


def test_edge_kinds_match_bloodhound_regex():
    # BloodHound OpenGraph edge `kind` must be ^[A-Za-z0-9_]+$ (no colons).
    import re

    b = OpenGraphBuilder()
    _add_admin_role_edges(b, admin_roles=_ROLES, role_assignments=_ASSIGN_SUPER, workspace_users=_USERS)
    pattern = re.compile(r"^[A-Za-z0-9_]+$")
    for _src, kind, _dst in b.edge_map:  # key order: (source, edge_type, destination)
        assert pattern.match(kind), kind
