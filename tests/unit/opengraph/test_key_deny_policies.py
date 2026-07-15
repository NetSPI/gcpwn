"""The --deny-policies final filter: effective access = allow minus deny.

Covers the two core rewrites:
  * a GROUP grant narrowed by an exemption -> re-pointed to the surviving member (a single
    survivor becomes a single-user edge), flagged deny_policy_in_play;
  * a grant fully blocked (no exemption reaches the principal) -> the edge is dropped.
"""
from __future__ import annotations

import json

from conftest import FakeSession, _policy

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_6_deny_policies import apply_deny_policies


def _tables(*, exception_principals):
    return {
        "abstract_tree_hierarchy": [{"name": "projects/proj-a", "type": "project",
                                     "display_name": "proj-a", "project_id": "proj-a", "parent": ""}],
        "iam_allow_policies": [
            {"project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
             "policy": _policy(("projects/proj-a/roles/Custom", ["group:eng@corp.com"]))},
        ],
        "iam_roles": [{"name": "projects/proj-a/roles/Custom",
                       "included_permissions": json.dumps(["resourcemanager.projects.setIamPolicy"])}],
        "iam_service_accounts": [], "iam_sa_keys": [], "cloudcompute_instances": [],
        "cloudfunctions_functions": [], "cloudrun_services": [], "cloudrun_jobs": [],
        "workload_identity_pools": [], "workload_identity_providers": [],
        "workspace_users": [{"email": "alice@corp.com", "user_id": "1"}, {"email": "bob@corp.com", "user_id": "2"}],
        "workspace_groups": [{"email": "eng@corp.com", "name": "groups/eng"}],
        "workspace_group_memberships": [
            {"group_member": "group:eng@corp.com", "member": "user:alice@corp.com", "source": "x"},
            {"group_member": "group:eng@corp.com", "member": "user:bob@corp.com", "source": "x"},
        ],
        "workspace_admin_roles": [], "workspace_role_assignments": [],
        "iam_deny_policies": [{
            "scope_type": "project", "scope_name": "projects/proj-a", "project_id": "proj-a",
            "policy_id": "denyEng", "display_name": "d", "etag": "", "rule_count": 1,
            "denied_principals": "principalSet://goog/group/eng@corp.com",
            "denied_permissions": "resourcemanager.projects.setIamPolicy",
            "exception_principals": exception_principals,
            "rules_json": json.dumps([{"deny_rule": {
                "denied_principals": ["principalSet://goog/group/eng@corp.com"],
                "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
                "exception_principals": ([p for p in exception_principals.split(";") if p.strip()]),
            }}]),
            "raw_json": "{}",
        }],
    }


def _build(tables):
    ctx = OpenGraphBuildContext(session=FakeSession(tables),
                                options=OpenGraphBuildOptions(expand_inheritance=True, deny_policies=True))
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    apply_deny_policies(ctx)
    return ctx


def _modify_iam_edges(ctx):
    return [e for e in ctx.builder.edge_map.values() if e.edge_type == "CAN_MODIFY_PROJECT_IAM"]


def test_deny_narrows_group_grant_to_exempted_member():
    ctx = _build(_tables(exception_principals="principal://goog/subject/alice@corp.com"))
    edges = _modify_iam_edges(ctx)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.source_id == "user:alice@corp.com"          # re-pointed from the group
    assert edge.properties["principal_member"] == "user:alice@corp.com"
    assert edge.properties["deny_policy_in_play"] is True
    assert edge.properties["deny_narrowed_from_group"] == "group:eng@corp.com"
    assert edge.properties["deny_effective_principals"] == ["user:alice@corp.com"]


def test_deny_narrows_group_grant_to_all_exempted_members():
    # Two members exempted -> the group grant becomes one edge per surviving member.
    ctx = _build(_tables(
        exception_principals="principal://goog/subject/alice@corp.com;principal://goog/subject/bob@corp.com"))
    edges = _modify_iam_edges(ctx)
    assert {e.source_id for e in edges} == {"user:alice@corp.com", "user:bob@corp.com"}
    for edge in edges:
        assert edge.properties["deny_narrowed_from_group"] == "group:eng@corp.com"
        assert edge.source_id == edge.properties["principal_member"]


def test_deny_with_no_exemption_drops_the_grant():
    ctx = _build(_tables(exception_principals=""))
    assert _modify_iam_edges(ctx) == []  # fully blocked -> edge removed


def test_deny_policies_off_by_default_leaves_group_grant_intact():
    # Without the deny filter the group keeps its grant (opt-in behavior).
    ctx = OpenGraphBuildContext(session=FakeSession(_tables(exception_principals="")),
                                options=OpenGraphBuildOptions(expand_inheritance=True, deny_policies=False))
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    edges = _modify_iam_edges(ctx)
    assert len(edges) == 1
    assert edges[0].properties["principal_member"] == "group:eng@corp.com"
    assert edges[0].properties.get("deny_policy_in_play") is None


# --- deny inheritance containment (uses REAL ancestry, gated on --expand-inheritance) ---

def _inherit_tables(*, deny_scope_type, deny_scope_name):
    """org 111 -> {folder 222 -> proj-a, folder 333 -> proj-b}; alice grants setIamPolicy
    at proj-a directly (user, not a group) so a covering deny simply DROPs the edge."""
    return {
        "abstract_tree_hierarchy": [
            {"name": "organizations/111", "type": "organization", "display_name": "corp", "project_id": "", "parent": ""},
            {"name": "folders/222", "type": "folder", "display_name": "fa", "project_id": "", "parent": "organizations/111"},
            {"name": "folders/333", "type": "folder", "display_name": "fb", "project_id": "", "parent": "organizations/111"},
            {"name": "projects/proj-a", "type": "project", "display_name": "proj-a", "project_id": "proj-a", "parent": "folders/222"},
            {"name": "projects/proj-b", "type": "project", "display_name": "proj-b", "project_id": "proj-b", "parent": "folders/333"},
        ],
        "iam_allow_policies": [
            {"project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
             "policy": _policy(("projects/proj-a/roles/Custom", ["user:alice@corp.com"]))},
        ],
        "iam_roles": [{"name": "projects/proj-a/roles/Custom",
                       "included_permissions": json.dumps(["resourcemanager.projects.setIamPolicy"])}],
        "iam_service_accounts": [], "iam_sa_keys": [], "cloudcompute_instances": [],
        "cloudfunctions_functions": [], "cloudrun_services": [], "cloudrun_jobs": [],
        "workload_identity_pools": [], "workload_identity_providers": [],
        "workspace_users": [{"email": "alice@corp.com", "user_id": "1"}],
        "workspace_groups": [], "workspace_group_memberships": [],
        "workspace_admin_roles": [], "workspace_role_assignments": [],
        "iam_deny_policies": [{
            "scope_type": deny_scope_type, "scope_name": deny_scope_name, "project_id": "",
            "policy_id": "denyAlice", "display_name": "d", "etag": "", "rule_count": 1,
            "denied_principals": "principal://goog/subject/alice@corp.com",
            "denied_permissions": "resourcemanager.projects.setIamPolicy",
            "exception_principals": "",
            "rules_json": json.dumps([{"deny_rule": {
                "denied_principals": ["principal://goog/subject/alice@corp.com"],
                "denied_permissions": ["resourcemanager.projects.setIamPolicy"],
                "exception_principals": [],
            }}]),
            "raw_json": "{}",
        }],
    }


def _build_inherit(tables, *, expand):
    ctx = OpenGraphBuildContext(session=FakeSession(tables),
                                options=OpenGraphBuildOptions(expand_inheritance=expand, deny_policies=True))
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    apply_deny_policies(ctx)
    return ctx


def test_ancestor_deny_reaches_descendant_only_with_expand_inheritance():
    # An org-level deny sits ABOVE proj-a: it should block alice's proj-a grant only when
    # --expand-inheritance models that downward reach.
    tbl = _inherit_tables(deny_scope_type="organization", deny_scope_name="organizations/111")
    assert _modify_iam_edges(_build_inherit(tbl, expand=True)) == []       # inherited down -> dropped
    assert len(_modify_iam_edges(_build_inherit(tbl, expand=False))) == 1  # confined to org scope -> untouched


def test_deny_in_a_sibling_subtree_never_touches_the_grant():
    # A deny under folder 333 (proj-b's subtree) must not affect proj-a even with expansion.
    tbl = _inherit_tables(deny_scope_type="folder", deny_scope_name="folders/333")
    assert len(_modify_iam_edges(_build_inherit(tbl, expand=True))) == 1


def test_project_scoped_deny_hits_its_own_project_without_expansion():
    # A deny at the grant's own project is an exact-scope hit -> applies regardless of the flag.
    tbl = _inherit_tables(deny_scope_type="project", deny_scope_name="projects/proj-a")
    assert _modify_iam_edges(_build_inherit(tbl, expand=False)) == []
