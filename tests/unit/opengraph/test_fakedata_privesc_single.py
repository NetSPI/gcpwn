"""Fake-data regression tests for single-permission DANGEROUS IAM rule edges.

Each test plants an iam_allow_policies binding that grants a CUSTOM role whose
included_permissions contain exactly one rule-triggering permission from
og_privilege_escalation_paths.json, then runs stage_1 (build_users_groups_graph)
followed by stage_2 (_run_iam_bindings_stage) and asserts the corresponding
dangerous edge_kind is emitted on the resolved binding node.

Resolved role->permissions comes from the iam_roles table (context key
"iam_custom_roles"), read via _custom_role_permissions() which uses the
`included_permissions` column -- NOT a predefined-role mapping. The trigger
permissions are all present in og_permission_to_roles_map.json, so none of these
rules land in binding_unsupported_rule_names (which would skip them).

Edge-target shape per rule:
- CAN_MODIFY_{PROJECT,FOLDER,ORG}_IAM have NO target_selector, so the bound
  scope itself is the target (no resource rows needed).
- CAN_MODIFY_SA_IAM / CAN_IMPERSONATE_SA / CAN_CREATE_SA_ACCESS_TOKEN /
  CAN_CREATE_SA_KEY select resource_type "service-account"; the bound project
  scope does not match that selector, so a service-account resource must exist
  in the same project (planted as an extra iam_allow_policies row of that type).
- CAN_READ_SECRET_DATA selects resource_type "secrets"; same idea with a
  secrets resource row.
"""

from __future__ import annotations

import json

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph

from conftest import FakeSession, _edge_kinds, _edges, _policy

# Hierarchy used across all single-permission tests: org -> folder -> project.
_HIERARCHY = [
    {"name": "organizations/111", "type": "organization", "display_name": "corp", "project_id": "", "parent": ""},
    {"name": "folders/222", "type": "folder", "display_name": "eng", "project_id": "", "parent": "organizations/111"},
    {"name": "projects/proj-a", "type": "project", "display_name": "proj-a", "project_id": "proj-a", "parent": "folders/222"},
]

_ATTACKER = "user:eve@corp.com"


def _base_tables(
    *,
    iam_allow_policies: list[dict],
    iam_roles: list[dict],
) -> dict[str, list[dict]]:
    return {
        "iam_allow_policies": iam_allow_policies,
        "iam_roles": iam_roles,
        "abstract_tree_hierarchy": _HIERARCHY,
        "iam_service_accounts": [],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }


def _custom_role(name: str, permission: str) -> dict:
    # _custom_role_permissions() reads the `included_permissions` column.
    return {"name": name, "included_permissions": json.dumps([permission])}


def _run(tables: dict[str, list[dict]]) -> OpenGraphBuildContext:
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    return ctx


def _scope_binding_tables(*, scope_name: str, scope_type: str, project_id: str, permission: str) -> dict[str, list[dict]]:
    """Grant a custom role with `permission` to the attacker at a single scope."""
    role = "projects/proj-a/roles/Custom"
    iam = [
        {
            "project_id": project_id,
            "resource_type": scope_type,
            "resource_name": scope_name,
            "policy": _policy((role, [_ATTACKER])),
        }
    ]
    return _base_tables(iam_allow_policies=iam, iam_roles=[_custom_role(role, permission)])


def _project_binding_with_resource_tables(
    *, permission: str, resource_type: str, resource_name: str
) -> dict[str, list[dict]]:
    """Grant a custom role with `permission` at the project, plus a target resource of `resource_type`."""
    role = "projects/proj-a/roles/Custom"
    iam = [
        {
            "project_id": "proj-a",
            "resource_type": "project",
            "resource_name": "projects/proj-a",
            "policy": _policy((role, [_ATTACKER])),
        },
        # Make a resource of the selected type visible in proj-a so it can be a
        # dangerous-edge TARGET (it just needs any IAM member to be flattened).
        {
            "project_id": "proj-a",
            "resource_type": resource_type,
            "resource_name": resource_name,
            "policy": _policy(("roles/viewer", ["user:bystander@corp.com"])),
        },
    ]
    return _base_tables(iam_allow_policies=iam, iam_roles=[_custom_role(role, permission)])


# --------------------------------------------------------------------------- #
# Scope-targeted rules (no target_selector): scope itself is the destination.
# --------------------------------------------------------------------------- #


def test_can_modify_project_iam_edge_emitted():
    ctx = _run(
        _scope_binding_tables(
            scope_name="projects/proj-a",
            scope_type="project",
            project_id="proj-a",
            permission="resourcemanager.projects.setIamPolicy",
        )
    )
    assert "CAN_MODIFY_PROJECT_IAM" in _edge_kinds(ctx)
    # destination is the project scope resource node; source is the binding node.
    assert (
        "iambinding:projects/proj-a/roles/Custom@project:proj-a",
        "CAN_MODIFY_PROJECT_IAM",
        "resource:projects/proj-a",
    ) in _edges(ctx)


def test_can_modify_folder_iam_edge_emitted():
    ctx = _run(
        _scope_binding_tables(
            scope_name="folders/222",
            scope_type="folder",
            project_id="",
            permission="resourcemanager.folders.setIamPolicy",
        )
    )
    assert "CAN_MODIFY_FOLDER_IAM" in _edge_kinds(ctx)
    assert (
        "iambinding:projects/proj-a/roles/Custom@folder:222",
        "CAN_MODIFY_FOLDER_IAM",
        "resource:folders/222",
    ) in _edges(ctx)


def test_can_modify_org_iam_edge_emitted():
    ctx = _run(
        _scope_binding_tables(
            scope_name="organizations/111",
            scope_type="organization",
            project_id="",
            permission="resourcemanager.organizations.setIamPolicy",
        )
    )
    assert "CAN_MODIFY_ORG_IAM" in _edge_kinds(ctx)
    assert (
        "iambinding:projects/proj-a/roles/Custom@org:111",
        "CAN_MODIFY_ORG_IAM",
        "resource:organizations/111",
    ) in _edges(ctx)


# --------------------------------------------------------------------------- #
# service-account targeted rules: need a service-account resource in-project.
# --------------------------------------------------------------------------- #

_SA_RESOURCE = "projects/proj-a/serviceAccounts/svc@proj-a.iam.gserviceaccount.com"
# A service-account target collapses onto its serviceAccount:<email> PRINCIPAL node
# (one SA node, actor + object) rather than a separate resource:... node.
_SA_TARGET_NODE = "serviceAccount:svc@proj-a.iam.gserviceaccount.com"
_PROJECT_BINDING_NODE = "iambinding:projects/proj-a/roles/Custom@project:proj-a"


def _assert_sa_edge(permission: str, edge_kind: str) -> None:
    ctx = _run(
        _project_binding_with_resource_tables(
            permission=permission,
            resource_type="service-account",
            resource_name=_SA_RESOURCE,
        )
    )
    assert edge_kind in _edge_kinds(ctx)
    # project-scope binding node -> the service-account PRINCIPAL node (unified: the SA
    # is one node that is both an actor and the object of this dangerous edge).
    assert (_PROJECT_BINDING_NODE, edge_kind, _SA_TARGET_NODE) in _edges(ctx)


def test_can_modify_sa_iam_edge_emitted():
    _assert_sa_edge("iam.serviceAccounts.setIamPolicy", "CAN_MODIFY_SA_IAM")


def test_can_impersonate_sa_edge_emitted():
    _assert_sa_edge("iam.serviceAccounts.implicitDelegation", "CAN_IMPERSONATE_SA")


def test_can_create_sa_access_token_edge_emitted():
    _assert_sa_edge("iam.serviceAccounts.getAccessToken", "CAN_CREATE_SA_ACCESS_TOKEN")


def test_can_create_sa_key_edge_emitted():
    _assert_sa_edge("iam.serviceAccountKeys.create", "CAN_CREATE_SA_KEY")


# --------------------------------------------------------------------------- #
# secrets targeted rule: need a secrets resource in-project.
# --------------------------------------------------------------------------- #


def test_can_read_secret_data_edge_emitted():
    ctx = _run(
        _project_binding_with_resource_tables(
            permission="secretmanager.versions.access",
            resource_type="secrets",
            resource_name="projects/proj-a/secrets/db-password",
        )
    )
    assert "CAN_READ_SECRET_DATA" in _edge_kinds(ctx)
    assert (
        _PROJECT_BINDING_NODE,
        "CAN_READ_SECRET_DATA",
        "resource:projects/proj-a/secrets/db-password",
    ) in _edges(ctx)
