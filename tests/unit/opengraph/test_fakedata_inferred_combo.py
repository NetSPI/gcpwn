"""Fake-data regression tests for stage_3 INFERRED edges and stage_2 multi-permission combos.

These prove two edge families survive future refactors:

1. Stage 3 (`build_iam_inferred_permissions_graph`): from a credential's recorded
   permission EVIDENCE (`session.get_actions()`), a principal that holds a dangerous
   single permission gets ``HAS_IMPLIED_PERMISSIONS`` to an implied-grant node and an
   ``INFERRED_<KIND>`` edge to the affected resource (e.g. INFERRED_CAN_MODIFY_PROJECT_IAM).

2. Stage 2 multi-permission combos (`_run_iam_bindings_stage`): when one principal holds
   ALL permissions in a multi-permission rule set (og_privilege_escalation_paths.json), the
   pipeline models a combo hop: subject -> (combo binding) -> GCPIamCapability -> the combo
   edge (CREATE_CLOUDSCHEDULER_JOB_AS_SA) on the target SA. When the permissions arrive via
   TWO bindings, a GCPIamMultiBinding node + HAS_COMBO_BINDING / CONTRIBUTES_TO_COMBO appear.

Driven end-to-end over a FakeSession of canned rows; copies the harness pattern from
test_pipeline_fakedata.py. If the combo wiring ever drops these edges, these fail.
"""

from __future__ import annotations

from conftest import FakeSession, _edge_kinds, _edges, _node_types, _policy
from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_3_inferred_permissions import (
    build_iam_inferred_permissions_graph,
)


def _empty_workspace_tables() -> dict[str, list[dict]]:
    return {
        "iam_allow_policies": [],
        "abstract_tree_hierarchy": [],
        "iam_roles": [],
        "iam_service_accounts": [],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }


_HIERARCHY = [
    {"name": "organizations/111", "type": "organization", "display_name": "corp", "project_id": ""},
    {
        "name": "projects/proj-a",
        "type": "project",
        "display_name": "proj-a",
        "project_id": "proj-a",
        "parent": "organizations/111",
    },
]

# A service account email used as the actAs target in combo scenarios.
_SA = "projects/proj-a/serviceAccounts/runner@proj-a.iam.gserviceaccount.com"


# --------------------------------------------------------------------------- #
# Stage 3: INFERRED_<KIND> edges from recorded credential permission evidence
# --------------------------------------------------------------------------- #


def _run_inferred(actions, session_rows):
    tables = _empty_workspace_tables()
    tables["abstract_tree_hierarchy"] = _HIERARCHY
    ctx = OpenGraphBuildContext(
        session=FakeSession(tables, actions=actions, session_rows=session_rows),
        options=OpenGraphBuildOptions(),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    build_iam_inferred_permissions_graph(ctx)
    return ctx


def test_inferred_project_iam_edge_from_credential_evidence():
    # Credential cred-eve (==user:eve) proved resourcemanager.projects.setIamPolicy at the
    # project scope; stage 3 must infer the CAN_MODIFY_PROJECT_IAM dangerous edge.
    ctx = _run_inferred(
        actions=[
            {
                "credname": "cred-eve",
                "project_actions_allowed": {"projects/proj-a": ["resourcemanager.projects.setIamPolicy"]},
            }
        ],
        session_rows=[{"credname": "cred-eve", "email": "eve@corp.com", "credtype": "user"}],
    )
    edges = _edges(ctx)
    kinds = _edge_kinds(ctx)

    assert "HAS_IMPLIED_PERMISSIONS" in kinds
    assert "INFERRED_CAN_MODIFY_PROJECT_IAM" in kinds

    # principal -> implied grant node -> INFERRED edge -> the project resource node.
    implied_from_principal = [
        (src, dst) for src, kind, dst in edges if kind == "HAS_IMPLIED_PERMISSIONS"
    ]
    assert implied_from_principal == [("user:eve@corp.com", implied_from_principal[0][1])]
    implied_node_id = implied_from_principal[0][1]
    assert (implied_node_id, "INFERRED_CAN_MODIFY_PROJECT_IAM", "resource:projects/proj-a") in edges

    types = _node_types(ctx)
    assert types.get(implied_node_id) == "GCPIamSimpleBinding"
    assert types.get("resource:projects/proj-a") == "GCPProject"


def test_inferred_org_iam_edge_from_credential_evidence():
    # A different INFERRED kind at org scope, to prove the family is not project-specific.
    ctx = _run_inferred(
        actions=[
            {
                "credname": "cred-eve",
                "organization_actions_allowed": {
                    "organizations/111": ["resourcemanager.organizations.setIamPolicy"]
                },
            }
        ],
        session_rows=[{"credname": "cred-eve", "email": "eve@corp.com", "credtype": "user"}],
    )
    edges = _edges(ctx)
    assert "INFERRED_CAN_MODIFY_ORG_IAM" in _edge_kinds(ctx)
    assert any(
        kind == "INFERRED_CAN_MODIFY_ORG_IAM" and dst == "resource:organizations/111"
        for _src, kind, dst in edges
    )


def test_no_inferred_edges_without_dangerous_evidence():
    # A benign permission must NOT produce any inferred dangerous edge.
    ctx = _run_inferred(
        actions=[
            {
                "credname": "cred-eve",
                "project_actions_allowed": {"projects/proj-a": ["resourcemanager.projects.get"]},
            }
        ],
        session_rows=[{"credname": "cred-eve", "email": "eve@corp.com", "credtype": "user"}],
    )
    kinds = _edge_kinds(ctx)
    assert not any(kind.startswith("INFERRED_") for kind in kinds)
    assert "HAS_IMPLIED_PERMISSIONS" not in kinds


# --------------------------------------------------------------------------- #
# Stage 2: multi-permission combo modeling from real IAM bindings
# --------------------------------------------------------------------------- #


def _run_combo(iam_roles, iam_policies):
    tables = _empty_workspace_tables()
    tables["abstract_tree_hierarchy"] = _HIERARCHY
    tables["iam_roles"] = iam_roles
    tables["iam_allow_policies"] = iam_policies
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    return ctx


# CREATE_CLOUDSCHEDULER_JOB_AS_SA requires (cloudscheduler.jobs.create) + (iam.serviceAccounts.actAs)
# held by the same principal in the same project, with a service-account target available.
_SA_TARGET_POLICY = {
    "project_id": "proj-a",
    "resource_type": "service-account",
    "resource_name": _SA,
    "policy": _policy(("roles/viewer", ["user:nobody@corp.com"])),
}


def test_combo_edge_single_role_emits_capability_hop_and_combo_edge():
    # One custom role grants BOTH combo permissions -> a single GCPIamSimpleBinding feeds the
    # capability hop and the combo edge lands on the SA target.
    ctx = _run_combo(
        iam_roles=[
            {
                "name": "projects/proj-a/roles/combo",
                "included_permissions": ["cloudscheduler.jobs.create", "iam.serviceAccounts.actAs"],
            }
        ],
        iam_policies=[
            {
                "project_id": "proj-a",
                "resource_type": "project",
                "resource_name": "projects/proj-a",
                "policy": _policy(("projects/proj-a/roles/combo", ["user:eve@corp.com"])),
            },
            _SA_TARGET_POLICY,
        ],
    )
    edges = _edges(ctx)
    kinds = _edge_kinds(ctx)
    types = _node_types(ctx)

    # capability hop edge (binding -> GCPIamCapability) and the combo edge (capability -> SA).
    assert "CAN_CREATE_CLOUDSCHEDULER_JOB" in kinds
    assert "CREATE_CLOUDSCHEDULER_JOB_AS_SA" in kinds

    capability_nodes = [nid for nid, ntype in types.items() if ntype == "GCPIamCapability"]
    assert len(capability_nodes) == 1
    capability_id = capability_nodes[0]

    # the combo edge terminates on the service-account PRINCIPAL node (unified: the SA
    # is one node, actor + object, not a separate resource:... node).
    sa_node = f"serviceAccount:{_SA.split('/')[-1]}"
    assert (capability_id, "CREATE_CLOUDSCHEDULER_JOB_AS_SA", sa_node) in edges
    assert types.get(sa_node) == "GCPServiceAccount"
    assert any(
        src == capability_id and kind == "CREATE_CLOUDSCHEDULER_JOB_AS_SA" for src, kind, _ in edges
    )


def test_combo_two_bindings_emit_multi_binding_node_and_combo_binding_edges():
    # The two combo permissions arrive via TWO separate role bindings on the same principal.
    # That triggers a GCPIamMultiBinding combo node with HAS_COMBO_BINDING + CONTRIBUTES_TO_COMBO.
    ctx = _run_combo(
        iam_roles=[
            {"name": "projects/proj-a/roles/sched", "included_permissions": ["cloudscheduler.jobs.create"]},
            {"name": "projects/proj-a/roles/actas", "included_permissions": ["iam.serviceAccounts.actAs"]},
        ],
        iam_policies=[
            {
                "project_id": "proj-a",
                "resource_type": "project",
                "resource_name": "projects/proj-a",
                "policy": _policy(
                    ("projects/proj-a/roles/sched", ["user:eve@corp.com"]),
                    ("projects/proj-a/roles/actas", ["user:eve@corp.com"]),
                ),
            },
            _SA_TARGET_POLICY,
        ],
    )
    edges = _edges(ctx)
    kinds = _edge_kinds(ctx)
    types = _node_types(ctx)

    assert "HAS_COMBO_BINDING" in kinds
    assert "CONTRIBUTES_TO_COMBO" in kinds
    assert "CREATE_CLOUDSCHEDULER_JOB_AS_SA" in kinds

    combo_nodes = [nid for nid, ntype in types.items() if ntype == "GCPIamMultiBinding"]
    assert len(combo_nodes) == 1
    combo_id = combo_nodes[0]

    # subject -> combo node, and each of the two simple bindings -> combo node.
    assert ("user:eve@corp.com", "HAS_COMBO_BINDING", combo_id) in edges
    contributing = sorted(
        src for src, kind, dst in edges if kind == "CONTRIBUTES_TO_COMBO" and dst == combo_id
    )
    assert contributing == [
        "iambinding:projects/proj-a/roles/actas@project:proj-a",
        "iambinding:projects/proj-a/roles/sched@project:proj-a",
    ]
