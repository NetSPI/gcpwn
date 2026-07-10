"""Fake-data tests for IAM CONDITION handling on bindings.

Conditional support is currently PASS-THROUGH (placeholder): the condition is
detected, hashed, and recorded on the binding node, but not CEL-evaluated, so
--cond-eval (conditional_evaluation) does not narrow anything. These tests pin
that contract:
- a conditioned binding gets a deterministic `#cond:<hash>` node-id suffix and
  `conditional` / `condition_expr_raw` / `condition_hash` properties;
- the same expression always hashes to the same node (dedup); distinct
  expressions produce distinct nodes;
- conditional_evaluation on vs off yields IDENTICAL output (pass-through).
"""

from __future__ import annotations

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph

from conftest import FakeSession, _policy


_TABLE_KEYS = (
    "iam_allow_policies", "iam_roles", "abstract_tree_hierarchy", "iam_service_accounts",
    "workspace_users", "workspace_groups", "workspace_group_memberships",
    "workspace_admin_roles", "workspace_role_assignments",
)
_HIER = [{"name": "projects/proj-a", "type": "project", "display_name": "proj-a", "project_id": "proj-a", "parent": ""}]
_EXPR = "resource.name.startsWith('projects/_/buckets/prod-')"


def _run(iam, *, cond_eval=False):
    tables = {k: [] for k in _TABLE_KEYS}
    tables["iam_allow_policies"] = iam
    tables["abstract_tree_hierarchy"] = _HIER
    ctx = OpenGraphBuildContext(
        session=FakeSession(tables),
        options=OpenGraphBuildOptions(conditional_evaluation=cond_eval, include_all=True),
    )
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    return ctx


def _binding_nodes(ctx):
    return [n for n in ctx.builder.node_map.values() if n.node_id.startswith("iambinding:")]


def _conditioned_iam(role="roles/editor", members=("user:bob@corp.com"), expr=_EXPR):
    return [{
        "project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
        "policy": _policy((role, list(members), {"expression": expr, "title": "t"})),
    }]


def test_conditioned_binding_gets_cond_suffix_and_properties():
    ctx = _run(_conditioned_iam())
    bindings = _binding_nodes(ctx)
    assert len(bindings) == 1
    node = bindings[0]
    assert "#cond:" in node.node_id
    props = node.properties or {}
    assert props.get("conditional") is True
    assert props.get("condition_expr_raw") == _EXPR
    chash = str(props.get("condition_hash") or "")
    assert len(chash) == 10 and node.node_id.endswith("#cond:" + chash)


def test_condition_hash_is_deterministic_and_dedups():
    # two policy rows with the SAME role+condition collapse to ONE binding node
    iam = _conditioned_iam() + _conditioned_iam()
    ctx = _run(iam)
    assert len(_binding_nodes(ctx)) == 1


def test_distinct_conditions_produce_distinct_binding_nodes():
    iam = (
        _conditioned_iam(expr="request.time < timestamp('2025-01-01T00:00:00Z')")
        + _conditioned_iam(expr="resource.type == 'storage.googleapis.com/Bucket'")
    )
    ctx = _run(iam)
    ids = {n.node_id for n in _binding_nodes(ctx)}
    assert len(ids) == 2
    assert all("#cond:" in i for i in ids)


def test_unconditioned_binding_has_no_cond_suffix():
    iam = [{
        "project_id": "proj-a", "resource_type": "project", "resource_name": "projects/proj-a",
        "policy": _policy(("roles/editor", ["user:bob@corp.com"])),
    }]
    ctx = _run(iam)
    node = _binding_nodes(ctx)[0]
    assert "#cond:" not in node.node_id
    assert not (node.properties or {}).get("conditional")


def test_cond_eval_is_passthrough_identical_output():
    # --cond-eval (conditional_evaluation) currently does NOT narrow; on vs off match.
    def snapshot(cond_eval):
        ctx = _run(_conditioned_iam(), cond_eval=cond_eval)
        return (
            {(n.node_id, n.node_type) for n in ctx.builder.node_map.values()},
            {(e.source_id, e.edge_type, e.destination_id) for e in ctx.builder.edge_map.values()},
        )
    assert snapshot(False) == snapshot(True)
