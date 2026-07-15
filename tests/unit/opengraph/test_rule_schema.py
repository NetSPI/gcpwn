"""Regression tests for the unified og_privilege_escalation_paths.json schema.

Covers three layers:
  1. _desugar_multi_permission_rule: new key names (requires/on/edge/via) AND
     legacy key names (subject_groups/target/subject_edge/subject_node) both expand
     to the same internal requires_groups + combo_hop structure.
  2. expand_single_permission_rules: new `permissions: [...]` + `on:` form expands
     correctly; legacy `permission: str` + `target_selector` still accepted.
  3. Full pipeline: for each multi-permission rule in the live JSON, a FakeSession
     with the minimum required permissions produces the expected capability and combo
     edges.  These are the "populate test data" checks.
"""
from __future__ import annotations

import json
import pathlib
import pytest

from conftest import FakeSession, _edge_kinds, _edges, _policy
from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _run_iam_bindings_stage
from gcpwn.modules.opengraph.utilities.helpers.graph.context import (
    OpenGraphBuildContext,
    OpenGraphBuildOptions,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    _desugar_multi_permission_rule,
    expand_single_permission_rules,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

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

_SA_EMAIL = "runner@proj-a.iam.gserviceaccount.com"
_SA_RESOURCE = f"projects/proj-a/serviceAccounts/{_SA_EMAIL}"


def _run_combo(iam_roles, iam_policies):
    tables = {
        "iam_allow_policies": iam_policies,
        "abstract_tree_hierarchy": _HIERARCHY,
        "iam_roles": iam_roles,
        "iam_service_accounts": [],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    return ctx


def _sa_policy():
    """IAM policy on the SA resource so actAs can find a target."""
    return {
        "project_id": "proj-a",
        "resource_type": "service-account",
        "resource_name": _SA_RESOURCE,
        "policy": _policy(("roles/viewer", ["user:nobody@corp.com"])),
    }


def _custom_role(name, permissions):
    return {"name": f"projects/proj-a/roles/{name}", "included_permissions": list(permissions)}


def _project_policy(role, members=("user:eve@corp.com",)):
    return {
        "project_id": "proj-a",
        "resource_type": "project",
        "resource_name": "projects/proj-a",
        "policy": _policy((role, list(members))),
    }


# --------------------------------------------------------------------------- #
# 1. _desugar_multi_permission_rule: new key names
# --------------------------------------------------------------------------- #

class TestDesugarsNewForm:
    """New keys: requires / on / edge / via / (no target_edge needed)."""

    def test_basic_2hop_capability(self):
        out = _desugar_multi_permission_rule("CREATE_CLOUDRUN_SERVICE_AS_SA", {
            "requires": [
                {"permissions": ["run.services.create"], "on": "cloudrunservice"},
            ],
            "edge": "CAN_CREATE_CLOUDRUN_SERVICE",
            "via": "capability",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "on": "service-account"},
        })
        groups = {g["id"]: g for g in out["requires_groups"]}
        assert set(groups) == {"subject_1", "act_as"}
        assert groups["subject_1"]["target_selector"] == {
            "mode": "resource_types", "resource_types": ["cloudrunservice"]}
        assert groups["act_as"]["target_selector"] == {
            "mode": "resource_types", "resource_types": ["service-account"]}
        hop = out["combo_hop"]["hops"][0]
        assert hop["edge_from_subject"] == "CAN_CREATE_CLOUDRUN_SERVICE"
        assert hop["node_mode"] == "capability"
        assert out["combo_hop"]["edge_to_target"] == "CREATE_CLOUDRUN_SERVICE_AS_SA"

    def test_resource_node_mode(self):
        out = _desugar_multi_permission_rule("RESET_COMPUTE_STARTUP_SA", {
            "requires": [
                {"permissions": ["compute.instances.get", "compute.instances.setMetadata",
                                 "compute.instances.reset"],
                 "on": "computeinstance", "status_in": ["RUNNING"]},
            ],
            "edge": "CAN_RESET_COMPUTE_WITH_STARTUP_SCRIPT",
            "via": "resource",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "on": "service-account"},
        })
        assert out["combo_hop"]["hops"][0]["node_mode"] == "resource"
        groups = {g["id"]: g for g in out["requires_groups"]}
        assert groups["subject_1"]["target_selector"]["status_in"] == ["RUNNING"]

    def test_multiple_requires_groups(self):
        out = _desugar_multi_permission_rule("CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA", {
            "requires": [
                {"permissions": ["cloudfunctions.functions.create",
                                 "cloudfunctions.functions.sourceCodeSet"], "on": "cloudfunction"},
                {"permissions": ["cloudfunctions.functions.call"], "on": "cloudfunction"},
            ],
            "edge": "CAN_CREATE_DEPLOY_INVOKE_CLOUDFUNCTION",
            "via": "capability",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "on": "service-account"},
        })
        assert out["combo_hop"]["hops"][0]["from_groups"] == ["subject_1", "subject_2"]
        # rule key = final edge when no explicit target_edge
        assert out["combo_hop"]["edge_to_target"] == "CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA"

    def test_no_on_in_requires_group(self):
        # CREATE_CLOUDSCHEDULER_JOB_AS_SA has no "on" in its requires group
        out = _desugar_multi_permission_rule("CREATE_CLOUDSCHEDULER_JOB_AS_SA", {
            "requires": [{"permissions": ["cloudscheduler.jobs.create"]}],
            "edge": "CAN_CREATE_CLOUDSCHEDULER_JOB",
            "via": "capability",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "on": "service-account"},
        })
        groups = {g["id"]: g for g in out["requires_groups"]}
        assert "target_selector" not in groups["subject_1"]
        assert groups["subject_1"]["resource_scopes_possible"] == ["project"]

    def test_description_passed_through(self):
        out = _desugar_multi_permission_rule("CREATE_CLOUDRUN_SERVICE_AS_SA", {
            "requires": [{"permissions": ["run.services.create"], "on": "cloudrunservice"}],
            "edge": "CAN_CREATE_CLOUDRUN_SERVICE",
            "via": "capability",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "on": "service-account"},
            "description": "should appear in output",
            "example_command": "modules exploit_cloudrun_as_sa --target-sa {target_sa}",
        })
        assert out.get("description") == "should appear in output"
        assert out.get("example_command") == "modules exploit_cloudrun_as_sa --target-sa {target_sa}"


# --------------------------------------------------------------------------- #
# 2. _desugar_multi_permission_rule: legacy key names still work
# --------------------------------------------------------------------------- #

class TestDesugarsLegacyForm:
    """Old keys: subject_groups / target / subject_edge / subject_node / target_edge."""

    def test_legacy_expands_identically(self):
        new = _desugar_multi_permission_rule("RESET_COMPUTE_STARTUP_SA", {
            "requires": [
                {"permissions": ["compute.instances.get", "compute.instances.reset"],
                 "on": "computeinstance", "status_in": ["RUNNING"]},
            ],
            "edge": "CAN_RESET_COMPUTE_WITH_STARTUP_SCRIPT",
            "via": "resource",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "on": "service-account"},
        })
        legacy = _desugar_multi_permission_rule("RESET_COMPUTE_STARTUP_SA", {
            "subject_groups": [
                {"permissions": ["compute.instances.get", "compute.instances.reset"],
                 "target": "computeinstance", "status_in": ["RUNNING"]},
            ],
            "subject_edge": "CAN_RESET_COMPUTE_WITH_STARTUP_SCRIPT",
            "subject_node": "resource",
            "target_edge": "RESET_COMPUTE_STARTUP_SA",
            "act_as": {"permissions": ["iam.serviceAccounts.actAs"], "target": "service-account"},
        })
        # Both forms should produce the same combo_hop and requires_groups
        assert new["combo_hop"] == legacy["combo_hop"]
        new_groups = {g["id"]: g for g in new["requires_groups"]}
        leg_groups = {g["id"]: g for g in legacy["requires_groups"]}
        assert new_groups == leg_groups

    def test_verbose_passthrough_unchanged(self):
        verbose = {
            "multi_permission_type": "complex",
            "requires_groups": [{"id": "g", "permissions": ["x"]}],
            "combo_hop": {"edge_to_target": "E", "hops": []},
        }
        assert _desugar_multi_permission_rule("R", verbose) is verbose

    def test_match_paths_blocks_sugar(self):
        rule = {
            "match_paths": [{"id": "p", "requires_groups": []}],
            "subject_groups": [{"permissions": ["x"]}],
            "act_as": {"permissions": ["y"]},
        }
        assert _desugar_multi_permission_rule("R", rule) is rule


# --------------------------------------------------------------------------- #
# 3. expand_single_permission_rules: new form
# --------------------------------------------------------------------------- #

class TestExpandSinglePermissionRules:

    def test_new_permissions_list(self):
        rules = expand_single_permission_rules({
            "CAN_MODIFY_PROJECT_IAM": {"permissions": ["resourcemanager.projects.setIamPolicy"]}
        })
        assert rules["CAN_MODIFY_PROJECT_IAM"]["requires_any"] == ["resourcemanager.projects.setIamPolicy"]

    def test_new_on_shorthand_builds_target_selector(self):
        rules = expand_single_permission_rules({
            "CAN_CREATE_SA_ACCESS_TOKEN": {
                "permissions": ["iam.serviceAccounts.getAccessToken"],
                "on": "service-account",
            }
        })
        r = rules["CAN_CREATE_SA_ACCESS_TOKEN"]
        assert r["requires_any"] == ["iam.serviceAccounts.getAccessToken"]
        assert r["target_selector"] == {"mode": "resource_types", "resource_types": ["service-account"]}

    def test_legacy_permission_singular_still_works(self):
        rules = expand_single_permission_rules({
            "OLD_RULE": {
                "permission": "some.perm",
                "target_selector": {"mode": "resource_types", "resource_types": ["foo"]},
            }
        })
        r = rules["OLD_RULE"]
        assert r["requires_any"] == ["some.perm"]
        assert r["target_selector"] == {"mode": "resource_types", "resource_types": ["foo"]}

    def test_description_and_scopes_stripped(self):
        rules = expand_single_permission_rules({
            "X": {
                "permissions": ["x.y.z"],
                "description": "verbose docs",
                "resource_scopes_possible": ["project"],
            }
        })
        r = rules["X"]
        assert "description" not in r
        assert "resource_scopes_possible" not in r

    def test_skips_rule_with_no_permissions(self):
        rules = expand_single_permission_rules({"EMPTY": {}})
        assert "EMPTY" not in rules


# --------------------------------------------------------------------------- #
# 4. Live JSON round-trip: file loads + all rules are present
# --------------------------------------------------------------------------- #

def _load_json():
    p = pathlib.Path(__file__).parent.parent.parent.parent / "gcpwn" / "mappings" / "og_privilege_escalation_paths.json"
    return json.loads(p.read_text())


def test_live_json_has_unified_rules_key():
    d = _load_json()
    assert "rules" in d
    assert "single_permission_rules" not in d
    assert "multi_permission_rules" not in d


def test_live_json_all_expected_rules_present():
    rules = _load_json()["rules"]
    expected_single = {
        "CAN_MODIFY_PROJECT_IAM", "CAN_MODIFY_FOLDER_IAM", "CAN_MODIFY_ORG_IAM",
        "CAN_MODIFY_SA_IAM", "CAN_MODIFY_COMPUTE_INSTANCE_IAM", "CAN_MODIFY_ClOUD_RUN_FUNCTION_IAM",
        "CAN_MODIFY_SECRET_MANAGER_SECRET_IAM", "CAN_IMPERSONATE_SA", "CAN_CREATE_SA_ACCESS_TOKEN",
        "CAN_CREATE_SA_KEY", "CAN_CREATE_CLOUDBUILD_DEFAULT_IDENTITY", "CAN_UPDATE_CLOUDBUILD_BUILD",
        "CAN_READ_SECRET_DATA",
    }
    expected_multi = {
        "RESET_COMPUTE_STARTUP_SA", "START_COMPUTE_STARTUP_SA",
        "CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA", "UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
        "CREATE_CLOUDSCHEDULER_JOB_AS_SA", "CREATE_CLOUDBUILD_AS_SA", "CREATE_CLOUDRUN_SERVICE_AS_SA",
    }
    for name in expected_single:
        assert name in rules, f"missing single rule: {name}"
        assert "permissions" in rules[name], f"{name}: should have 'permissions'"
        assert "requires" not in rules[name], f"{name}: should NOT have 'requires'"
    for name in expected_multi:
        assert name in rules, f"missing multi rule: {name}"
        assert "requires" in rules[name], f"{name}: should have 'requires'"
        assert "act_as" in rules[name], f"{name}: should have 'act_as'"
        assert "edge" in rules[name], f"{name}: should have 'edge'"


def test_live_json_no_old_keys():
    rules = _load_json()["rules"]
    old_keys = {"permission", "subject_groups", "subject_edge", "subject_node", "target_edge",
                "resource_scopes_possible"}
    for name, rule in rules.items():
        bad = old_keys & set(rule)
        assert not bad, f"rule {name!r} still has old keys: {bad}"


# --------------------------------------------------------------------------- #
# 5. Full pipeline: each multi-permission rule produces the right edges
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rule_name,perms,subject_edge,combo_edge", [
    (
        "CREATE_CLOUDSCHEDULER_JOB_AS_SA",
        ["cloudscheduler.jobs.create", "iam.serviceAccounts.actAs"],
        "CAN_CREATE_CLOUDSCHEDULER_JOB",
        "CREATE_CLOUDSCHEDULER_JOB_AS_SA",
    ),
    (
        "CREATE_CLOUDBUILD_AS_SA",
        ["cloudbuild.builds.create", "iam.serviceAccounts.actAs"],
        "CAN_CREATE_CLOUDBUILD_BUILD",
        "CREATE_CLOUDBUILD_AS_SA",
    ),
    (
        "CREATE_CLOUDRUN_SERVICE_AS_SA",
        ["run.services.create", "iam.serviceAccounts.actAs"],
        "CAN_CREATE_CLOUDRUN_SERVICE",
        "CREATE_CLOUDRUN_SERVICE_AS_SA",
    ),
    (
        "CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
        ["cloudfunctions.functions.create", "cloudfunctions.functions.sourceCodeSet",
         "cloudfunctions.functions.call", "iam.serviceAccounts.actAs"],
        "CAN_CREATE_DEPLOY_INVOKE_CLOUDFUNCTION",
        "CREATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
    ),
    (
        "UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
        ["cloudfunctions.functions.update", "cloudfunctions.functions.sourceCodeSet",
         "cloudfunctions.functions.call", "iam.serviceAccounts.actAs"],
        "CAN_UPDATE_DEPLOY_INVOKE_CLOUDFUNCTION",
        "UPDATE_AND_INVOKE_CLOUDFUNCTION_AS_SA",
    ),
])
def test_multi_rule_produces_correct_edges(rule_name, perms, subject_edge, combo_edge):
    """Each multi-permission rule: single role with all required permissions ->
    subject edge + combo edge to the SA target."""
    ctx = _run_combo(
        iam_roles=[_custom_role("combo", perms)],
        iam_policies=[
            _project_policy("projects/proj-a/roles/combo"),
            _sa_policy(),
        ],
    )
    kinds = _edge_kinds(ctx)
    assert subject_edge in kinds, f"{rule_name}: missing subject edge {subject_edge!r}"
    assert combo_edge in kinds, f"{rule_name}: missing combo edge {combo_edge!r}"

    # combo edge must terminate on the SA node
    sa_node = f"serviceAccount:{_SA_EMAIL}"
    assert any(
        kind == combo_edge and dst == sa_node for _src, kind, dst in _edges(ctx)
    ), f"{rule_name}: combo edge {combo_edge!r} does not reach SA {sa_node!r}"


@pytest.mark.parametrize("rule_name,perms,subject_edge,combo_edge", [
    (
        "RESET_COMPUTE_STARTUP_SA",
        ["compute.instances.get", "compute.instances.setMetadata",
         "compute.instances.reset", "iam.serviceAccounts.actAs"],
        "CAN_RESET_COMPUTE_WITH_STARTUP_SCRIPT",
        "RESET_COMPUTE_STARTUP_SA",
    ),
    (
        "START_COMPUTE_STARTUP_SA",
        ["compute.instances.get", "compute.instances.setMetadata",
         "compute.instances.start", "iam.serviceAccounts.actAs"],
        "CAN_START_COMPUTE_WITH_STARTUP_SCRIPT",
        "START_COMPUTE_STARTUP_SA",
    ),
])
def test_compute_combo_rules_produce_correct_edges(rule_name, perms, subject_edge, combo_edge):
    """Compute startup-script rules: require a running/stopped VM resource in the DB
    for the subject-group target_selector to match."""
    vm_status = "RUNNING" if "reset" in perms else "STOPPED"
    tables = {
        "iam_allow_policies": [
            _project_policy("projects/proj-a/roles/combo"),
            _sa_policy(),
        ],
        "abstract_tree_hierarchy": _HIERARCHY,
        "iam_roles": [_custom_role("combo", perms)],
        "iam_service_accounts": [],
        "cloudcompute_instances": [
            {
                "project_id": "proj-a",
                "name": "projects/proj-a/zones/us-central1-a/instances/vm1",
                "status": vm_status,
                "service_account": _SA_EMAIL,
            }
        ],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)

    kinds = _edge_kinds(ctx)
    assert combo_edge in kinds, f"{rule_name}: missing combo edge {combo_edge!r}"
    sa_node = f"serviceAccount:{_SA_EMAIL}"
    assert any(
        kind == combo_edge and dst == sa_node for _src, kind, dst in _edges(ctx)
    ), f"{rule_name}: combo edge does not reach SA {sa_node!r}"


@pytest.mark.parametrize("rule_name,perm,expected_edge", [
    # Project-scoped rules: no "on" → edge points to the project node (always present).
    ("CAN_MODIFY_PROJECT_IAM", "resourcemanager.projects.setIamPolicy", "CAN_MODIFY_PROJECT_IAM"),
    ("CAN_CREATE_CLOUDBUILD_DEFAULT_IDENTITY", "cloudbuild.builds.create", "CAN_CREATE_CLOUDBUILD_DEFAULT_IDENTITY"),
    # SA-scoped rules: "on: service-account" → edge points to the SA node (_sa_policy adds it).
    ("CAN_CREATE_SA_ACCESS_TOKEN", "iam.serviceAccounts.getAccessToken", "CAN_CREATE_SA_ACCESS_TOKEN"),
    ("CAN_CREATE_SA_KEY", "iam.serviceAccountKeys.create", "CAN_CREATE_SA_KEY"),
    ("CAN_IMPERSONATE_SA", "iam.serviceAccounts.implicitDelegation", "CAN_IMPERSONATE_SA"),
])
def test_single_permission_rule_produces_edge(rule_name, perm, expected_edge):
    """Each single-permission rule fires when a binding grants the required permission."""
    ctx = _run_combo(
        iam_roles=[_custom_role("single", [perm])],
        iam_policies=[
            _project_policy("projects/proj-a/roles/single"),
            _sa_policy(),
        ],
    )
    kinds = _edge_kinds(ctx)
    assert expected_edge in kinds, (
        f"{rule_name}: expected edge {expected_edge!r} not found in {sorted(kinds)}"
    )


def test_can_read_secret_data_fires_when_secret_resource_present():
    """CAN_READ_SECRET_DATA has on: secrets -> edge only emits when a secrets node exists."""
    tables = {
        "iam_allow_policies": [
            _project_policy("projects/proj-a/roles/single"),
            {
                "project_id": "proj-a",
                "resource_type": "secrets",
                "resource_name": "projects/proj-a/secrets/my-secret",
                "policy": _policy(("roles/viewer", ["user:nobody@corp.com"])),
            },
        ],
        "abstract_tree_hierarchy": _HIERARCHY,
        "iam_roles": [_custom_role("single", ["secretmanager.versions.access"])],
        "iam_service_accounts": [],
        "workspace_users": [],
        "workspace_groups": [],
        "workspace_group_memberships": [],
        "workspace_admin_roles": [],
        "workspace_role_assignments": [],
    }
    ctx = OpenGraphBuildContext(session=FakeSession(tables), options=OpenGraphBuildOptions())
    build_users_groups_graph(ctx)
    _run_iam_bindings_stage(ctx)
    assert "CAN_READ_SECRET_DATA" in _edge_kinds(ctx)
