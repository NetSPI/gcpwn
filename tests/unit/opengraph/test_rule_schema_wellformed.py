"""Well-formedness guard for the og_defined_edges.json rule file itself.

test_rule_schema.py proves the PARSER desugars correct input. This file proves
the shipped RULE FILE contains only valid shapes, so a mis-authored edge fails
at commit time instead of silently dropping its act_as pivot in a live run.

The format is discriminated by field presence:
  - simple edge  -> top-level `permissions` + `on`      -> GCPIamSimpleBinding
  - combo edge   -> `requires` array (+ optional `act_as`) -> GCPIamMultiBinding

_desugar_multi_permission_rule only desugars a combo when BOTH `requires` (list)
and `act_as` (dict) are present; an edge authored with top-level `permissions`
AND an `act_as` block has its `act_as` silently ignored. That exact shape shipped
7 broken edges once. These assertions reject it.
"""

from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.constants import (
    load_privilege_escalation_rules,
    load_resource_iam_edge_types,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_bindings_shared_helpers import (
    load_normalized_dangerous_rules_by_family,
)

_VIA_VALUES = {"capability", "resource"}

# Resource-level setIamPolicy edges (sa_token_theft_without_actas=false/"partial") that are
# hidden from the default graph (they can't reach the attached SA without actAs).
_RESOURCE_IAM_EDGES = {
    "CAN_MODIFY_BUCKET_IAM",
    "CAN_MODIFY_COMPUTE_INSTANCE_IAM",
    "CAN_MODIFY_KMS_CRYPTOKEY_IAM",
    "CAN_MODIFY_CLOUD_RUN_SERVICE_IAM",
    "CAN_MODIFY_CLOUD_RUN_JOB_IAM",
    "CAN_MODIFY_CLOUD_RUN_FUNCTION_IAM",
}
# setIamPolicy edges KEPT by default: only org/folder/project/SA (which let you grant
# yourself roles) plus secret (user decision: keep as a secret-access path).
_KEPT_SETIAMPOLICY_EDGES = {
    "CAN_MODIFY_ORG_IAM",
    "CAN_MODIFY_FOLDER_IAM",
    "CAN_MODIFY_PROJECT_IAM",
    "CAN_MODIFY_SA_IAM",
    "CAN_MODIFY_SECRET_MANAGER_SECRET_IAM",
}


def test_resource_iam_edge_types_detected():
    """Regression: load_resource_iam_edge_types() silently returned an empty set once
    (it read raw rules' edge_type, which single-perm rules omit — it defaults to the rule
    NAME at normalization). An empty set makes the default resource-IAM filter a no-op, so
    bucket/KMS/compute/cloud-run setIamPolicy edges leak into every default graph."""
    detected = load_resource_iam_edge_types()
    assert detected == frozenset(_RESOURCE_IAM_EDGES), (
        f"resource-IAM edge detection drifted. got={sorted(detected)} "
        f"expected={sorted(_RESOURCE_IAM_EDGES)}"
    )
    # The kept setIamPolicy edges must NEVER be classified resource-IAM (they would then be
    # hidden by default, losing real self-grant privilege-escalation paths).
    assert not (_KEPT_SETIAMPOLICY_EDGES & detected), (
        f"a kept setIamPolicy edge is mis-tagged resource-IAM: {sorted(_KEPT_SETIAMPOLICY_EDGES & detected)}"
    )


def _default_single_rule_names():
    single, _multi = load_normalized_dangerous_rules_by_family(categories=frozenset({"priv_escalation"}))
    return {r["name"] for r in single if not r.get("include_all_only")}


def test_default_edge_set_includes_secret_read_only_resource_edge():
    """Default graph = all PE edges + exactly ONE resource-access edge (CAN_READ_SECRET_DATA,
    flagged default_include). The other sensitive_resource_access reads stay opt-in."""
    names = _default_single_rule_names()
    assert "CAN_READ_SECRET_DATA" in names, "secret-read must be on by default (default_include)"
    other_sensitive = {
        "DECRYPT_WITH_KMS_KEY", "SIGN_WITH_KMS_KEY", "BQ_STORAGE_READ_API_EXFIL",
        "EXPORT_BQ_TABLE_TO_GCS", "CONNECT_TO_CLOUD_SQL_DB", "CREATE_CLOUDSQL_SSL_CERT",
        "READ_API_KEY_STRING", "READ_WORKSTATION_ACCESS_TOKEN",
        "READ_DEVELOPERCONNECT_GIT_TOKEN", "READ_DEVELOPERCONNECT_GIT_READ_TOKEN",
    }
    leaked = other_sensitive & names
    assert not leaked, f"non-secret sensitive_resource_access edges leaked into default graph: {sorted(leaked)}"
    assert "CAN_READ_STORAGE_OBJECT" not in names, "storage read must stay opt-in"


def _iter_edges():
    """Yield (category, edge_name, rule_dict) for every leaf edge rule, across
    the full category/service nesting, using the same loader the pipeline uses."""
    single_rules, multi_rules, _collapsed = load_privilege_escalation_rules(categories=None)
    for name, rule in (single_rules or {}).items():
        yield ("single", name, rule)
    for name, rule in (multi_rules or {}).items():
        yield ("multi", name, rule)


def test_no_combo_edge_uses_the_single_perm_shape():
    """An edge with an act_as pivot MUST use the `requires` array shape, or the
    desugarer ignores act_as and the SA-impersonation hop is never emitted."""
    offenders = []
    for _kind, name, rule in _iter_edges():
        if not isinstance(rule, dict):
            continue
        has_act_as = isinstance(rule.get("act_as"), dict)
        has_requires = isinstance(rule.get("requires"), list)
        has_top_permissions = "permissions" in rule and "requires" not in rule
        if has_act_as and not has_requires:
            offenders.append(name)
        if has_act_as and has_top_permissions:
            offenders.append(name)
    assert not offenders, (
        "edges declare act_as with the single-perm `permissions` shape; act_as is "
        f"silently dropped. Convert to the `requires` array form: {sorted(set(offenders))}"
    )


def test_no_edge_mixes_both_shapes():
    """`permissions` (top-level) and `requires` are mutually exclusive discriminators."""
    offenders = [
        name
        for _kind, name, rule in _iter_edges()
        if isinstance(rule, dict) and "permissions" in rule and "requires" in rule
    ]
    assert not offenders, f"edges set both top-level `permissions` and `requires`: {sorted(set(offenders))}"


def test_via_values_are_known():
    offenders = [
        (name, rule.get("via"))
        for _kind, name, rule in _iter_edges()
        if isinstance(rule, dict) and rule.get("via") is not None and str(rule.get("via")) not in _VIA_VALUES
    ]
    assert not offenders, f"edges declare an unknown `via` value (expected {_VIA_VALUES}): {offenders}"


def test_every_edge_has_at_least_one_permission():
    """Every rule must name at least one permission somewhere, or it can never match."""
    offenders = []
    for _kind, name, rule in _iter_edges():
        if not isinstance(rule, dict):
            continue
        perms = list(rule.get("permissions") or [])
        for group in rule.get("requires") or []:
            if isinstance(group, dict):
                perms.extend(group.get("permissions") or [])
        if not perms:
            offenders.append(name)
    assert not offenders, f"edges name no permissions at all (can never match): {sorted(set(offenders))}"
