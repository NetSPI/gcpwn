from __future__ import annotations

from typing import Any

from google.cloud import orgpolicy_v2

from gcpwn.core.resource import GcpListResource


def _rule_summary(spec: dict[str, Any]) -> str:
    """Build a compact, human-readable summary of an org-policy's effective rules.

    Org policies (constraints) are high-value recon: they tell an operator which
    attacks the project has *already blocked*. The offensively interesting signal
    is whether a boolean constraint is ``enforced`` (e.g.
    ``iam.disableServiceAccountKeyCreation`` enforced -> SA-key priv-esc is shut
    off) and, for list constraints, which values are allowed/denied. This folds
    ``spec.rules`` into a short string like
    ``enforce; allow_all; allow=[a,b]; deny=[c]`` so the summary table is readable
    without dumping raw_json.
    """
    if not isinstance(spec, dict):
        return ""
    rules = spec.get("rules")
    if not isinstance(rules, list) or not rules:
        # An empty spec with inherit_from_parent is itself meaningful recon.
        if spec.get("reset"):
            return "reset"
        if spec.get("inherit_from_parent"):
            return "inherit_from_parent"
        return ""
    parts: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("enforce") is True:
            parts.append("enforce")
        if rule.get("enforce") is False:
            parts.append("not_enforced")
        if rule.get("allow_all") is True:
            parts.append("allow_all")
        if rule.get("deny_all") is True:
            parts.append("deny_all")
        values = rule.get("values") if isinstance(rule.get("values"), dict) else None
        if values:
            allowed = values.get("allowed_values") or []
            denied = values.get("denied_values") or []
            if allowed:
                parts.append("allow=[" + ",".join(str(v) for v in allowed) + "]")
            if denied:
                parts.append("deny=[" + ",".join(str(v) for v in denied) + "]")
        condition = rule.get("condition") if isinstance(rule.get("condition"), dict) else None
        if condition and (condition.get("expression") or condition.get("title")):
            parts.append("conditional")
    return "; ".join(parts)


class OrgPolicyPoliciesResource(GcpListResource):
    """List/get Organization Policy constraints set on a project via orgpolicy_v2.

    These are the org-policy *constraints* enforced on the project (e.g.
    ``iam.disableServiceAccountKeyCreation``, ``compute.requireOsLogin``). The
    Policy resource is ``projects/<p>/policies/<constraint>`` with a ``spec.rules``
    body; the ``rule_summary`` derived column condenses that into
    enforced/allow/deny so an operator can see at a glance which guardrails are
    active (i.e. which attack paths are blocked) for the project.

    Org Policy exposes no per-policy ``testIamPermissions`` on the GAPIC client, so
    the component runs with ``supports_iam=False``.
    """

    SERVICE_LABEL = "Organization Policy"
    TABLE_NAME = "orgpolicy_policies"
    COLUMNS = ["constraint", "name", "rule_summary", "inherit_from_parent", "reset", "etag"]
    ACTION_RESOURCE_TYPE = "policies"
    LIST_PERMISSION = "orgpolicy.policies.list"
    GET_PERMISSION = "orgpolicy.policy.get"
    ID_FIELD = "constraint"
    PARENT_FROM_PROJECT = True  # parent = projects/<p>; list scoped as a project permission

    def _build_client(self, session):
        return orgpolicy_v2.OrgPolicyClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_policies(request=orgpolicy_v2.ListPoliciesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_policy(request=orgpolicy_v2.GetPolicyRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        spec = raw.get("spec") if isinstance(raw.get("spec"), dict) else {}
        return {
            "rule_summary": _rule_summary(spec),
            "inherit_from_parent": "yes" if spec.get("inherit_from_parent") else "no",
            "reset": "yes" if spec.get("reset") else "no",
            "etag": str(spec.get("etag") or raw.get("etag") or ""),
        }
