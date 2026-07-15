"""Deny-policy FILTER (opt-in via --deny-policies) -- runs LAST, after the whole allow
graph is built, and rewrites it to reflect effective access = allow MINUS deny.

IAM v2 Deny Policies block a set of permissions for a set of principals at an org/folder/
project scope (inheriting DOWNWARD), unless the principal is in the rule's exception set,
gated by an optional CEL denialCondition. Rather than add a parallel "deny layer", this
stage edits the existing edges:

  * For each already-emitted grant edge (a binding/dangerous edge that carries a principal
    + the permissions it grants + a scope), it finds deny rules whose scope covers the
    edge's scope and whose denied permissions overlap the edge's permissions.
  * If the edge's principal is denied and NOT exempt -> the grant is blocked:
      - direct principal (user/SA), no exemption reaching it  -> DROP the edge.
      - GROUP principal with exempted members still in the group -> the grant now applies
        only to those members: the edge is RE-POINTED (source group node -> the exempted
        member; if exactly one member remains it becomes a single-user edge) and flagged.
  * Every edge left in play that a deny touched is flagged ``deny_policy_in_play=True`` with
    ``deny_policy_ids`` / ``deny_effective_principals`` so the operator sees deny is active.

Basic first cut: condition is recorded (via the shared conditional engine) and treated as
"applies" (no CEL evaluation of request context yet); non-group denied principals with an
exemption that isn't the principal itself are treated as blocked.
"""
from __future__ import annotations

import json
from typing import Any

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    OpenGraphEdge,
    _scope_type_from_id,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.iam_conditionals import (
    StatementConditionalsEngine,
)
from gcpwn.modules.opengraph.utilities.helpers.graph.normalization import normalized_token_list


def _split_semicolon(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return normalized_token_list(value)
    return normalized_token_list(str(value or "").split(";"))


def _principal_node_id(deny_principal: str) -> str:
    """Map an IAM deny principal identifier to the graph's principal node id (best-effort)."""
    token = str(deny_principal or "").strip()
    if not token:
        return ""
    low = token.lower()
    if "serviceaccounts/" in low or ".iam.gserviceaccount.com" in low:
        email = token.rstrip("/").rsplit("/", 1)[-1]
        return f"serviceAccount:{email}" if "@" in email else ""
    if "/group/" in low or low.startswith("group:"):
        email = token.rstrip("/").rsplit("/", 1)[-1].split(":", 1)[-1]
        return f"group:{email}" if "@" in email else ""
    if "/subject/" in low or low.startswith("user:"):
        email = token.rstrip("/").rsplit("/", 1)[-1].split(":", 1)[-1]
        return f"user:{email}" if "@" in email else ""
    if "@" in token and "/" not in token and ":" not in token:
        return f"user:{token}"
    return ""


_MULTI_SCOPE = "MULTI_SCOPE"


def _edge_scope_anchor(props: dict[str, Any]) -> str:
    """The resource-manager scope where this grant edge is EFFECTIVE (deny applies here).

    Returns the first usable scope id.  MULTI_SCOPE combo edges store their full scope
    list in effective_scope_ids; we fall through to that list rather than returning the
    sentinel string so _scope_chain can build a real ancestry chain from the first
    concrete scope."""
    for key in ("effective_scope_id", "attached_scope_id"):
        val = str(props.get(key) or "").strip()
        if val and val != _MULTI_SCOPE:
            return val
    # MULTI_SCOPE or no single-value scope — try the list forms
    for key in ("effective_scope_ids", "attached_scope_ids"):
        vals = props.get(key)
        if isinstance(vals, (list, tuple)):
            first = next((str(v).strip() for v in vals if v), "")
            if first:
                return first
    # Fall back to target resource or project
    for key in ("target_resource_id",):
        val = str(props.get(key) or "").strip()
        if val:
            return val
    project_id = str(props.get("project_id") or "").strip()
    return f"projects/{project_id}" if project_id else ""


def _scope_chain(anchor: str, project_id: str, parent_by_name: dict[str, str]) -> list[str]:
    """Ancestry chain [home_scope, parent, grandparent, ...] for a grant edge's scope.

    A resource-level anchor (an SA email, an instance path -- anything without an
    org/folder/project prefix) is normalized to its owning project so org/folder/project
    denies can be tested against real ancestry rather than a blind 'applies to everything'."""
    if anchor and not _scope_type_from_id(anchor):
        anchor = f"projects/{project_id}" if project_id else anchor
    chain: list[str] = []
    seen: set[str] = set()
    cur = anchor
    while cur and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = str(parent_by_name.get(cur) or "").strip()
    return chain


class _DenyRule:
    __slots__ = ("scope_name", "scope_type", "denied", "permissions", "exempt", "policy_id", "condition")

    def __init__(self, *, scope_name, scope_type, denied, permissions, exempt, policy_id, condition):
        self.scope_name = scope_name
        self.scope_type = scope_type
        self.denied = denied            # set[node_id]
        self.permissions = permissions  # set[str]
        self.exempt = exempt            # set[node_id]
        self.policy_id = policy_id
        self.condition = condition       # str summary

    def covers(self, scope_chain: list[str], expand_inheritance: bool) -> bool:
        """Deny inherits DOWNWARD. `scope_chain` is the grant edge's ancestry
        [home_scope, parent, ...]. The deny covers the edge when:
          * it is at the edge's own home scope (exact match -- always), or
          * it sits ABOVE the edge in the real hierarchy AND --expand-inheritance is on,
            so an org/folder deny only reaches its genuine descendants (not the whole
            tenant), mirroring the way the allow graph only models inheritance under that
            flag. With --expand-inheritance off, a deny is confined to its exact scope."""
        if not self.scope_name or not scope_chain:
            return False
        if self.scope_name == scope_chain[0]:
            return True
        return bool(expand_inheritance) and self.scope_name in scope_chain[1:]


def _load_deny_rules(context, engine: StatementConditionalsEngine) -> list[_DenyRule]:
    rules: list[_DenyRule] = []
    for row in (context.rows("iam_deny_policies") or []):
        scope_name = str(row.get("scope_name") or "").strip()
        if not scope_name:
            continue
        denied = {nid for p in _split_semicolon(row.get("denied_principals")) if (nid := _principal_node_id(p))}
        exempt = {nid for p in _split_semicolon(row.get("exception_principals")) if (nid := _principal_node_id(p))}
        perms = set(_split_semicolon(row.get("denied_permissions")))
        try:
            raw_rules = json.loads(row.get("rules_json") or "[]")
        except Exception:
            raw_rules = []
        cond_summ = []
        for rule in raw_rules if isinstance(raw_rules, list) else []:
            deny = (rule or {}).get("deny_rule") or (rule or {}).get("denyRule") or {}
            cond = deny.get("denial_condition") or deny.get("denialCondition") or {}
            if isinstance(cond, dict) and str(cond.get("expression") or "").strip():
                try:
                    cond_summ.append("; ".join(str(o.filter_summary or "") for o in engine.evaluate_options(cond)))
                except Exception:
                    cond_summ.append(str(cond.get("expression")))
        if denied and perms:
            rules.append(_DenyRule(scope_name=scope_name, scope_type=str(row.get("scope_type") or "").strip(),
                                   denied=denied, permissions=perms, exempt=exempt,
                                   policy_id=str(row.get("policy_id") or ""), condition="; ".join(c for c in cond_summ if c)))
    return rules


def _group_members(context) -> dict[str, set[str]]:
    """group node id -> set of member principal node ids (from GOOGLE_MEMBER_OF edges)."""
    members: dict[str, set[str]] = {}
    for e in context.builder.edge_map.values():
        if e.edge_type == "GOOGLE_MEMBER_OF":
            members.setdefault(e.destination_id, set()).add(e.source_id)
    return members


def _edge_permissions(edge: OpenGraphEdge) -> set[str]:
    props = edge.properties or {}
    out: set[str] = set()
    for key in ("permissions", "matched_permissions", "contributing_permissions", "permissions_required_by_rule"):
        val = props.get(key)
        if isinstance(val, (list, tuple, set)):
            out.update(str(x).strip() for x in val if str(x).strip())
    return out


def apply_deny_policies(context) -> dict[str, int]:
    """Final filter: rewrite the allow graph to effective access (allow minus deny)."""
    engine = StatementConditionalsEngine(enabled=True)
    rules = _load_deny_rules(context, engine)
    if not rules:
        print("[*] Deny-policy filter: no deny rules found (run enum_gcp_policy_bindings to populate)")
        return {"deny_rules": 0, "edges_dropped": 0, "edges_flagged": 0, "edges_repointed": 0}

    group_members = _group_members(context)
    expand_inheritance = bool(getattr(context.options, "expand_inheritance", False))
    parent_by_name = context.hierarchy_data().get("parent_by_name", {}) or {}
    dropped = flagged = repointed = 0
    edge_ids = list(context.builder.edge_map.keys())

    for eid in edge_ids:
        edge = context.builder.edge_map.get(eid)
        if edge is None:
            continue
        props = edge.properties or {}
        principal = str(props.get("principal_member") or "").strip()
        if not principal or str(props.get("source") or "") == "iam_deny_policies":
            continue
        edge_perms = _edge_permissions(edge)
        if not edge_perms:
            continue
        project_id = str(props.get("project_id") or "").strip()
        scope_chain = _scope_chain(_edge_scope_anchor(props), project_id, parent_by_name)

        applied: list[_DenyRule] = []
        for rule in rules:
            if not (edge_perms & rule.permissions):
                continue
            if principal not in rule.denied:
                continue
            if not rule.covers(scope_chain, expand_inheritance):
                continue
            applied.append(rule)
        if not applied:
            continue

        # Who can STILL exercise this grant after deny? Direct principal survives only if
        # exempt; a group narrows to its exempted members.
        exempt_union: set[str] = set()
        for r in applied:
            exempt_union |= r.exempt
        policy_ids = sorted({r.policy_id for r in applied if r.policy_id})
        cond = "; ".join(sorted({r.condition for r in applied if r.condition}))

        if principal in exempt_union:
            effective = [principal]  # the principal itself is explicitly exempted
        elif principal.startswith("group:"):
            effective = sorted(exempt_union & group_members.get(principal, set()))
        else:
            effective = []  # direct principal, denied, no self-exemption

        if not effective:
            # Fully blocked -> remove the edge (allow minus deny).
            context.builder.edge_map.pop(eid, None)
            dropped += 1
            continue

        new_props = dict(props)
        new_props["deny_policy_in_play"] = True
        new_props["deny_policy_ids"] = policy_ids
        new_props["deny_effective_principals"] = effective
        if cond:
            new_props["deny_condition_summary"] = cond

        if principal.startswith("group:") and effective != [principal]:
            # Group narrowed by an exemption: the grant now belongs to the surviving
            # member(s), not the whole group. Emit one edge per survivor (a single
            # survivor is just the N==1 case) and drop the original group edge, so the
            # graph shows exactly who can still exercise the grant.
            context.builder.edge_map.pop(eid, None)
            for member in effective:
                member_props = dict(new_props)
                member_props["principal_member"] = member
                member_props["deny_narrowed_from_group"] = principal
                context.builder.edge_map[(member, edge.edge_type, edge.destination_id)] = OpenGraphEdge(
                    source_id=member, destination_id=edge.destination_id,
                    edge_type=edge.edge_type, properties=member_props,
                )
            repointed += 1
        else:
            context.builder.edge_map[eid] = OpenGraphEdge(
                source_id=edge.source_id, destination_id=edge.destination_id,
                edge_type=edge.edge_type, properties=new_props,
            )
            flagged += 1

    print(f"[*] Deny-policy filter: {len(rules)} rule(s) -> dropped {dropped}, "
          f"re-pointed {repointed}, flagged {flagged} edge(s)")
    return {"deny_rules": len(rules), "edges_dropped": dropped, "edges_flagged": flagged, "edges_repointed": repointed}
