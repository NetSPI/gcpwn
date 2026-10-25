"""Collapse raw graph walks into logical hops and render them as text.

A raw path threads through binding nodes (``principal -> iambinding:<role>@<scope>
-> target``). A human counts hops in identities, not in binding nodes, so each
binding is folded into the hop it enables and reported as the role that made the
hop possible.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .model import AttackGraph, GRANT_EDGE_KINDS
from .search import RawPath

_RULE = "-" * 78


@dataclass
class Hop:
    """One logical step: an identity reaching something, and the role that allowed it."""

    src: str
    dst: str
    edge_kind: str
    role: str | None
    scope: str | None
    scope_display: str | None
    # Ancestor the binding was inherited from, when the graph was built with
    # --expand-inherited; this is the node an operator must actually fix.
    inherited_from: str | None
    conditional: bool
    # True when the path ends by acquiring the role itself (dst is a binding node).
    acquires_role: bool
    # For combo bindings: the component role@scope pairs from permission_source_summary.
    permission_sources: tuple[str, ...] | None = None


def _parse_permission_sources(raw: list) -> tuple[str, ...] | None:
    """Parse ``permission_source_summary`` entries into ``role@scope`` strings.

    Each entry has the form ``"roles/foo @ scope: perm.name"``.  We keep only
    the ``role@scope`` part for display -- the permission name adds noise.
    """
    results = []
    for item in raw:
        text = str(item)
        if " @ " not in text:
            continue
        role, rest = text.split(" @ ", 1)
        scope = rest.rsplit(": ", 1)[0] if ": " in rest else rest
        scope = scope.replace(".iam.gserviceaccount.com", "")
        results.append(f"{role.strip()}@{scope.strip()}")
    return tuple(results) if results else None


def _binding_facts(graph: AttackGraph, binding_id: str) -> dict:
    properties = graph.props(binding_id)
    inherited_from = None
    if properties.get("inherited"):
        inherited_from = properties.get("source_scope_id") or properties.get("source_scope_display")
    pss = properties.get("permission_source_summary")
    return {
        "role": graph.role_of_binding(binding_id),
        "scope": graph.scope_of_binding(binding_id),
        "scope_display": properties.get("attached_scope_display"),
        "inherited_from": str(inherited_from) if inherited_from else None,
        "conditional": bool(properties.get("conditional") or properties.get("condition_expr_raw")),
        "permission_sources": _parse_permission_sources(pss) if isinstance(pss, list) else None,
    }


def collapse_path(graph: AttackGraph, path: RawPath) -> list[Hop]:
    """Fold graph plumbing out of a raw path, yielding one Hop per real transition.

    Binding nodes and synthetic ``CAP:`` capability nodes exist to preserve
    authorization fidelity in the graph, but they are not places an attacker
    "arrives at" -- so a hop runs from one real node to the next real node, and the
    intermediates it skipped supply the role/scope that made the hop possible.

    The final node is always an anchor: a ``--to-role`` query legitimately ends at a
    binding node, and that is reported as acquiring the role.
    """
    nodes, edge_indices = path.nodes, path.edge_indices
    last = len(nodes) - 1
    anchors = [i for i in range(len(nodes)) if i in (0, last) or not graph.is_synthetic(nodes[i])]

    hops: list[Hop] = []
    for start, end in zip(anchors, anchors[1:]):
        # Role/scope come from the binding node skipped on the way, if any.
        facts = {
            "role": None,
            "scope": None,
            "scope_display": None,
            "inherited_from": None,
            "conditional": bool(graph.edges[edge_indices[start]]["properties"].get("conditional")),
            "permission_sources": None,
        }
        for position in range(start + 1, end + 1):
            if graph.is_binding(nodes[position]):
                facts = _binding_facts(graph, nodes[position])
                break

        # Prefer the first non-grant edge in the segment as the hop label.
        # For CAP: paths (combo_binding → CAP:node → SA) this picks the exploit
        # edge name (combo_binding→CAP) rather than the trailing RunsAs (CAP→SA).
        edge_kind = graph.edges[edge_indices[end - 1]]["kind"]
        for _pos in range(start, end):
            _ek = graph.edges[edge_indices[_pos]]["kind"]
            if _ek not in GRANT_EDGE_KINDS:
                edge_kind = _ek
                break

        hops.append(
            Hop(
                src=nodes[start],
                dst=nodes[end],
                edge_kind=edge_kind,
                acquires_role=(end == last and graph.is_binding(nodes[end])),
                **facts,
            )
        )

    return hops


def _elide_middle(text: str, limit: int) -> str:
    """Shorten to ``limit`` chars by eliding the MIDDLE, keeping both ends.

    A plain tail-truncation drops the end of the string -- but for a resource
    scope like ``projects/p/.../secrets/MY-SECRET`` the end (the resource type and
    name) is exactly what identifies it. Eliding the middle keeps the leading
    context (project) and the trailing resource name; the tail gets the larger
    share of the budget since the resource name matters most.
    """
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    budget = limit - 1  # one char for the ellipsis
    tail = (budget * 2) // 3
    head = budget - tail
    return f"{text[:head]}…{text[-tail:]}" if head > 0 else f"…{text[-(limit - 1):]}"


# Backstop so a single malformed/adversarial node id can't blow up a line; real GCP
# resource ids are well under this, so identifiers are shown in full in practice.
_SHORT_ID_HARD_CAP = 512


def short_id(node_id: str, *, limit: int | None = None) -> str:
    """Strip the display-only prefixes/suffix from a node id, keeping it otherwise intact.

    Identifiers are shown in full by default -- for text attack-path analysis the whole
    resource path is what matters, so nothing is truncated unless an explicit ``limit`` is
    passed (or the id is pathologically long, in which case the middle is elided to keep
    both ends). The only parts removed are the internal ``iambinding:``/``resource:``/
    ``cap:new:`` prefixes; the service-account email (including its full
    ``...gserviceaccount.com`` domain) is kept intact so every SA renders consistently.
    """
    text = node_id
    for prefix in ("iambinding:", "resource:", "cap:new:"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    cap = limit if limit is not None else _SHORT_ID_HARD_CAP
    return _elide_middle(text, cap)


def _scope_label(scope: str | None, display: str | None) -> str:
    if not scope:
        return "unspecified scope"
    if scope == "MULTI_SCOPE":
        return "multiple scopes"
    label = short_id(scope)
    if display and display.lower() not in scope.lower():
        return f"{label} ({display})"
    return label


def describe_target(graph: AttackGraph, node_id: str) -> str:
    """Human label for a path endpoint."""
    if graph.is_binding(node_id):
        role = graph.role_of_binding(node_id) or "(unknown role)"
        properties = graph.props(node_id)
        label = f"{role} on {_scope_label(graph.scope_of_binding(node_id), properties.get('attached_scope_display'))}"
        # A grant inherited from an ancestor is a DIFFERENT node from a grant attached
        # directly at this scope; without this they render identically and look like a
        # duplicate target. Naming the source scope distinguishes the two.
        if properties.get("inherited"):
            source = properties.get("source_scope_id") or properties.get("source_scope_display")
            if source:
                label += f" (inherited from {short_id(str(source))})"
        return label
    return f"{graph.kind_of(node_id)} {short_id(node_id)}"


def _notes_suffix(*, inherited_from: str | None, conditional: bool) -> str:
    """The `   [inherited from …; conditional]` suffix shared by the collapsed hop line and
    its terminal line (both 3-space lead). The expanded view's inline `[…]` note differs and
    is intentionally not folded in here."""
    notes = []
    if inherited_from:
        notes.append(f"inherited from {short_id(inherited_from)}")
    if conditional:
        notes.append("conditional")
    return f"   [{'; '.join(notes)}]" if notes else ""


def _hop_line(graph: AttackGraph, hop: Hop) -> str:
    suffix = _notes_suffix(inherited_from=hop.inherited_from, conditional=hop.conditional)

    scope = _scope_label(hop.scope, hop.scope_display)
    if hop.permission_sources:
        via = "via " + " + ".join(hop.permission_sources)
    elif hop.role:
        via = f"via {hop.role} on {scope}"
    else:
        via = "direct"
    return f"        └─[{hop.edge_kind}]─> {short_id(hop.dst)}  ({via}){suffix}"


def _attack_hops(hops: list[Hop]) -> tuple[list[Hop], Hop | None]:
    """Split hops into attack steps and the optional terminal role-acquisition fact.

    The last hop of a role-targeted path has ``acquires_role=True``.  It is not
    an action an attacker takes -- the destination SA already holds that role.
    Separating it lets render_path count and display only real lateral moves.
    """
    if hops and hops[-1].acquires_role:
        return hops[:-1], hops[-1]
    return hops, None


def hop_count(graph: AttackGraph, path: RawPath) -> int:
    """Number of real attack steps in a path (binding/CAP nodes folded out; terminal acquires-role excluded)."""
    return len(_attack_hops(collapse_path(graph, path))[0])


def _terminal_annotation(
    terminal: Hop | None,
    iam_control_targets: frozenset[str] = frozenset(),
    iam_control_note: str = "",
) -> str:
    if terminal is None:
        return ""
    scope = _scope_label(terminal.scope, terminal.scope_display)
    extra = (
        f" -- {iam_control_note}"
        if iam_control_note and terminal.dst in iam_control_targets
        else ""
    )
    return f"  [holds {terminal.role or '?'} on {scope}{extra}]"


def render_path(
    graph: AttackGraph,
    path: RawPath,
    *,
    iam_control_targets: frozenset[str] = frozenset(),
    iam_control_note: str = "",
) -> list[str]:
    """Collapsed view: one line per logical hop, binding/CAP nodes folded in.

    This is the ``--compact`` output.  For the default fully-expanded view that
    shows every raw node and edge, use :func:`render_path_expanded`.
    """
    hops = collapse_path(graph, path)
    steps, terminal = _attack_hops(hops)
    count = len(steps)
    label = "direct" if (count == 0 and terminal) else ("hop " if count == 1 else "hops")
    annotation = _terminal_annotation(terminal, iam_control_targets, iam_control_note)

    count_label = label if count == 0 else f"{count} {label}"
    lines = [f" [{count_label}] {short_id(path.source)}{annotation if count == 0 else ''}"]
    lines.extend(_hop_line(graph, hop) for hop in steps)
    if terminal and count > 0:
        scope = _scope_label(terminal.scope, terminal.scope_display)
        suffix = _notes_suffix(inherited_from=terminal.inherited_from, conditional=terminal.conditional)
        note = (
            f" -- {iam_control_note}"
            if iam_control_note and terminal.dst in iam_control_targets
            else ""
        )
        lines.append(f"        └─ holds {terminal.role or '?'} on {scope}{note}{suffix}")
    return lines


def render_path_expanded(
    graph: AttackGraph,
    path: RawPath,
    *,
    iam_control_targets: frozenset[str] = frozenset(),
    iam_control_note: str = "",
) -> list[str]:
    """Expanded view: every raw node and edge shown, including binding and CAP: nodes.

    This is the default output.  Binding nodes show the role (or component roles
    for combo bindings) that they carry.  CAP: nodes appear as-is.
    """
    hops = collapse_path(graph, path)
    steps, terminal = _attack_hops(hops)
    count = len(steps)
    label = "direct" if (count == 0 and terminal) else ("hop " if count == 1 else "hops")
    count_label = label if count == 0 else f"{count} {label}"
    lines = [f" [{count_label}] {short_id(path.nodes[0])}"]

    nodes, edge_indices = path.nodes, path.edge_indices
    last = len(nodes) - 1
    for i, edge_idx in enumerate(edge_indices):
        edge = graph.edges[edge_idx]
        dst_node = nodes[i + 1]
        edge_kind = edge["kind"]
        dst_short = short_id(dst_node)

        extra = ""
        if graph.is_binding(dst_node):
            props = graph.props(dst_node)
            pss = props.get("permission_source_summary")
            if isinstance(pss, list) and pss:
                parsed = _parse_permission_sources(pss)
                if parsed:
                    extra = f"  (needs: {' + '.join(parsed)})"
            else:
                role = graph.role_of_binding(dst_node)
                scope_val = _scope_label(
                    graph.scope_of_binding(dst_node), props.get("attached_scope_display")
                )
                if role:
                    is_terminal = i + 1 == last
                    verb = "holds" if is_terminal else "role"
                    control = (
                        f" -- {iam_control_note}"
                        if is_terminal and iam_control_note and dst_node in iam_control_targets
                        else ""
                    )
                    extra = f"  ({verb} {role} on {scope_val}{control})"
                    notes = []
                    if props.get("inherited"):
                        src = props.get("source_scope_id") or props.get("source_scope_display")
                        if src:
                            notes.append(f"inherited from {short_id(str(src))}")
                    if props.get("conditional") or props.get("condition_expr_raw"):
                        notes.append("conditional")
                    if notes:
                        extra += f"  [{'; '.join(notes)}]"

        if edge["properties"].get("conditional") or edge["properties"].get("condition_expr_raw"):
            extra += "  [conditional]"

        lines.append(f"        └─[{edge_kind}]─> {dst_short}{extra}")
    return lines


def render_config_header(config: dict, *, query: dict) -> list[str]:
    files = config.get("files_loaded") or []
    source = files[0] if len(files) == 1 else f"{len(files)} files"
    pairs = config.get("cross_project_actas_pairs") or []
    cross = "True" if config.get("cross_project_actas") else "False"
    if pairs:
        cross += f"  ({len(pairs)} project pair{'s' if len(pairs) != 1 else ''})"

    containment = "followed" if query.get("include_containment") else "not followed"
    principals = config.get("principal_count", 0)
    agents = config.get("service_agent_count", 0)

    lines = [
        "=" * 78,
        "  GCPWN OPENGRAPH ATTACK PATHS",
        "=" * 78,
        "",
        "GRAPH CONFIGURATION",
        f"  Source                       : {source}",
        f"  Nodes / Edges                : {config.get('nodes', 0)} / {config.get('edges', 0)}",
        f"  Inheritance Expanded         : {config.get('inheritance_expanded')}",
        f"  Conditional Bindings Present : {config.get('conditional_bindings')}",
        f"  Deny Policies Present        : {config.get('deny_policies')}",
        f"  Cross-Project ActAs Observed : {cross}",
        f"  Containment Traversal        : {bool(query.get('include_containment'))}  (ExistsInProject {containment})",
        f"  Principals                   : {principals}  ({agents} Google service agent(s))",
        f"  IAM Binding Nodes            : {config.get('binding_count', 0)}",
        f"  Distinct Edge Kinds          : {config.get('distinct_edge_kinds', 0)}",
    ]
    projects = config.get("known_projects") or []
    if projects:
        shown = ", ".join(projects[:6]) + (f", +{len(projects) - 6} more" if len(projects) > 6 else "")
        lines.append(f"  Projects In Graph            : {len(projects)}  ({shown})")

    lines += [
        "",
        "QUERY",
        f"  Targets                      : {query.get('description')}",
        f"  Target nodes matched         : {query.get('target_count')}",
        f"  Mode                         : {query.get('mode')}",
        f"  Max depth                    : {query.get('max_depth')}",
    ]
    if query.get("exclude_service_agents"):
        lines.append("  Service agents as sources    : excluded (--exclude-service-agents)")
    if query.get("mode") == "all-paths":
        lines.append(f"  Max paths                    : {query.get('max_paths')}")
    if len(files) > 1:
        lines.append("")
        lines.append("  Files loaded:")
        lines.extend(f"    - {path}" for path in files)
    lines.append("")
    return lines


def _summary_table(graph: AttackGraph, ordered: list[tuple[str, list[RawPath]]], hop_counts: dict) -> list[str]:
    """Per-target rollup. On a large org this is the part that is actually readable."""
    lines = [
        _RULE,
        " TARGET SUMMARY",
        _RULE,
        f" {'Shortest':>8}  {'Principals':>10}  {'Paths':>6}  Target",
    ]
    for target, group in ordered:
        principals = len({path.source for path in group})
        lines.append(
            f" {hop_counts[id(group[0])]:>8}  {principals:>10}  {len(group):>6}  {describe_target(graph, target)}"
        )
    lines.append("")
    return lines


def render_report(
    graph: AttackGraph,
    paths: list[RawPath],
    *,
    config: dict,
    query: dict,
    compact: bool = False,
    expand: bool = True,
    truncated: bool = False,
    detail_limit: int | None = None,
    summary_only: bool = False,
    iam_control_targets: frozenset[str] = frozenset(),
    iam_control_note: str = "",
) -> str:
    """Full text report: config header, then targets ordered by how easily reached.

    ``iam_control_targets`` are binding nodes that were added as targets because the
    query asked for a basic role and these bindings can set the scope's IAM (so their
    holder can grant themselves that role). When a path terminates on one of them,
    ``iam_control_note`` is appended to the terminal "holds ... on ..." line to spell
    out the equivalence.
    """
    lines = render_config_header(config, query=query)

    if not paths:
        lines += [
            _RULE,
            " NO PATHS FOUND",
            _RULE,
            "",
            " No principal in this graph can reach the requested target(s).",
            " If that is unexpected, check:",
            "   - the target selector actually matched nodes (see 'Target nodes matched')",
            "   - --max-depth is high enough for a long chain",
            "   - the graph was built with the scopes you expect (re-run process_og --reset)",
            "",
        ]
        return "\n".join(lines)

    # Collapse once per path; every ordering below needs the hop count.
    # Count only real attack steps — the terminal acquires_role hop is a fact
    # about the endpoint (it already holds the role), not a lateral-move step.
    hop_counts = {id(path): len(_attack_hops(collapse_path(graph, path))[0]) for path in paths}

    grouped: dict[str, list[RawPath]] = {}
    for path in paths:
        grouped.setdefault(path.target, []).append(path)
    for group in grouped.values():
        group.sort(key=lambda p: (hop_counts[id(p)], p.source))

    # Most immediately reachable target first, then most exposed.
    ordered = sorted(
        grouped.items(),
        key=lambda item: (hop_counts[id(item[1][0])], -len(item[1]), item[0]),
    )

    total_principals = len({path.source for path in paths})
    lines += [
        _RULE,
        f" RESULTS  {len(paths)} path(s)  |  {total_principals} distinct principal(s)  |  {len(ordered)} target(s)",
        _RULE,
        "",
    ]
    if truncated:
        lines += [
            " ! Search budget reached -- these are the shortest paths found, not the",
            " ! complete set. Raise --max-paths / --max-expansions for more.",
            "",
        ]

    lines += _summary_table(graph, ordered, hop_counts)

    if summary_only:
        lines += [" (summary only; drop --summary to list individual paths)", ""]
        return "\n".join(lines)

    shown = 0
    for target, group in ordered:
        if detail_limit is not None and shown >= detail_limit:
            break

        principals = len({path.source for path in group})
        shortest = hop_counts[id(group[0])]
        lines += [
            _RULE,
            f" TARGET  {describe_target(graph, target)}",
            _RULE,
            f" {principals} principal(s) can reach this via {len(group)} path(s); shortest = {shortest} hop(s)",
            "",
        ]
        for path in group:
            if detail_limit is not None and shown >= detail_limit:
                break
            if expand:
                lines.extend(
                    render_path_expanded(
                        graph,
                        path,
                        iam_control_targets=iam_control_targets,
                        iam_control_note=iam_control_note,
                    )
                )
            else:
                lines.extend(
                    render_path(
                        graph,
                        path,
                        iam_control_targets=iam_control_targets,
                        iam_control_note=iam_control_note,
                    )
                )
            lines.append("")
            shown += 1

    if shown < len(paths):
        lines += [
            _RULE,
            f" {len(paths) - shown} further path(s) not shown (detail capped at {detail_limit}).",
            " Raise --max-paths, narrow the query, or use --summary for counts only.",
            _RULE,
            "",
        ]

    return "\n".join(lines)


def paths_to_json(
    graph: AttackGraph,
    paths: list[RawPath],
    *,
    config: dict,
    query: dict,
    detail_limit: int | None = None,
) -> str:
    """Machine-readable form of the same findings.

    Applies the SAME ``detail_limit`` the text report uses so the two never disagree on how
    many paths are shown; ``paths_total`` / ``paths_shown`` make the cap explicit for
    machine consumers (raise --max-paths to get more)."""
    total = len(paths)
    shown = paths if detail_limit is None else paths[: max(0, int(detail_limit))]
    entries = []
    for path in shown:
        hops = collapse_path(graph, path)
        steps, _terminal = _attack_hops(hops)
        entries.append(
            {
                "source": path.source,
                "target": path.target,
                "target_description": describe_target(graph, path.target),
                "hop_count": len(steps),
                "raw_nodes": list(path.nodes),
                "hops": [asdict(hop) for hop in hops],
            }
        )
    return json.dumps(
        {
            "config": config,
            "query": query,
            "paths_total": total,
            "paths_shown": len(entries),
            "paths_truncated": len(entries) < total,
            "paths": entries,
        },
        indent=2,
        ensure_ascii=False,
    )
