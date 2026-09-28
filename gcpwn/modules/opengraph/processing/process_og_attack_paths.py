"""Text-based attack-path analysis over an exported OpenGraph JSON graph.

BloodHound's UI struggles with very large graphs, so this module answers the same
questions offline, PMapper-style: given the JSON that ``process_og_gcpwn_data``
already emits, who can reach a privileged role, a service account, or a resource
-- reported shortest path first.

It is a pure consumer: it reads the exported JSON and never re-derives or mutates
the graph, so the BloodHound output contract is untouched.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from gcpwn.core.console import UtilityTools
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.model import AttackGraph
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.render import (
    describe_target,
    paths_to_json,
    render_report,
)
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.search import (
    enumerate_paths,
    path_signature,
    resolve_targets,
    shortest_paths,
)

# With no target selector, report the two roles that matter most to a defender.
DEFAULT_ROLES = ("roles/owner", "roles/editor")


def _split_csv(values: list[str] | None) -> list[str]:
    """Flatten repeated and comma-separated flag values into one list."""
    out: list[str] = []
    for value in values or []:
        out.extend(part.strip() for part in str(value).split(",") if part.strip())
    return out


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find and print attack paths through an exported OpenGraph JSON graph",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--graph-json",
        required=True,
        help="Path to the exported OpenGraph JSON file, or a directory of split-JSON parts",
    )

    targets = parser.add_argument_group("Target selection (default: roles/owner + roles/editor)")
    targets.add_argument("--to-role", action="append", help="Target a role, e.g. roles/owner (repeatable, comma-separated)")
    targets.add_argument("--to-sa", action="append", help="Target service accounts matching this substring (repeatable)")
    targets.add_argument("--to-kind", action="append", help="Target every node of this kind, e.g. GCPBucket (repeatable)")
    targets.add_argument("--to-node", action="append", help="Target an exact node id (repeatable)")
    targets.add_argument(
        "--at-scope",
        help="Restrict targets to a scope subtree, e.g. projects/my-proj, folders/123, organizations/456",
    )

    sources = parser.add_argument_group("Source selection")
    sources.add_argument(
        "--from",
        dest="from_principals",
        action="append",
        help="Only start paths at principals matching this substring (default: every principal)",
    )

    search = parser.add_argument_group("Search behaviour")
    search.add_argument(
        "--all-paths",
        action="store_true",
        help="Enumerate every path, not just the shortest one per principal (slower)",
    )
    search.add_argument("--max-depth", type=int, default=0, help="Max hops to follow (default: 12 shortest / 8 all-paths)")
    search.add_argument("--max-paths", type=int, default=250, help="Cap on paths reported in --all-paths mode (default: 250)")
    search.add_argument(
        "--max-expansions",
        type=int,
        default=400_000,
        help="Search budget for --all-paths mode (default: 400000)",
    )
    search.add_argument(
        "--include-containment",
        action="store_true",
        help="Also follow ExistsInProject (project -> contained resource); greatly increases path counts",
    )
    search.add_argument(
        "--exclude-service-agents",
        action="store_true",
        help="Skip Google-managed service agents as path sources (cuts a lot of expected-by-design noise)",
    )

    output = parser.add_argument_group("Output")
    output.add_argument("--compact", action="store_true", help="One line per path instead of an indented hop list")
    output.add_argument(
        "--summary",
        action="store_true",
        help="Print only the per-target rollup (shortest hops / principals / paths), no individual paths",
    )
    output.add_argument("--json", dest="as_json", action="store_true", help="Emit machine-readable JSON instead of text")
    output.add_argument("--output", help="Write the report to this file instead of stdout")
    output.add_argument("--list-targets", action="store_true", help="List the nodes the target selector matched, then exit")
    output.add_argument("--stats", action="store_true", help="Print graph configuration and edge-kind histogram, then exit")
    output.add_argument("-v", "--debug", action="store_true", help="Verbose output")
    return parser


def run_module(user_args, session):
    args = _build_parser().parse_args(user_args)

    try:
        graph = AttackGraph.from_path(args.graph_json)
    except (FileNotFoundError, ValueError) as exc:
        print(f"{UtilityTools.RED}[X] {exc}{UtilityTools.RESET}")
        return -1
    except Exception as exc:
        print(f"{UtilityTools.RED}[X] Failed to parse graph JSON: {type(exc).__name__}: {exc}{UtilityTools.RESET}")
        if args.debug:
            raise
        return -1

    config = graph.config_summary()

    if args.stats:
        print(f"\nGraph: {args.graph_json}")
        print(f"  Nodes: {config['nodes']}   Edges: {config['edges']}")
        print(f"  Inheritance expanded         : {config['inheritance_expanded']}")
        print(f"  Conditional bindings present : {config['conditional_bindings']}")
        print(f"  Deny policies present        : {config['deny_policies']}")
        print(f"  Cross-project actAs observed : {config['cross_project_actas']}")
        for pair in config["cross_project_actas_pairs"]:
            print(f"      {pair}")
        print(f"  Principals / bindings        : {config['principal_count']} / {config['binding_count']}")
        print("\n  Node kinds:")
        for kind, count in config["top_node_kinds"]:
            print(f"    {count:6}  {kind}")
        print("\n  Edge kinds:")
        for kind, count in config["edge_kind_counts"]:
            print(f"    {count:6}  {kind}")
        return 1

    roles = _split_csv(args.to_role)
    service_accounts = _split_csv(args.to_sa)
    kinds = _split_csv(args.to_kind)
    node_ids = _split_csv(args.to_node)
    if not (roles or service_accounts or kinds or node_ids):
        roles = list(DEFAULT_ROLES)
        # Not printed in --json mode: stdout must be parseable as a single JSON
        # document, and query.description in the payload already records the default.
        if not args.as_json:
            print(f"[*] No target selector given; defaulting to {', '.join(roles)}")

    target_set = resolve_targets(
        graph,
        roles=roles,
        service_accounts=service_accounts,
        kinds=kinds,
        node_ids=node_ids,
        scope=args.at_scope,
    )

    if args.list_targets:
        print(f"\n[*] Target selector: {target_set.description}")
        print(f"[*] Matched {len(target_set.node_ids)} node(s):\n")
        for node_id in sorted(target_set.node_ids):
            print(f"  {describe_target(graph, node_id)}")
            print(f"      id: {node_id}")
        return 1

    if not target_set.node_ids:
        print(
            f"{UtilityTools.YELLOW}[!] Target selector matched no nodes "
            f"({target_set.description}). Use --list-targets or --stats to explore the graph."
            f"{UtilityTools.RESET}"
        )
        return -1

    sources = None
    if args.from_principals:
        needles = [value.lower() for value in _split_csv(args.from_principals)]
        sources = [
            node_id
            for node_id in graph.principals()
            if any(needle in node_id.lower() for needle in needles)
        ]
        if not sources:
            print(f"{UtilityTools.YELLOW}[!] --from matched no principals in this graph.{UtilityTools.RESET}")
            return -1

    truncated = False
    if args.all_paths:
        max_depth = args.max_depth or 8
        paths, truncated = enumerate_paths(
            graph,
            target_set.node_ids,
            sources=sources,
            include_containment=args.include_containment,
            max_depth=max_depth,
            max_paths=args.max_paths,
            max_expansions=args.max_expansions,
            exclude_service_agents=args.exclude_service_agents,
        )
        # Raw walks differing only in which binding carried the same role at the
        # same scope are one finding to a human -- keep the first (shortest).
        seen: set[tuple] = set()
        deduped = []
        for path in paths:
            signature = path_signature(graph, path)
            if signature in seen:
                continue
            seen.add(signature)
            deduped.append(path)
        paths = deduped
        mode = "all-paths"
    else:
        max_depth = args.max_depth or 12
        paths = shortest_paths(
            graph,
            target_set.node_ids,
            sources=sources,
            include_containment=args.include_containment,
            max_depth=max_depth,
            exclude_service_agents=args.exclude_service_agents,
        )
        mode = "shortest-path per principal"

    query = {
        "description": target_set.description,
        "target_count": len(target_set.node_ids),
        "mode": mode,
        "max_depth": max_depth,
        "max_paths": args.max_paths if args.all_paths else None,
        "include_containment": bool(args.include_containment),
        "exclude_service_agents": bool(args.exclude_service_agents),
        "truncated": truncated,
    }

    if args.as_json:
        report = paths_to_json(graph, paths, config=config, query=query)
    else:
        report = render_report(
            graph,
            paths,
            config=config,
            query=query,
            compact=args.compact,
            truncated=truncated,
            detail_limit=args.max_paths,
            summary_only=args.summary,
        )

    if args.output:
        destination = Path(args.output).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report + "\n", encoding="utf-8")
        print(f"{UtilityTools.GREEN}[*] Wrote {len(paths)} path(s) to {destination}{UtilityTools.RESET}")
    else:
        print(report)

    return 1
