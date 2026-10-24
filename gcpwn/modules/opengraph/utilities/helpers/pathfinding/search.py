"""Path search over an :class:`~.model.AttackGraph`.

Two modes, because "every path" is exponential in the worst case and a defender
usually wants the cheap answer first:

* :func:`shortest_paths` -- one reverse BFS from the whole target set gives, in a
  single ``O(V+E)`` pass, the shortest path from every principal that can reach
  any target. This is the default and stays fast on large org graphs.
* :func:`enumerate_paths` -- full enumeration, ordered shortest-first, using the
  reverse-BFS distances as an A* heuristic so branches that cannot reach a
  target are never walked. Bounded by explicit path/expansion budgets.
"""

from __future__ import annotations

import heapq
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .model import BINDING_KINDS, AttackGraph


@dataclass(frozen=True)
class RawPath:
    """A concrete walk through the raw graph, including binding nodes."""

    nodes: tuple[str, ...]
    edge_indices: tuple[int, ...]

    @property
    def target(self) -> str:
        return self.nodes[-1]

    @property
    def source(self) -> str:
        return self.nodes[0]


@dataclass
class TargetSet:
    """Resolved set of endpoint node ids, plus how it was described."""

    node_ids: set[str] = field(default_factory=set)
    description: str = ""


def resolve_targets(
    graph: AttackGraph,
    *,
    roles: Iterable[str] | None = None,
    service_accounts: Iterable[str] | None = None,
    node_ids: Iterable[str] | None = None,
    kinds: Iterable[str] | None = None,
    scope: str | None = None,
    scope_exact: bool = False,
    to_any: bool = False,
) -> TargetSet:
    """Turn CLI-style selectors into a concrete set of target node ids.

    Pass ``to_any=True`` to target every privilege endpoint in the graph (all
    role-binding nodes and all service-account nodes).  When combined with
    ``--from``, this shows every privilege the specified principal can reach.
    """
    if to_any:
        resolved = {
            node_id
            for node_id in graph.nodes
            if graph.kind_of(node_id) in ("GCPIamSimpleBinding", "GCPServiceAccount")
        }
        return TargetSet(node_ids=resolved, description="(all privilege endpoints)")

    resolved: set[str] = set()
    described: list[str] = []

    roles = [r for r in (roles or []) if r]
    if roles:
        resolved.update(graph.find_role_bindings(roles))
        described.append(f"role={','.join(roles)}")

    for needle in service_accounts or []:
        lowered = needle.lower()
        matched = {
            node_id
            for node_id in graph.nodes
            if graph.kind_of(node_id) == "GCPServiceAccount" and lowered in node_id.lower()
        }
        resolved.update(matched)
        described.append(f"sa~{needle}")

    for kind in kinds or []:
        matched = {node_id for node_id in graph.nodes if graph.kind_of(node_id) == kind}
        resolved.update(matched)
        described.append(f"kind={kind}")

    for node_id in node_ids or []:
        if node_id in graph.nodes:
            resolved.add(node_id)
            described.append(f"node={node_id}")

    if scope:
        resolved = {node_id for node_id in resolved if graph.scope_matches(node_id, scope, exact=scope_exact)}
        described.append(f"scope{'=' if scope_exact else '~'}{scope}")

    return TargetSet(node_ids=resolved, description=" ".join(described) or "(none)")


def _edge_is_conditional(edge: dict) -> bool:
    """True when an edge carries an unevaluated IAM condition.

    IAM conditions are not CEL-evaluated, so a conditionally-scoped grant is emitted as if
    unconditional (a potential over-grant). ``--exclude-conditional`` lets a defender drop
    these from traversal; they stay in the graph and are shown by default."""
    props = edge.get("properties") or {}
    return bool(props.get("conditional") or props.get("condition_expr_raw"))


def reverse_distances(
    graph: AttackGraph,
    targets: set[str],
    traversable: frozenset[str],
    *,
    max_depth: int,
    exclude_conditional: bool = False,
    excluded_nodes: frozenset[str] = frozenset(),
) -> tuple[dict[str, int], dict[str, tuple[str, int]]]:
    """Multi-source BFS backwards from ``targets``.

    Returns ``(dist, succ)`` where ``dist[n]`` is the fewest raw edges from ``n``
    to the nearest target and ``succ[n]`` is ``(next_node, edge_index)`` -- the
    first step of one such shortest path. Following ``succ`` forward from any
    node reconstructs a shortest path without a second search.

    ``excluded_nodes`` are treated as if absent from the graph: no path may pass
    through them (nor start/end on them), so any path that would contain one is
    never discovered.
    """
    dist: dict[str, int] = {
        target: 0 for target in targets if target in graph.nodes and target not in excluded_nodes
    }
    succ: dict[str, tuple[str, int]] = {}
    queue = deque(dist)

    while queue:
        node = queue.popleft()
        depth = dist[node]
        if depth >= max_depth:
            continue
        for predecessor, edge_index in graph.radj.get(node, ()):
            if predecessor in excluded_nodes:
                continue
            if graph.edges[edge_index]["kind"] not in traversable:
                continue
            if exclude_conditional and _edge_is_conditional(graph.edges[edge_index]):
                continue
            if predecessor in dist:
                continue
            dist[predecessor] = depth + 1
            succ[predecessor] = (node, edge_index)
            queue.append(predecessor)

    return dist, succ


def _reconstruct(source: str, succ: dict[str, tuple[str, int]], targets: set[str]) -> RawPath | None:
    nodes = [source]
    edge_indices: list[int] = []
    current = source
    seen = {source}
    while current not in targets:
        step = succ.get(current)
        if step is None:
            return None
        current, edge_index = step
        if current in seen:
            return None
        seen.add(current)
        nodes.append(current)
        edge_indices.append(edge_index)
    return RawPath(tuple(nodes), tuple(edge_indices))


def shortest_paths(
    graph: AttackGraph,
    targets: set[str],
    *,
    sources: Iterable[str] | None = None,
    include_containment: bool = False,
    max_depth: int = 12,
    exclude_service_agents: bool = False,
    exclude_conditional: bool = False,
    excluded_nodes: frozenset[str] = frozenset(),
) -> list[RawPath]:
    """One shortest path per principal that can reach any target.

    Single reverse BFS over the whole target set -- the cheap default mode.
    """
    traversable = graph.traversable_kinds(include_containment=include_containment)
    reachable_targets = targets - excluded_nodes
    dist, succ = reverse_distances(
        graph, reachable_targets, traversable, max_depth=max_depth,
        exclude_conditional=exclude_conditional, excluded_nodes=excluded_nodes,
    )

    candidates = (
        list(sources)
        if sources is not None
        else graph.principals(exclude_service_agents=exclude_service_agents)
    )
    results: list[RawPath] = []
    for source in candidates:
        if source in reachable_targets or source not in dist or source in excluded_nodes:
            continue
        path = _reconstruct(source, succ, reachable_targets)
        if path is not None:
            results.append(path)

    results.sort(key=lambda p: (len(p.edge_indices), p.source))
    return results


def enumerate_paths(
    graph: AttackGraph,
    targets: set[str],
    *,
    sources: Iterable[str] | None = None,
    include_containment: bool = False,
    max_depth: int = 8,
    max_paths: int = 250,
    max_expansions: int = 400_000,
    exclude_service_agents: bool = False,
    exclude_conditional: bool = False,
    excluded_nodes: frozenset[str] = frozenset(),
    progress_callback: Callable[[int, int, int], None] | None = None,
) -> tuple[list[RawPath], bool]:
    """Every simple path from ``sources`` to ``targets``, shortest first.

    Best-first (A*) over partial paths with ``h(n)`` = reverse-BFS distance to the
    nearest target. Because ``h`` is exact on the raw graph, popped paths come out
    in nondecreasing length, so results are already shortest-first and the search
    can stop the moment the budget is hit.

    ``excluded_nodes`` are treated as absent: no reported path contains one.

    Returns ``(paths, truncated)``; ``truncated`` is True when a budget stopped the
    search before it was exhausted.
    """
    traversable = graph.traversable_kinds(include_containment=include_containment)
    targets = targets - excluded_nodes
    dist, _ = reverse_distances(
        graph, targets, traversable, max_depth=max_depth,
        exclude_conditional=exclude_conditional, excluded_nodes=excluded_nodes,
    )

    candidates = [
        source
        for source in (
            list(sources)
            if sources is not None
            else graph.principals(exclude_service_agents=exclude_service_agents)
        )
        if source in dist and source not in targets and source not in excluded_nodes
    ]
    if not candidates:
        return [], False

    # (priority, tie, nodes, edge_indices) -- tie keeps the heap total-ordered
    # without comparing tuples of differing length.
    heap: list[tuple[int, int, tuple[str, ...], tuple[int, ...]]] = []
    counter = 0
    for source in candidates:
        heapq.heappush(heap, (dist[source], counter, (source,), ()))
        counter += 1

    found: list[RawPath] = []
    expansions = 0
    truncated = False
    _PROGRESS_EVERY = 20_000

    while heap:
        if len(found) >= max_paths:
            truncated = True
            break
        if expansions >= max_expansions:
            truncated = True
            break
        if progress_callback is not None and expansions % _PROGRESS_EVERY == 0 and expansions:
            progress_callback(expansions, max_expansions, len(found))

        _, _, nodes, edge_indices = heapq.heappop(heap)
        current = nodes[-1]

        if current in targets and len(nodes) > 1:
            found.append(RawPath(nodes, edge_indices))
            continue

        if len(edge_indices) >= max_depth:
            continue

        expansions += 1
        visited = set(nodes)
        for neighbour, edge_index in graph.adj.get(current, ()):
            if neighbour in visited or neighbour in excluded_nodes:
                continue
            if graph.edges[edge_index]["kind"] not in traversable:
                continue
            if exclude_conditional and _edge_is_conditional(graph.edges[edge_index]):
                continue
            remaining = dist.get(neighbour)
            if remaining is None:
                continue
            next_nodes = nodes + (neighbour,)
            next_edges = edge_indices + (edge_index,)
            heapq.heappush(heap, (len(next_edges) + remaining, counter, next_nodes, next_edges))
            counter += 1

    return found, truncated


def path_signature(graph: AttackGraph, path: RawPath) -> tuple:
    """Identity of a path after binding nodes collapse away.

    Two raw paths that differ only in which binding node carried the same role at
    the same scope are the same finding to a human, so dedup on the collapsed form.
    """
    parts: list[tuple[str, ...]] = []
    for position, node_id in enumerate(path.nodes):
        if graph.kind_of(node_id) in BINDING_KINDS:
            parts.append(
                (
                    "binding",
                    str(graph.role_of_binding(node_id) or ""),
                    str(graph.scope_of_binding(node_id) or ""),
                )
            )
        else:
            parts.append(("node", node_id))
        if position < len(path.edge_indices):
            parts.append(("edge", graph.edges[path.edge_indices[position]]["kind"]))
    return tuple(parts)
