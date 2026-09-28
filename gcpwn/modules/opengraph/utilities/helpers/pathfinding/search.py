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
from typing import Iterable

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
) -> TargetSet:
    """Turn CLI-style selectors into a concrete set of target node ids."""
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
        resolved = {node_id for node_id in resolved if graph.scope_matches(node_id, scope)}
        described.append(f"scope~{scope}")

    return TargetSet(node_ids=resolved, description=" ".join(described) or "(none)")


def reverse_distances(
    graph: AttackGraph,
    targets: set[str],
    traversable: frozenset[str],
    *,
    max_depth: int,
) -> tuple[dict[str, int], dict[str, tuple[str, int]]]:
    """Multi-source BFS backwards from ``targets``.

    Returns ``(dist, succ)`` where ``dist[n]`` is the fewest raw edges from ``n``
    to the nearest target and ``succ[n]`` is ``(next_node, edge_index)`` -- the
    first step of one such shortest path. Following ``succ`` forward from any
    node reconstructs a shortest path without a second search.
    """
    dist: dict[str, int] = {target: 0 for target in targets if target in graph.nodes}
    succ: dict[str, tuple[str, int]] = {}
    queue = deque(dist)

    while queue:
        node = queue.popleft()
        depth = dist[node]
        if depth >= max_depth:
            continue
        for predecessor, edge_index in graph.radj.get(node, ()):
            if graph.edges[edge_index]["kind"] not in traversable:
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
) -> list[RawPath]:
    """One shortest path per principal that can reach any target.

    Single reverse BFS over the whole target set -- the cheap default mode.
    """
    traversable = graph.traversable_kinds(include_containment=include_containment)
    dist, succ = reverse_distances(graph, targets, traversable, max_depth=max_depth)

    candidates = (
        list(sources)
        if sources is not None
        else graph.principals(exclude_service_agents=exclude_service_agents)
    )
    results: list[RawPath] = []
    for source in candidates:
        if source in targets or source not in dist:
            continue
        path = _reconstruct(source, succ, targets)
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
) -> tuple[list[RawPath], bool]:
    """Every simple path from ``sources`` to ``targets``, shortest first.

    Best-first (A*) over partial paths with ``h(n)`` = reverse-BFS distance to the
    nearest target. Because ``h`` is exact on the raw graph, popped paths come out
    in nondecreasing length, so results are already shortest-first and the search
    can stop the moment the budget is hit.

    Returns ``(paths, truncated)``; ``truncated`` is True when a budget stopped the
    search before it was exhausted.
    """
    traversable = graph.traversable_kinds(include_containment=include_containment)
    dist, _ = reverse_distances(graph, targets, traversable, max_depth=max_depth)

    candidates = [
        source
        for source in (
            list(sources)
            if sources is not None
            else graph.principals(exclude_service_agents=exclude_service_agents)
        )
        if source in dist and source not in targets
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

    while heap:
        if len(found) >= max_paths:
            truncated = True
            break
        if expansions >= max_expansions:
            truncated = True
            break

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
            if neighbour in visited:
                continue
            if graph.edges[edge_index]["kind"] not in traversable:
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
