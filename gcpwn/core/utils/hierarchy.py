"""Resource-hierarchy graph traversal shared across gcpwn.

The org/folder/project tree (materialized in the ``abstract_tree_hierarchy``
table) is walked in several places -- IAM inheritance rollup, OpenGraph
policy-binding expansion, and enum_all's ``--parent-allowlist`` scope resolution.
They all need the same primitive: given a ``{parent_name: [child_name, ...]}``
adjacency map, enumerate a subtree. This module is the single home for that walk
so the algorithm (and its cycle-guard) lives in exactly one place.
"""

from __future__ import annotations

from collections import deque
from typing import Callable


def descendants(children_by_parent: dict[str, list[str]], root: str) -> list[str]:
    """BFS all descendant scope names under ``root`` (excludes root), cycle-safe.

    Used to fan a parent-scope binding/permission down its resource-hierarchy
    subtree. The ``seen`` set guards against malformed cyclic hierarchy data.
    Returns descendants in breadth-first order; an empty/blank root yields ``[]``.
    """
    root_name = str(root or "").strip()
    if not root_name:
        return []
    out: list[str] = []
    seen = {root_name}
    queue: deque[str] = deque(children_by_parent.get(root_name, []))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        out.append(current)
        for child in children_by_parent.get(current, []):
            if child not in seen:
                queue.append(child)
    return out


def render_tree_lines(
    roots: list[str],
    children_by_parent: dict[str, list[str]],
    label_of: Callable[[str], str],
) -> list[str]:
    """Render an ASCII tree from a ``{parent_name: [child_name, ...]}`` adjacency map.

    Roots are emitted flush-left with no branch glyph; every other node gets a
    ``├─ ``/``└─ `` branch and its subtree is indented by ``│  ``/``   ``. ``label_of``
    turns a node name into its display string (a colorized label, a short token, ...),
    so each caller keeps its own labeling and scoping while sharing this one tree walk.
    Children are rendered in the order the adjacency map already holds them (callers sort
    upstream). Returns the lines in pre-order for the caller to print or collect.
    """
    lines: list[str] = []

    def _walk(name: str, prefix: str, is_last: bool) -> None:
        lines.append(f"{prefix}{'└─ ' if is_last else '├─ '}{label_of(name)}")
        kids = children_by_parent.get(name, [])
        child_prefix = prefix + ("   " if is_last else "│  ")
        for index, kid in enumerate(kids):
            _walk(kid, child_prefix, index == len(kids) - 1)

    for root in roots:
        lines.append(label_of(root))
        kids = children_by_parent.get(root, [])
        for index, kid in enumerate(kids):
            _walk(kid, "", index == len(kids) - 1)

    return lines
