"""Characterization test for hierarchy.render_tree_lines.

The CLI tree renderers (workspace_instructions.print_gcp_hierarchy and
module_actions._render_known_project_tree) were de-duplicated onto the shared
``render_tree_lines`` primitive. Only the final tree-walk was replaced; the
node/children/sort construction upstream is untouched. So preserving output
reduces to: does render_tree_lines emit byte-identical lines to the two old
inline walks for the same (roots, children, label) inputs? These verbatim copies
of the pre-refactor walks are the golden reference; the test asserts all three
agree across randomized trees and edge cases.
"""
from __future__ import annotations

import random

from gcpwn.core.utils.hierarchy import render_tree_lines


def _old_module_actions_walk(children, label_of):
    """Verbatim copy of the pre-refactor module_actions._render_known_project_tree walk."""
    lines: list[str] = []

    def _walk(parent, prefix=""):
        siblings = children.get(parent, [])
        for index, name in enumerate(siblings):
            is_last = index == len(siblings) - 1
            if parent is None:
                lines.append(f"{prefix}{label_of(name)}")
                _walk(name, prefix)
                continue
            branch = "└─ " if is_last else "├─ "
            lines.append(f"{prefix}{branch}{label_of(name)}")
            _walk(name, prefix + ("   " if is_last else "│  "))

    _walk(None)
    return lines


def _old_workspace_instructions_walk(filtered_roots, filtered_children, label_of):
    """Verbatim copy of the pre-refactor workspace_instructions.print_gcp_hierarchy walk."""
    out: list[str] = []
    tee, elbow, pipe, space = "├─ ", "└─ ", "│  ", "   "

    def render(node_name, prefix="", is_last=True):
        branch = elbow if is_last else tee
        out.append(prefix + branch + label_of(node_name))
        visible_children = filtered_children.get(node_name, [])
        for index, child in enumerate(visible_children):
            child_prefix = prefix + (space if is_last else pipe)
            render(child, child_prefix, index == len(visible_children) - 1)

    for root in filtered_roots:
        out.append(label_of(root))
        visible_children = filtered_children.get(root, [])
        for child_index, child in enumerate(visible_children):
            render(child, "", child_index == len(visible_children) - 1)
    return out


def _random_tree(rng, n_nodes):
    """Build a random forest as a {parent_or_None: [child, ...]} adjacency map."""
    names = [f"n{i}" for i in range(n_nodes)]
    children: dict[object, list[str]] = {}
    for i, name in enumerate(names):
        # each node's parent is an earlier node (a real tree) or None (a root)
        parent = None if i == 0 or rng.random() < 0.3 else names[rng.randrange(0, i)]
        children.setdefault(parent, []).append(name)
    roots = children.get(None, [])
    # label maps a node name to a distinctive display string (mimics colorized labels)
    label_of = lambda name: f"<{name}:{len(children.get(name, []))}>"  # noqa: E731
    return roots, children, label_of


def test_render_tree_lines_matches_both_old_walks_randomized():
    rng = random.Random(1337)
    for _ in range(400):
        roots, children, label_of = _random_tree(rng, rng.randint(1, 40))
        new = render_tree_lines(roots, children, label_of)
        assert new == _old_module_actions_walk(children, label_of)
        assert new == _old_workspace_instructions_walk(roots, children, label_of)


def test_render_tree_lines_edge_cases():
    label_of = lambda name: name  # noqa: E731
    # empty forest
    assert render_tree_lines([], {}, label_of) == []
    # single root, no children -> flush, no branch glyph
    assert render_tree_lines(["r"], {}, label_of) == ["r"]
    # one root, two children -> last gets └─, first gets ├─
    lines = render_tree_lines(["r"], {"r": ["a", "b"]}, label_of)
    assert lines == ["r", "├─ a", "└─ b"]
    # deep chain indents with └─ / spaces
    lines = render_tree_lines(["r"], {"r": ["a"], "a": ["b"]}, label_of)
    assert lines == ["r", "└─ a", "   └─ b"]
    # sibling continuation uses │
    lines = render_tree_lines(["r"], {"r": ["a", "c"], "a": ["b"]}, label_of)
    assert lines == ["r", "├─ a", "│  └─ b", "└─ c"]
    # multiple roots each flush-left
    assert render_tree_lines(["r1", "r2"], {}, label_of) == ["r1", "r2"]
