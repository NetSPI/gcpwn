"""Characterization tests for enum_all's --parent-allowlist scope resolution.

`_resolve_parent_descendants` expands a set of parent folder/org IDs into the
concrete {projects, folders, organizations} scope by walking the cached
`abstract_tree_hierarchy`. These tests pin the exact current behavior so the walk
can be refactored onto the shared `core.utils.hierarchy.descendants` helper
without drift:

  - the roots themselves are INCLUDED in the result (a parent folder is in scope);
  - descendants are classified by node type (project/folder/org);
  - projects contribute their `project_id`; folders/orgs contribute the numeric
    tail of their name, and NON-digit tails are dropped;
  - a root that has no row in the cached hierarchy contributes nothing;
  - cyclic/overlapping roots are handled without duplication or infinite loops.
"""

from __future__ import annotations

from gcpwn.modules.everything.enumeration.enum_all import _resolve_parent_descendants

# org 111 -> folder 222 -> {project proj-a, folder 333 -> project proj-b}
_HIERARCHY = [
    {"name": "organizations/111", "parent": "", "type": "org", "project_id": ""},
    {"name": "folders/222", "parent": "organizations/111", "type": "folder", "project_id": ""},
    {"name": "projects/proj-a", "parent": "folders/222", "type": "project", "project_id": "proj-a"},
    {"name": "folders/333", "parent": "folders/222", "type": "folder", "project_id": ""},
    {"name": "projects/proj-b", "parent": "folders/333", "type": "project", "project_id": "proj-b"},
]


def test_no_roots_returns_empty():
    out = _resolve_parent_descendants(_HIERARCHY, parent_folder_ids=set(), parent_org_ids=set())
    assert out == {"projects": set(), "folders": set(), "organizations": set()}


def test_parent_folder_includes_root_and_descendants():
    out = _resolve_parent_descendants(_HIERARCHY, parent_folder_ids={"222"}, parent_org_ids=set())
    assert out == {
        "projects": {"proj-a", "proj-b"},
        "folders": {"222", "333"},  # root 222 itself is included
        "organizations": set(),
    }


def test_parent_org_expands_whole_subtree():
    out = _resolve_parent_descendants(_HIERARCHY, parent_folder_ids=set(), parent_org_ids={"111"})
    assert out == {
        "projects": {"proj-a", "proj-b"},
        "folders": {"222", "333"},
        "organizations": {"111"},  # root org itself is included
    }


def test_deeper_folder_scopes_only_its_subtree():
    out = _resolve_parent_descendants(_HIERARCHY, parent_folder_ids={"333"}, parent_org_ids=set())
    assert out == {"projects": {"proj-b"}, "folders": {"333"}, "organizations": set()}


def test_root_absent_from_hierarchy_contributes_nothing():
    out = _resolve_parent_descendants(_HIERARCHY, parent_folder_ids={"999"}, parent_org_ids=set())
    assert out == {"projects": set(), "folders": set(), "organizations": set()}


def test_overlapping_roots_dedupe_and_terminate():
    # org 111 and folder 222 (a descendant of 111) both given: union, no dup, no hang.
    out = _resolve_parent_descendants(_HIERARCHY, parent_folder_ids={"222"}, parent_org_ids={"111"})
    assert out == {
        "projects": {"proj-a", "proj-b"},
        "folders": {"222", "333"},
        "organizations": {"111"},
    }


def test_cyclic_hierarchy_does_not_hang():
    cyclic = [
        {"name": "folders/1", "parent": "folders/2", "type": "folder", "project_id": ""},
        {"name": "folders/2", "parent": "folders/1", "type": "folder", "project_id": ""},
    ]
    out = _resolve_parent_descendants(cyclic, parent_folder_ids={"1"}, parent_org_ids=set())
    assert out == {"projects": set(), "folders": {"1", "2"}, "organizations": set()}
