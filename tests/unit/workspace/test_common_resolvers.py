"""Coverage for the workspace customer-id / org-id resolvers in workspace/common.py.

These feed every Admin SDK Directory module (the `customer=` selector). The
explicit / config / cached-hierarchy-walk paths are exercised here; the Resource
Manager API fallbacks need live credentials and are out of scope.
"""

from __future__ import annotations

from types import SimpleNamespace

from gcpwn.cli.workspace_instructions import CONFIG_COMPLETION_KEYS
from gcpwn.modules.workspace.common import (
    resolve_directory_customer_id,
    resolve_org_id,
    resolve_workspace_admin_subject,
)


class _FakeSession:
    def __init__(self, hierarchy, *, project_id="proj-a", customer_id=None):
        self._hierarchy = hierarchy
        self.project_id = project_id
        self.workspace_config = SimpleNamespace(workspace_customer_id=customer_id)

    def get_data(self, table_name, columns="*", conditions=None, *, where=None, params=None):
        if str(table_name) != "abstract_tree_hierarchy":
            return []
        rows = self._hierarchy
        if where:
            rows = [r for r in rows if all(str(r.get(k, "")) == str(v) for k, v in where.items())]
        return [dict(r) for r in rows]


_HIERARCHY = [
    {"type": "project", "project_id": "proj-a", "name": "projects/proj-a", "parent": "folders/222"},
    {"type": "folder", "project_id": "", "name": "folders/222", "parent": "organizations/111"},
    {"type": "organization", "project_id": "", "name": "organizations/111", "parent": ""},
]


def test_resolve_org_id_explicit_wins():
    assert resolve_org_id(_FakeSession([]), explicit_org_id="999888") == "999888"


def test_resolve_org_id_walks_cached_hierarchy_to_org():
    # project -> folder -> organization, via cached abstract_tree_hierarchy parents
    assert resolve_org_id(_FakeSession(_HIERARCHY)) == "111"


def test_resolve_directory_customer_id_explicit_wins():
    assert resolve_directory_customer_id(_FakeSession([]), customer_id="C0explicit") == "C0explicit"


def test_resolve_directory_customer_id_from_config():
    session = _FakeSession([], customer_id="C0config")
    assert resolve_directory_customer_id(session) == "C0config"


def test_resolve_directory_customer_id_explicit_beats_config():
    session = _FakeSession([], customer_id="C0config")
    assert resolve_directory_customer_id(session, customer_id="C0override") == "C0override"


def test_workspace_admin_subject_is_a_settable_config_key():
    # Regression: workspace_admin_subject must be a real `configs set` key (it was
    # read by resolve_workspace_admin_subject but not registered in the handler).
    assert "workspace_admin_subject" in CONFIG_COMPLETION_KEYS


def test_resolve_workspace_admin_subject_config_then_impersonate_override():
    session = SimpleNamespace(workspace_config=SimpleNamespace(workspace_admin_subject="admin@corp.com"))
    assert resolve_workspace_admin_subject(session) == "admin@corp.com"          # from config
    assert resolve_workspace_admin_subject(session, "cli@corp.com") == "cli@corp.com"  # --impersonate wins
