"""enum_resources must brute-force / cover the known (current) project even when
Resource Manager search() returns nothing.

A narrowly-scoped credential (e.g. a custom role with only storage.buckets.create)
has no resourcemanager.projects.get, so projects.search() comes back empty. But
projects.testIamPermissions works WITHOUT get -- that is the permission-brute-force
use case. The module injects the session's current/known project id(s) as targets so
--iam tests them and they land in the hierarchy for downstream per-project enumeration.
"""

from types import SimpleNamespace

from gcpwn.modules.gcp.resourcemanager.enumeration import enum_resources


class _FakeProjectsResource:
    """Minimal stand-in exercising the code path _collect_resource_rows drives."""

    def __init__(self, search_result):
        self._search_result = search_result
        self.saved = []
        self.tested = []  # (resource_name, permissions)

    def search(self, *, debug=False):
        return self._search_result

    def save(self, rows):
        self.saved.extend(list(rows or []))

    def resource_name(self, row):
        return str((row or {}).get("name") or "").strip()

    def load_permissions(self, *, all_permissions=False):
        return ["storage.buckets.create", "resourcemanager.projects.get"]

    def test_iam_permissions(self, *, resource_name, permissions, **_kwargs):
        granted = ["storage.buckets.create"]  # what the scoped SA actually holds
        self.tested.append((resource_name, list(permissions)))
        return granted

    def record_permissions(self, action_dict, row, permissions):
        pass


def _args(**over):
    base = dict(iam=True, get=False, all_permissions=False, debug=False, record_failed_permissions=False)
    base.update(over)
    return SimpleNamespace(**base)


def test_known_project_is_brute_forced_when_search_is_empty():
    resource = _FakeProjectsResource(search_result=[])
    result = enum_resources._collect_resource_rows(
        resource,
        component_key="projects",
        args=_args(),
        action_dict={},
        allowed_ids=set(),
        enforce_scope=False,
        ensure_ids={"bsidesnovapocproject"},
    )
    # The known project was synthesized, saved, and testIamPermissions ran against it.
    assert any(r.get("project_id") == "bsidesnovapocproject" for r in resource.saved)
    assert resource.tested == [("projects/bsidesnovapocproject", resource.load_permissions())]
    assert result["not_enabled"] is False
    assert any(r.get("project_id") == "bsidesnovapocproject" for r in result["rows"])


def test_known_project_not_duplicated_when_search_already_returned_it():
    discovered = [{"name": "projects/bsidesnovapocproject", "project_id": "bsidesnovapocproject"}]
    resource = _FakeProjectsResource(search_result=discovered)
    enum_resources._collect_resource_rows(
        resource,
        component_key="projects",
        args=_args(),
        action_dict={},
        allowed_ids=set(),
        enforce_scope=False,
        ensure_ids={"bsidesnovapocproject"},
    )
    # Only one testIamPermissions call -- the injected id matched the discovered one.
    assert len(resource.tested) == 1


def test_ensure_ids_ignored_for_non_project_components():
    resource = _FakeProjectsResource(search_result=[])
    enum_resources._collect_resource_rows(
        resource,
        component_key="organizations",
        args=_args(),
        action_dict={},
        allowed_ids=set(),
        enforce_scope=False,
        ensure_ids={"bsidesnovapocproject"},
    )
    assert resource.tested == []  # no project injection for the organizations component
