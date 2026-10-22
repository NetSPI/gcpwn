"""`_auto_cross_project_sa_projects` detects SA home-projects where the org policy leaves
iam.disableCrossProjectServiceAccountUsage not_enforced (cross-project impersonation allowed).
"""

from __future__ import annotations

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import _auto_cross_project_sa_projects


class _Source:
    def __init__(self, rows):
        self._rows = rows

    def get_data(self, table):
        return self._rows if table == "orgpolicy_policies" else []


def test_detects_not_enforced_constraint():
    rows = [
        {"project_id": "loose-proj", "constraint": "constraints/iam.disableCrossProjectServiceAccountUsage", "rule_summary": "not_enforced"},
        {"project_id": "strict-proj", "constraint": "constraints/iam.disableCrossProjectServiceAccountUsage", "rule_summary": "enforce"},
        {"project_id": "other", "constraint": "constraints/iam.disableServiceAccountKeyCreation", "rule_summary": "not_enforced"},
    ]
    assert _auto_cross_project_sa_projects(_Source(rows)) == frozenset({"loose-proj"})


def test_empty_orgpolicy_is_empty():
    assert _auto_cross_project_sa_projects(_Source([])) == frozenset()


def test_ignores_rows_without_project_id():
    rows = [{"project_id": "", "constraint": "iam.disableCrossProjectServiceAccountUsage", "rule_summary": "not_enforced"}]
    assert _auto_cross_project_sa_projects(_Source(rows)) == frozenset()
