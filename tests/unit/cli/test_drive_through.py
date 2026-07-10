"""Authenticated drive-through (non-interactive `--module ... --workspace ... --cred ...`).

Covers the pure resolution helpers and the non-interactive project guard that keeps a
drive-through from ever blocking on the interactive all-vs-current project prompt.
"""

from __future__ import annotations

from types import SimpleNamespace

import gcpwn.cli.module_actions as module_actions
from gcpwn.cli.main import _resolve_module_path, _resolve_workspace_by_name
from gcpwn.cli.module_actions import RunnerArgs, _resolve_targets_for_per_project
from gcpwn.core.session import SessionUtility

_ENUM_IAM = "gcpwn.modules.gcp.iam.enumeration.enum_iam"


def test_resolve_module_path_short_full_and_unknown():
    assert _resolve_module_path("enum_iam") == _ENUM_IAM          # registered short name
    assert _resolve_module_path(_ENUM_IAM) == _ENUM_IAM           # full import path
    assert _resolve_module_path("gcpwn/modules/gcp/iam/enumeration/enum_iam") == _ENUM_IAM  # slashes normalized
    assert _resolve_module_path("totally_unknown") == ""          # unknown bare name
    assert _resolve_module_path("foo.bar.baz") == "foo.bar.baz"   # unknown dotted path passes through


def test_resolve_workspace_by_name_exact_match():
    dc = SimpleNamespace(get_workspaces=lambda: [(1, "PROD"), (2, "TEST")])
    assert _resolve_workspace_by_name(dc, "TEST") == (2, "TEST")
    assert _resolve_workspace_by_name(dc, "prod") is None   # case-sensitive, exact
    assert _resolve_workspace_by_name(dc, "NOPE") is None
    assert _resolve_workspace_by_name(dc, "") is None


def _session(*, non_interactive: bool):
    # per-project resolution reads these; >1 known project is what would normally prompt
    return SimpleNamespace(
        project_id="proj-1",
        global_project_list=["proj-1", "proj-2"],
        workspace_config=SimpleNamespace(preferred_project_ids=[]),
        _non_interactive=non_interactive,
    )


def _no_selector():
    return RunnerArgs(project_ids=[], current_project=False, all_projects=False, passthrough=[])


def test_non_interactive_guard_defaults_to_current_without_prompting(monkeypatch):
    # Drive-through: per-project module + >1 known project + no selector must resolve to the
    # current project WITHOUT ever calling the interactive prompt.
    monkeypatch.setattr(
        module_actions, "_prompt_for_project_scope",
        lambda session: (_ for _ in ()).throw(AssertionError("prompt must not run in non-interactive mode")),
    )
    targets = _resolve_targets_for_per_project(_session(non_interactive=True), _no_selector(), _ENUM_IAM)
    assert targets == ["proj-1"]


def test_interactive_still_reaches_the_prompt(monkeypatch):
    # Same setup WITHOUT the flag still reaches the prompt (guard is scoped to drive-through).
    calls = {"n": 0}

    def _fake_prompt(session):
        calls["n"] += 1
        return "Current/Single"

    monkeypatch.setattr(module_actions, "_prompt_for_project_scope", _fake_prompt)
    targets = _resolve_targets_for_per_project(_session(non_interactive=False), _no_selector(), _ENUM_IAM)
    assert calls["n"] == 1
    assert targets == ["proj-1"]


# --- non-interactive session prompt guards (so a prompting module never hangs stdin) ---
# The methods short-circuit on self._non_interactive before touching other state, so a
# minimal stand-in exercises exactly the guard branch.

def test_choice_prompt_non_interactive_returns_none_instead_of_blocking():
    stub = SimpleNamespace(_non_interactive=True)
    assert SessionUtility.choice_prompt(stub, "pick something: ") is None


def test_choice_selector_non_interactive_auto_selects_sole_candidate():
    stub = SimpleNamespace(_non_interactive=True)
    only = {"name": "the-only-one"}
    assert SessionUtility.choice_selector(stub, rows_returned=[only]) is only


def test_choice_selector_non_interactive_skips_on_zero_or_many():
    stub = SimpleNamespace(_non_interactive=True)
    assert SessionUtility.choice_selector(stub, rows_returned=[{"a": 1}, {"b": 2}]) is None
    assert SessionUtility.choice_selector(stub, rows_returned=[]) is None
