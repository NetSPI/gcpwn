"""Module dispatch policy and execution: auth gating, project-scope planning, per-project loop.

interact_with_module() is the single chokepoint that the REPL (and passthrough mode) use to
run any module. It decides, via get_module_action()/MODULE_POLICY_REGISTRY, whether a module
needs credentials, runs once vs once-per-project, and accepts project selector flags; resolves
the target project list; then imports the module and calls its run_module(args, session)
contract for each project, temporarily swapping session.project_id per run.

Module return-value contract observed here: run_module returns truthy/0 == success, -1 ==
failure. enum_all additionally uses return code 2 to signal "newly discovered projects should
be appended to the run queue" (cross-project resumable enumeration).
"""
from __future__ import annotations

import argparse
import importlib
import traceback
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from typing import Any, Sequence

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.hierarchy import render_tree_lines
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.service_runtime import flatten_arg_groups, parse_id_input_values


@dataclass(frozen=True)
class ModuleAction:
    """Resolved execution policy for one module.

    requires_auth: needs loaded credentials before running.
    run_once: run a single time instead of once per target project.
    use_context_project: when run_once, still resolve and set a single context project_id.
    accepts_project_flags: whether --project-id/--current-project/--all-projects apply.
    """

    requires_auth: bool
    run_once: bool
    use_context_project: bool
    accepts_project_flags: bool = True


@dataclass(frozen=True)
class RunnerArgs:
    """Parsed project-targeting selectors plus the remaining (passthrough) module args.

    project_ids/current_project/all_projects are mutually exclusive selectors;
    passthrough holds every arg interact_with_module hands straight to run_module.
    """

    project_ids: list[str]
    current_project: bool
    all_projects: bool
    passthrough: list[str] = field(default_factory=list)

# (run_once, use_context_project, accepts_project_flags) tuple consumed by get_module_action.
DEFAULT_MODULE_POLICY = (False, False, True)
MODULE_POLICY_REGISTRY: dict[str, tuple[bool, bool, bool]] = {
    "enum_resources": (True, True, True),
    "enum_gcp_policy_bindings": (True, True, True),
    "process_gcp_iam_bindings": (True, True, True),
    "process_og_gcpwn_data": (True, False, False),
    "process_og_node_color_images": (True, False, False),
    "enum_cloud_identity": (True, True, False),
    # Google Workspace modules are tenant/user-scoped, not per-GCP-project -> run once.
    "enum_drive": (True, True, False),
}

UNAUTH_ALLOWED_MODULE_KEYS: set[str] = {
    # OpenGraph local-processing / utility modules do not require live GCP API auth.
    "process_og_gcpwn_data",
    "process_og_node_color_images",
}

def _is_unknown_project_token(value: Any) -> bool:
    token = str(value or "").strip().lower()
    return token in {"unknown", "n/a", "<unknown-project>", "<unknown>", "none"}


def _normalize_project_ids(values: Sequence[str]) -> list[str]:
    """Trim, drop placeholder/unknown tokens, and de-duplicate project ids preserving order."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        token = str(value or "").strip()
        if not token or _is_unknown_project_token(token) or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _parse_runner_args(argv: Sequence[str]) -> RunnerArgs:
    """Split module argv into project selectors (consumed here) and passthrough args (for run_module).

    Recognizes --project-id(s) (inline space/comma lists), --project-id-file(s) (one id per
    line), --current-project, and --all-projects; everything unrecognized stays in `passthrough`
    untouched so modules define their own flags. parse_known_args is used so module flags never
    error here.
    """
    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    p.add_argument(
        "--project-id",
        "--project-ids",
        dest="project_ids",
        action="append",
        nargs="+",
        help=(
            "Target project ID(s). Supports space/comma separated inline values. Overrides prompts."
        ),
    )
    p.add_argument(
        "--project-id-file",
        "--project-ids-file",
        dest="project_id_files",
        action="append",
        nargs="+",
        help="File path(s) containing project IDs (one ID per line). Overrides prompts.",
    )
    p.add_argument("--current-project", action="store_true", help="Target ONLY current session project (no prompts).")
    p.add_argument("--all-projects", action="store_true", help="Target ALL already-known projects (no prompts).")

    known, rest = p.parse_known_args(list(argv or []))
    flattened_project_tokens = flatten_arg_groups(known.project_ids)
    file_project_tokens = flatten_arg_groups(known.project_id_files)
    parsed_project_ids_inline = parse_id_input_values(
        flattened_project_tokens,
        value_label="project id",
        numeric_only=False,
    )
    parsed_project_ids_files = parse_id_input_values(
        file_project_tokens,
        value_label="project id",
        numeric_only=False,
        files_only=True,
    )
    parsed_project_ids = list(dict.fromkeys([*parsed_project_ids_inline, *parsed_project_ids_files]))
    return RunnerArgs(
        project_ids=_normalize_project_ids(parsed_project_ids),
        current_project=known.current_project,
        all_projects=known.all_projects,
        passthrough=list(rest),
    )

@contextmanager
def _temporary_attr(obj: Any, attr: str, value: Any):
    """Context manager that sets obj.attr to value, then restores the prior value/absence.

    Used to scope session.project_id (and _module_run_context) to a single module run so
    the per-project loop never leaks state between projects. Restoration is best-effort.
    """
    old = getattr(obj, attr, None)
    had = hasattr(obj, attr)
    try:
        setattr(obj, attr, value)
        yield
    finally:
        try:
            if had:
                setattr(obj, attr, old)
            else:
                delattr(obj, attr)
        except Exception:
            pass


def _parallel_services_count(passthrough_args: Sequence[str]) -> int:
    """Peek at --parallel-services N in the passthrough args (clamped >=1); 1 on any error.

    Used to detect enum_all's opt-in cross-project parallel orchestrator mode without
    consuming the flag (it is still forwarded to run_parallel).
    """
    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    p.add_argument("--parallel-services", dest="parallel_services", type=int, default=1)
    try:
        known, _ = p.parse_known_args(list(passthrough_args or []))
        return max(1, int(known.parallel_services or 1))
    except (SystemExit, ValueError):
        return 1


def _is_unauth_module(module_import_path: str) -> bool:
    lowered = str(module_import_path or "").lower()
    return ".unauthenticated." in lowered or lowered.split(".")[-1].startswith("unauth_")


def get_module_action(module_import_path: str) -> ModuleAction:
    """Resolve a module's execution policy (auth/run-once/project-scope) from its import path.

    Unauth modules (by name prefix or '.unauthenticated.' segment) always run once, no auth,
    no project flags. Otherwise the trailing module name is looked up in MODULE_POLICY_REGISTRY
    (DEFAULT_MODULE_POLICY = per-project, accepts flags). requires_auth is True unless the name
    is in UNAUTH_ALLOWED_MODULE_KEYS (local-processing modules that need no live GCP API).
    """
    if _is_unauth_module(module_import_path):
        return ModuleAction(
            requires_auth=False,
            run_once=True,
            use_context_project=False,
            accepts_project_flags=False,
        )

    key = str(module_import_path or "").replace("/", ".").split(".")[-1]
    run_once, use_context_project, accepts_project_flags = MODULE_POLICY_REGISTRY.get(key, DEFAULT_MODULE_POLICY)
    requires_auth = key not in UNAUTH_ALLOWED_MODULE_KEYS
    return ModuleAction(
        requires_auth=requires_auth,
        run_once=run_once,
        use_context_project=use_context_project,
        accepts_project_flags=accepts_project_flags,
    )


def _should_prompt_all_projects(module_import_path: str) -> bool:
    """Whether to offer the all-vs-current project prompt for this module.

    Suppressed for exploit/process/unauthenticated modules, where blasting every known
    project by accident is undesirable; those default to the current project only.
    """
    lowered = str(module_import_path or "").lower()
    no_prompt_tokens = (
        ".exploit.",
        ".process.",
        ".unauthenticated.",
    )
    return not any(token in lowered for token in no_prompt_tokens)


def _short_hierarchy_token(row: dict[str, Any]) -> str:
    resource_type = str(row.get("type") or "").strip().lower()
    display_name = str(row.get("display_name") or "").strip()
    resource_name = str(row.get("name") or "").strip()
    project_id = str(row.get("project_id") or "").strip()

    if resource_type == "project":
        return project_id or display_name or extract_path_tail(resource_name, default=resource_name)
    if display_name:
        return display_name
    return resource_name or project_id


def _render_current_project_hierarchy(session) -> str:
    """Build an 'org > folder > project' breadcrumb for the current project (current node in red).

    Loads abstract_tree_hierarchy once and walks parent links in-memory (avoids a query per
    ancestor on every per-project run). Returns "" if no current project or it isn't cached.
    """
    current_project_id = str(getattr(session, "project_id", "") or "").strip()
    if not current_project_id or _is_unknown_project_token(current_project_id):
        return ""

    # Load the hierarchy once and walk parents in-memory (avoids one query per
    # ancestor on every per-project module run).
    all_rows = session.get_data(
        "abstract_tree_hierarchy",
        columns=["name", "display_name", "type", "parent", "project_id"],
    ) or []
    rows_by_name = {
        str(row.get("name") or "").strip(): row
        for row in all_rows
        if str(row.get("name") or "").strip()
    }
    current_row = next(
        (
            row
            for row in all_rows
            if str(row.get("type") or "").strip().lower() == "project"
            and str(row.get("project_id") or "").strip() == current_project_id
        ),
        None,
    )
    if not current_row:
        return ""

    chain: list[dict[str, Any]] = [current_row]
    seen = {str(current_row.get("name") or "").strip()}
    parent_name = str(current_row.get("parent") or "").strip()

    while parent_name and parent_name.upper() != "N/A":
        parent_row = rows_by_name.get(parent_name)
        if not parent_row:
            break
        parent_resource_name = str(parent_row.get("name") or "").strip()
        if not parent_resource_name or parent_resource_name in seen:
            break
        seen.add(parent_resource_name)
        chain.append(parent_row)
        parent_name = str(parent_row.get("parent") or "").strip()

    chain.reverse()
    if not chain:
        return ""

    parts: list[str] = []
    for index, row in enumerate(chain):
        token = _short_hierarchy_token(row)
        if not token:
            continue
        if index == len(chain) - 1:
            token = f"{UtilityTools.BRIGHT_RED}{UtilityTools.BOLD}{token}{UtilityTools.RESET}"
        parts.append(token)
    return " > ".join(parts)


def _project_tree_label(row: dict[str, Any], *, current_project_id: str) -> str:
    token = _short_hierarchy_token(row)
    if not token:
        token = str(row.get("name") or row.get("project_id") or "").strip()
    resource_type = str(row.get("type") or "").strip().lower()
    if resource_type == "org":
        return f"{UtilityTools.BOLD}{UtilityTools.CYAN}{token} [ORG]{UtilityTools.RESET}"
    if str(row.get("project_id") or "").strip() == current_project_id:
        return f"{UtilityTools.BRIGHT_RED}{UtilityTools.BOLD}{token}{UtilityTools.RESET}"
    return token


def _render_known_project_tree(session) -> list[str]:
    """Render an ASCII org/folder/project tree limited to the workspace's known projects.

    Includes each known project and all of its ancestors from abstract_tree_hierarchy;
    synthesizes a standalone project node when a known project has no cached hierarchy row.
    Children are sorted org->folder->project then by label; current project shown in red,
    orgs in cyan. Returns the rendered lines (empty list if there are no known projects).
    """
    current_project_id = str(getattr(session, "project_id", "") or "").strip()
    known_projects = {
        str(project_id).strip()
        for project_id in (getattr(session, "global_project_list", None) or [])
        if str(project_id).strip() and not _is_unknown_project_token(str(project_id).strip())
    }
    if current_project_id and not _is_unknown_project_token(current_project_id):
        known_projects.add(current_project_id)
    if not known_projects:
        return []

    rows = session.get_data(
        "abstract_tree_hierarchy",
        columns=["name", "display_name", "type", "parent", "project_id"],
    ) or []
    nodes: dict[str, dict[str, Any]] = {}
    project_rows_by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        normalized = dict(row)
        normalized["name"] = name
        parent = str(row.get("parent") or "").strip()
        normalized["parent"] = None if not parent or parent.upper() == "N/A" else parent
        normalized["type"] = str(row.get("type") or "").strip().lower()
        nodes[name] = normalized
        project_id = str(row.get("project_id") or "").strip()
        if project_id and normalized["type"] == "project":
            project_rows_by_id[project_id] = normalized

    included: set[str] = set()
    for project_id in sorted(known_projects):
        project_row = project_rows_by_id.get(project_id)
        if project_row is None:
            synthetic_name = f"projects/{project_id}"
            project_row = {
                "name": synthetic_name,
                "display_name": project_id,
                "type": "project",
                "parent": None,
                "project_id": project_id,
            }
            nodes[synthetic_name] = project_row
            project_rows_by_id[project_id] = project_row
        current_name = str(project_row.get("name") or "").strip()
        while current_name and current_name not in included:
            included.add(current_name)
            parent_name = str(nodes.get(current_name, {}).get("parent") or "").strip()
            if not parent_name or parent_name not in nodes:
                break
            current_name = parent_name

    children: dict[str | None, list[str]] = {}
    for name in included:
        parent = str(nodes.get(name, {}).get("parent") or "").strip() or None
        if parent is not None and parent not in included:
            parent = None
        children.setdefault(parent, []).append(name)

    def _sort_key(name: str) -> tuple[int, str]:
        row = nodes.get(name, {})
        row_type = str(row.get("type") or "").strip().lower()
        order = {"org": 0, "folder": 1, "project": 2}.get(row_type, 3)
        label = str(row.get("display_name") or row.get("project_id") or row.get("name") or "").lower()
        return (order, label)

    for child_names in children.values():
        child_names.sort(key=_sort_key)

    def _label(name: str) -> str:
        return _project_tree_label(nodes.get(name, {}), current_project_id=current_project_id)

    return render_tree_lines(children.get(None, []), children, _label)


def _prompt_for_project_scope(session) -> str | None:
    """Interactively ask whether to target all known projects or just the current one.

    Prints the known-project tree (or current breadcrumb) for context. Returns
    "All Projects", "Current/Single", or None (exit/cancel/Ctrl-C).
    """
    tree_lines = _render_known_project_tree(session)
    if tree_lines:
        print("[*] Known project tree:")
        for line in tree_lines:
            print(f"    {line}")
    else:
        hierarchy = _render_current_project_hierarchy(session)
        if hierarchy:
            print(f"[*] Current project context: {hierarchy}")

    print(
        "> Do you want to scan all projects or current single project? "
        "If not, specify project-id(s) with '--project-id <id>' / '--project-ids id1,id2' "
        "or '--project-id-file <path>'"
    )
    print(">> [A|1] All Projects")
    print(">> [C|2] Current/Single")
    print("> [3] Exit\n")

    while True:
        try:
            choice = input("> Choose an option: ").strip().upper()
        except KeyboardInterrupt:
            return None

        if choice in {"A", "1"}:
            return "All Projects"
        if choice in {"C", "2"}:
            print("[*] Proceeding with just the current project ID")
            return "Current/Single"
        if choice in {"3"}:
            return None
        print("Please enter A, C, 1, 2, or 3.")


def _resolve_targets_for_per_project(session, runner: RunnerArgs, module_import_path: str) -> list[str] | None:
    """Decide the project id list a per-project module runs against.

    Precedence: explicit --project-id(s) > --current-project > --all-projects > workspace
    configured preferred_project_ids > interactive prompt / current project.
    Returns: a non-empty list to run, [] when the user explicitly cancelled selection, or
    None when there is no usable project context at all (caller surfaces guidance).
    """
    current_project_id = str(getattr(session, "project_id", "") or "").strip()
    if _is_unknown_project_token(current_project_id):
        current_project_id = ""
    known_projects = _normalize_project_ids(list(getattr(session, "global_project_list", None) or []))

    if runner.project_ids:
        return list(runner.project_ids)

    if runner.current_project:
        return [current_project_id] if current_project_id else None

    if runner.all_projects:
        if known_projects:
            return known_projects
        if current_project_id:
            return [current_project_id]
        return None

    if getattr(session.workspace_config, "preferred_project_ids", None):
        print("[*] Proceeding with workspace configuration for project IDs")
        for project_id in session.workspace_config.preferred_project_ids or []:
            print(f"[-]  {project_id}")
        return list(session.workspace_config.preferred_project_ids or [])

    if not current_project_id:
        return None

    if not _should_prompt_all_projects(module_import_path):
        return [current_project_id]

    project_list = [current_project_id]
    if len(known_projects) <= 1:
        return project_list

    # Non-interactive (drive-through) runs must never block on the all-vs-current
    # prompt: default to the current project. Pass --all-projects/--project-id to override.
    if getattr(session, "_non_interactive", False):
        return project_list

    choice = _prompt_for_project_scope(session)
    if choice == "All Projects":
        return known_projects
    if choice == "Current/Single":
        return project_list
    return []


def _resolve_context_project_id(session, runner: RunnerArgs) -> str | None:
    """Pick a single context project_id for run-once modules that still need one.

    Tries, in order: session.project_id, first --project-id, first preferred config project,
    first known project. Returns the first non-placeholder value, else None.
    """
    for candidate in (
        getattr(session, "project_id", None),
        runner.project_ids[0] if runner.project_ids else None,
        next(iter(getattr(session.workspace_config, "preferred_project_ids", None) or []), None),
        next(iter(getattr(session, "global_project_list", None) or []), None),
    ):
        token = str(candidate or "").strip()
        if token and not _is_unknown_project_token(token):
            return token
    return None


def _plan_execution(
    session,
    action: ModuleAction,
    runner: RunnerArgs,
    module_import_path: str,
) -> tuple[tuple[bool, str | None, list[str]] | None, str | None]:
    """Compute the execution plan for a module, or an error message to show the user.

    Returns (plan, None) on success where plan = (run_once, context_project_id, target_ids):
      - run-once modules -> (True, optional context project, []).
      - per-project modules -> (False, None, [project_ids...]).
    Returns (None, error_message) when no projects are available or selection was cancelled.
    """
    if action.run_once:
        ctx = _resolve_context_project_id(session, runner) if action.use_context_project else None
        return ((True, ctx, []), None)

    targets = _resolve_targets_for_per_project(session, runner, module_import_path)
    if targets is None:
        return (
            None,
            (
                f"{UtilityTools.RED}[X] No project context available.{UtilityTools.RESET} "
                "Use `projects list` to view known projects, then set one with "
                "`projects set <project_id>`, or pass `--project-id` / `--project-ids` / `--project-id-file`."
            ),
        )
    if targets == []:
        return (None, f"{UtilityTools.RED}[X] No target projects selected.{UtilityTools.RESET}")
    return ((False, None, targets), None)


def _execute_module_for_project(
    session,
    run_module,
    *,
    mod_short: str,
    project_id: str | None,
    passthrough_args: Sequence[str],
    run_index: int = 0,
    run_total: int = 1,
) -> tuple[Any, bool]:
    """Run run_module once for a single project, scoping session state and catching failures.

    Temporarily sets session.project_id (when given) and session._module_run_context
    (index/total) for the duration of the call, and logs START/END markers. Returns
    (module_return_value, ok) where ok is False if the module raised (traceback printed);
    an exception is treated as failure, not propagated, so the per-project loop continues.
    """
    label = project_id or "N/A"
    suffix = "" if project_id is None else f" for {label}"
    start_msg = f"[START_MODULE] Entering {mod_short} module{suffix}..."
    end_msg = f"[END_MODULE] Exiting {mod_short} module{suffix}..."
    UtilityTools.log_action(session.workspace_directory_name, start_msg)
    try:
        run_ctx = _temporary_attr(session, "_module_run_context", {"index": int(run_index), "total": int(run_total)})
        project_ctx = _temporary_attr(session, "project_id", project_id) if project_id is not None else nullcontext()
        with project_ctx:
            with run_ctx:
                return (run_module(list(passthrough_args), session), True)
    except Exception:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Module failed for project {label}. Details below:{UtilityTools.RESET}")
        print(traceback.format_exc())
        return (None, False)
    finally:
        UtilityTools.log_action(session.workspace_directory_name, end_msg)


def interact_with_module(session, module_path: str, module_args: Sequence[str]) -> int:
    """Validate, gate, plan, and execute a module; return 0 on success, -1 on failure.

    The single entrypoint used by both the REPL (`modules run`) and passthrough mode.
    Steps: parse project selectors -> reject conflicting selectors / warn-and-ignore on
    modules that don't accept them -> auth gate (refuse if requires_auth and no creds) ->
    import the module and grab its run_module -> forward -h/--help straight to the module ->
    special-case enum_all --parallel-services>1 (delegates to run_parallel) -> plan execution
    -> run once or loop per target project, swapping session.project_id per run.

    enum_all per-project loop: a return code of 2 means the module discovered new projects;
    their ids are merged into the pending queue so enumeration fans out resumably. Any
    per-project failure is collected and causes an overall -1 return. session.project_id is
    always restored after the loop. KeyboardInterrupt returns 0 (clean abort).
    """
    try:
        runner = _parse_runner_args(module_args)
        passthrough_args = list(runner.passthrough)

        module_import_path = str(module_path or "").replace("/", ".").strip()
        if not module_import_path:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Invalid module path.{UtilityTools.RESET}")
            return -1

        action = get_module_action(module_import_path)
        mod_short = module_import_path.split(".")[-1]

        if int(bool(runner.project_ids)) + int(bool(runner.current_project)) + int(bool(runner.all_projects)) > 1:
            print(
                f"{UtilityTools.RED}[X] Use only one selector: "
                f"--project-id/--project-ids/--project-id-file OR --current-project OR --all-projects."
                f"{UtilityTools.RESET}"
            )
            return -1

        if not action.accepts_project_flags and (runner.project_ids or runner.current_project or runner.all_projects):
            print(
                f"{UtilityTools.YELLOW}[!] {mod_short} ignores project selectors "
                f"(--project-id/--project-ids/--project-id-file/--current-project/--all-projects). "
                f"Running once.{UtilityTools.RESET}"
            )
            runner = RunnerArgs(project_ids=[], current_project=False, all_projects=False, passthrough=passthrough_args)

        # Auth gate
        if action.requires_auth and getattr(session, "credentials", None) is None:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] "
                f"Credentials are None. Load creds or run an unauth module.{UtilityTools.RESET}"
            )
            return -1

        try:
            module = importlib.import_module(module_import_path)
        except ModuleNotFoundError as exc:
            missing_name = str(getattr(exc, "name", "") or "").strip()
            if not missing_name:
                raise
            missing_target_module = (
                missing_name == module_import_path
                or module_import_path.startswith(f"{missing_name}.")
            )
            if not missing_target_module:
                raise

            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to load module import path "
                f"'{module_import_path}' (missing '{missing_name}').{UtilityTools.RESET}"
            )
            print(
                f"{UtilityTools.YELLOW}[!] Verify module mappings and package contents for this runtime."
                f"{UtilityTools.RESET}"
            )
            return -1
        run_module = getattr(module, "run_module", None)
        if not callable(run_module):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Module has no callable run_module().{UtilityTools.RESET}")
            return -1

        # Help passthrough
        if "-h" in passthrough_args or "--help" in passthrough_args:
            run_module(list(passthrough_args), session)
            return 0

        # enum_all cross-project parallel mode: drive all projects through one
        # orchestrator (RM-once -> services pool -> bindings-once) instead of the
        # per-project sequential loop. Opt-in via --parallel-services N (N>1).
        if mod_short in ("enum_all", "enum_gcp") and _parallel_services_count(passthrough_args) > 1:
            run_parallel = getattr(module, "run_parallel", None)
            if callable(run_parallel):
                if runner.project_ids:
                    explicit_targets = list(runner.project_ids)
                elif runner.current_project:
                    explicit_targets = [t for t in [str(getattr(session, "project_id", "") or "").strip()] if t]
                else:
                    explicit_targets = None  # discover all projects after RM phase
                try:
                    result = run_parallel(session, list(passthrough_args), explicit_targets)
                    return 0 if result in (0, 1, 2) else -1
                except KeyboardInterrupt:
                    print(f"{UtilityTools.YELLOW}[!] Interrupted. Re-run to resume from the task ledger.{UtilityTools.RESET}")
                    return -1

        plan, err = _plan_execution(session, action, runner, module_import_path)
        if not plan:
            print(err or f"{UtilityTools.RED}[X] Failed to plan module execution.{UtilityTools.RESET}")
            return -1

        run_once, context_project_id, target_project_ids = plan

        if run_once:
            with _temporary_attr(session, "project_id", context_project_id) if context_project_id else nullcontext():
                _callback, ok = _execute_module_for_project(
                    session,
                    run_module,
                    mod_short=mod_short,
                    project_id=None,
                    passthrough_args=passthrough_args,
                    run_index=0,
                    run_total=1,
                )
            return 0 if ok else -1

        original_project_id = session.project_id
        failures: list[str] = []
        pending_project_ids = list(target_project_ids)
        index = 0
        try:
            while index < len(pending_project_ids):
                project_id = pending_project_ids[index]
                run_total = len(pending_project_ids)
                print(
                    f"{UtilityTools.BOLD}[*] Target project {index + 1}/{run_total}: "
                    f"{project_id}{UtilityTools.RESET}"
                )
                callback, ok = _execute_module_for_project(
                    session,
                    run_module,
                    mod_short=mod_short,
                    project_id=project_id,
                    passthrough_args=passthrough_args,
                    run_index=index,
                    run_total=run_total,
                )
                if not ok:
                    failures.append(str(project_id))
                    index += 1
                    continue
                if (
                    callback == 2
                    and mod_short in ("enum_all", "enum_gcp")
                    and not runner.project_ids
                    and not runner.current_project
                ):
                    pending_project_ids = _normalize_project_ids(
                        [*pending_project_ids, *(getattr(session, "global_project_list", []) or [])]
                    )
                index += 1

            # enum_all (top orchestrator): after the GCP per-project loop, run the
            # tenant-scoped Google Workspace phase ONCE. enum_gcp does not (GCP only);
            # the --parallel-services path runs Workspace inside run_parallel instead.
            if mod_short == "enum_all":
                try:
                    from gcpwn.modules.everything.enumeration.enum_google_workspace import (
                        run_module as run_workspace_all,
                    )
                    print(f"{UtilityTools.BOLD}[*] enum_all | Google Workspace phase (tenant-scoped, once){UtilityTools.RESET}")
                    ws_args = ["-v"] if ("-v" in passthrough_args or "--debug" in passthrough_args) else []
                    if "--download-google-drive" in passthrough_args:
                        ws_args.append("--download-google-drive")
                    run_workspace_all(ws_args, session)
                except Exception:
                    print(traceback.format_exc())

            if failures:
                print(
                    f"{UtilityTools.YELLOW}[!] {mod_short} completed with failures on "
                    f"{len(failures)}/{len(pending_project_ids)} target projects.{UtilityTools.RESET}"
                )
                return -1
            return 0
        finally:
            session.project_id = original_project_id

    except KeyboardInterrupt:
        return 0
    except Exception:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] A generic error occurred while executing the module. See details below:{UtilityTools.RESET}")
        print(traceback.format_exc())
        return -1
