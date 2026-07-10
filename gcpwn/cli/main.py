"""GCPwn entrypoint: workspace selection REPL launcher plus `--module` unauth passthrough.

`main()` is the `python -m gcpwn` / `gcpwn` console entry. Two startup modes:
  - Interactive: pick/create a workspace, then drop into the CommandProcessor REPL.
  - Passthrough (`--module <name>`): run a single UNAUTHENTICATED module non-interactively
    and exit with a process return code, no creds/REPL involved.

PassthroughSession here is a minimal stand-in for SessionUtility used only by passthrough
runs: it carries workspace/project context and a DataController but no live credentials, and
deliberately makes insert_actions a no-op (unauth modules have no credential to attribute
permissions to).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional, Tuple

from gcpwn.cli.module_actions import get_module_action, interact_with_module
from gcpwn.core.console import UtilityTools
from gcpwn.core.db import DataController
from gcpwn.core.output_paths import build_output_path, make_workspace_slug
from gcpwn.core.utils.module_helpers import iter_module_rows, load_mapping_data


PASSTHROUGH_WORKSPACE_NAME = "PASSTHROUGH"


def create_workspace(dc: DataController, workspace_name: str) -> Optional[int]:
    """Validate and persist a new workspace, returning its id (None if rejected).

    Rejects numeric-only names (they collide with the menu index UX in choose_workspace)
    and duplicate names. Prints a user-facing reason on rejection.
    """
    workspace_name = (workspace_name or "").strip()
    if workspace_name.isdigit():
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Workspace name cannot be numeric-only."
            f" Use a descriptive name (for example: TEST, PROD, LAB).{UtilityTools.RESET}"
        )
        return None

    existing_names = dc.fetch_all_workspace_names() or []
    if workspace_name in existing_names:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] A workspace with that name already exists.{UtilityTools.RESET}")
        return None

    workspace_id = dc.insert_workspace(workspace_name)
    if workspace_id:
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Workspace '{workspace_name}' created.{UtilityTools.RESET}")
    return workspace_id


def create_workspace_flow(
    dc: DataController,
    *,
    startup_silent: bool = False,
) -> None:
    """Prompt for a new workspace name until valid, create it, then enter its REPL.

    Loops on invalid names (length or create_workspace rejection). Imports
    workspace_instructions lazily to avoid a circular import at module load.
    """
    from gcpwn.cli.workspace_instructions import workspace_instructions

    while True:
        workspace_name = input("> New workspace name: ").strip()
        if 1 <= len(workspace_name) <= 80:
            workspace_id = create_workspace(dc, workspace_name)
            if workspace_id:
                workspace_instructions(
                    workspace_id,
                    workspace_name,
                    startup_silent=startup_silent,
                )
                return
        else:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Workspace names must be between 1 and 80 characters."
                f"{UtilityTools.RESET}"
            )


def list_workspaces(workspaces: List[Tuple[int, str]]) -> None:
    print("[*] Found existing sessions:")
    print("  [0] New session")
    for idx, name in workspaces:
        print(f"  [{idx}] {name}")
    print(f"  [{len(workspaces) + 1}] exit")


def choose_workspace(
    workspaces: List[Tuple[int, str]],
    dc: DataController,
    *,
    startup_silent: bool = False,
) -> None:
    """Render the workspace menu, then enter the chosen (or newly created) workspace REPL.

    Menu option 0 creates a new workspace; the last option exits the process. Any other
    number is treated as a workspace id; an unknown id prints an error and exits non-zero.
    """
    from gcpwn.cli.workspace_instructions import workspace_instructions

    list_workspaces(workspaces)
    while True:
        try:
            option = int(input("Choose an option: ").strip())
            break
        except ValueError:
            print("Please enter a valid number.")

    if option == 0:
        create_workspace_flow(dc, startup_silent=startup_silent)
        return
    if option == len(workspaces) + 1:
        raise SystemExit(0)

    workspace_name = dc.get_workspace(option, columns="name")
    if workspace_name:
        workspace_instructions(
            option,
            workspace_name,
            startup_silent=startup_silent,
        )
        return
    print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] No workspace was found with this option. Quitting...{UtilityTools.RESET}")
    raise SystemExit(1)


class PassthroughSession:
    """Credential-free SessionUtility stand-in for non-interactive unauth `--module` runs.

    Implements just enough of the session data API (get_data/insert_data, choice
    prompts, output-path resolution) for unauthenticated modules to run outside the
    REPL. Holds a DataController and workspace/project context but `credentials` is
    always None and `insert_actions` is a no-op (no credential => no permissions to
    attribute). All get_data/insert_data calls inject workspace_id, keeping rows
    workspace-scoped like the real session.
    """

    def __init__(
        self,
        *,
        workspace_id: int,
        workspace_name: str,
        project_id: str = "",
    ) -> None:
        self.data_master = DataController()
        self.data_master.create_service_databases()
        self.workspace_id = int(workspace_id)
        self.workspace_name = str(workspace_name or PASSTHROUGH_WORKSPACE_NAME).strip() or PASSTHROUGH_WORKSPACE_NAME
        self.workspace_directory_name = make_workspace_slug(self.workspace_id, self.workspace_name)
        self.project_id = str(project_id or "").strip()
        self.credentials = None
        self.credname = "unauth_passthrough"
        # Load the workspace's known projects through the canonical loader (same path
        # SessionUtility uses), not a hand-rolled literal_eval of the stored blob.
        self.global_project_list = [
            str(project).strip()
            for project in (self.data_master.sync_workspace_projects(self.workspace_id) or [])
            if str(project).strip()
        ]
        if self.project_id and self.project_id not in self.global_project_list:
            self.global_project_list.append(self.project_id)
            self.data_master.sync_workspace_projects(self.workspace_id, add=self.global_project_list)
        self.workspace_config = SimpleNamespace(preferred_project_ids=[])

    def close(self) -> None:
        try:
            if self.data_master is not None:
                self.data_master.close()
        except Exception:
            pass

    def choice_prompt(self, prompt: str, regex: str | None = None):
        while True:
            answer = str(input(str(prompt or "")) or "").strip()
            if not regex or re.match(regex, answer):
                return answer
            print("Please provide a valid input.")

    def choice_selector(self, rows_returned=None, custom_message: str = "", fields=None, **_kwargs):
        """Print a numbered menu of dict rows and return the selected row (None on cancel/empty).

        Single-row lists default to [1] on empty input. `fields` selects which row keys to
        join into each label; otherwise falls back to printout/name/id/str(row).
        """
        rows = [row for row in (rows_returned or []) if isinstance(row, dict)]
        if not rows:
            return None

        message = str(custom_message or "Choose an option:").strip()
        if message:
            print(f"[*] {message}")

        normalized_fields = [str(field).strip() for field in (fields or []) if str(field).strip()]
        for index, row in enumerate(rows, start=1):
            if normalized_fields:
                label_parts = [str(row.get(field) or "").strip() for field in normalized_fields if str(row.get(field) or "").strip()]
                label = " | ".join(label_parts)
            else:
                label = (
                    str(row.get("printout") or "").strip()
                    or str(row.get("name") or "").strip()
                    or str(row.get("id") or "").strip()
                    or str(row)
                )
            print(f"  [{index}] {label}")

        while True:
            if len(rows) == 1:
                answer = self.choice_prompt("Choose [1] (or q to cancel): ", regex=r"^(1|q|Q)?$")
                if not answer:
                    answer = "1"
            else:
                answer = self.choice_prompt(
                    f"Choose an option [1-{len(rows)}] (or q to cancel): ",
                    regex=r"^\d+$|^[qQ]$",
                )

            if str(answer).lower() == "q":
                return None
            try:
                choice = int(answer)
            except (TypeError, ValueError):
                print("Please provide a valid input.")
                continue
            if 1 <= choice <= len(rows):
                return rows[choice - 1]
            print("Please provide a valid input.")

    def resolve_output_path(
        self,
        *,
        requested_path: str | Path | None = None,
        service_name: str,
        filename: str = "",
        project_id: str | None = None,
        subdirs: list[str] | None = None,
        target: str = "export",
        mkdir: bool = True,
    ) -> Path:
        """Resolve where a module should write output, honoring an explicit path or deriving one.

        An explicit `requested_path` wins (its parent is created when mkdir). Otherwise builds
        a workspace-scoped path under exports/ or downloads/ (chosen by target) keyed by
        service/project. Mirrors SessionUtility.resolve_output_path so modules behave the same
        in passthrough mode.
        """
        if requested_path:
            output_path = Path(requested_path).expanduser()
            if mkdir:
                output_path.parent.mkdir(parents=True, exist_ok=True)
            return output_path

        bucket = "downloads" if str(target or "export").strip().lower() == "download" else "exports"
        scope = project_id or self.project_id or "global"
        return build_output_path(
            self.workspace_directory_name,
            bucket=bucket,
            service_name=service_name,
            filename=filename,
            scope=scope if service_name else None,
            subdirs=subdirs,
            mkdir=mkdir,
        )

    def get_data(self, *args, **kwargs):
        """Read service-DB rows, force-scoped to this workspace via an injected workspace_id."""
        table_name = args[0] if args else kwargs.get("table_name")
        columns = kwargs.get("columns", "*")
        conditions = kwargs.get("conditions")
        params = kwargs.get("params")
        where = dict(kwargs.get("where") or {})
        where["workspace_id"] = self.workspace_id
        if not table_name:
            return []
        return self.data_master.select_rows(
            str(table_name),
            db="service",
            columns=columns,
            conditions=conditions,
            params=params,
            where=where,
        )

    def insert_data(self, table_name, save_data, only_if_new_columns=None, update_only=False, dont_change=None, if_column_matches=None):
        """Upsert a service-DB row, stamping workspace_id and stringifying values.

        The mutually-exclusive flags map to DataController.save_service_row merge modes:
        only_if_new_columns -> only_if_missing, dont_change -> dont_change,
        if_column_matches -> replace_on. update_only routes to an update keyed on the
        caller's primary_keys_to_match (plus workspace_id).
        """
        if only_if_new_columns:
            save_kwargs = {"only_if_missing": only_if_new_columns}
        elif dont_change:
            save_kwargs = {"dont_change": dont_change}
        elif if_column_matches:
            save_kwargs = {"replace_on": if_column_matches}
        else:
            save_kwargs = {}

        if update_only:
            save_data["primary_keys_to_match"]["workspace_id"] = self.workspace_id
            self.data_master.save_service_row(table_name, update_data=save_data)
            return

        save_payload = {key: str(value) for key, value in (save_data or {}).items()}
        save_payload["workspace_id"] = self.workspace_id
        self.data_master.save_service_row(table_name, save_payload, **save_kwargs)

    def insert_actions(self, *args, **kwargs):
        """No-op: passthrough runs have no credential, so there are no permissions to record."""
        return None


def _module_lookup(*, unauth_only: bool = False) -> dict[str, str]:
    """Build {short_name|import_path -> import_path} for registered modules.

    Both the short module name and the full import path key the same location, so either
    token resolves. With ``unauth_only=True`` the map is restricted to UNAUTHENTICATED
    modules (category 'unauthenticated', an '.unauthenticated.' path segment, or an
    'unauth_' name prefix) -- the set runnable in credential-free passthrough mode.
    """
    payload = load_mapping_data("module_mappings.json", kind="json") or {}
    lookup: dict[str, str] = {}
    for row in iter_module_rows(payload):
        module_name = str(row.get("module_name") or "").strip()
        location = str(row.get("location") or "").strip()
        if not module_name or not location:
            continue
        if unauth_only:
            category = str(row.get("module_category") or "").strip().lower()
            if category != "unauthenticated" and ".unauthenticated." not in location.lower() and not module_name.lower().startswith("unauth_"):
                continue
        lookup[module_name] = location
        lookup[location] = location
    return lookup


def _resolve_registered_token(token: str, lookup: dict[str, str]) -> Optional[str]:
    """Resolve a normalized token against a lookup by exact match then trailing short name.

    Returns the import path on a hit, or None so callers can apply their own fallback.
    """
    if token in lookup:
        return lookup[token]
    short_name = token.split(".")[-1]
    if short_name in lookup:
        return lookup[short_name]
    return None


def _resolve_unauth_module_path(module_token: str) -> str:
    """Resolve a user-supplied module token to a full import path, or "" if not unauth-runnable.

    Accepts a full path, a registered short name, or the trailing short name of a dotted
    path. As a last resort accepts any path whose module action does not require auth.
    Returns "" when the token is unknown or maps to an auth-required module.
    """
    token = str(module_token or "").strip().replace("/", ".")
    if not token:
        return ""

    hit = _resolve_registered_token(token, _module_lookup(unauth_only=True))
    if hit is not None:
        return hit

    if not get_module_action(token).requires_auth:
        return token

    return ""


def _resolve_passthrough_workspace() -> tuple[int, str]:
    """Find or create the shared 'PASSTHROUGH' workspace used for non-interactive runs.

    Passthrough runs all share one reusable workspace so their data persists across
    invocations without polluting named workspaces. Raises RuntimeError only if it can
    neither create nor locate any workspace.
    """
    DataController.create_initial_workspace_session_database()
    with DataController() as dc:
        workspaces = dc.get_workspaces() or []
        for workspace_row in workspaces:
            workspace_id = int(workspace_row[0])
            workspace_name = str(workspace_row[1] or "").strip()
            if workspace_name == PASSTHROUGH_WORKSPACE_NAME:
                return workspace_id, workspace_name

        created_workspace_id = dc.insert_workspace(PASSTHROUGH_WORKSPACE_NAME)
        if not created_workspace_id:
            fallback = dc.get_workspaces() or []
            if fallback:
                workspace_id = int(fallback[0][0])
                workspace_name = str(fallback[0][1] or "").strip() or PASSTHROUGH_WORKSPACE_NAME
                return workspace_id, workspace_name
            raise RuntimeError("Unable to create or locate passthrough workspace.")
        return int(created_workspace_id), PASSTHROUGH_WORKSPACE_NAME


def run_unauth_module_passthrough(module_name: str, module_args: list[str], *, project_id: str = "") -> int:
    """Run one unauthenticated module non-interactively and return a process exit code.

    Resolves the module (printing the available unauth list on an unknown name), refuses
    auth-required modules, strips a leading '--' separator from module_args, then executes
    via interact_with_module against a fresh PassthroughSession. Returns 0 only when the
    module returns 0 (success), else 1. Always closes the session's DataController.
    """
    module_import_path = _resolve_unauth_module_path(module_name)
    if not module_import_path:
        if _resolve_module_path(module_name):
            print(
                f"{UtilityTools.YELLOW}[!] '{module_name}' is an authenticated module. Run it "
                f"non-interactively with:  --module {module_name} --workspace <name> --cred <credname>"
                f"{UtilityTools.RESET}"
            )
            return 1
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown unauth module: {module_name}{UtilityTools.RESET}")
        known = sorted(
            {
                key
                for key in _module_lookup(unauth_only=True).keys()
                if not key.startswith("gcpwn.modules.")
            }
        )
        if known:
            print("[*] Available unauth passthrough modules:")
            for name in known:
                print(f"    - {name}")
        return 1

    action = get_module_action(module_import_path)
    if action.requires_auth:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Passthrough mode only supports unauthenticated modules.{UtilityTools.RESET}")
        return 1

    cleaned_args = list(module_args or [])
    if cleaned_args and cleaned_args[0] == "--":
        cleaned_args = cleaned_args[1:]

    workspace_id, workspace_name = _resolve_passthrough_workspace()
    session = PassthroughSession(
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        project_id=project_id,
    )
    if session.project_id:
        print(f"[*] Passthrough project context: {session.project_id}")
    print(f"[*] Passthrough workspace: {workspace_name} (id={workspace_id})")
    print(f"[*] Running unauth module: {module_import_path}")
    try:
        result = interact_with_module(session, module_import_path, cleaned_args)
        return 0 if result == 0 else 1
    finally:
        session.close()


def _resolve_module_path(module_token: str) -> str:
    """Resolve a module token to a full import path across ALL modules (auth + unauth).

    Accepts a registered short name, a full import path, or the trailing short name of a
    dotted path; falls back to any dotted path (import errors surface later). Returns "" for
    an unknown bare name.
    """
    token = str(module_token or "").strip().replace("/", ".")
    if not token:
        return ""
    hit = _resolve_registered_token(token, _module_lookup())
    if hit is not None:
        return hit
    return token if "." in token else ""


def _resolve_workspace_by_name(dc: DataController, workspace_name: str) -> Optional[Tuple[int, str]]:
    """Return (workspace_id, name) for an existing workspace matched by exact name, else None."""
    target = str(workspace_name or "").strip()
    if not target:
        return None
    for workspace_row in dc.get_workspaces() or []:
        name = str(workspace_row[1] or "").strip()
        if name == target:
            return int(workspace_row[0]), name
    return None


def _close_session(session) -> None:
    """Best-effort close of a session's DataController (process is exiting anyway)."""
    try:
        data_master = getattr(session, "data_master", None)
        if data_master is not None:
            data_master.close()
    except Exception:
        pass


def run_authenticated_module_passthrough(
    module_name: str,
    module_args: list[str],
    *,
    workspace_name: str,
    credname: str,
    project_id: str = "",
) -> int:
    """Run one module non-interactively against a stored credential; return a process exit code.

    The authenticated counterpart of run_unauth_module_passthrough (the "drive-through"): it
    resolves the module and the named workspace, loads the named credential into a real
    SessionUtility (resume mode -> load_stored_creds sets .credentials and .project_id), marks
    the session non-interactive so per-project modules never block on the all-vs-current prompt,
    then dispatches via interact_with_module. Project scope flows through the module args
    (--project-id / --current-project / --all-projects); a single --project-id given as a
    top-level flag is injected here for convenience. Returns 0 only when the module succeeds.
    Prints actionable errors (with the available workspaces / credentials) on a bad name.
    """
    from gcpwn.core.session import SessionUtility

    if not str(workspace_name or "").strip():
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] --workspace <name> is required (the workspace that holds the credential).{UtilityTools.RESET}")
        return 1
    if not str(credname or "").strip():
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] --cred <credname> is required (the stored credential to load).{UtilityTools.RESET}")
        return 1

    module_import_path = _resolve_module_path(module_name)
    if not module_import_path:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown module: {module_name}{UtilityTools.RESET}")
        return 1

    DataController.create_initial_workspace_session_database()
    with DataController() as dc:
        resolved = _resolve_workspace_by_name(dc, workspace_name)
        if not resolved:
            available = sorted(str(row[1] or "").strip() for row in (dc.get_workspaces() or []))
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] No workspace named '{workspace_name}'.{UtilityTools.RESET}")
            if available:
                print(f"[*] Available workspaces: {', '.join(name for name in available if name)}")
            return 1
        workspace_id, resolved_name = resolved
        available_creds = sorted(
            {str(row["credname"]).strip() for row in (dc.list_creds(workspace_id) or []) if row["credname"]}
        )

    session = None
    try:
        session = SessionUtility(workspace_id, resolved_name, credname, None, resume=True, quiet=True)
    except Exception as exc:
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to load credential '{credname}' "
            f"in workspace '{resolved_name}': {exc}{UtilityTools.RESET}"
        )
        _close_session(session)
        return 1

    if getattr(session, "credentials", None) is None:
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Could not load credential '{credname}' "
            f"in workspace '{resolved_name}'.{UtilityTools.RESET}"
        )
        if available_creds:
            print(f"[*] Available credentials in '{resolved_name}': {', '.join(available_creds)}")
        else:
            print(f"[*] Workspace '{resolved_name}' has no stored credentials; add one via the interactive REPL first.")
        _close_session(session)
        return 1

    session._non_interactive = True

    cleaned_args = list(module_args or [])
    if cleaned_args and cleaned_args[0] == "--":
        cleaned_args = cleaned_args[1:]
    # Inject the top-level --project-id ONLY when the module args don't already carry a
    # project selector (avoids a confusing "use only one selector" conflict).
    _selectors = {"--project-id", "--project-ids", "--project-id-file", "--project-ids-file", "--current-project", "--all-projects"}
    if project_id and not any(arg in _selectors for arg in cleaned_args):
        cleaned_args = ["--project-id", str(project_id), *cleaned_args]

    print(
        f"[*] Drive-through: workspace='{resolved_name}' (id={workspace_id}) "
        f"cred='{session.credname}' project='{session.project_id}'"
    )
    print(f"[*] Running module: {module_import_path}")
    try:
        result = interact_with_module(session, module_import_path, cleaned_args)
        return 0 if result == 0 else 1
    finally:
        _close_session(session)


def _add_passthrough_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the shared --silent/--module/--project-id/--workspace/--cred flags to a parser."""
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Start GCPwn without printing the initial help banner.",
    )
    parser.add_argument(
        "--module",
        dest="module_name",
        help=(
            "Run a single module non-interactively (no REPL). Unauthenticated by default; "
            "add --workspace <name> --cred <credname> to run an authenticated module against a "
            "stored credential. Accepts a short module name or full import path."
        ),
    )
    parser.add_argument(
        "--project-id",
        dest="project_id",
        default="",
        help=(
            "Project context for passthrough runs. Unauth: the target project id. Authenticated "
            "drive-through: shorthand for a single --project-id selector."
        ),
    )
    parser.add_argument(
        "--workspace",
        dest="workspace_name",
        default="",
        help="Authenticated drive-through: name of the workspace that holds the credential.",
    )
    parser.add_argument(
        "--cred",
        "--credname",
        dest="credname",
        default="",
        help="Authenticated drive-through: name of the stored credential to load (requires --workspace).",
    )


def main() -> None:
    """Console entrypoint: dispatch to `--module` passthrough or the interactive workspace REPL.

    Parses args twice on purpose: a first add_help=False pass detects `--module` and, if
    present, runs run_unauth_module_passthrough and SystemExits with its code (so unknown
    module flags pass through to the module, not argparse). Otherwise a normal parser
    (with --help) runs, the workspace/session DB is initialized, and control enters
    create_workspace_flow (no workspaces) or choose_workspace.
    """
    raw_argv = list(sys.argv[1:])

    passthrough_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    _add_passthrough_arguments(passthrough_parser)
    passthrough_args, unknown_args = passthrough_parser.parse_known_args(raw_argv)

    if passthrough_args.module_name:
        # --workspace/--cred select the authenticated drive-through; otherwise unauth passthrough.
        if passthrough_args.credname or passthrough_args.workspace_name:
            raise SystemExit(
                run_authenticated_module_passthrough(
                    passthrough_args.module_name,
                    list(unknown_args),
                    workspace_name=passthrough_args.workspace_name,
                    credname=passthrough_args.credname,
                    project_id=passthrough_args.project_id,
                )
            )
        raise SystemExit(
            run_unauth_module_passthrough(
                passthrough_args.module_name,
                list(unknown_args),
                project_id=passthrough_args.project_id,
            )
        )

    parser = argparse.ArgumentParser(add_help=True)
    _add_passthrough_arguments(parser)
    args = parser.parse_args(raw_argv)

    DataController.create_initial_workspace_session_database()
    with DataController() as dc:
        workspaces = dc.get_workspaces()
        if len(workspaces) == 0:
            print("[*] No workspaces were detected. Please provide the name for your first workspace below.")
            create_workspace_flow(dc, startup_silent=args.silent)
            return
        choose_workspace(workspaces, dc, startup_silent=args.silent)


if __name__ == "__main__":
    main()
