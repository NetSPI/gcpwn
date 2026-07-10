# Standard libraries
from __future__ import annotations

import argparse
import ast
import csv
import importlib.util
import os
import re
import shlex
import subprocess
import textwrap
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List

from gcpwn.cli.module_actions import interact_with_module
from gcpwn.core.action_schema import (
    ACTION_COLUMN_TO_RESOURCE_TYPE,
    ACTION_EVIDENCE_LABELS,
    ACTION_PROVENANCE_COLUMN,
    ACTION_SCOPE_COLUMNS,
)
from gcpwn.core.console import UtilityTools
from gcpwn.core.db import DataController
from gcpwn.core.output_paths import build_output_path, make_workspace_slug
from gcpwn.core.utils.hierarchy import render_tree_lines
from gcpwn.core.utils.module_helpers import (
    dedupe_strs,
    extract_location_from_resource_name,
    extract_path_segment,
    extract_path_tail,
    export_hierarchy_tree_image,
    export_sqlite_dbs_to_csv_blob,
    export_sqlite_dbs_to_excel_blob,
    export_sqlite_dbs_to_json_blob,
    iter_module_rows,
    load_mapping_data,
    load_service_locations,
)
from gcpwn.core.session import SessionUtility


# -----------------------------
# Shared CLI spec helpers
# -----------------------------

ArgumentSpec = tuple[tuple[str, ...], Dict[str, Any]]

CREDENTIAL_TYPES = ["adc", "oauth2", "service"]
DATA_EXPORT_FLAGS = ["--out-dir", "--out-file"]
DATA_WIPE_FLAGS = ["--all-workspaces", "--yes"]
CONFIG_COMPLETION_KEYS = [
    "std_output_format",
    "projects",
    "zones",
    "regions",
    "workspace_customer_id",
    "workspace_admin_subject",
]
CONFIG_SET_VALUE_CHOICES = {
    "std_output_format": ["table", "text"],
}

_READLINE_MODULE: Any | None = None
_READLINE_IMPORT_ATTEMPTED = False


def _optional_readline() -> Any | None:
    """Return readline when available; None on platforms without it (e.g. Windows)."""
    global _READLINE_MODULE, _READLINE_IMPORT_ATTEMPTED
    if _READLINE_IMPORT_ATTEMPTED:
        return _READLINE_MODULE
    _READLINE_IMPORT_ATTEMPTED = True
    try:
        import readline as _readline  # type: ignore
    except Exception:
        _READLINE_MODULE = None
    else:
        _READLINE_MODULE = _readline
    return _READLINE_MODULE


def apply_argument_specs(parser: argparse.ArgumentParser, argument_specs: List[ArgumentSpec]) -> None:
    for names, kwargs in argument_specs:
        parser.add_argument(*names, **kwargs)


def credential_mutation_argument_specs(*, credname_optional: bool) -> List[ArgumentSpec]:
    credname_spec = (
        {"nargs": "?", "help": "Specify credential name"}
        if credname_optional
        else {"help": "Specify credential name"}
    )
    return [
        (("credname",), credname_spec),
        (("--type",), {"choices": CREDENTIAL_TYPES, "required": True, "help": "Specify credential type (adc|oauth2|service)"}),
        (("--service-file",), {"help": "Service credential file", "required": False}),
        (("--token",), {"help": "OAuth2 access token (bare token; expires ~1h, no refresh)", "required": False}),
        (("--token-file",), {"dest": "token_file", "help": "OAuth2 authorized-user token.json (carries a refresh token; auto-renews)", "required": False}),
        (("--filepath-to-adc",), {"dest": "filepath_to_adc", "help": "ADC credential file path", "required": False}),
        (("--assume",), {"action": "store_true", "help": "Assume credentials after adding", "required": False}),
        (("--tokeninfo",), {"action": "store_true", "help": "Display token information", "required": False}),
    ]


def resolve_stored_credname(answer: str, available_creds: List[tuple[Any, ...]]) -> str | None:
    normalized = str(answer or "").strip()
    if not normalized:
        return None
    if any(normalized == str(row[0]) for row in available_creds):
        return normalized
    if is_integer_within_bounds(normalized, len(available_creds)):
        return str(available_creds[int(normalized) - 1][0]).strip()
    return None


# -----------------------------
# Workspace display helpers
# -----------------------------

def format_resource_label(row: Dict[str, Any], *, highlight_project: str | None = None) -> str:
    resource_name = str(row.get("name") or "").strip()
    display_name = str(row.get("display_name") or "").strip()
    project_id = str(row.get("project_id") or "").strip()
    resource_type = str(row.get("type") or "").strip().lower()

    def _resource_leaf(value: str) -> str:
        return extract_path_tail(value)

    if resource_type == "project":
        identifier = project_id or resource_name
        simple_name = display_name or identifier or "<unknown>"
    else:
        identifier = resource_name
        if display_name and "/" not in display_name:
            simple_name = display_name
        else:
            simple_name = _resource_leaf(identifier) or identifier or "<unknown>"

    if simple_name and identifier and simple_name != identifier:
        base = f"{simple_name} ({identifier})"
    else:
        base = simple_name

    if resource_type == "org":
        return f"{UtilityTools.BOLD}{UtilityTools.CYAN}{base} [ORG]{UtilityTools.RESET}"
    if project_id and highlight_project and project_id == highlight_project:
        return f"{UtilityTools.BOLD}{UtilityTools.RED}{base}{UtilityTools.RESET}"
    return base


def print_gcp_hierarchy(
    rows: List[Dict[str, Any]],
    *,
    current_project_id: str | None = None,
    focus_types: set[str] | None = None,
) -> bool:
    if not rows:
        print("[X] No cached hierarchy rows found. Run `modules run enum_resources` first.")
        return False

    nodes: Dict[str, Dict[str, Any]] = {}
    parent_of: Dict[str, str | None] = {}

    for row in rows:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        parent = str(row.get("parent") or "").strip() or None
        if parent == "N/A":
            parent = None
        row_type = str(row.get("type") or "").strip().lower()
        nodes[name] = {**row, "name": name, "parent": parent, "type": row_type}
        parent_of[name] = parent

    def _infer_resource_type(resource_name: str) -> str:
        token = str(resource_name or "").strip()
        if token.startswith("organizations/"):
            return "org"
        if token.startswith("folders/"):
            return "folder"
        if token.startswith("projects/"):
            return "project"
        return "resource"

    # Handle partial hierarchy caches by creating placeholder parent nodes.
    # This preserves project/folder/org tree rendering even if only project rows exist.
    for node_name in list(parent_of.keys()):
        parent = parent_of.get(node_name)
        if parent and parent not in nodes:
            nodes[parent] = {
                "name": parent,
                "display_name": parent,
                "project_id": "",
                "type": _infer_resource_type(parent),
                "parent": None,
                "synthetic": True,
            }
            parent_of[parent] = None

    # If we only know one org, prefer rendering orphan folders under that org
    # so org view is consistently hierarchical (org -> folder -> project).
    org_nodes = [name for name, row in nodes.items() if str(row.get("type") or "").lower() == "org"]
    if len(org_nodes) == 1:
        sole_org = org_nodes[0]
        for name, row in nodes.items():
            row_type = str(row.get("type") or "").lower()
            if row_type != "folder":
                continue
            if parent_of.get(name) is None and name != sole_org:
                parent_of[name] = sole_org
                row["parent"] = sole_org

    children: Dict[str | None, List[str]] = {}
    for name, parent in parent_of.items():
        children.setdefault(parent, []).append(name)
    for kid_list in children.values():
        kid_list.sort(key=lambda item: str(nodes.get(item, {}).get("display_name") or item).lower())

    roots = [name for name, row in nodes.items() if row.get("parent") is None or row.get("type") == "org"]
    roots.sort(key=lambda item: str(nodes.get(item, {}).get("display_name") or item).lower())

    normalized_focus_types = {str(t or "").strip().lower() for t in (focus_types or set()) if str(t or "").strip()}
    candidate_names = {
        name
        for name, row in nodes.items()
        if not normalized_focus_types or str(row.get("type") or "").lower() in normalized_focus_types
    }

    if not candidate_names:
        print("[*] No cached hierarchy rows match the selected view.")
        return False

    def nearest_candidate_parent(node_name: str) -> str | None:
        cursor = parent_of.get(node_name)
        visited: set[str] = set()
        while cursor and cursor not in visited:
            visited.add(cursor)
            if cursor in candidate_names:
                return cursor
            cursor = parent_of.get(cursor)
        return None

    filtered_children: Dict[str | None, List[str]] = {}
    for node_name in candidate_names:
        candidate_parent = nearest_candidate_parent(node_name)
        filtered_children.setdefault(candidate_parent, []).append(node_name)

    for kid_list in filtered_children.values():
        kid_list.sort(key=lambda item: str(nodes.get(item, {}).get("display_name") or item).lower())

    filtered_roots = sorted(
        filtered_children.get(None, []),
        key=lambda item: str(nodes.get(item, {}).get("display_name") or item).lower(),
    )

    if current_project_id:
        current_rows = [row for row in rows if str(row.get("project_id") or "") == str(current_project_id)]
        project_row = next((row for row in current_rows if str(row.get("type") or "").lower() == "project"), None)
        if project_row:
            current_path = []
            cursor = str(project_row.get("name") or "")
            visited: set[str] = set()
            while cursor and cursor not in visited:
                visited.add(cursor)
                row = nodes.get(cursor)
                if not row:
                    current_path.append(str(cursor))
                    break
                current_path.append(format_resource_label(row, highlight_project=current_project_id))
                cursor = str(parent_of.get(cursor) or "")
            current_path.reverse()
            print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] Current path:{UtilityTools.RESET} {' / '.join(current_path)}")

    if not filtered_roots:
        fallback_roots = [root for root in roots if root in candidate_names]
        remaining = sorted(
            [root for root in candidate_names if root not in fallback_roots],
            key=lambda item: str(nodes.get(item, {}).get("display_name") or item).lower(),
        )
        fallback_roots.extend(remaining)
        filtered_roots = fallback_roots

    def _label(name: str) -> str:
        return format_resource_label(nodes[name], highlight_project=current_project_id)

    for line in render_tree_lines(filtered_roots, filtered_children, _label):
        print(line)
    return True


def project_choice_rows(rows: List[Dict[str, Any]], global_project_list: List[str] | None = None) -> List[Dict[str, Any]]:
    project_rows = [row for row in rows if str(row.get("type") or "").lower() == "project"]
    deduped: Dict[str, Dict[str, Any]] = {}
    for row in project_rows:
        project_id = str(row.get("project_id") or "").strip()
        if not project_id:
            continue
        deduped.setdefault(project_id, row)

    for project_id in (global_project_list or []):
        normalized = str(project_id).strip()
        if not normalized:
            continue
        deduped.setdefault(
            normalized,
            {
                "project_id": normalized,
                "display_name": normalized,
                "name": f"projects/{normalized}",
                "type": "project",
            },
        )

    return sorted(deduped.values(), key=lambda row: str(row.get("display_name") or row.get("project_id") or "").lower())


def project_label(row: Dict[str, Any]) -> str:
    project_id = str(row.get("project_id") or row.get("name") or "").strip()
    display_name = str(row.get("display_name") or "").strip()
    label = display_name or project_id or "<unknown-project>"
    return f"{UtilityTools.CYAN}{label}{UtilityTools.RESET}  {UtilityTools.BRIGHT_BLACK}({project_id}){UtilityTools.RESET}"

# Banner when you drop into workspace, Shoutout to Pacu where i grabbed this from and customized to match use case
def help_banner():
    banner = r"""
      ██████╗  ██████╗██████╗ ██╗    ██╗███╗   ██╗
     ██╔════╝ ██╔════╝██╔══██╗██║    ██║████╗  ██║
     ██║  ███╗██║     ██████╔╝██║ █╗ ██║██╔██╗ ██║
     ██║   ██║██║     ██╔═══╝ ██║███╗██║██║╚██╗██║
     ╚██████╔╝╚██████╗██║     ╚███╔███╔╝██║ ╚████║
      ╚═════╝  ╚═════╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝

                      Welcome to GCPwn.
                 Enumerate. Escalate. Persist.

    GCPwn - https://github.com/NetSPI/gcpwn
    Maintained by NetSPI. Heavy inspiration/code snippets from Rhino Security Labs - https://rhinosecuritylabs.com/

    Like Pacu for AWS, the goal of this tool is to be a more pentesty tool for red team individuals or those who are less concerned with configuration statistics.
    A wiki was created that explains all the modules/options listed below found here: https://github.com/NetSPI/gcpwn/wiki.

    GCPwn command info:
        

        creds
            list/info/tokeninfo/set                    Show stored creds / print cred details / query tokeninfo / set email+project
            add/update                                Add or refresh credentials (adc, oauth2, service)
            swap [<credname>]                         Swap credentials (interactive if omitted)

        creds info [<credname>] [--csv]
        creds tokeninfo [<credname>]
        creds set [<credname>] [--email <email>] [--project-id <project_id>]
        creds add <credname> --type adc [--filepath-to-adc <adc_json_path>] [--tokeninfo] [--assume]
        creds add <credname> --type oauth2 --token <access_token> [--tokeninfo] [--assume]
        creds add <credname> --type oauth2 --token-file <token_json_path> [--tokeninfo] [--assume]
        creds add <credname> --type service --service-file <service_account_json_path> [--assume]
        creds update [<credname>] --type <adc|oauth2|service> [credential flags...] [--assume]

        
        modules [list]                                              List all Modules
        modules search <keyword>                                    Search for Module Name
        modules info   <module_name>                                Get Info about specific module
        modules run <module name> [--project-ids project-id1,project-id2]    Specify project ID(s) if desired

        
        projects
            list                                        Print project-focused GCP hierarchy
            add <project_id>                            Add project to known list
            set [<project_id>]                          Set current project (pick if omitted)
            rm  <project_id>                            Remove project from known list

        folders / orgs
            list                                        Print folder/org-focused GCP hierarchy

        configs
            list | set | unset | regions list          Workspace configs / known regions

            Keys:
              std_output_format                        (table|text; default text)
              projects                                 (comma list; project-id-1,project-id-2,...)
              zones                                    (comma list; zone1,zone2,zone3,...)
              regions                                  (comma list; region1,region2,region3,...)
              workspace_customer_id                    (Google Workspace directoryCustomerId, e.g. C0xxxxxxx)
              workspace_admin_subject                  (admin@domain to impersonate for SA domain-wide delegation)

        data
            export <csv|json|excel|treeimage> [--out-dir ...] [--out-file ...]
                                                        Unified data export command
                                                        csv: service DB rows in one flat CSV (includes resource=table name)
                                                        json: service DB tables as JSON blob (rows include resource)
                                                        excel: one workbook for service DB (single-sheet condensed format)
                                                        treeimage: org/folder/project hierarchy graph (SVG with built-in pan/zoom)
            sql --db <service|metadata> <SQL>
                                                        Run SQL directly against SQLite tables
                                                        example: data sql --db service "SELECT * FROM compute_instances LIMIT 25"
            wipe-service [--all-workspaces] [--yes]
                                                        Delete rows from service DB tables
                                                        default scope: ALL service tables for current workspace_id
                                                        (tables without workspace_id are skipped)
                                                        add --all-workspaces to wipe all workspace rows
                 
        help                                Display this page of information       
        exit/quit                           Exit GCPwn

    Other command info:
        Google Workspace enumeration        Tenant-scoped (Google Workspace / Cloud Identity) -- separate from GCP project enum.
                                                modules run enum_google_workspace     (groups, users, admin roles, OUs, domains, devices, OAuth grants)
                                                Needs Workspace admin creds OR a service account with domain-wide delegation:
                                                configs set workspace_admin_subject admin@domain   (or per-run --impersonate admin@domain)

        gcloud/bq/gsutil <command>            Run GCP CLI tool. It is recommended if you want to add a set of creds while in GCPwn
                                                to run the following command to set them at the command line
                                                
                                                gcloud auth login
                                                gcloud auth application-default login

Welcome to your workspace! Type 'help' or '?' to see available commands."""
    print(banner)

class CommandProcessor:
    EXIT_SIGNAL = "__GCPWN_EXIT__"
    DATA_EXPORT_FORMATS = ["csv", "json", "excel", "treeimage"]
    DATA_SQL_HINTS = ["--db", "service", "metadata"]
    PASSTHROUGH_COMMANDS = ("gcloud", "bq", "gsutil")
    WORKSPACE_COMMANDS = (
        "creds",
        "projects",
        "folders",
        "orgs",
        "modules",
        "data",
        "configs",
        "global_configs",
    )
    CONFIG_COMMAND_NAMES = ("configs", "global_configs")
    CREDS_SUBCOMMANDS = ["list", "info", "tokeninfo", "set", "add", "update", "swap"]
    PROJECTS_SUBCOMMANDS = ["list", "set", "add", "rm"]
    TREE_SUBCOMMANDS = ["list"]
    MODULES_SUBCOMMANDS = ["list", "search", "info", "run"]
    DATA_SUBCOMMANDS = ["export", "sql", "wipe-service"]
    CONFIGS_SUBCOMMANDS = ["list", "set", "unset", "regions"]
    TREE_FOCUS_TYPES = {
        "projects": {"project"},
        "folders": {"folder", "project"},
        "orgs": {"org", "folder", "project"},
    }

    def __init__(self, workspace_id, session):
        self.workspace_id = workspace_id
        self.session = session
        self._module_rows = self._load_module_rows()
        self._module_name_to_path = {
            str(row["module_name"]): str(row["location"])
            for row in self._module_rows
        }
        self._module_names = sorted(self._module_name_to_path.keys())
        self._module_cli_flag_cache: Dict[str, List[str]] = {}
        self.parser = argparse.ArgumentParser(prog="GCPwn", description="GCPwn CLI")
        self.subparsers = self.parser.add_subparsers(dest="subcommand")
        self.command_handlers = {
            "creds": self.process_creds_command,
            "modules": self.process_modules_command,
            "configs": self.process_configs_command,
            "data": self.process_data_command,
            "projects": self.process_projects_command,
            "folders": lambda *_args: self.print_gcp_hierarchy(focus_types=self.TREE_FOCUS_TYPES["folders"]),
            "orgs": lambda *_args: self.print_gcp_hierarchy(focus_types=self.TREE_FOCUS_TYPES["orgs"]),
            "global_configs": self.process_configs_command,
            "gcloud": self.run_passthrough_command,
            "bq": self.run_passthrough_command,
            "gsutil": self.run_passthrough_command,
            "help": lambda *_args: help_banner(),
            "?": lambda *_args: help_banner(),
            "exit": lambda *_args: self.EXIT_SIGNAL,
            "quit": lambda *_args: self.EXIT_SIGNAL,
        }

        self.setup_parsers()
        self.setup_folder_structure()

    # -----------------------------
    # Readline completion
    # -----------------------------
    @property
    def _top_level_commands(self) -> List[str]:
        return [
            *list(self.WORKSPACE_COMMANDS),
            *list(self.PASSTHROUGH_COMMANDS),
            "help",
            "?",
            "exit",
            "quit",
        ]

    @staticmethod
    def _match_prefix(candidates: List[str], prefix: str) -> List[str]:
        p = (prefix or "").strip()
        out = [c for c in candidates if c.startswith(p)]
        return sorted(out)

    def _complete_simple_subcommands(self, args: List[str], trailing_space: bool, subcommands: List[str]) -> List[str]:
        if not args and trailing_space:
            return subcommands
        if len(args) == 1 and not trailing_space:
            return self._match_prefix(subcommands, args[0])
        return []

    def _complete_command_args(self, command_name: str, args: List[str], trailing_space: bool) -> List[str]:
        base_subcommands = {
            "creds": self.CREDS_SUBCOMMANDS,
            "projects": self.PROJECTS_SUBCOMMANDS,
            "folders": self.TREE_SUBCOMMANDS,
            "orgs": self.TREE_SUBCOMMANDS,
            "modules": self.MODULES_SUBCOMMANDS,
            "data": self.DATA_SUBCOMMANDS,
            "configs": self.CONFIGS_SUBCOMMANDS,
            "global_configs": self.CONFIGS_SUBCOMMANDS,
        }
        basic = self._complete_simple_subcommands(args, trailing_space, base_subcommands[command_name])
        if basic:
            return basic
        if not args:
            return []

        subcmd = args[0]

        if command_name == "modules":
            if len(args) == 1 and trailing_space and subcmd == "run":
                return self._module_names
            if len(args) == 2 and not trailing_space and subcmd == "run":
                return self._match_prefix(self._module_names, args[1])
            return []

        if command_name == "projects":
            if subcmd not in {"add", "set", "rm"}:
                return []
            if len(args) == 1 and trailing_space:
                return self._known_project_ids()
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(self._known_project_ids(), args[1])
            return []

        if command_name == "data" and subcmd == "export":
            if len(args) == 1 and trailing_space:
                return self.DATA_EXPORT_FORMATS
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(self.DATA_EXPORT_FORMATS, args[1])
            current = args[-1]
            if trailing_space:
                return DATA_EXPORT_FLAGS
            if current.startswith("-"):
                return self._match_prefix(DATA_EXPORT_FLAGS, current)
            return []
        if command_name == "data" and subcmd == "sql" and len(args) == 1 and trailing_space:
            return self.DATA_SQL_HINTS
        if command_name == "data" and subcmd == "wipe-service":
            if len(args) == 1 and trailing_space:
                return DATA_WIPE_FLAGS
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(DATA_WIPE_FLAGS, args[1])
            return []

        if command_name in {"configs", "global_configs"} and subcmd in ("set", "unset"):
            if len(args) == 1 and trailing_space:
                return CONFIG_COMPLETION_KEYS
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(CONFIG_COMPLETION_KEYS, args[1])
            if subcmd == "set" and len(args) >= 2:
                key = args[1]
                choices = CONFIG_SET_VALUE_CHOICES.get(key, [])
                if len(args) == 2 and trailing_space:
                    return choices
                if len(args) == 3 and not trailing_space:
                    return self._match_prefix(choices, args[2])
        if command_name in {"configs", "global_configs"} and subcmd == "regions":
            if len(args) == 1 and trailing_space:
                return ["list"]
            if len(args) == 2 and not trailing_space:
                return self._match_prefix(["list"], args[1])
        return []

    def _command_candidates(self, line_buffer: str) -> List[str]:
        line = (line_buffer or "").lstrip()
        tokens = line.split()
        trailing_space = line.endswith(" ")

        if not tokens:
            return self._top_level_commands

        if len(tokens) == 1 and not trailing_space:
            return self._match_prefix(self._top_level_commands, tokens[0])

        cmd = tokens[0]
        args = tokens[1:]
        if cmd not in self.WORKSPACE_COMMANDS:
            return []
        return self._complete_command_args(cmd, args, trailing_space)

    def readline_complete(self, text: str, state: int):
        _ = text
        readline = _optional_readline()
        if not readline:
            return None
        line = readline.get_line_buffer()
        candidates = self._command_candidates(line)
        if not candidates:
            return None
        if state < len(candidates):
            return candidates[state]
        return None

    @staticmethod
    def _load_module_rows() -> List[Dict[str, Any]]:
        payload = load_mapping_data("module_mappings.json", kind="json") or {}
        # Shared parser owns the module-registry schema walk; the REPL layers on its own
        # display defaults ("Unknown"/"Uncategorized") and attribution normalization.
        rows = iter_module_rows(payload)
        for row in rows:
            row["service"] = row.get("service") or "Unknown"
            row["module_category"] = row.get("module_category") or "Uncategorized"
            if "attribution" in row:
                attribution = row.get("attribution")
                if isinstance(attribution, str):
                    normalized = [attribution.strip()] if attribution.strip() else []
                elif isinstance(attribution, list):
                    normalized = [str(item).strip() for item in attribution if str(item).strip()]
                else:
                    normalized = [str(attribution).strip()] if str(attribution or "").strip() else []
                if normalized:
                    row["attribution"] = normalized
                else:
                    row.pop("attribution", None)
        return rows

    @staticmethod
    def _flags_in_python_file(path: Path) -> set[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text, filename=str(path))
        except Exception:
            return set()

        out: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "add_argument"):
                continue
            for arg in (node.args or []):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("-"):
                    out.add(str(arg.value))
        return out

    def _module_cli_flags(self, module_import_path: str) -> List[str]:
        key = str(module_import_path or "").strip()
        if not key:
            return []

        cached = self._module_cli_flag_cache.get(key)
        if cached is not None:
            return list(cached)

        try:
            spec = importlib.util.find_spec(key)
        except Exception:
            spec = None
        if spec is None or not spec.origin:
            self._module_cli_flag_cache[key] = []
            return []

        module_file = Path(spec.origin)
        candidates = [module_file]
        service_root = module_file.parent.parent
        utilities_dir = service_root / "utilities"
        if utilities_dir.exists() and utilities_dir.is_dir():
            candidates.extend(sorted(utilities_dir.rglob("*.py")))

        flags: set[str] = set()
        for file_path in candidates:
            flags |= self._flags_in_python_file(file_path)

        out = sorted(flags)
        self._module_cli_flag_cache[key] = out
        return list(out)

    # -----------------------------
    # General command helpers
    # -----------------------------

    @staticmethod
    def _list_available_creds(workspace_id: int):
        with DataController() as dc:
            return dc.list_creds(workspace_id)

    @staticmethod
    def _dispatch_subcommand(
        subcommand: str | None,
        handlers: Dict[str | None, Any],
        *,
        unknown_message: str | None = None,
    ):
        if handler := handlers.get(subcommand):
            return handler()
        if unknown_message:
            print(unknown_message)
        return None

    def _known_project_ids(self) -> List[str]:
        project_ids = {
            str(project_id).strip()
            for project_id in (getattr(self.session, "global_project_list", None) or [])
            if str(project_id).strip()
        }
        project_ids.update(
            str(row.get("project_id") or "").strip()
            for row in self._project_choice_rows()
            if str(row.get("project_id") or "").strip()
        )
        return sorted(project_ids)

    @staticmethod
    def _validate_credential_source_args(args) -> bool:
        token = getattr(args, "token", None)
        token_file = getattr(args, "token_file", None)
        adc_filepath = getattr(args, "filepath_to_adc", None)
        if args.type == "oauth2" and not token and not token_file:
            print("[X] Cannot proceed with adding Oauth2 credentials. Supply a bare access token via --token, or a token.json via --token-file.")
            return False
        if token_file and not os.path.exists(token_file):
            print(f"[X] File {token_file} does not exist...")
            return False
        if adc_filepath and not os.path.exists(adc_filepath):
            print(f"[X] File {adc_filepath} does not exist...")
            return False
        return True

    def _handle_oauth_credential(self, *, args, credname, email=None, scopes=None, refresh_attempt=False):
        if not self._validate_credential_source_args(args):
            return
        self.session.add_oauth2_account(
            credname,
            project_id=self.session.project_id,
            token=getattr(args, "token", None),
            token_file=getattr(args, "token_file", None),
            tokeninfo=args.tokeninfo,
            scopes=scopes,
            email=email,
            adc_filepath=getattr(args, "filepath_to_adc", None),
            assume=args.assume if not refresh_attempt else True,
            refresh_attempt=refresh_attempt,
        )

    def _handle_service_credential(self, *, args, credname, refresh_attempt=False):
        filepath = args.service_file
        if not os.path.exists(filepath):
            print(f"[X] File {filepath} does not exist...")
            return
        self.session.add_service_account(
            filepath,
            credname,
            assume=args.assume,
            refresh_attempt=refresh_attempt,
        )

    # -----------------------------
    # Parser setup and passthrough
    # -----------------------------

    def setup_folder_structure(self):
        workspace_directory_name = make_workspace_slug(
            self.session.workspace_id,
            self.session.workspace_name,
        )
        self.session.workspace_directory_name = workspace_directory_name
        build_output_path(workspace_directory_name, bucket="logs", mkdir=True)

    def setup_parsers(self):
        for cmd in ["help", "?", "exit", "quit"]:
            self.subparsers.add_parser(cmd)

        self.setup_passthrough_parsers()
        self.setup_creds_parsers()
        self.setup_module_parsers()
        self.setup_data_parsers()
        self.setup_configs_parsers()
        self.setup_projects_parsers()
        self.setup_tree_parsers()

    # -----------------------------
    # Creds parsers
    # -----------------------------

    def setup_creds_parsers(self):
        creds = self.subparsers.add_parser("creds")
        sub = creds.add_subparsers(dest="creds_subcommand")

        sub.add_parser("list")

        info = sub.add_parser("info")
        apply_argument_specs(
            info,
            [
                (("credname",), {"nargs": "?", "help": "Specify credname (none defaults to current)"}),
                (("--csv",), {"required": False, "action": "store_true", "help": "Export info to CSV file"}),
            ],
        )

        tokeninfo = sub.add_parser("tokeninfo")
        tokeninfo.add_argument("credname", nargs="?", help="Specify credential name")

        set_cmd = sub.add_parser("set")
        apply_argument_specs(
            set_cmd,
            [
                (("credname",), {"nargs": "?", "help": "Specify credential name"}),
                (("--email",), {"help": "Specify email"}),
                (("--project-id",), {"help": "Specify project"}),
            ],
        )

        apply_argument_specs(sub.add_parser("add"), credential_mutation_argument_specs(credname_optional=False))
        apply_argument_specs(sub.add_parser("update"), credential_mutation_argument_specs(credname_optional=True))

        swap = sub.add_parser("swap")
        swap.add_argument("credname", nargs="?", help="Specify credential name")

    # -----------------------------
    # Module parsers
    # -----------------------------

    def setup_module_parsers(self):
        modules = self.subparsers.add_parser("modules")
        sub = modules.add_subparsers(dest="modules_subcommand")

        sub.add_parser("list")
        sub.add_parser("search").add_argument("search_term", help="Specify search term")
        sub.add_parser("info").add_argument("module_name", help="Module name")

        run = sub.add_parser("run")
        run.add_argument("module_name", help="Name of module to run")
        run.add_argument("module_args", nargs=argparse.REMAINDER, help="Arguments for the module")

    # -----------------------------
    # Data parsers
    # -----------------------------

    def setup_data_parsers(self):
        data = self.subparsers.add_parser("data")
        sub = data.add_subparsers(dest="data_subcommand")

        export = sub.add_parser("export")
        apply_argument_specs(
            export,
            [
                (("format",), {"choices": self.DATA_EXPORT_FORMATS, "help": "Export format"}),
                (("--out-dir",), {"required": False, "help": "Output directory"}),
                (("--out-file",), {"required": False, "help": "Output file path"}),
            ],
        )

        sql = sub.add_parser("sql")
        apply_argument_specs(
            sql,
            [
                (("--db",), {"choices": ["service", "metadata"], "default": "service", "help": "Target SQLite DB"}),
                (("query",), {"nargs": argparse.REMAINDER, "help": "SQL query to execute"}),
            ],
        )
        wipe = sub.add_parser("wipe-service")
        apply_argument_specs(
            wipe,
            [
                (("--all-workspaces",), {"action": "store_true", "help": "Wipe all workspace rows from service tables"}),
                (("--yes",), {"action": "store_true", "help": "Skip interactive confirmation"}),
            ],
        )

    # -----------------------------
    # Config parsers
    # -----------------------------

    def setup_configs_parsers(self):
        for command_name in self.CONFIG_COMMAND_NAMES:
            parser = self.subparsers.add_parser(command_name)
            sub = parser.add_subparsers(dest="configs_subcommand")

            sub.add_parser("list")

            set_cmd = sub.add_parser("set")
            apply_argument_specs(
                set_cmd,
                [
                    (("type_of_entity",), {"help": "Config key (std_output_format|projects|zones|regions|workspace_customer_id)"}),
                    (("objects",), {"nargs": "*", "help": "Config value (use comma list for projects/zones/regions)"}),
                ],
            )

            unset_cmd = sub.add_parser("unset")
            unset_cmd.add_argument("type_of_entity", help="Config key to clear/reset")

            regions_cmd = sub.add_parser("regions", help="Region helpers")
            regions_sub = regions_cmd.add_subparsers(dest="configs_regions_subcommand")
            regions_sub.add_parser("list", help="List known regions")

    # -----------------------------
    # Projects parsers
    # -----------------------------

    def setup_projects_parsers(self):
        projects = self.subparsers.add_parser("projects")
        sub = projects.add_subparsers(dest="projects_subcommand")

        sub.add_parser("list")
        sub.add_parser("set").add_argument("project_id", nargs="?", help="Project ID to enter")
        sub.add_parser("add").add_argument("project_id", help="Project ID to enter")
        sub.add_parser("rm").add_argument("project_id", help="Project ID to enter")

    # -----------------------------
    # Folders / orgs parsers
    # -----------------------------

    def setup_tree_parsers(self):
        for command_name, dest in (("folders", "folders_subcommand"), ("orgs", "orgs_subcommand")):
            parser = self.subparsers.add_parser(command_name)
            sub = parser.add_subparsers(dest=dest)
            sub.add_parser("list")

    def setup_passthrough_parsers(self):
        for command_name in self.PASSTHROUGH_COMMANDS:
            parser = self.subparsers.add_parser(command_name)
            parser.add_argument(f"{command_name}_args", nargs=argparse.REMAINDER, help=f"Arguments for {command_name}")

    def run_passthrough_command(self, args):
        command_name = str(getattr(args, "subcommand", "") or "").strip()
        command_args = list(getattr(args, f"{command_name}_args", []) or [])
        if not command_args:
            print(f"[X] No arguments passed to `{command_name}`.")
            return
        try:
            subprocess.run([command_name, *command_args], check=False)
        except OSError as exc:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed to run `{command_name}`:{UtilityTools.RESET} "
                f"{type(exc).__name__}: {exc}"
            )

    # -----------------------------
    # Hierarchy helpers
    # -----------------------------

    def _hierarchy_rows(self) -> List[Dict[str, Any]]:
        rows = self.session.get_data("abstract_tree_hierarchy") or []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def print_gcp_hierarchy(self, *, focus_types: set[str] | None = None) -> None:
        print_gcp_hierarchy(
            self._hierarchy_rows(),
            current_project_id=self.session.project_id,
            focus_types=focus_types,
        )

    def _project_choice_rows(self) -> List[Dict[str, Any]]:
        return project_choice_rows(self._hierarchy_rows(), self.session.global_project_list or [])

    def _cached_hierarchy_project_ids(self) -> set[str]:
        rows = self._hierarchy_rows()
        return {
            str(row.get("project_id") or "").strip()
            for row in rows
            if str(row.get("type") or "").strip().lower() == "project" and str(row.get("project_id") or "").strip()
        }

    def process_command(self, command):
        try:
            args = self.parser.parse_args(shlex.split(command))
            if handler := self.command_handlers.get(args.subcommand):
                return handler(args)
            print(f"[X] Unknown command '{args.subcommand}'. Type 'help' or '?'.")
        except SystemExit:
            pass  # Prevent argparse from exiting the program on error

    # -----------------------------
    # Credential commands
    # -----------------------------

    def process_creds_command(self, args):
        current_credname = getattr(args, "credname", None) or self.session.credname
        return self._dispatch_subcommand(
            args.creds_subcommand,
            {
                None: self.print_creds_table,
                "list": self.print_creds_table,
                "set": lambda: self._set_active_cred(args),
                "tokeninfo": lambda: self.session.get_and_save_tokeninfo(current_credname),
                "info": lambda: self.info_printout_save(current_credname, csv=bool(getattr(args, "csv", False))),
                "add": lambda: self._mutate_credential(args),
                "update": lambda: self._mutate_credential(args, refresh_attempt=True),
                "swap": lambda: self.swap_cred(args),
            },
        )

    def _set_active_cred(self, args):
        credname = args.credname or self.session.credname
        email = args.email or self.session.email
        project_id = args.project_id or self.session.project_id
        try:
            updates = {}
            if email is not None:
                updates["email"] = email
            if project_id is not None:
                updates["default_project"] = project_id
            if updates:
                self.session.data_master.update_credential(
                    self.session.workspace_id,
                    credname,
                    updates,
                )
            self.session.email = email
            self.session.project_id = project_id
        except Exception as exc:
            print("[X] There was an error changing either project ID or email. The change was not performed")
            print(str(exc))

    def _mutate_credential(self, args, *, refresh_attempt: bool = False):
        credname = args.credname or self.session.credname if refresh_attempt else args.credname
        email = None
        scopes = None
        if refresh_attempt:
            old_cred_info = self.session.get_credinfo(credname=credname)
            email = old_cred_info.get("email")
            scopes = old_cred_info.get("scopes")

        if args.type in {"adc", "oauth2"}:
            self._handle_oauth_credential(
                args=args,
                credname=credname,
                email=email,
                scopes=scopes,
                refresh_attempt=refresh_attempt,
            )
            return
        if args.type == "service":
            self._handle_service_credential(args=args, credname=credname, refresh_attempt=refresh_attempt)

    def swap_cred(self, args):
        if args.credname:
            self.session.load_stored_creds(args.credname)
            return

        available_creds = self.print_creds_table()
        answer = input("[*] Choose the username or index you want to assume: ")
        credname = resolve_stored_credname(answer, available_creds)
        if credname:
            self.session.load_stored_creds(credname)

    def _credential_rows_for_display(self):
        rows = self.session.get_session_data("session") or []
        normalized_rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            normalized_rows.append(
                {
                    "credname": str(row.get("credname") or "").strip(),
                    "credtype": str(row.get("credtype") or "").strip(),
                    "email": str(row.get("email") or "").strip(),
                    "default_project": str(row.get("default_project") or "").strip(),
                }
            )

        normalized_rows = [row for row in normalized_rows if row["credname"]]
        normalized_rows.sort(key=lambda item: item["credname"].lower())
        return normalized_rows

    def print_creds_table(self):
        normalized_rows = self._credential_rows_for_display()
        if not normalized_rows:
            print("\n[-] No creds found")
            return []

        print("\n[*] Stored credentials")
        available_creds = []
        for idx, row in enumerate(normalized_rows, start=1):
            is_current = row["credname"] == str(getattr(self.session, "credname", "") or "").strip()
            marker = " (current)" if is_current else ""
            credtype = row["credtype"] or "unknown"
            email = row["email"] or "-"
            default_project = row["default_project"] or "Unknown"
            print(
                f"  [{idx}] {row['credname']}{marker} | type={credtype} | email={email} | default_project={default_project}"
            )
            available_creds.append((row["credname"], row["credtype"], row["email"]))
        return available_creds

    # -----------------------------
    # Permission and role formatting
    # -----------------------------

    @staticmethod
    def _display_service_name(action_column: str) -> str:
        labels = {
            "organization_actions_allowed": "Organization Scope",
            "folder_actions_allowed": "Folder Scope",
            "project_actions_allowed": "Project Scope",
            "workspace_actions_allowed": "Google Workspace",
            "storage_actions_allowed": "Cloud Storage",
            "function_actions_allowed": "Cloud Functions",
            "compute_actions_allowed": "Cloud Compute",
            "cloudsql_actions_allowed": "Cloud SQL",
            "firestore_actions_allowed": "Firestore",
            "service_account_actions_allowed": "Service Accounts",
            "secret_actions_allowed": "Secret Manager",
        }
        return labels.get(action_column, action_column.replace("_", " ").title())

    @staticmethod
    def _format_provenance_sources(provenance_sources: list[str] | tuple[str, ...] | None) -> str:
        labels = []
        for source in provenance_sources or []:
            normalized = str(source or "").strip()
            if not normalized:
                continue
            labels.append(ACTION_EVIDENCE_LABELS.get(normalized, normalized.replace("_", " ")))
        return " / ".join(sorted(set(labels)))

    @classmethod
    def _format_scope_evidence(cls, scope_name: str, provenance_sources: list[str] | tuple[str, ...] | None = None) -> str:
        source_label = cls._format_provenance_sources(provenance_sources)
        if source_label:
            return f"{source_label}; scope={scope_name}"
        return f"scope cache: {scope_name}"

    @staticmethod
    def _shorten_asset_name(asset_type: str, asset_name: str) -> str:
        token = str(asset_name or "").strip()
        if not token or "/" not in token:
            return token

        resource_type = str(asset_type or "").strip().lower()
        location = extract_location_from_resource_name(token)

        if resource_type == "repositories":
            repository_id = extract_path_segment(token, "repositories")
            if location and repository_id:
                return f"{location}/{repository_id}"
            return repository_id or token

        if resource_type == "packages":
            repository_id = extract_path_segment(token, "repositories")
            package_id = extract_path_segment(token, "packages")
            if location and repository_id and package_id:
                return f"{location}/{repository_id}/{package_id}"
            return package_id or token

        if resource_type == "versions":
            repository_id = extract_path_segment(token, "repositories")
            package_id = extract_path_segment(token, "packages")
            version_id = extract_path_segment(token, "versions")
            if location and repository_id and package_id and version_id:
                return f"{location}/{repository_id}/{package_id}/{version_id}"
            return version_id or token

        return token

    @staticmethod
    def _group_permission_display_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, str]], set[int]]:
        grouped: dict[str, list[str]] = {}
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            permission = str(row.get("Permission") or "").strip()
            derived_from = str(row.get("Derived From") or "").strip()
            if not permission:
                continue
            grouped.setdefault(derived_from, []).append(permission)

        display_rows: list[dict[str, str]] = []
        divider_indices: set[int] = set()
        group_keys = sorted(grouped, key=lambda item: (item == "", item))
        for group_index, derived_from in enumerate(group_keys):
            permissions = sorted(set(grouped.get(derived_from) or []))
            for permission_index, permission in enumerate(permissions):
                display_rows.append(
                    {
                        "Permission": permission,
                        "Derived From": derived_from if permission_index == 0 else "",
                    }
                )
            if permissions and group_index != len(group_keys) - 1:
                divider_indices.add(len(display_rows) - 1)

        return display_rows, divider_indices

    def _permission_tables(self, permission_record: dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        action_provenance = permission_record.get(ACTION_PROVENANCE_COLUMN) or {}
        scope_columns = {column for _, column in ACTION_SCOPE_COLUMNS}
        for scope_key, action_column in ACTION_SCOPE_COLUMNS:
            scope_permissions = permission_record.get(action_column) or {}
            if not isinstance(scope_permissions, dict):
                continue
            service_name = self._display_service_name(action_column)
            column_provenance = action_provenance.get(action_column) if isinstance(action_provenance, dict) else {}
            for scope_name, permissions in scope_permissions.items():
                for permission in sorted(str(item) for item in (permissions or []) if str(item).strip()):
                    provenance_sources = []
                    if isinstance(column_provenance, dict):
                        permission_sources = column_provenance.get(scope_name, {})
                        if isinstance(permission_sources, dict):
                            provenance_sources = permission_sources.get(permission, []) or []
                    grouped.setdefault(service_name, []).append(
                        {
                            "Permission": permission,
                            "Derived From": self._format_scope_evidence(str(scope_name), provenance_sources),
                        }
                    )

        for action_column in ACTION_COLUMN_TO_RESOURCE_TYPE:
            if action_column in scope_columns:
                continue
            resource_permissions = permission_record.get(action_column) or {}
            if not isinstance(resource_permissions, dict):
                continue
            service_name = self._display_service_name(action_column)
            column_provenance = action_provenance.get(action_column) if isinstance(action_provenance, dict) else {}
            for project_id, permission_map in resource_permissions.items():
                if not isinstance(permission_map, dict):
                    continue
                for permission, asset_map in permission_map.items():
                    provenance_sources = []
                    if isinstance(column_provenance, dict):
                        permission_sources = column_provenance.get(project_id, {})
                        if isinstance(permission_sources, dict):
                            provenance_sources = permission_sources.get(permission, []) or []
                    grouped.setdefault(service_name, []).append(
                        {
                            "Permission": str(permission),
                            "Derived From": self._format_asset_evidence(
                                str(project_id or ""),
                                asset_map if isinstance(asset_map, dict) else {},
                                provenance_sources,
                            ),
                        }
                    )

        for service_name, rows in grouped.items():
            seen = set()
            deduped = []
            for row in rows:
                key = (row["Permission"], row["Derived From"])
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(row)
            grouped[service_name] = sorted(deduped, key=lambda item: (item["Permission"], item["Derived From"]))
        return grouped

    @staticmethod
    def _flatten_cred_permissions_for_csv(credname: str, permission_record: dict[str, Any]) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        dedupe: set[tuple[str, str, str, str]] = set()
        scope_columns = {column_name for _, column_name in ACTION_SCOPE_COLUMNS}

        def _append(permission: str, resource_type: str, resource_name: str) -> None:
            permission_token = str(permission or "").strip()
            resource_type_token = str(resource_type or "").strip()
            resource_name_token = str(resource_name or "").strip()
            if not (permission_token and resource_type_token and resource_name_token):
                return
            key = (str(credname or "").strip(), permission_token, resource_type_token, resource_name_token)
            if key in dedupe:
                return
            dedupe.add(key)
            rows.append(
                {
                    "credname": key[0],
                    "permission": key[1],
                    "resource_type": key[2],
                    "resource_name": key[3],
                }
            )

        for _scope_key, action_column in ACTION_SCOPE_COLUMNS:
            scope_permissions = permission_record.get(action_column) or {}
            if not isinstance(scope_permissions, dict):
                continue
            scope_type = str(ACTION_COLUMN_TO_RESOURCE_TYPE.get(action_column) or "").strip()
            for scope_name, permissions in scope_permissions.items():
                for permission in permissions or []:
                    _append(str(permission), scope_type, str(scope_name))

        for action_column in ACTION_COLUMN_TO_RESOURCE_TYPE:
            if action_column in scope_columns:
                continue
            resource_permissions = permission_record.get(action_column) or {}
            if not isinstance(resource_permissions, dict):
                continue
            default_resource_type = str(ACTION_COLUMN_TO_RESOURCE_TYPE.get(action_column) or "").strip()
            for project_id, permission_map in resource_permissions.items():
                project_token = str(project_id or "").strip()
                if not isinstance(permission_map, dict):
                    continue
                for permission, asset_map in permission_map.items():
                    permission_token = str(permission or "").strip()
                    if not permission_token:
                        continue

                    # Keep project-level evidence for each permission in addition to resource-level rows.
                    if project_token:
                        _append(permission_token, "project", project_token)

                    if isinstance(asset_map, dict):
                        for asset_type, asset_names in asset_map.items():
                            asset_type_token = str(asset_type or "").strip() or default_resource_type
                            values = asset_names if isinstance(asset_names, list) else [asset_names]
                            for asset_name in values or []:
                                _append(permission_token, asset_type_token, str(asset_name))
                    else:
                        values = asset_map if isinstance(asset_map, list) else [asset_map]
                        for asset_name in values or []:
                            _append(permission_token, default_resource_type, str(asset_name))

        return sorted(
            rows,
            key=lambda row: (
                str(row.get("credname") or ""),
                str(row.get("permission") or ""),
                str(row.get("resource_type") or ""),
                str(row.get("resource_name") or ""),
            ),
        )

    @classmethod
    def _asset_evidence_preview_limit(cls) -> int:
        return 5

    @classmethod
    def _format_asset_evidence(
        cls,
        project_id: str,
        asset_map: dict[str, Any],
        provenance_sources: list[str] | tuple[str, ...] | None = None,
    ) -> str:
        sections: list[str] = []
        for asset_type, asset_names in (asset_map or {}).items():
            names = sorted(
                cls._shorten_asset_name(str(asset_type), str(name))
                for name in (asset_names or [])
                if str(name).strip()
            )
            if not names:
                continue
            preview = names[: cls._asset_evidence_preview_limit()]
            if len(names) > cls._asset_evidence_preview_limit():
                preview.append(f"(+{len(names) - cls._asset_evidence_preview_limit()} more)")
            sections.append(
                "\n".join(
                    [
                        f"{asset_type}:",
                        *[f"- {name}" for name in preview],
                    ]
                )
            )
        prefix_parts = []
        source_label = cls._format_provenance_sources(provenance_sources)
        if source_label:
            prefix_parts.append(source_label)
        if project_id:
            prefix_parts.append(f"project={project_id}")
        lines = []
        prefix = "; ".join(prefix_parts)
        if prefix:
            lines.append(prefix)
        lines.extend(sections)
        return "\n".join(lines) or "cached permission evidence"

    def _print_permission_tables(self, permission_record: dict[str, Any]) -> None:
        grouped = self._permission_tables(permission_record)
        if not grouped:
            print("[*] No cached permission evidence found for this credential.")
            return
        for service_name in sorted(grouped):
            print(f"\n{UtilityTools.BOLD}[*] {service_name}{UtilityTools.RESET}")
            display_rows, divider_indices = self._group_permission_display_rows(grouped[service_name])
            UtilityTools.print_limited_table(
                display_rows,
                ["Permission", "Derived From"],
                max_rows=500,
                sort_key=None,
                truncate=0,
                column_max_widths={"Permission": 56, "Derived From": 88},
                divider_after_row_indices=divider_indices,
            )

    def _print_role_tables(self, roles_and_assets: dict[str, Any]) -> None:
        if not roles_and_assets:
            return
        pretty_names = {
            "org": "Organizations",
            "folder": "Folders",
            "project": "Projects",
            "bucket": "Cloud Storage",
            "cloudfunction": "Cloud Functions",
            "computeinstance": "Cloud Compute",
            "saaccounts": "Service Accounts",
            "secrets": "Secret Manager",
        }
        for asset_type, asset_rows in roles_and_assets.items():
            rows = []
            for asset_name, asset_details in (asset_rows or {}).items():
                if not isinstance(asset_details, dict):
                    continue
                inherited = asset_details.get("Inherited Permissions") or []
                inherited_roles = []
                for entry in inherited:
                    roles = sorted(str(role) for role in (entry.get("roles") or []) if str(role).strip())
                    ancestor = str(entry.get("ancestor") or "").strip()
                    if roles:
                        inherited_roles.append(f"{ancestor}: {', '.join(roles)}" if ancestor else ", ".join(roles))
                rows.append(
                    {
                        "Resource": str(asset_name),
                        "Parent": str(asset_details.get("parent_name") or asset_details.get("parent_id") or ""),
                        "Direct Roles": ", ".join(sorted(str(role) for role in (asset_details.get("Direct Permissions") or []) if str(role).strip())) or "-",
                        "Inherited Roles": " | ".join(inherited_roles) or "-",
                    }
                )
            if rows:
                print(f"\n{UtilityTools.BOLD}[*] IAM Roles - {pretty_names.get(asset_type, asset_type.title())}{UtilityTools.RESET}")
                UtilityTools.print_limited_table(rows, ["Resource", "Parent", "Direct Roles", "Inherited Roles"], max_rows=200, sort_key="Resource")

    # -----------------------------
    # Project and hierarchy commands
    # -----------------------------

    def process_projects_command(self, args):
        project_id = getattr(args, "project_id", None)
        return self._dispatch_subcommand(
            args.projects_subcommand,
            {
                None: self.list_projects,
                "list": self.list_projects,
                "add": lambda: self.add_projects(project_id),
                "set": lambda: self.set_projects(project_id),
                "rm": lambda: self.remove_projects(project_id),
            },
        )

    def list_projects(self):
        self.print_gcp_hierarchy(focus_types=self.TREE_FOCUS_TYPES["projects"])

        cached_project_ids = self._cached_hierarchy_project_ids()
        orphaned_projects = sorted(
            project_id
            for project_id in (self.session.global_project_list or [])
            if project_id not in cached_project_ids
        )

        if orphaned_projects:
            print(f"\n{UtilityTools.BOLD}[*] Known projects without cached hierarchy rows:{UtilityTools.RESET}")
            for project_id in orphaned_projects:
                marker = " [current]" if project_id == self.session.project_id else ""
                print(f"  - {project_id}{marker}")

    def add_projects(self, project_id):
        if not project_id:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Project ID is required.{UtilityTools.RESET}")
            return

        if project_id not in self.session.global_project_list:
            self.session.global_project_list.append(project_id)
            self.session.data_master.sync_workspace_projects(self.workspace_id, add=[project_id])
            print(f"{UtilityTools.GREEN}[*] Added project: {project_id}{UtilityTools.RESET}")
        else:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {project_id} already exists in the list as seen below:{UtilityTools.RESET}")
            for project_id_value in self.session.global_project_list:
                if project_id == project_id_value:
                    print(f" {UtilityTools.GREEN}{UtilityTools.BOLD}- {project_id_value}{UtilityTools.RESET}")
                else:
                    print(f" - {project_id_value}")

    def set_projects(self, project_id, set_as_default=False):
        if not project_id:
            project_choices = self._project_choice_rows()
            if not project_choices:
                print("[X] No target projects selected.")
                return

            print(f"{UtilityTools.BOLD}[*] Select a project to SET as current{UtilityTools.RESET}")
            for index, row in enumerate(project_choices, start=1):
                print(f"  [{index}] {project_label(row)}")

            answer = input("[*] Choose project name or index: ").strip()
            chosen_row = None
            if is_integer_within_bounds(answer, len(project_choices)):
                chosen_row = project_choices[int(answer) - 1]
            else:
                for row in project_choices:
                    pid = str(row.get("project_id") or "").strip()
                    display_name = str(row.get("display_name") or "").strip()
                    if answer == pid or (display_name and answer.lower() == display_name.lower()):
                        chosen_row = row
                        break
            if not chosen_row:
                print("[X] Invalid project selection.")
                return
            project_id = str(chosen_row.get("project_id") or "").strip()

        if project_id not in self.session.global_project_list:
            print(f"[X] {project_id} is not in the list of project_ids. Adding...")
            self.add_projects(project_id)

        self.session.project_id = project_id
        print(f"{UtilityTools.GREEN}[*] Current project set to: {project_id}{UtilityTools.RESET}")

        # Set default project as well
        if set_as_default:
            self.session.data_master.update_credential(
                self.session.workspace_id,
                self.session.credname,
                {"default_project": project_id},
            )

    def remove_projects(self, project_id):
        if not project_id:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Project ID is required.{UtilityTools.RESET}")
            return

        if project_id in self.session.global_project_list:
            self.session.global_project_list.remove(project_id)
            self.session.data_master.sync_workspace_projects(self.workspace_id, remove=[project_id])
            if project_id == self.session.project_id:
                if len(self.session.global_project_list) > 0:
                    self.session.project_id = self.session.global_project_list[-1]
                else:
                    self.session.project_id = None
            print(f"{UtilityTools.GREEN}[*] Removed project: {project_id}{UtilityTools.RESET}")
        else:
            print("[X] The project ID specified does not exist")

    # -----------------------------
    # Data commands
    # -----------------------------

    def process_data_command(self, args):
        return self._dispatch_subcommand(
            args.data_subcommand,
            {
                "export": lambda: self.handle_export_command(args),
                "sql": lambda: self.handle_sql_command(args),
                "wipe-service": lambda: self.handle_wipe_service_command(args),
            },
            unknown_message="[X] Unknown data subcommand.",
        )

    @staticmethod
    def _write_csv_rows(output_path: str | Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
        resolved = Path(output_path).expanduser()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with resolved.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({field: row.get(field, "") for field in fieldnames})

    def handle_sql_command(self, args):
        query = " ".join(list(getattr(args, "query", []) or [])).strip()
        if not query:
            print(
                f"{UtilityTools.RED}[X] Missing SQL query.{UtilityTools.RESET} "
                "Example: data sql --db service \"SELECT * FROM iam_allow_policies LIMIT 20\""
            )
            return

        db_choice = str(getattr(args, "db", "service") or "service").strip().lower()
        try:
            result = self.session.execute_sql(query, db=db_choice, fetch_limit=200)
            print(f"[*] Running SQL on {result['db']} DB: {result['db_path']}")
            if result.get("read_query"):
                rows = list(result.get("rows") or [])
                if rows:
                    UtilityTools.print_limited_table(rows, list(rows[0].keys()), max_rows=200, sort_key=None)
                else:
                    print("[*] No rows.")
            else:
                print(
                    f"{UtilityTools.GREEN}[*] SQL executed successfully.{UtilityTools.RESET} "
                    f"Rows affected: {result.get('rows_affected')}"
                )
        except Exception as exc:
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] SQL execution failed:{UtilityTools.RESET} {type(exc).__name__}: {exc}")

    def handle_wipe_service_command(self, args):
        all_workspaces = bool(getattr(args, "all_workspaces", False))
        force_yes = bool(getattr(args, "yes", False))
        target_ws = int(getattr(self, "workspace_id", 0) or 0)

        try:
            plan = self.session.data_master.plan_service_wipe(target_ws, all_workspaces=all_workspaces)
            if not (plan.get("plans") or []):
                print("[*] No service tables found.")
                return

            total_rows = int(plan.get("total_rows") or 0)
            candidate_tables = list(plan.get("candidate_tables") or [])
            non_workspace_tables = list(plan.get("non_workspace_tables") or [])
            tables_with_rows = list(plan.get("tables_with_rows") or [])
            scope_label = str(plan.get("scope_label") or ("all workspaces" if all_workspaces else f"workspace_id={target_ws}"))

            print(f"[*] Service DB: {plan.get('db_path')}")
            print(f"[*] Wipe scope: {scope_label}")
            print(f"[*] Candidate tables (have workspace_id): {len(candidate_tables)}")
            print(f"[*] Candidate rows to delete: {total_rows}")
            if non_workspace_tables:
                print(f"[!] Skipping tables without workspace_id: {len(non_workspace_tables)}")

            if total_rows <= 0:
                print("[*] Nothing to delete for selected scope.")
                return

            if not force_yes:
                confirm = input(
                    f"[!] This will delete {total_rows} row(s) from service DB ({scope_label}). Type WIPE to continue: "
                ).strip()
                if confirm != "WIPE":
                    print("[*] Wipe cancelled.")
                    return

            result = self.session.data_master.wipe_service_rows(
                target_ws,
                all_workspaces=all_workspaces,
                planned_tables_with_rows=tables_with_rows,
            )
            print(
                f"{UtilityTools.GREEN}[*] Wipe complete.{UtilityTools.RESET} "
                f"Deleted {int(result.get('deleted_rows') or 0)} row(s) "
                f"from {int(result.get('deleted_tables') or 0)} table(s)."
            )
        except Exception as exc:
            try:
                if self.session.data_master.conn is not None:
                    self.session.data_master.conn.rollback()
            except Exception:
                pass
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Service wipe failed:{UtilityTools.RESET} "
                f"{type(exc).__name__}: {exc}"
            )

    def handle_export_command(self, args):
        export_format = str(getattr(args, "format", "") or "").strip().lower()
        out_dir_arg = str(getattr(args, "out_dir", "") or "")
        out_file_arg = str(getattr(args, "out_file", "") or "")

        def _default_out_dir(subdir: str) -> Path:
            if out_dir_arg:
                out = Path(out_dir_arg).expanduser()
            else:
                out = self.session.resolve_output_path(
                    service_name="data",
                    project_id="global",
                    subdirs=[subdir],
                    target="export",
                )
            out.mkdir(parents=True, exist_ok=True)
            return out

        db_paths = [str(self.session.data_master.database_path)]
        exporters = {
            "csv": {
                "subdir": "sqlite_csv",
                "filename": "sqlite_blob.csv",
                "error_label": "CSV data blob",
                "runner": lambda path: export_sqlite_dbs_to_csv_blob(db_paths=db_paths, out_csv_path=path),
                "summary": lambda result: (
                    f"[*] CSV export complete -> {result['csv_path']} "
                    f"(databases={result['databases']}, tables={result['tables']}, rows={result['rows']})"
                ),
            },
            "json": {
                "subdir": "sqlite_json",
                "filename": "sqlite_blob.json",
                "error_label": "JSON blob",
                "runner": lambda path: export_sqlite_dbs_to_json_blob(db_paths=db_paths, out_json_path=path),
                "summary": lambda result: (
                    f"[*] JSON export complete -> {result['json_path']} "
                    f"(databases={result['databases']}, tables={result['tables']}, rows={result['rows']})"
                ),
            },
            "excel": {
                "subdir": "sqlite_excel",
                "filename": "sqlite_blob.xlsx",
                "error_label": "Excel workbook",
                "runner": lambda path: export_sqlite_dbs_to_excel_blob(db_paths=db_paths, out_xlsx_path=path, single_sheet=True),
                "summary": lambda result: (
                    f"[*] Excel export complete -> {result['xlsx_path']} "
                    f"(format={result.get('format','xlsx')}, databases={result['databases']}, tables={result['tables']}, rows={result['rows']}, single_sheet={result['single_sheet']})"
                ),
            },
            "treeimage": {
                "subdir": "resource_reports",
                "filename": "hierarchy_tree.svg",
                "error_label": "hierarchy graph",
                "runner": lambda path: export_hierarchy_tree_image(db_path=db_paths[0], out_path=path, workspace_id=self.workspace_id),
                "summary": lambda result: (
                    f"[*] Hierarchy tree export complete -> {result['image_path']} "
                    f"(format={result.get('format')}, renderer={result.get('renderer')}, resources={result.get('resources', 0)})"
                ),
            },
        }
        export_config = exporters.get(export_format)
        if not export_config:
            print(f"{UtilityTools.RED}[X] Unsupported export format: {export_format}{UtilityTools.RESET}")
            return

        output_path = (
            str(Path(out_file_arg).expanduser())
            if out_file_arg
            else str(_default_out_dir(export_config["subdir"]) / export_config["filename"])
        )
        try:
            result = export_config["runner"](output_path)
        except Exception as exc:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Failed exporting {export_config['error_label']}:{UtilityTools.RESET} "
                f"{type(exc).__name__}: {exc}"
            )
            return
        print(export_config["summary"](result))

    # -----------------------------
    # Config commands
    # -----------------------------

    def _discover_known_regions(self) -> List[str]:
        regions: set[str] = set()
        region_pattern = re.compile(r"^[a-z]+(?:-[a-z0-9]+)*\d+$")
        zone_pattern = re.compile(r"^[a-z]+(?:-[a-z0-9]+)*\d+-[a-z]$")

        # Source the static region/zone inventory from the consolidated
        # mappings/service_locations.txt (all services) rather than scanning per-module
        # data files, which have been consolidated into that single file.
        for locations in load_service_locations().values():
            for raw_line in locations:
                line = str(raw_line).strip().lower()
                if not line or line.startswith("#"):
                    continue
                if zone_pattern.match(line):
                    regions.add(line.rsplit("-", 1)[0])
                elif region_pattern.match(line):
                    regions.add(line)

        preferred = getattr(self.session.workspace_config, "preferred_regions", None) or []
        for region in preferred:
            normalized = str(region).strip().lower()
            if normalized:
                regions.add(normalized)
        return sorted(regions)

    def _print_known_regions(self) -> None:
        current_preferred = {
            str(region).strip().lower()
            for region in (getattr(self.session.workspace_config, "preferred_regions", None) or [])
            if str(region).strip()
        }
        known_regions = self._discover_known_regions()
        if not known_regions:
            print("[*] No known regions found in local module data files.")
            return

        print(f"{UtilityTools.BOLD}[*] Known regions:{UtilityTools.RESET}")
        for region_name in known_regions:
            if region_name in current_preferred:
                print(f"  - {UtilityTools.BOLD}{UtilityTools.GREEN}{region_name}{UtilityTools.RESET}")
            else:
                print(f"  - {region_name}")
        if current_preferred:
            print(
                f"{UtilityTools.BRIGHT_BLACK}[*] Highlighted entries are currently set in workspace configs.regions.{UtilityTools.RESET}"
            )

    def process_configs_command(self, args):
        command = getattr(args, "configs_subcommand", None)
        if command in {None, "list"}:
            self.session.workspace_config.print_json_formatted()
            return None

        if command == "regions":
            region_subcommand = str(getattr(args, "configs_regions_subcommand", "") or "list").strip().lower()
            if region_subcommand in {"", "list"}:
                self._print_known_regions()
                return None
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown configs regions command: {region_subcommand}{UtilityTools.RESET}")
            return None

        key = str(getattr(args, "type_of_entity", "") or "").strip().lower()
        alias_to_attr = {
            "projects": "preferred_project_ids",
            "zones": "preferred_zones",
            "regions": "preferred_regions",
            "workspace_customer_id": "workspace_customer_id",
            "workspace_admin_subject": "workspace_admin_subject",
        }
        known_config_keys = ["projects", "regions", "std_output_format", "workspace_admin_subject", "workspace_customer_id", "zones"]
        if key not in {"std_output_format", *alias_to_attr.keys()}:
            print(
                f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Unknown configs key: {args.type_of_entity}{UtilityTools.RESET}. "
                f"Supported keys: {', '.join(known_config_keys)}"
            )
            return -1

        if command == "set":
            values = list(getattr(args, "objects", None) or [])
            if key == "std_output_format":
                if not values:
                    return None
                try:
                    self.session.workspace_config.set_std_output_format(values[0])
                except ValueError:
                    print(f"{values[0]} is not supported. Please provide table or text")
                    return -1
            elif not values:
                return None
            elif key in {"projects", "zones", "regions"}:
                setattr(self.session.workspace_config, alias_to_attr[key], dedupe_strs(values[0].split(",")))
            else:
                setattr(self.session.workspace_config, alias_to_attr[key], str(values[0]).strip() or None)

            self.session.set_configs()
            return None

        if command == "unset":
            if key == "std_output_format":
                self.session.workspace_config.set_std_output_format("text")
            else:
                setattr(self.session.workspace_config, alias_to_attr[key], None)
            self.session.set_configs()
            return None

        print("[X] Unknown configs subcommand.")

    # -----------------------------
    # Module commands
    # -----------------------------

    def process_modules_command(self, args):
        return self._dispatch_subcommand(
            args.modules_subcommand,
            {
                None: self.print_modules,
                "list": self.print_modules,
                "info": lambda: self.print_module_info(args.module_name),
                "search": lambda: self.print_modules(search_term=args.search_term),
                "run": lambda: self._run_module(args.module_name, args.module_args),
            },
        )

    def _run_module(self, module_name: str, module_args: List[str]):
        if module_path := self._module_name_to_path.get(module_name):
            interact_with_module(self.session, module_path, module_args)
            return
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Module \"{module_name}\" not found.{UtilityTools.RED}{UtilityTools.RESET}")

    def print_module_info(self, module_name, max_width=100):
        found = False
        for module in self._module_rows:
            if module['module_name'] == module_name:
                print(f"\n{UtilityTools.BOLD}Service Name:{UtilityTools.RESET} {UtilityTools.GREEN + UtilityTools.BOLD}{module['service']}{UtilityTools.RESET}")
                print(f"{UtilityTools.BOLD}Category:{UtilityTools.RESET} {UtilityTools.BLUE}{module['module_category']}{UtilityTools.RESET}")
                print(f"{UtilityTools.BOLD}Module Name:{UtilityTools.RESET} {UtilityTools.YELLOW}{module['module_name']}{UtilityTools.RESET}")
                attribution = module.get("attribution")
                if isinstance(attribution, list):
                    attribution_text = ", ".join(str(item).strip() for item in attribution if str(item).strip())
                elif isinstance(attribution, str):
                    attribution_text = attribution.strip()
                else:
                    attribution_text = ""
                if attribution_text:
                    print(f"{UtilityTools.BOLD}Attribution:{UtilityTools.RESET} {attribution_text}")
                version_text = str(module.get("version") or "").strip()
                if version_text:
                    print(f"{UtilityTools.BOLD}Version:{UtilityTools.RESET} {version_text}")
                print(f"{UtilityTools.BOLD}Location:{UtilityTools.RESET} {module['location']}")
                print(f"{UtilityTools.BOLD}Description:{UtilityTools.RESET}\n{textwrap.fill(module['info_blurb'], max_width)}\n")
                found = True
                break

        if not found:
            print(f"{UtilityTools.RED}Module \"{module_name}\" not found.{UtilityTools.RESET}")

    def print_modules(self, search_term=None):
        header_color = UtilityTools.BOLD
        category_color = UtilityTools.BLUE + UtilityTools.BOLD
        module_color = UtilityTools.YELLOW
        service_color = UtilityTools.GREEN + UtilityTools.BOLD
        reset = UtilityTools.RESET

        term = str(search_term or "").strip().lower()
        rows = []
        for module in self._module_rows:
            module_name = str(module.get("module_name") or "")
            service_name = str(module.get("service") or "Unknown")
            module_category = str(module.get("module_category") or "Uncategorized").capitalize()
            location = str(module.get("location") or "")
            info_blurb = str(module.get("info_blurb") or "")

            matched_flags: List[str] = []
            if term:
                metadata_blob = " ".join([module_name, service_name, module_category, location, info_blurb]).lower()
                module_flags = self._module_cli_flags(location)
                matched_flags = [flag for flag in module_flags if term in flag.lower()]
                if term not in metadata_blob and not matched_flags:
                    continue

            rows.append(
                {
                    "service": service_name,
                    "category": module_category,
                    "module": module_name,
                    "matched_flags": matched_flags,
                }
            )

        if not rows:
            print(f"{UtilityTools.RED}No matching modules found.{reset}")
            return

        rows.sort(
            key=lambda row: (
                str(row.get("service") or "").lower(),
                str(row.get("category") or "").lower(),
                str(row.get("module") or "").lower(),
            )
        )

        row_tuples = [(row["service"], row["category"], row["module"]) for row in rows]
        header = ("Service", "Category", "Module")
        col_widths = [max(map(len, col)) for col in zip(*row_tuples)]
        col_widths = [max(width, len(label)) for width, label in zip(col_widths, header)]
        separator_length = sum(col_widths) + 6

        print(f"{header_color}{header[0]:<{col_widths[0]}} | {header[1]:<{col_widths[1]}} | {header[2]:<{col_widths[2]}}{reset}")
        print("-" * separator_length)

        current_service = None
        current_category = None
        for row in rows:
            service_name = row["service"]
            module_category = row["category"]
            module = row["module"]
            matched_flags = list(row.get("matched_flags") or [])
            service_cell = ""
            category_cell = ""
            row_divider = (
                f"{'':<{col_widths[0]}} | "
                f"{'-' * (col_widths[1] + 3 + col_widths[2])}"
            )

            if service_name != current_service:
                if current_service is not None:
                    print("-" * separator_length)
                current_service = service_name
                current_category = None
                service_cell = f"{service_color}{service_name:<{col_widths[0]}}{reset}"
            else:
                service_cell = f"{'':<{col_widths[0]}}"

            if module_category != current_category:
                if current_category is not None:
                    print(row_divider)
                current_category = module_category
                category_cell = f"{category_color}{module_category:<{col_widths[1]}}{reset}"
            else:
                category_cell = f"{'':<{col_widths[1]}}"

            print(f"{service_cell} | {category_cell} | {module_color}{module:<{col_widths[2]}}{reset}")

            if term and matched_flags:
                print(
                    f"{'':<{col_widths[0]}} | "
                    f"{'':<{col_widths[1]}} | "
                    f"{UtilityTools.BRIGHT_BLACK}matched flags: {', '.join(sorted(matched_flags))}{reset}"
                )

    # -----------------------------
    # Credential reporting
    # -----------------------------

    def info_printout_save(self, credname, csv=False):
        if not credname:
            print(f"{UtilityTools.RED}[X] No active credential selected.{UtilityTools.RESET}")
            return None

        cred_record = self.session.get_credinfo(credname=credname)
        if not cred_record:
            print(f"{UtilityTools.RED}[X] Credential '{credname}' was not found.{UtilityTools.RESET}")
            print("[*] Tip: use `creds info` for current credential, or `creds info <credname> --csv` for export.")
            return None

        permissions_fetch = self.session.get_actions(credname = credname, include_provenance = not csv)
        role_member, roles_and_assets = None, None
        email = str(cred_record.get("email") or self.session.email or "").strip()
        if email:
            all_auth_binding = self.session.get_data("member_permissions_summary", conditions = f"member = \"user:{email}\" OR member = \"serviceAccount:{email}\"")
      
            if all_auth_binding:
                if all_auth_binding[0]["crednames"] and credname in all_auth_binding[0]["crednames"]:
                    role_member, roles_and_assets = all_auth_binding[0]["member"], ast.literal_eval(all_auth_binding[0]["roles_and_assets"])
                 

        if csv:
            permission_record = dict(permissions_fetch[0]) if permissions_fetch else {}
            flattened_rows = self._flatten_cred_permissions_for_csv(credname, permission_record)
            output_path = self.session.resolve_output_path(
                service_name="reports",
                project_id="global",
                subdirs=["snapshots"],
                filename=f"{credname}_permissions_{int(time.time())}.csv",
                target="export",
            )
            self._write_csv_rows(
                output_path,
                flattened_rows,
                ["credname", "permission", "resource_type", "resource_name"],
            )
            if flattened_rows:
                print(f"[*] Saved {len(flattened_rows)} permission row(s) to {output_path}")
            else:
                print(f"[*] Saved empty permission CSV (no cached permissions found) to {output_path}")
            return 1

        summary_rows = [
            {
                "credname": credname,
                "credtype": str(cred_record.get("credtype") or ""),
                "email": email or "-",
                "default_project": str(cred_record.get("default_project") or self.session.default_project_id or "-"),
                "scopes": ", ".join(self.session.scopes or []) or "-",
                "cached_projects": ", ".join(sorted(self.session.global_project_list or [])) or "-",
            }
        ]
        print(f"\n{UtilityTools.BOLD}[*] Credential Summary{UtilityTools.RESET}")
        UtilityTools.print_limited_table(summary_rows, ["credname", "credtype", "email", "default_project", "scopes", "cached_projects"], max_rows=10, sort_key=None)

        if permissions_fetch:
            self._print_permission_tables(dict(permissions_fetch[0]))

        if role_member:
            self._print_role_tables(roles_and_assets)


# -----------------------------
# Startup and entrypoint helpers
# -----------------------------

def list_all_creds_for_user(available_creds):
    if not available_creds:
        print("\n[-] No creds found")
        return

    print("\n[*] Listing existing credentials...")
    for index, cred in enumerate(available_creds):
        name, type_of_cred = cred[0], cred[1]
        print(f"  [{index + 1}] {name} ({type_of_cred})")
    print("\n")


def is_integer_within_bounds(user_input, upper_bound):
    try:
        user_input_int = int(user_input)
        return 1 <= user_input_int <= upper_bound
    except ValueError:
        return False


def initial_instructions(workspace_id: int, workspace_name: str, *, startup_silent: bool = False):
    # Some terminals emit raw ANSI escape sequences (for example arrow keys)
    # unless readline is initialized before input(). Keep startup prompt UX
    # consistent with the main REPL loop.
    readline = _optional_readline()
    if readline:
        readline.parse_and_bind("tab: complete")

    # Initial print setup
    def first_time_message(available_creds):
        # Print standard help menu (unless silenced by startup flag).
        if not startup_silent:
            help_banner()

        # Print stored creds for the current workspace (may be empty).
        list_all_creds_for_user(available_creds)

        # Prompt user for new credentials.
        new_credentials_instructions = textwrap.dedent(
            """\
            Submit the name or index of an existing credential from above, or add NEW credentials via:
              [1] adc      <credential_name> [--filepath-to-adc <adc_json_path>] [--tokeninfo]
              [2] oauth2   <credential_name> --token <access_token> [--tokeninfo]
              [3] service-acc-key <credential_name> --service-file <service_account_json_path>

            Tip: `--tokeninfo` queries Google's tokeninfo endpoint to capture scope/email for OAuth-style creds.

            Input: """
        )

        answer = ""
        if readline:
            existing_names = [str(row[0]) for row in (available_creds or []) if row and row[0]]
            existing_indexes = [str(index + 1) for index, _row in enumerate(available_creds or [])]
            command_roots = ["adc", "oauth2", "service-acc-key"]
            command_flags = {
                "adc": ["--filepath-to-adc", "--tokeninfo"],
                "oauth2": ["--token", "--tokeninfo"],
                "service-acc-key": ["--service-file"],
            }

            def _startup_cred_complete(_text: str, state: int):
                line = (readline.get_line_buffer() or "").lstrip()
                trailing_space = line.endswith(" ")
                tokens = line.split()
                candidates: list[str] = []

                if not tokens:
                    candidates = [*existing_names, *existing_indexes, *command_roots]
                else:
                    head = tokens[0]
                    if len(tokens) == 1 and not trailing_space:
                        root_candidates = [*existing_names, *existing_indexes, *command_roots]
                        candidates = [candidate for candidate in root_candidates if candidate.startswith(head)]
                    elif head in command_roots:
                        flags = command_flags.get(head, [])
                        if trailing_space:
                            candidates = flags
                        else:
                            current = tokens[-1]
                            if current.startswith("-"):
                                candidates = [flag for flag in flags if flag.startswith(current)]
                            else:
                                candidates = [name for name in existing_names if name.startswith(current)]

                candidates = sorted(dict.fromkeys(candidates))
                if state < len(candidates):
                    return candidates[state]
                return None

            previous_completer = readline.get_completer()
            previous_delims = readline.get_completer_delims()
            try:
                readline.set_completer_delims(" \t\n")
                readline.set_completer(_startup_cred_complete)
                answer = input(new_credentials_instructions)
            finally:
                readline.set_completer(previous_completer)
                readline.set_completer_delims(previous_delims)
        else:
            answer = input(new_credentials_instructions)
        arguments = shlex.split(answer) if answer and answer.strip() else []
        return answer, arguments

    initial_startup_parser = argparse.ArgumentParser(description="Handle addition of credentials", exit_on_error=False)
    subparsers = initial_startup_parser.add_subparsers(dest="command", metavar="<command>", required=True)
    startup_specs = {
        "adc": (
            "Set default credentials",
            [
                (("credential_name",), {"help": "Arbitrary credential name (ex. ExampleCreds)"}),
                (("--filepath-to-adc",), {"dest": "filepath_to_adc", "required": False, "help": "Optional filepath to ADC JSON (ex. /tmp/adc_refreshtokens.json)"}),
                (("--tokeninfo",), {"action": "store_true", "help": "Send tokens to tokeninfo endpoint"}),
            ],
        ),
        "oauth2": (
            "Set OAuth2 token",
            [
                (("credential_name",), {"help": "Arbitrary credential name (ex. ExampleCreds)"}),
                (("--token",), {"dest": "token_value", "required": True, "help": "OAuth2 access token (ex. ya[TRUNCATED]i3jJK)"}),
                (("--tokeninfo",), {"action": "store_true", "help": "Send tokens to tokeninfo endpoint"}),
            ],
        ),
        "service-acc-key": (
            "Set service credentials",
            [
                (("credential_name",), {"help": "Arbitrary credential name (ex. ExampleCreds)"}),
                (("--service-file",), {"dest": "filepath_to_service_creds", "required": True, "help": "Filepath to service credentials (ex. /tmp/name2.json)"}),
            ],
        ),
    }
    for command_name, (help_text, argument_specs) in startup_specs.items():
        parser = subparsers.add_parser(command_name, help=help_text)
        apply_argument_specs(parser, argument_specs)

    # Fetch existing creds in format: (credname, credtype, email).
    with DataController() as dc:
        available_creds = dc.list_creds(workspace_id)

    # Prompt the user. Accept existing name, existing index, or a new auth command.
    answer, arguments = first_time_message(available_creds)

    # If the user presses ENTER, start with no creds loaded.
    if answer == "":
        return SessionUtility(workspace_id, workspace_name, None, None)

    credname = resolve_stored_credname(answer, available_creds)
    if credname:
        return SessionUtility(workspace_id, workspace_name, credname, None, resume=True)

    # Otherwise parse a new credential command.
    try:
        args = initial_startup_parser.parse_args(arguments)
    except argparse.ArgumentError:
        print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Incorrect input. Make sure to either type the name of credentials that exist or start with adc/oauth2/service-acc-key. Entering GCPwn with no credentials or project set...{UtilityTools.RESET}")
        return SessionUtility(workspace_id, workspace_name, None, None)

    if args.command in {"adc", "oauth2"}:
        oauth_token = getattr(args, "token_value", None)
        adc_filepath = getattr(args, "filepath_to_adc", None)

        return SessionUtility(
            workspace_id,
            workspace_name,
            args.credential_name,
            args.command,
            oauth_token=oauth_token,
            adc_filepath=adc_filepath,
            tokeninfo=args.tokeninfo,
        )

    if args and args.command == "service-acc-key":
        filepath = args.filepath_to_service_creds
        if not os.path.exists(filepath):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] File {filepath} does not exist. Proceeding with no credentials...{UtilityTools.RESET}")
            return SessionUtility(workspace_id, workspace_name, None, None)
        return SessionUtility(
            workspace_id,
            workspace_name,
            args.credential_name,
            "service",
            filepath=filepath,
        )

    return SessionUtility(workspace_id, workspace_name, None, None)


# Entrypoint for workspace
def workspace_instructions(workspace_id, workspace_name, *, startup_silent: bool = False):
    # Handle the user choosing existing creds or adding new creds.
    # Returns a Session object with workspace/auth/config context.
    session = initial_instructions(workspace_id, workspace_name, startup_silent=startup_silent)

    # Pass workspace ID + populated Session into the command processor.
    command_processor = CommandProcessor(workspace_id, session)

    # Add tab completion + history when readline is available.
    readline = _optional_readline()
    if readline:
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t\n")
        readline.set_completer(command_processor.readline_complete)
        readline.set_history_length(25)

    # Main loop for interactive prompts.
    while True:
        cli_prefix = f"{session.project_id}:{session.credname}"

        try:
            user_input = input(f'({cli_prefix})> ')

            # Avoid recording setup noise in the readline history.
            if readline:
                readline.set_auto_history(False)

            keep_running = command_processor.process_command(user_input)
            if keep_running == CommandProcessor.EXIT_SIGNAL:
                break

        except (ValueError, KeyboardInterrupt):
            break

        except Exception:

            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Program failed for unknown reasons. See below:{UtilityTools.RESET}")
            print(traceback.format_exc())

        finally:
            # Re-enable readline history tracking.
            if readline:
                readline.set_auto_history(True)
