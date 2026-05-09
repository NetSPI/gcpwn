from __future__ import annotations

import re
import shutil
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from gcpwn.core.output_paths import resolve_named_save_path


class UtilityTools:
    TABLE_OUTPUT_FORMAT = "text"
    _PRETTYTABLE_UNAVAILABLE_WARNED = False
    _REDACTED = "<redacted>"
    _SENSITIVE_KEY_TOKENS = (
        "token",
        "secret",
        "password",
        "passphrase",
        "authorization",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "private_key",
        "security_token",
        "credential",
    )

    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    BOLD = "\033[1m"

    @staticmethod
    def validate_input_format(resource, sections):
        pattern = r"^" + r"/".join([r"[^/]+" for _ in range(sections)]) + r"$"
        if isinstance(resource, list):
            for key in resource:
                if not re.match(pattern, key):
                    return -1, key
        elif not re.match(pattern, resource):
            return -1, resource
        return 0, None

    @staticmethod
    def validate_user_format(member):
        pattern = r"^(user:|serviceaccount:)[^\[\]]+$"
        if not re.compile(pattern, re.IGNORECASE).match(member):
            return -1, member
        return 0, None

    @staticmethod
    def get_save_filepath(workspace_name, file_name, key_to_get):
        return str(resolve_named_save_path(workspace_name, filename=file_name, key=key_to_get))

    @staticmethod
    def print_403_api_disabled(service_type, project_id):
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 403:{UtilityTools.RESET}"
            f"{UtilityTools.RED} {service_type} API does not appear to be enabled for project {project_id}"
            f"{UtilityTools.RESET}"
        )

    @staticmethod
    def print_error(message: str):
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X]{UtilityTools.RESET}"
            f"{UtilityTools.RED} {message}{UtilityTools.RESET}"
        )

    @staticmethod
    def print_403_api_denied(permission_name, resource_name=None, project_id=None):
        if project_id:
            printout = f"project {project_id}"
        else:
            printout = resource_name or "target resource"
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 403:{UtilityTools.RESET}"
            f"{UtilityTools.RED} User does not have {permission_name} permissions on {printout}"
            f"{UtilityTools.RESET}"
        )

    @staticmethod
    def print_403_insufficient_scopes(
        permission_name: str,
        *,
        project_id: str | None = None,
        resource_name: str | None = None,
        current_scopes: Any = None,
        suggested_scope: str = "https://www.googleapis.com/auth/cloud-platform",
    ) -> None:
        if project_id:
            printout = f"project {project_id}"
        else:
            printout = resource_name or "target resource"
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 403 - INSUFF TOKEN SCOPE:{UtilityTools.RESET}"
            f"{UtilityTools.RED} Token scope is insufficient for {permission_name} on {printout}{UtilityTools.RESET}"
        )
        scope_display = ""
        if isinstance(current_scopes, (list, tuple, set)):
            scope_display = ", ".join(str(item).strip() for item in current_scopes if str(item).strip())
        else:
            scope_display = str(current_scopes or "").strip()
        if scope_display:
            print(f"[*] Current credential scopes: {scope_display}")
        else:
            print("[*] Current credential scopes: unknown")
        print(f"[*] Suggested scope for broad enumeration: {suggested_scope}")

    @staticmethod
    def print_404_resource(resource_name):
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 404:{UtilityTools.RESET}"
            f"{UtilityTools.RED} {resource_name} was not found"
            f"{UtilityTools.RESET}"
        )

    @staticmethod
    def print_500(resource_name, permission, error):
        print(
            f"{UtilityTools.RED}{UtilityTools.BOLD}[X] STATUS 500 (UNKNOWN):{UtilityTools.RESET}"
            f"{UtilityTools.RED} {permission} failed for {resource_name}. See below:"
        )
        print(str(error) + f"{UtilityTools.RESET}")

    @staticmethod
    def _is_sensitive_key(key: Any) -> bool:
        key_str = str(key or "").strip().lower()
        return bool(key_str) and any(token in key_str for token in UtilityTools._SENSITIVE_KEY_TOKENS)

    @staticmethod
    def sanitize_url(url: str) -> str:
        try:
            parsed = urlparse(str(url or ""))
            if not parsed.query:
                return str(url or "")
            sanitized_qs = []
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                sanitized_qs.append((key, UtilityTools._REDACTED if UtilityTools._is_sensitive_key(key) else value))
            return urlunparse(parsed._replace(query=urlencode(sanitized_qs, doseq=True)))
        except Exception:
            return str(url or "")

    @staticmethod
    def sanitize_args(obj: Any, *, max_str_len: int = 1024) -> Any:
        if isinstance(obj, dict):
            output = {}
            for key, value in obj.items():
                if UtilityTools._is_sensitive_key(key):
                    output[key] = UtilityTools._REDACTED
                elif str(key).strip().lower() == "url" and isinstance(value, str):
                    output[key] = UtilityTools.sanitize_url(value)
                else:
                    output[key] = UtilityTools.sanitize_args(value, max_str_len=max_str_len)
            return output
        if isinstance(obj, list):
            return [UtilityTools.sanitize_args(item, max_str_len=max_str_len) for item in obj]
        if isinstance(obj, tuple):
            return tuple(UtilityTools.sanitize_args(item, max_str_len=max_str_len) for item in obj)
        if isinstance(obj, str):
            if "bearer " in obj.lower():
                return UtilityTools._REDACTED
            if len(obj) > max_str_len:
                return obj[: max_str_len - 3] + "..."
        return obj

    @staticmethod
    def dlog(debug: bool, message: str, **kv: Any) -> None:
        if not debug:
            return
        if not kv:
            print(f"[DEBUG] {message}")
            return

        rendered = []
        for key, value in kv.items():
            try:
                sanitized = UtilityTools.sanitize_args(value)
                if "url" in str(key).lower() and isinstance(sanitized, str):
                    sanitized = UtilityTools.sanitize_url(sanitized)
                value_str = repr(sanitized)
                if len(value_str) > 280:
                    value_str = value_str[:277] + "..."
                rendered.append(f"{key}={value_str}")
            except Exception:
                rendered.append(f"{key}=<unrepr>")
        print(f"[DEBUG] {message} :: {' '.join(rendered)}")

    @staticmethod
    def _is_path_field(field_name: str) -> bool:
        lowered = str(field_name or "").strip().lower()
        return lowered.endswith("path") or "path" in lowered

    @staticmethod
    def _shorten_resource_ref(value: str) -> str:
        token = str(value or "").strip()
        if not token or "/" not in token:
            return token
        parts = [part for part in token.split("/") if part]
        return parts[-1] if parts else token

    @staticmethod
    def _normalize_cell(
        value: Any,
        *,
        truncate: int = 300,
        preserve_paths: bool = False,
        field_name: str = "",
    ) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            rendered = "\n".join(str(item) for item in value)
        elif isinstance(value, dict):
            rendered = "\n".join(f"{key}: {item}" for key, item in value.items())
        else:
            rendered = str(value)
        token = str(field_name or "").strip().lower()
        should_shorten = (
            bool(token)
            and (
                (token != "name" and token.endswith("_name"))
                or token in {"region", "network", "zone", "location"}
                or token.endswith(("_region", "_network", "_zone", "_location"))
            )
        )
        if should_shorten and "\n" not in rendered:
            rendered = UtilityTools._shorten_resource_ref(rendered)
        if truncate and len(rendered) > truncate and not preserve_paths:
            return rendered[: truncate - 11] + "[TRUNCATED]"
        return rendered

    @staticmethod
    def print_limited_table(
        data: Iterable[dict[str, Any]],
        fields: list[str],
        *,
        title: str | None = None,
        resource_type: str | None = None,
        sort_key: str | None = None,
        reverse: bool = False,
        max_rows: int = 50,
        truncate: int = 120,
        auto_wrap_to_terminal: bool = True,
        min_col_width: int = 10,
        max_col_width: int = 120,
        column_max_widths: dict[str, int] | None = None,
        align: str | None = "l",
        highlight_row_indices: set[int] | None = None,
        divider_after_row_indices: set[int] | None = None,
        highlight_prefix: str = "",
        highlight_suffix: str = "",
    ) -> None:
        indexed_rows = [(index, dict(row)) for index, row in enumerate(data)]
        if sort_key:
            try:
                indexed_rows.sort(key=lambda item: str(item[1].get(sort_key, "")), reverse=reverse)
            except Exception:
                pass
        if highlight_row_indices:
            highlight_row_indices = {
                sorted_index
                for sorted_index, (original_index, _row) in enumerate(indexed_rows)
                if original_index in highlight_row_indices
            }
        if divider_after_row_indices:
            divider_after_row_indices = {
                sorted_index
                for sorted_index, (original_index, _row) in enumerate(indexed_rows)
                if original_index in divider_after_row_indices
            }
        rows = [row for _index, row in indexed_rows]

        if title:
            print(f"\n[*] {title}")

        if resource_type:
            print(f"{UtilityTools.BOLD}Resource Type:{UtilityTools.RESET} {resource_type}")

        if not rows:
            print("[*] No resources found.")
            return

        hidden_path_fields = {
            "file_path",
            "filepath",
            "output_path",
            "save_path",
            "local_path",
            "download_path",
            "raw_json",
            "workspace_id",
        }
        filtered_fields = [
            field
            for field in fields
            if str(field or "").strip().lower() not in hidden_path_fields
        ]
        if rows:
            def has_value(value: Any) -> bool:
                if value is None:
                    return False
                if isinstance(value, str):
                    return bool(value.strip())
                return True
            non_empty_fields = [
                field for field in filtered_fields
                if any(has_value(row.get(field)) for row in rows)
            ]
            fields = non_empty_fields or filtered_fields
        else:
            fields = filtered_fields
        output_format = str(getattr(UtilityTools, "TABLE_OUTPUT_FORMAT", "text") or "text").strip().lower()

        def _print_text_rows() -> None:
            shown = rows[:max_rows]
            print(f"{UtilityTools.BOLD}Columns:{UtilityTools.RESET} " + " | ".join(fields))
            print(f"{UtilityTools.BOLD}Rows:{UtilityTools.RESET} showing {len(shown)} of {len(rows)}")
            if shown:
                print("")
            for index, entry in enumerate(shown, start=1):
                item_prefix = ""
                item_suffix = ""
                if highlight_row_indices and (index - 1) in highlight_row_indices:
                    item_prefix = highlight_prefix
                    item_suffix = highlight_suffix
                print(f"{item_prefix}{UtilityTools.BOLD}- item {index}{UtilityTools.RESET}{item_suffix}")
                for field in fields:
                    value = str(entry.get(field, ""))
                    if truncate and len(value) > truncate and not UtilityTools._is_path_field(field):
                        value = value[: truncate - 1] + "…"
                    print(f"{item_prefix}    {field}: {value}{item_suffix}")
                if index != len(shown):
                    print("")
            if len(rows) > max_rows:
                print(f"{UtilityTools.BRIGHT_BLACK}... ({len(rows) - max_rows} more rows){UtilityTools.RESET}")

        if output_format in {"txt", "text"}:
            _print_text_rows()
            return

        try:
            from prettytable import PrettyTable
        except Exception:
            if not UtilityTools._PRETTYTABLE_UNAVAILABLE_WARNED:
                print(
                    f"{UtilityTools.YELLOW}[!] prettytable is not installed. Falling back to text output. "
                    "Install optional table rendering with `pip install gcpwn[table]` or `pip install prettytable`."
                    f"{UtilityTools.RESET}"
                )
                UtilityTools._PRETTYTABLE_UNAVAILABLE_WARNED = True
            _print_text_rows()
            return

        table = PrettyTable()
        headers = [field.capitalize() for field in fields]
        table.field_names = headers
        if align in {"l", "c", "r"}:
            table.align = align

        shown = rows[:max_rows]
        rendered_rows = []
        for entry in shown:
            current_row = []
            for field in fields:
                value = str(entry.get(field, ""))
                if truncate and len(value) > truncate and not UtilityTools._is_path_field(field):
                    value = value[: truncate - 1] + "…"
                current_row.append(value)
            rendered_rows.append(current_row)

        if auto_wrap_to_terminal and headers:
            try:
                term_width = shutil.get_terminal_size(fallback=(120, 24)).columns
                # Keep table width slightly under terminal width to avoid awkward wraps.
                effective_width = max(60, int(term_width) - 2)
                ncols = len(headers)
                target_total = max(40, effective_width - (3 * ncols) - 1)
                widths = []
                max_col_width = max(min_col_width, int(max_col_width))
                min_col_width = max(6, int(min_col_width))
                for index, header in enumerate(headers):
                    field_name = fields[index]
                    col_vals = [row[index] for row in rendered_rows if index < len(row)]
                    observed = max([len(header)] + [len(value) for value in col_vals]) if col_vals else len(header)
                    local_max_width = max_col_width
                    if column_max_widths and field_name in column_max_widths:
                        try:
                            local_max_width = max(min_col_width, int(column_max_widths[field_name]))
                        except Exception:
                            local_max_width = max_col_width
                    widths.append(min(local_max_width, max(min_col_width, observed)))
                while sum(widths) > target_total:
                    reducible = [index for index, width in enumerate(widths) if width > min_col_width]
                    if not reducible:
                        break
                    largest = max(reducible, key=lambda idx: widths[idx])
                    widths[largest] -= 1
                for index, header in enumerate(headers):
                    table.max_width[header] = widths[index]
            except Exception:
                pass

        for row_index, row in enumerate(rendered_rows):
            table.add_row(
                row,
                divider=bool(
                    divider_after_row_indices
                    and row_index in divider_after_row_indices
                    and row_index != len(rendered_rows) - 1
                ),
            )

        table_output = table.get_string()
        if highlight_row_indices and highlight_prefix and highlight_suffix:
            table_lines = table_output.splitlines()
            content_line_index = max(len(table.get_string(start=0, end=0).splitlines()) - 1, 0)
            for row_index in range(len(rendered_rows)):
                content_lines = table.get_string(
                    start=row_index,
                    end=row_index + 1,
                    header=False,
                    border=False,
                ).splitlines()
                if row_index in highlight_row_indices:
                    for offset in range(len(content_lines)):
                        target_index = content_line_index + offset
                        if 0 <= target_index < len(table_lines):
                            table_lines[target_index] = f"{highlight_prefix}{table_lines[target_index]}{highlight_suffix}"
                content_line_index += len(content_lines)
            table_output = "\n".join(table_lines)

        print(table_output)
        if len(rows) > max_rows:
            print(f"{UtilityTools.BRIGHT_BLACK}... ({len(rows) - max_rows} more rows){UtilityTools.RESET}")

    @staticmethod
    def summary_wrapup(
        project_id,
        service_account_name,
        objects_list,
        properties_list,
        primary_resource=None,
        secondary_title_name=None,
        max_width=None,
        output_format=None,
        primary_sort_key=None,
        show_breakers: bool = False,
    ):
        from gcpwn.core.utils.module_helpers import extract_location_from_resource_name, extract_path_segment

        _ = (service_account_name, max_width)
        candidates = (
            [output_format]
            if isinstance(output_format, (str, bytes))
            else list(output_format or [UtilityTools.TABLE_OUTPUT_FORMAT])
        )
        normalized = [str(token or "").strip().lower() for token in candidates if str(token or "").strip()]
        default_output = str(getattr(UtilityTools, "TABLE_OUTPUT_FORMAT", "text") or "text").strip().lower()
        if default_output not in {"table", "text"}:
            default_output = "text"
        formats = [next((token for token in normalized if token in {"table", "text"}), default_output)]
        fields = list(properties_list)
        if secondary_title_name:
            fields.append(secondary_title_name)

        def _is_parent_reference_field(field_name: str) -> bool:
            token = str(field_name or "").strip().lower()
            if not token or token == "name":
                return False
            if token.endswith("_name"):
                return True
            return token in {
                "repository",
                "package",
                "instance",
                "service",
                "api",
                "namespace",
                "cluster",
                "dataset",
                "table",
                "pipeline",
                "release",
                "target",
                "keyring",
                "key",
                "router",
                "queue",
            }

        if isinstance(objects_list, list):
            normalized_fields = [str(field or "").strip() for field in fields]
            if not any(
                _is_parent_reference_field(field_name)
                for field_name in normalized_fields
                if field_name != "name"
            ):
                candidates: dict[str, tuple[int, int]] = {}
                for obj in objects_list or []:
                    if not isinstance(obj, dict):
                        continue
                    for key, value in obj.items():
                        field_name = str(key or "").strip()
                        rendered = str(value or "").strip()
                        if not field_name or field_name in normalized_fields:
                            continue
                        if not _is_parent_reference_field(field_name) or "/" not in rendered:
                            continue
                        path_depth = rendered.count("/")
                        seen_count, max_depth = candidates.get(field_name, (0, 0))
                        candidates[field_name] = (seen_count + 1, max(max_depth, path_depth))
                if candidates:
                    parent_field = min(
                        candidates,
                        key=lambda field_name: (
                            -candidates[field_name][1],
                            -candidates[field_name][0],
                            field_name,
                        ),
                    )
                    fields = [parent_field, *fields]

        rows = []
        if isinstance(objects_list, dict):
            for obj, secondary_values in objects_list.items():
                row = {
                    prop: UtilityTools._normalize_cell(
                        getattr(obj, prop, "N/A"),
                        field_name=prop,
                        preserve_paths=UtilityTools._is_path_field(prop),
                    )
                    for prop in fields
                }
                if secondary_title_name:
                    rendered = [str(item) for item in secondary_values or []]
                    row[secondary_title_name] = "* " + "\n* ".join(rendered) if rendered else "[EMPTY]"
                rows.append(row)
        else:
            for obj in objects_list or []:
                row = {}
                for prop in fields:
                    if isinstance(obj, dict):
                        value = obj.get(prop, "")
                    else:
                        value = getattr(obj, prop, "")
                    row[prop] = UtilityTools._normalize_cell(
                        value,
                        field_name=prop,
                        preserve_paths=UtilityTools._is_path_field(prop),
                    )
                rows.append(row)

        normalized_fields = [str(field or "").strip() for field in fields]
        if (
            "name" in normalized_fields
            and not any(
                any(token in str(field_name or "").strip().lower() for token in ("location", "region", "zone"))
                for field_name in normalized_fields
                if field_name != "name"
            )
        ):
            def _derive_location(resource_name: str) -> str:
                token = str(resource_name or "").strip()
                if not token or "/" not in token:
                    return ""
                location = extract_location_from_resource_name(token, include_zones=True)
                if location:
                    return location
                return extract_path_segment(token, "regions")

            if any(
                _derive_location(str((row or {}).get("name") or "").strip())
                for row in rows or []
                if isinstance(row, dict)
            ):
                output_rows: list[dict[str, Any]] = []
                for row in rows or []:
                    if not isinstance(row, dict):
                        output_rows.append(row)
                        continue
                    normalized_row = dict(row)
                    resource_name = str(normalized_row.get("name") or "").strip()
                    derived_location = _derive_location(resource_name)
                    if derived_location:
                        normalized_row["location"] = derived_location
                        normalized_row["name"] = UtilityTools._shorten_resource_ref(resource_name)
                    output_rows.append(normalized_row)
                rows = output_rows

                output_fields: list[str] = []
                inserted = False
                for field_name in normalized_fields:
                    if field_name == "name" and not inserted:
                        output_fields.append("location")
                        inserted = True
                    output_fields.append(field_name)
                fields = output_fields

        terminal_width = shutil.get_terminal_size((120, 24)).columns
        breaker = "-" * max(20, terminal_width - 10)
        if show_breakers:
            print(f"{UtilityTools.BOLD}[*] {breaker} [*]{UtilityTools.RESET}")

        if not rows:
            return

        print(
            f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] GCPwn found {len(rows)} {primary_resource} in project {project_id}"
            f"{UtilityTools.RESET}"
        )

        previous_output_format = UtilityTools.TABLE_OUTPUT_FORMAT
        try:
            if "table" in formats:
                print(f"{UtilityTools.BOLD}[*] TABLE OUTPUT ({project_id}){UtilityTools.RESET}")
                UtilityTools.TABLE_OUTPUT_FORMAT = "table"
                UtilityTools.print_limited_table(
                    rows,
                    fields,
                    resource_type=primary_resource,
                    sort_key=primary_sort_key,
                )
            elif "text" in formats:
                print(f"{UtilityTools.BOLD}[*] TEXT OUTPUT ({project_id}){UtilityTools.RESET}")
                UtilityTools.TABLE_OUTPUT_FORMAT = "text"
                UtilityTools.print_limited_table(
                    rows,
                    fields,
                    resource_type=primary_resource,
                    sort_key=primary_sort_key,
                    max_rows=len(rows),
                    auto_wrap_to_terminal=False,
                )
        finally:
            UtilityTools.TABLE_OUTPUT_FORMAT = previous_output_format

        if show_breakers:
            print(f"{UtilityTools.BOLD}[*] {breaker} [*]{UtilityTools.RESET}")

    @staticmethod
    def log_action(workspace_name, action):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file = resolve_named_save_path(workspace_name, filename="history_log.txt", key="System Log")
        with open(log_file, "a", encoding="utf-8") as file_handle:
            file_handle.write(f"[{timestamp}] {action}\n")
