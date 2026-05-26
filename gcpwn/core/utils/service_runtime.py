from __future__ import annotations

import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, Sequence

from gcpwn.core.console import UtilityTools

_API_DISABLED_SUBSTRINGS = (
    "Enable it by visiting",
    "has not been used in project",
)

try:  # pragma: no cover
    from google.api_core.exceptions import Forbidden as _Forbidden, NotFound as _NotFound

    _FORBIDDEN_EXCEPTIONS = (_Forbidden,)
    _NOTFOUND_EXCEPTIONS = (_NotFound,)
except Exception:  # pragma: no cover
    _FORBIDDEN_EXCEPTIONS: tuple[type[BaseException], ...] = ()
    _NOTFOUND_EXCEPTIONS: tuple[type[BaseException], ...] = ()


STANDARD_ARGUMENT_SPECS = {
    "iam": {
        "flags": ("--iam",),
        "kwargs": {
            "action": "store_true",
            "help": "Run TestIamPermissions checks",
        },
    },
    "get": {
        "flags": ("--get",),
        "kwargs": {
            "action": "store_true",
            "help": "After listing, also fetch per-resource metadata where supported",
        },
    },
    "download": {
        "flags": ("--download",),
        "kwargs": {
            "action": "store_true",
            "help": "Download supported artifacts",
        },
    },
    "debug": {
        "flags": ("-v", "--debug"),
        "kwargs": {
            "action": "store_true",
            "help": "Verbose debug output",
        },
    },
    "threads": {
        "flags": ("--threads",),
        "kwargs": {
            "type": int,
            "default": 3,
            "help": "Worker threads for region/zone fan-out (default: 3)",
        },
    },
}


def is_api_disabled_error(exc: Exception | str) -> bool:
    message = str(exc or "")
    return any(needle in message for needle in _API_DISABLED_SUBSTRINGS)


def handle_service_error(
    exc: Exception,
    *,
    api_name: str,
    resource_name: str,
    service_label: str,
    project_id: str | None = None,
    return_not_enabled: bool = True,
    not_found_label: str | None = None,
    quiet_not_found: bool = False,
) -> str | None:
    if _FORBIDDEN_EXCEPTIONS and isinstance(exc, _FORBIDDEN_EXCEPTIONS):
        if is_api_disabled_error(exc):
            UtilityTools.print_403_api_disabled(service_label, project_id)
            return "Not Enabled" if return_not_enabled else None
        UtilityTools.print_403_api_denied(api_name, resource_name=resource_name)
        return None
    if _NOTFOUND_EXCEPTIONS and isinstance(exc, _NOTFOUND_EXCEPTIONS):
        if not quiet_not_found:
            UtilityTools.print_404_resource(not_found_label or resource_name)
        return None
    UtilityTools.print_500(resource_name, api_name, exc)
    return None


def build_discovery_service(credentials, service_name: str, version: str, *, scopes: Iterable[str] | None = None):
    from googleapiclient.discovery import build  # type: ignore
    import google.auth.credentials

    scoped = google.auth.credentials.with_scopes_if_required(credentials, scopes or ())
    return build(str(service_name), str(version), credentials=scoped, cache_discovery=False)


def extract_discovery_http_error(exc: Exception) -> tuple[int | None, str]:
    status = None
    message = str(exc)
    try:
        from googleapiclient.errors import HttpError  # type: ignore

        if isinstance(exc, HttpError):
            resp = getattr(exc, "resp", None)
            if resp is not None:
                try:
                    status = int(getattr(resp, "status", None))
                except Exception:
                    status = None

            content = getattr(exc, "content", b"")
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="ignore")
            if content:
                try:
                    payload = json.loads(content)
                    message = (
                        payload.get("error", {}).get("details", [{}])[0].get("message")
                        or payload.get("error", {}).get("message")
                        or str(content)
                    )
                except Exception:
                    message = str(content)
    except Exception:
        pass
    return status, message


def handle_discovery_error(
    session,
    api_name: str,
    resource_name: str,
    exc: Exception,
    *,
    service_label: str | None = None,
) -> str | None:
    status, _message = extract_discovery_http_error(exc)
    if status == 403:
        if service_label and is_api_disabled_error(exc):
            UtilityTools.print_403_api_disabled(service_label, getattr(session, "project_id", None))
        else:
            UtilityTools.print_403_api_denied(api_name, resource_name=resource_name)
        return "Not Enabled"
    if status == 404:
        UtilityTools.print_404_resource(resource_name)
        return None
    UtilityTools.print_500(resource_name, api_name, exc)
    return None


def paged_list(
    request_builder: Callable[[str | None], Any],
    *,
    items_key: str,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    page_token: str | None = None
    while True:
        req = request_builder(page_token)
        resp = req.execute()
        items = resp.get(items_key, []) if isinstance(resp, dict) else []
        if isinstance(items, list):
            output.extend([item for item in items if isinstance(item, dict)])
        page_token = resp.get("nextPageToken") if isinstance(resp, dict) else None
        if not page_token:
            break
    return output


def add_standard_arguments(
    parser: argparse.ArgumentParser,
    argument_names: Sequence[str],
    *,
    overrides: dict[str, dict] | None = None,
) -> argparse.ArgumentParser:
    for argument_name in argument_names or []:
        spec = STANDARD_ARGUMENT_SPECS.get(argument_name)
        if spec is None:
            raise ValueError(f"Unknown standard argument: {argument_name}")
        flags = spec["flags"]
        kwargs = dict(spec["kwargs"])
        override = (overrides or {}).get(argument_name, {})
        if "flags" in override:
            flags = tuple(override["flags"])
        kwargs.update({key: value for key, value in override.items() if key != "flags"})
        parser.add_argument(*flags, **kwargs)
    return parser


def parse_component_args(
    user_args: Sequence[str],
    *,
    description: str,
    components: Sequence[tuple[str, str]],
    add_extra_args=None,
    standard_args: Sequence[str] | None = None,
    standard_arg_overrides: dict[str, dict] | None = None,
):
    parser = argparse.ArgumentParser(description=description, allow_abbrev=False)
    for component_key, help_text in components:
        parser.add_argument(
            f"--{component_key.replace('_', '-')}",
            dest=component_key,
            action="store_true",
            help=help_text,
        )
    add_standard_arguments(parser, standard_args or (), overrides=standard_arg_overrides)
    if callable(add_extra_args):
        add_extra_args(parser)
    if not any(getattr(action, "dest", "") == "threads" for action in parser._actions):
        parser.add_argument("--threads", type=int, default=3, help="Worker threads for region/zone fan-out (default: 3)")
    return parser.parse_args(list(user_args))


def resolve_selected_components(args: argparse.Namespace, component_keys: Sequence[str]) -> dict[str, bool]:
    keys = list(component_keys or [])
    any_selected = any(bool(getattr(args, key, False)) for key in keys)
    return {key: (bool(getattr(args, key, False)) if any_selected else True) for key in keys}


def parse_csv_arg(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def parse_csv_file_args(csv_value: str | None = None, file_path: str | None = None) -> list[str]:
    file_entries: list[str] = []
    filepath = str(file_path or "").strip()
    if filepath:
        with open(filepath, encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                file_entries.extend(parse_csv_arg(line))

    values: list[str] = []
    seen: set[str] = set()
    for entry in [*parse_csv_arg(csv_value), *file_entries]:
        if entry in seen:
            continue
        seen.add(entry)
        values.append(entry)
    return values


def parse_id_input_values(
    values: Sequence[str] | None,
    *,
    value_label: str = "id",
    numeric_only: bool = False,
    files_only: bool = False,
) -> list[str]:
    """
    Parse identifiers from inline tokens or explicit file tokens.

    Supported token forms:
    - direct IDs (comma or space-separated via argparse tokenization)
    - file paths (one ID per line, comments allowed with '#') when files_only=True
    """
    output: list[str] = []
    seen: set[str] = set()
    label = str(value_label or "id").strip()

    def _emit(candidate: str) -> None:
        token = str(candidate or "").strip()
        if not token or token.startswith("#"):
            return
        for parsed in parse_csv_arg(token):
            normalized = str(parsed or "").strip()
            if not normalized:
                continue
            if numeric_only and not normalized.isdigit():
                raise ValueError(f"Invalid {label} '{normalized}'. Expected an integer value.")
            if normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)

    for raw_token in values or []:
        token = str(raw_token or "").strip()
        if not token:
            continue
        if files_only and not os.path.isfile(token):
            raise ValueError(f"Invalid {label} file '{token}'. Expected an existing file path.")
        if files_only:
            with open(token, encoding="utf-8") as handle:
                for line in handle:
                    _emit(line)
            continue
        _emit(token)

    return output


def parallel_map(
    items: Iterable[Any],
    worker: Callable[[Any], Any],
    *,
    threads: int = 3,
    progress_label: str | None = None,
    show_progress: bool = True,
) -> list[Any]:
    entries = list(items or [])
    if not entries:
        return []

    label = str(progress_label or "Progress").strip() or "Progress"
    total = len(entries)

    def _progress_token(item: Any) -> str:
        token = str(item)
        return token if len(token) <= 64 else token[:61] + "..."

    def _should_emit(completed: int) -> bool:
        if total <= 50:
            return True
        if completed in (1, total):
            return True
        step = max(5, total // 20)
        return completed % step == 0

    if show_progress:
        print(f"[*] {label}: starting {total} work item(s)")

    try:
        parsed_threads = int(threads)
    except Exception:
        parsed_threads = 3
    if parsed_threads < 1:
        parsed_threads = 1
    worker_count = min(parsed_threads, 32, len(entries))
    if worker_count <= 1:
        output = []
        for idx, item in enumerate(entries, start=1):
            output.append(worker(item))
            if show_progress and _should_emit(idx):
                print(f"[*] {label}: {idx}/{total} completed (last={_progress_token(item)})")
        return output

    results: list[Any] = [None] * len(entries)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_context = {executor.submit(worker, item): (idx, item) for idx, item in enumerate(entries)}
        completed = 0
        for future in as_completed(future_to_context):
            idx, item = future_to_context[future]
            try:
                results[idx] = future.result()
            except Exception:
                results[idx] = None
            finally:
                completed += 1
                if show_progress and _should_emit(completed):
                    print(f"[*] {label}: {completed}/{total} completed (last={_progress_token(item)})")
    return results


def map_regions_with_disabled_short_circuit(
    regions: Iterable[str],
    worker: Callable[[str], Any],
    *,
    threads: int = 3,
    progress_label: str | None = None,
    show_progress: bool = True,
) -> list[tuple[str, Any]]:
    region_list = [str(region or "").strip() for region in regions or [] if str(region or "").strip()]
    if not region_list:
        return []

    first_region = region_list[0]
    first_result = worker(first_region)
    results: list[tuple[str, Any]] = [(first_region, first_result)]
    if first_result == "Not Enabled":
        if show_progress:
            label = str(progress_label or "Region scan").strip() or "Region scan"
            print(
                f"[*] {label}: API not enabled (detected in region '{first_region}'); "
                "skipping remaining regions."
            )
        return results

    remaining_regions = region_list[1:]
    if not remaining_regions:
        return results

    remaining_results = parallel_map(
        remaining_regions,
        lambda region: (region, worker(region)),
        threads=threads,
        progress_label=progress_label,
        show_progress=show_progress,
    )
    return [*results, *remaining_results]


def get_cached_rows(session, table_name: str, *, project_id: str | None = None, columns="*", conditions: str | None = None):
    final_conditions: list[str] = []
    if project_id:
        final_conditions.append(f'project_id="{project_id}"')
    if conditions:
        final_conditions.append(f"({conditions})")
    return session.get_data(
        table_name,
        columns=columns,
        conditions=" AND ".join(final_conditions) if final_conditions else None,
    )


def print_missing_dependency(
    *,
    component_name: str,
    dependency_name: str,
    module_name: str,
    manual_flags: Sequence[str] | None = None,
) -> None:
    hint = ""
    if manual_flags:
        hint = f"Supply {' or '.join(manual_flags)} to target {dependency_name.lower()} manually, or "
    print(
        f"{UtilityTools.YELLOW}[*] Skipping {component_name} because no {dependency_name.lower()} were available."
        f"{UtilityTools.RESET}"
    )
    print(
        f"    {hint}run `modules run {module_name} --{dependency_name.lower().replace(' ', '-')}` first"
        " so the dependency is cached."
    )
