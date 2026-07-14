"""Shared module runtime helpers: arg parsing, error handling, paging, fan-out.

The building blocks every module composes from -- standard argparse flags
(--iam/--get/--threads/...), the Google API error handlers that normalize
"API disabled" vs "403 denied" vs "404", region/zone fan-out with disabled-API
short-circuit, and the action-accumulator helpers that batch discovered
permissions for a single main-thread flush.

Error-handling contract (relied on by the enum framework and GcpListResource):
``handle_service_error``/``handle_discovery_error`` return the sentinel string
``"Not Enabled"`` for a disabled API (so a region scan can stop early) and
``None`` for denied/404/500.

Threading contract: ``parallel_map``/``ThreadPoolExecutor`` workers must do only
network/CPU work and RETURN results; DB writes (session.insert_*/get_data) are
main-thread only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from collections import defaultdict
from time import perf_counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, Sequence

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions

_API_DISABLED_SUBSTRINGS = (
    "Enable it by visiting",
    "has not been used in project",
)

# Cooperative cancellation. A single Ctrl+C in the REPL sets this flag so every
# fan-out loop -- ``parallel_map`` here AND the enum_all service pool -- stops
# starting NEW work immediately instead of draining its whole queue (the reason a
# lone Ctrl+C used to look ignored: the pool kept feeding queued units). Cleared
# at the start of each fresh orchestrator run.
_CANCEL_EVENT = threading.Event()


def request_cancel() -> None:
    """Signal all cooperative fan-out loops to stop launching new work ASAP."""
    _CANCEL_EVENT.set()


def clear_cancel() -> None:
    """Reset the cancel flag at the start of a fresh run."""
    _CANCEL_EVENT.clear()


def cancel_requested() -> bool:
    """True once :func:`request_cancel` fired (until :func:`clear_cancel`)."""
    return _CANCEL_EVENT.is_set()


# Opt-in "fail fast on 403 denied": when set, a permission-denied 403 short-circuits
# region/zone fan-out just like a disabled API does, instead of probing every region on
# the chance that permissions differ per region. Process-global (like the cancel flag)
# so it reaches the deep error handlers without threading a param through every list
# call; the CLI resets it before each module run and enum_all sets it from --stop-on-denied.
_STOP_ON_DENIED = threading.Event()


def set_stop_on_denied(enabled: bool) -> None:
    """Enable/disable short-circuiting region fan-out on the first 403 permission denial."""
    if enabled:
        _STOP_ON_DENIED.set()
    else:
        _STOP_ON_DENIED.clear()


def stop_on_denied() -> bool:
    """True when --stop-on-denied is active for the current run."""
    return _STOP_ON_DENIED.is_set()

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
            "default": 4,
            "help": "Worker threads for region/zone fan-out (default: 4)",
        },
    },
}


def is_api_disabled_error(exc: Exception | str) -> bool:
    """True if the error text looks like a "service not enabled" 403 (vs a real
    permission denial). Distinguishing the two drives the short-circuit behavior."""
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
    """Classify a google-api-core exception, print the right message, return a sentinel.

    For GAPIC/client-library calls. Returns ``"Not Enabled"`` for a disabled-API
    403 (when ``return_not_enabled``) so callers can short-circuit region fan-out,
    and ``None`` for a 403 denial, 404, or any other error. Never re-raises -- the
    caller treats a falsy/non-sentinel result as "no rows from this region".
    """
    if _FORBIDDEN_EXCEPTIONS and isinstance(exc, _FORBIDDEN_EXCEPTIONS):
        if is_api_disabled_error(exc):
            UtilityTools.print_403_api_disabled(service_label, project_id)
            return "Not Enabled" if return_not_enabled else None
        UtilityTools.print_403_api_denied(api_name, resource_name=resource_name)
        # --stop-on-denied: treat the denial like a disabled API so region/zone fan-out
        # short-circuits (returns the same "Not Enabled" sentinel) instead of probing on.
        if return_not_enabled and stop_on_denied():
            print(f"[*] --stop-on-denied: skipping remaining regions/zones for {api_name} after a 403 denial.")
            return "Not Enabled"
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
    """Pull (HTTP status, best human message) out of a googleapiclient HttpError.

    Digs the message out of the JSON error body (preferring ``error.details[0]``,
    then ``error.message``). Returns ``(None, str(exc))`` for non-HttpError or
    unparseable errors. Used by ``handle_discovery_error`` to branch on status."""
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
    """Discovery-API (googleapiclient) counterpart to ``handle_service_error``.

    Branches on the HTTP status: 403 prints disabled-vs-denied and returns
    ``"Not Enabled"`` (the short-circuit sentinel); 404 prints and returns
    ``None``; anything else prints a 500 and returns ``None``."""
    status, _message = extract_discovery_http_error(exc)
    if status == 403:
        if service_label and is_api_disabled_error(exc):
            UtilityTools.print_403_api_disabled(service_label, getattr(session, "project_id", None))
            return "Not Enabled"  # disabled API -> short-circuit the rest of the region scan
        # A permission denial on one resource/region normally does NOT stop the scan
        # (matches handle_service_error); return None so other regions still run --
        # unless --stop-on-denied opted into short-circuiting on the first denial.
        UtilityTools.print_403_api_denied(api_name, resource_name=resource_name)
        if stop_on_denied():
            print(f"[*] --stop-on-denied: skipping remaining regions/zones for {api_name} after a 403 denial.")
            return "Not Enabled"
        return None
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
    """Drain a discovery-API paginated list into one flat list of item dicts.

    ``request_builder(page_token)`` must return an executable request for that
    page; this loops on ``nextPageToken`` and accumulates ``resp[items_key]``."""
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
    """Register the named standard flags (from STANDARD_ARGUMENT_SPECS) onto ``parser``.

    ``argument_names`` are keys like "iam"/"get"/"threads"; ``overrides`` can swap
    a flag's strings or kwargs per-call. Raises ValueError for an unknown name."""
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
    """Build a module's argparse namespace from a component list + standard flags.

    Adds a ``--<key>`` store_true flag per (component_key, help) pair, then the
    requested standard args and any module-specific ``add_extra_args(parser)``,
    and guarantees a ``--threads`` flag exists. ``allow_abbrev=False`` so partial
    flags don't silently match. Returns the parsed Namespace."""
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
        parser.add_argument("--threads", type=int, default=4, help="Worker threads for region/zone fan-out (default: 4)")
    return parser.parse_args(list(user_args))


def resolve_selected_components(args: argparse.Namespace, component_keys: Sequence[str]) -> dict[str, bool]:
    """Decide which components run: explicit subset if any --X flag is set, else ALL.

    Returns {key: should_run}. The "no flags => everything" default is what lets
    `modules run enum_<svc>` with no args enumerate the whole service."""
    keys = list(component_keys or [])
    any_selected = any(bool(getattr(args, key, False)) for key in keys)
    return {key: (bool(getattr(args, key, False)) if any_selected else True) for key in keys}


def parse_csv_arg(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def flatten_arg_groups(values: list[list[str]] | None) -> list[str]:
    """Flatten an argparse ``action="append", nargs="+"`` result into a flat token list.

    Repeating such a flag (and/or passing multiple values per use) yields a
    list-of-lists; this collapses it to a single list, tolerating None groups.
    """
    return [token for group in (values or []) for token in (group or [])]


class DownloadBudget:
    """Per-download-TYPE wall-clock cap for enum downloads.

    Create ONE per download UNIT (a download type like log entries / function
    sources, OR a finer unit like a single storage bucket) at the START of that
    unit's download loop, then call ``exceeded()`` before each item. Once the unit
    has run longer than the session's ``download_time_budget`` seconds (set by
    enum_all's ``--download-timeout``; 0/unset = unlimited), ``exceeded()`` returns
    True -- printing a one-time notice -- so the caller skips the REST of that unit
    and moves on. The clock resets per instance, so a fast unit isn't penalized by a
    slow one (storage makes this per-bucket; most services make it per-type). The read
    path is thread-safe (perf_counter); the one-time notice is best-effort under
    concurrency (a rare double-print is harmless).
    """

    def __init__(self, session, *, label: str) -> None:
        self.budget = int(getattr(session, "download_time_budget", 0) or 0)
        self.label = label
        self._start = perf_counter()
        self._announced = False

    def exceeded(self) -> bool:
        if self.budget <= 0:
            return False
        if (perf_counter() - self._start) <= self.budget:
            return False
        if not self._announced:
            self._announced = True
            print(
                f"{UtilityTools.YELLOW}[!] Download time budget ({self.budget}s) reached for "
                f"{self.label}; skipping the rest and moving on.{UtilityTools.RESET}"
            )
        return True


def parse_csv_file_args(csv_value: str | None = None, file_path: str | None = None) -> list[str]:
    """Merge tokens from an inline CSV string and a file (one/CSV per line, '#'
    comments) into a de-duplicated, order-preserving list. Backs the manual
    --X-ids / --X-ids-file flags."""
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
    """Apply ``worker`` to each item across a thread pool, preserving input order.

    The workhorse fan-out primitive for region/parent enumeration. A failing
    worker yields ``None`` in that slot (errors are swallowed, never raised) so
    one bad region doesn't sink the batch. Pool size is capped at min(threads,
    32, len(items)); a size of 1 runs serially.

    THREADING INVARIANT: workers must do only network/CPU work and RETURN their
    result. DB writes are main-thread only -- calling session.get_data/insert_*
    from inside ``worker`` raises sqlite3.ProgrammingError. Collect the returned
    results, then write on the main thread."""
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
            if cancel_requested():
                break
            output.append(worker(item))
            if show_progress and _should_emit(idx):
                print(f"[*] {label}: {idx}/{total} completed (last={_progress_token(item)})")
        return output

    results: list[Any] = [None] * len(entries)
    executor = ThreadPoolExecutor(max_workers=worker_count)
    try:
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
            # A single Ctrl+C sets the cancel flag; stop collecting and let the
            # finally-block drop the still-queued regions/zones rather than draining
            # the whole fan-out.
            if cancel_requested():
                break
    except KeyboardInterrupt:
        request_cancel()
        raise
    finally:
        # cancel_futures drops the still-queued regions/zones immediately. On the
        # cancel/interrupt path we DO wait for the <=worker_count in-flight calls to
        # finish so nothing keeps printing after control returns to the REPL; on the
        # normal path every future is already done so the wait is a no-op.
        executor.shutdown(wait=cancel_requested(), cancel_futures=True)
    return results


def map_regions_with_disabled_short_circuit(
    regions: Iterable[str],
    worker: Callable[[str], Any],
    *,
    threads: int = 3,
    progress_label: str | None = None,
    show_progress: bool = True,
) -> list[tuple[str, Any]]:
    """Run ``worker(region)`` across regions, but bail early if the API is disabled.

    Probes the FIRST region serially: if it returns the ``"Not Enabled"`` sentinel
    the API is off everywhere, so the remaining (potentially hundreds of) regions
    are skipped. Otherwise the rest fan out via ``parallel_map``. Returns
    ``[(region, result)]`` pairs in region order."""
    region_list = [str(region or "").strip() for region in regions or [] if str(region or "").strip()]
    if not region_list:
        return []
    if cancel_requested():  # a Ctrl+C landed mid-service: don't start a new region scan
        return []

    first_region = region_list[0]
    first_result = worker(first_region)
    results: list[tuple[str, Any]] = [(first_region, first_result)]
    if first_result == "Not Enabled":
        if show_progress:
            label = str(progress_label or "Region scan").strip() or "Region scan"
            # "Not Enabled" is the short-circuit sentinel for a disabled API OR (under
            # --stop-on-denied) a 403 denial; the specific reason was printed above.
            print(
                f"[*] {label}: short-circuiting remaining regions "
                f"(see the reason reported for region '{first_region}' above)."
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


def get_cached_rows(
    session,
    table_name: str,
    *,
    project_id: str | None = None,
    columns="*",
    conditions: str | None = None,
    where: dict[str, Any] | None = None,
    params: Iterable[Any] | None = None,
):
    """Read previously-enumerated rows from a service table, scoped to project_id.

    Adds ``project_id`` to the where clause so NESTED components can fall back to
    cached parents from an earlier run. Service tables are workspace-scoped --
    session.get_data adds workspace_id automatically. Main-thread only."""
    scoped_where = dict(where or {})
    if project_id:
        scoped_where["project_id"] = project_id
    return session.get_data(
        table_name,
        columns=columns,
        conditions=conditions,
        where=scoped_where or None,
        params=params,
    )


def print_missing_dependency(
    *,
    component_name: str,
    dependency_name: str,
    module_name: str,
    manual_flags: Sequence[str] | None = None,
) -> None:
    """Print the standard "skipping <component>; no <dependency> cached" notice with
    a hint to run the parent enumeration (or use ``manual_flags``) first."""
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


def process_with_progress(items, fn, *, label: str = "resources", min_show: int = 25):
    """Apply ``fn`` to each item, showing an in-place ``reviewed X/Y`` counter for
    large sets. Ctrl+C stops the rest and moves on, returning the partial results.

    Lets the user bail out of pathologically large enumerations (e.g. a bucket
    with millions of objects) without killing the whole module. The counter only
    renders on an interactive TTY for sets >= ``min_show`` so non-interactive /
    parallel (buffered) runs stay clean.
    """
    items = list(items)
    total = len(items)
    show = total >= min_show and sys.stdout.isatty()
    results = []
    try:
        for index, item in enumerate(items, 1):
            results.append(fn(item))
            if show:
                sys.stdout.write(f"\r{UtilityTools.BOLD}[*] {label}: reviewed {index}/{total} (Ctrl+C to skip rest){UtilityTools.RESET}")
                sys.stdout.flush()
        if show:
            sys.stdout.write("\r" + " " * 70 + "\r")
            sys.stdout.flush()
    except KeyboardInterrupt:
        if show:
            sys.stdout.write("\n")
            sys.stdout.flush()
        print(f"[!] Interrupted while reviewing {label} at {len(results)}/{total}; moving on.")
    return results


def make_action_accumulators():
    """The standard (scope, api, iam) action accumulators every enum module builds."""
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    return scope_actions, api_actions, iam_actions


def flush_actions(session, project_id, column_name, accumulators, *, credname_override=None):
    """Persist the three accumulators under one service action column (the tail
    repeated verbatim at the end of every enum module). ``credname_override``
    attributes the discovered permissions to specific credentials (e.g. an HMAC
    key's service account) instead of the active session credential.

    Permissions are recorded as evidence with provenance, not booleans: the scope
    and api accumulators flush as direct_api evidence, while iam_actions flushes
    tagged ACTION_EVIDENCE_TEST_IAM_PERMISSIONS. Empty accumulators are skipped.
    DB write -- MAIN THREAD ONLY (must run after all parallel_map workers return)."""
    scope_actions, api_actions, iam_actions = accumulators
    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name=column_name, credname_override=credname_override)
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name=column_name, credname_override=credname_override)
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name=column_name,
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
            credname_override=credname_override,
        )

