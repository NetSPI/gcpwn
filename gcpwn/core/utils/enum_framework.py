"""Declarative enumeration framework.

Every ``enum_<service>`` module describes its resources as a list of ``Component``
specs and hands them to :func:`run_components`. The runner provides the single
uniform enumeration loop that used to be copy-pasted into every module:

    (optional) manual --X-ids/--X-names  -> hydrate those specific resources
    otherwise list (region fan-out / project / parent-nested)
      -> --get hydrate
      -> --iam testIamPermissions
      -> save
      -> summary_wrapup (or a "No <title> found" line)
    ... then flush the three action accumulators once.

This mirrors the config-driven ``GcpListResource`` base (Move 2): modules become
declarations, the shared behavior lives in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_location_from_resource_name, name_from_input
from gcpwn.core.utils.service_runtime import (
    flush_actions,
    get_cached_rows,
    make_action_accumulators,
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_csv_file_args,
    print_missing_dependency,
    process_with_progress,
    resolve_selected_components,
)

# Scope modes
REGION = "region"      # fan out resource.list(project_id=, location=<each region>)
PROJECT = "project"    # single resource.list(project_id=, location="global") (parent = projects/<p>)
NESTED = "nested"      # resource.list(parent=<each parent name>) for every parent component row


@dataclass
class Component:
    """Declarative spec for one enumerable resource type within an enum module.

    A module supplies a list of these to :func:`run_components`. Each Component
    maps a CLI flag (``--<key>``) to a ``GcpListResource`` subclass and the knobs
    that shape its enumeration. Key fields beyond the obvious:

      scope          REGION (fan out list across regions), PROJECT (single global
                     list), or NESTED (list under every parent component's rows).
      parent_key     NESTED only: the component whose rows are the parents. Parents
                     come from this run's discovered rows, explicit manual parent
                     names, or the DB cache (in that order) -- so a child can run
                     without re-listing its parent.
      parent_filter  NESTED only: only nest under parent rows where it returns true.
      persist        False => list/summarize only, never save() (resource has no table).
      summarize      False => skip the framework summary; the module renders its own.
      enrich_fn      Per-row hook after get/iam, before save (e.g. fetch a sensitive
                     key, anonymous-access probe). Signature:
                     enrich_fn(rows, *, resource, args, api_actions) -> rows.
      list_kwargs    Static dict, or callable(args)->dict, of extra kwargs forwarded
                     to list()/get() (lets flags like --full-view vary the call).
      manual_id_arg  Enables --<arg>/--<arg>-file to target specific resources by
                     name/id (hydrated via get(), which requires --get).
    """

    key: str
    resource_cls: type
    title: str
    primary_resource: str
    help_text: str = ""
    scope: str = REGION
    locations: Sequence[str] | None = None          # REGION: fixed locations; None => region_resolver
    parent_key: str | None = None                   # NESTED: component key whose rows are the parents
    dependency_label: str | None = None             # NESTED: name shown in the missing-dependency notice
    save_parent_kwarg: str | None = None            # NESTED: extra save kwarg carrying the parent name
    parent_filter: Callable | None = None           # NESTED: only nest under parent rows where parent_filter(row) is true
    primary_sort_key: str = "location"
    columns: Sequence[str] | None = None            # None => resource.COLUMNS
    persist: bool = True                            # False => list/summarize only, never save() (resource has no table)
    summarize: bool = True                          # False => skip the framework summary (module renders a bespoke one)
    supports_get: bool = True                       # False => never call get() even with --get
    supports_iam: bool = True
    iam_unsupported_message: str | None = None
    list_kwargs: dict[str, Any] = field(default_factory=dict)  # extra kwargs forwarded to list()/get()
    # Per-row enrichment after get/iam, before save (e.g. fetch a sensitive key/auth string,
    # anonymous-access probe). Signature: enrich_fn(rows, *, resource, args, api_actions) -> rows.
    enrich_fn: Callable | None = None
    # --- manual name-list support (--<manual_id_arg> / --<manual_id_arg>-file) ---
    manual_id_arg: str | None = None                # e.g. "trigger_ids" -> --trigger-ids / --trigger-ids-file
    manual_template: tuple | None = None            # name_from_input template; None => tokens are full names
    manual_error: str | None = None                 # error message for a malformed token
    manual_help: str | None = None


def component_args(components: Sequence[Component]) -> list[tuple[str, str]]:
    """The (key, help) pairs for parse_component_args."""
    return [(c.key, c.help_text or f"Enumerate {c.title}") for c in components]


def build_extra_args(components: Sequence[Component], *, extra: Callable | None = None) -> Callable:
    """Return an add_extra_args(parser) that registers every component's manual
    name-list flags (--X-ids / --X-ids-file), then any module-specific extras."""

    def _add(parser):
        for c in components:
            if not c.manual_id_arg:
                continue
            flag = "--" + c.manual_id_arg.replace("_", "-")
            parser.add_argument(flag, dest=c.manual_id_arg, required=False,
                                help=c.manual_help or f"{c.title} IDs/names in comma-separated format.")
            parser.add_argument(f"{flag}-file", dest=f"{c.manual_id_arg}_file", required=False,
                                help=f"File containing {c.title} IDs/names (one per line or comma-separated).")
        if callable(extra):
            extra(parser)

    return _add


def _location_of(row: dict) -> str:
    return str(extract_location_from_resource_name(str((row or {}).get("name") or "").strip()) or "").strip()


def _list_kwargs(component, args) -> dict:
    """Resolve a component's extra list/get kwargs. Accepts a static dict or a
    callable(args) -> dict so a module can vary kwargs by flags (e.g. full_view)."""
    spec = component.list_kwargs
    if callable(spec):
        return dict(spec(args) or {})
    return dict(spec or {})


def _process_listed(listed, resource, component, args, api_actions, iam_actions):
    """list() result -> hydrated + iam-tested rows (or [] for empty/disabled)."""
    if listed in ("Not Enabled", None):
        return []
    rows = list(listed or [])
    if not rows:
        return []
    extra = _list_kwargs(component, args)
    if component.supports_get and getattr(args, "get", False):
        def _hydrate_get(row):
            # Keep the freshly-fetched resource, but fall back to the listed row when get()
            # returns None (error) or the "Not Enabled" sentinel string -- otherwise a
            # truthy non-row (the sentinel) would replace the dict and AttributeError in the
            # later save/iam row.get(...) calls. NOTE: a successful GAPIC get() returns a
            # proto Message (not a dict), so only None/sentinel fall back, not "not a dict".
            got = resource.get(resource_id=str(row.get("name") or "").strip(), action_dict=api_actions, **extra)
            if got is None or (isinstance(got, str) and got == "Not Enabled"):
                return row
            return got
        rows = process_with_progress(rows, _hydrate_get, label=f"{component.primary_resource} (get)")
    if component.supports_iam and getattr(args, "iam", False) and getattr(resource, "TEST_IAM_PERMISSIONS", ()):
        def _test_iam(row):
            name = str(row.get("name") or "").strip()
            if name:
                resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
        process_with_progress(rows, _test_iam, label=f"{component.primary_resource} (testIamPermissions)")
    if component.enrich_fn:
        rows = component.enrich_fn(rows, resource=resource, args=args, api_actions=api_actions) or []
    return rows


def _resolve_manual_names(component, args, project_id):
    """Tokens from --X-ids/--X-ids-file -> full resource names (or None if none given)."""
    if not component.manual_id_arg:
        return None
    tokens = parse_csv_file_args(getattr(args, component.manual_id_arg, None),
                                 getattr(args, f"{component.manual_id_arg}_file", None))
    if not tokens:
        return None
    if component.manual_template:
        return [
            name_from_input(token, project_id=project_id, template=component.manual_template,
                            error_message=component.manual_error or "Invalid resource ID format.")
            for token in tokens
        ]
    return [str(token).strip() for token in tokens if str(token).strip()]


def _run_manual(resource, component, names, args, api_actions, project_id):
    """Hydrate the explicitly-requested resources by name (requires --get)."""
    if not (component.supports_get and getattr(args, "get", False)):
        return []
    extra = _list_kwargs(component, args)
    rows = []
    for name in names:
        row = resource.get(resource_id=name, action_dict=api_actions, **extra)
        if isinstance(row, dict) and row:
            rows.append(row)
    if component.enrich_fn:
        rows = component.enrich_fn(rows, resource=resource, args=args, api_actions=api_actions) or []
    if component.persist:
        for row in rows:
            resource.save([row], project_id=project_id, location=_location_of(row))
    return rows


def run_components(
    session,
    args,
    *,
    components: Sequence[Component],
    column_name: str,
    region_resolver: Callable[[Any, Any], Sequence[str]] | None = None,
    module_name: str = "",
    credname_override: Any = None,
) -> dict[str, list[dict]]:
    """Run the uniform enumeration loop for every selected component.

    For each selected Component this lists (region fan-out / project / nested
    under parents or explicit --X-ids), optionally hydrates with --get, probes
    --iam, runs enrich_fn, saves (unless persist=False), and emits a summary
    (unless summarize=False). The three action accumulators are flushed once at
    the end under ``column_name``.

    Threading invariant: the list/get/iam network work fans out via parallel_map /
    map_regions_with_disabled_short_circuit, but all save()/insert calls happen
    here on the MAIN THREAD -- workers only return rows. Don't move DB writes into
    a worker (DataController is single-threaded and will raise).

    Component selection: if no --X flags are passed, ALL components run; passing
    any --X (or any --X-ids) restricts to just those. Manual --X-ids implies
    selecting that component.

    Args:
      column_name: service action column the flushed permissions are stored under.
      region_resolver: (session, args) -> regions, used for REGION components that
        don't pin component.locations.
      credname_override: attribute discovered permissions to specific credentials
        (e.g. an HMAC key's SA) instead of the active session credential.

    Returns ``{component_key: saved_rows}`` so callers can drive extra behavior
    (downloads, exports) off the enumerated rows.
    """
    project_id = session.project_id
    accumulators = make_action_accumulators()
    scope_actions, api_actions, iam_actions = accumulators
    threads = getattr(args, "threads", 3)

    try:
        resources = {c.key: c.resource_cls(session) for c in components}
    except RuntimeError as exc:
        print(f"[X] {exc}")
        return {}

    # Resolve manual name-lists first; supplying --X-ids implies selecting that component.
    manual_names: dict[str, list[str]] = {}
    for component in components:
        try:
            names = _resolve_manual_names(component, args, project_id)
        except ValueError as exc:
            UtilityTools.print_error(str(exc))
            return {}
        if names:
            manual_names[component.key] = names
            setattr(args, component.key, True)

    selected = resolve_selected_components(args, [c.key for c in components])
    discovered: dict[str, list[dict]] = {}

    for component in components:
        if not selected.get(component.key, False):
            continue
        resource = resources[component.key]
        columns = list(component.columns) if component.columns is not None else resource.COLUMNS
        manual = manual_names.get(component.key)
        manual_requested = bool(manual)
        rows: list[dict] = []

        if getattr(args, "iam", False) and not component.supports_iam and component.iam_unsupported_message:
            print(component.iam_unsupported_message)

        if manual_requested:
            rows = _run_manual(resource, component, manual, args, api_actions, project_id)
            # IAM targets the requested names directly, with or without --get.
            if component.supports_iam and getattr(args, "iam", False) and getattr(resource, "TEST_IAM_PERMISSIONS", ()):
                for name in manual:
                    resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
        elif component.scope == NESTED:
            manual_parent_names = [name for name in (manual_names.get(component.parent_key) or []) if name]
            parent_enumerated = component.parent_key in discovered
            if manual_parent_names:
                # Parent targeted by explicit manual names (e.g. --bucket-names): nest
                # under them directly even when the parent wasn't hydrated into rows
                # (no --get). Prefer an enumerated row when present so parent_filter
                # still has its fields; otherwise synthesize a name-only parent.
                by_name = {
                    str(row.get("name") or "").strip(): row
                    for row in (discovered.get(component.parent_key) or [])
                    if row.get("name")
                }
                parent_source = [by_name.get(name, {"name": name}) for name in manual_parent_names]
                parent_enumerated = True
            elif parent_enumerated:  # parent ran this invocation (even if it found nothing)
                parent_source = discovered.get(component.parent_key) or []
            else:  # parent not selected this run -> fall back to the DB cache
                cache_columns = ["name"]
                if component.parent_filter:  # need the filter field(s) too
                    cache_columns = list(dict.fromkeys(["name", *resources[component.parent_key].COLUMNS]))
                parent_source = get_cached_rows(
                    session, resources[component.parent_key].TABLE_NAME, project_id=project_id, columns=cache_columns
                ) or []
            if component.parent_filter:
                parent_source = [row for row in parent_source if component.parent_filter(row)]
            parent_names = [str(row.get("name") or "").strip() for row in parent_source if row.get("name")]
            parent_names = [name for name in parent_names if name]
            if not parent_names:
                if parent_enumerated:
                    print(f"[*] No {component.title} found in project {project_id}.")
                else:
                    print_missing_dependency(
                        component_name=component.title,
                        dependency_name=component.dependency_label or component.parent_key,
                        module_name=module_name,
                    )
                discovered[component.key] = []
                continue
            nested_extra = _list_kwargs(component, args)
            listed_by_parent = parallel_map(
                parent_names,
                lambda parent_name: (parent_name, resource.list(parent=parent_name, action_dict=scope_actions, **nested_extra)),
                threads=threads,
            )
            for parent_name, listed in listed_by_parent:
                batch = _process_listed(listed, resource, component, args, api_actions, iam_actions)
                if batch:
                    if component.persist:
                        save_kwargs = {component.save_parent_kwarg: parent_name} if component.save_parent_kwarg else {}
                        resource.save(batch, project_id=project_id, **save_kwargs)
                    rows.extend(batch)
        else:
            if component.scope == PROJECT:
                locations = ["global"]
            elif component.locations is not None:
                locations = list(component.locations)
            elif region_resolver is not None:
                locations = list(region_resolver(session, args))
            else:
                locations = ["global"]
            scoped_extra = _list_kwargs(component, args)
            listed_by_location = map_regions_with_disabled_short_circuit(
                locations,
                lambda location: resource.list(project_id=project_id, location=location, action_dict=scope_actions, **scoped_extra),
                threads=threads,
            )
            for location, listed in listed_by_location:
                batch = _process_listed(listed, resource, component, args, api_actions, iam_actions)
                if batch:
                    if component.persist:
                        resource.save(batch, project_id=project_id, location=location)
                    rows.extend(batch)

        if not component.summarize:
            # Module renders its own summary off the returned rows (e.g. a
            # bucket -> blobs map that the uniform list summary can't express).
            pass
        elif rows:
            UtilityTools.summary_wrapup(
                project_id,
                component.title,
                rows,
                columns,
                primary_resource=component.primary_resource,
                primary_sort_key=component.primary_sort_key,
            )
        elif not manual_requested:
            print(f"[*] No {component.title} found in project {project_id}.")
        elif getattr(args, "get", False):
            print(f"[*] No {component.title} found for the supplied IDs/names.")
        else:
            print(f"[*] Manual {component.title} IDs/names supplied without --get; skipping summary.")
        discovered[component.key] = rows

    flush_actions(session, project_id, column_name, accumulators, credname_override=credname_override)
    return discovered
