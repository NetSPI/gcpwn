# CLAUDE.md

Guidance for AI assistants (and humans) working in this repo. Read this before
making changes — it captures the module contract and a few non-obvious
invariants that are easy to violate.

## What this is

GCPwn is a Pacu-style interactive GCP offensive-security framework. A REPL loads
credentials into a workspace, then runs per-service **modules** that enumerate
resources, run exploits, and feed a SQLite-backed data model used for
permission analysis and BloodHound-style attack-path graphing (OpenGraph).

## Layout

- `gcpwn/cli/` — REPL, command parsing, and module dispatch.
  - `main.py` — entrypoint (`python -m gcpwn` / `gcpwn`), workspace selection,
    and `--module` passthrough for unauthenticated modules.
  - `workspace_instructions.py` — the `CommandProcessor` REPL (creds/projects/
    modules/data/configs commands, readline completion).
  - `module_actions.py` — `interact_with_module()`: auth gating, project-scope
    planning, and per-project execution of a module's `run_module`.
- `gcpwn/core/` — framework primitives.
  - `session.py` — `SessionUtility`: credentials, project context, and the
    `get_data`/`insert_data`/`insert_actions` data API modules call.
  - `db.py` — `DataController`: one unified SQLite DB (`databases/gcpwn.db`)
    and all SQL. `workspaces` is the parent table; `session`/`session_actions`
    and every service table carry a `workspaces(id)` FK with `ON DELETE CASCADE`
    (one file so FKs can span the groups; `foreign_keys=ON`).
  - `service_runtime.py` — shared module helpers (arg parsing, error handling,
    paging, `parallel_map`).
  - `action_schema.py` — the permission/provenance column model.
- `gcpwn/modules/<service>/<category>/<module>.py` — modules. Categories:
  `enumeration`, `exploit`, `unauthenticated`, `process`, `utilities`.
  Per-service `utilities/helpers.py` holds the real API logic; the module file
  is a thin CLI wrapper.
- `gcpwn/mappings/*.json` — module registry + static IAM/escalation data.
- `databases/` — runtime SQLite stores (gitignored).

## Run / test / lint

```bash
python -m gcpwn                                  # run the REPL
python -m pytest -q tests/unit tests/module_contracts   # tests
ruff check .                                     # lint (BLOCKING in CI)
mypy                                             # type-check core (informational)
```

Install dev tooling with `pip install .[dev]` (adds pytest, ruff, mypy).

## The module contract

Every runnable module exposes:

```python
def run_module(user_args, session):
    ...
    return 1   # truthy/0 == success; -1 == failure
```

- `user_args` is a `list[str]` (argparse-style); parse it with the helpers in
  `service_runtime.py` (`parse_component_args`, `add_standard_arguments`).
- `session` is the `SessionUtility` (or `PassthroughSession` for unauth runs).
- Some modules take an extra `dependency=`/`callback=` flag used when one module
  calls another; default it to `False`.
- Register new modules in `gcpwn/mappings/module_mappings.json`. The contract
  tests (`tests/module_contracts/`) assert every mapped location exists and
  defines `run_module`, and that no `ArgumentParser(output_format=...)` slips in.
- Module behavior policy (auth required, run-once vs per-project, project flags)
  is decided in `module_actions.get_module_action()` /
  `MODULE_POLICY_REGISTRY`. Unauth modules are detected by an `unauth_` name
  prefix or an `.unauthenticated.` path segment.

## Critical invariants

1. **DB access is serialized by one process-wide lock — concurrent threads are
   safe, but writes still queue.** `DataController` opens its connections with
   `check_same_thread=False` and wraps **every** public method in `@_synchronized`
   against a process-wide re-entrant `RLock` (`db.py`). So calling `session.get_data`
   / `insert_data` / `insert_actions` from a worker thread is *safe* (it blocks on
   the lock; it will **not** raise `sqlite3.ProgrammingError`). `enum_all`'s parallel
   orchestrator and the IAM-bindings pipeline deliberately rely on this — their pool
   workers run whole `run_module`s, saves included. **Nested pools are fine** (the
   `enum_all` outer service pool × a service's inner region/zone fan-out via
   `parallel_map`); peak concurrency ≈ `--threads²` API calls, so watch *GCP rate
   limits*, not the DB.
   Still **prefer the collect-on-main pattern** inside `run_components` and similar
   fan-out: workers do network/CPU work and **return** results, the caller saves.
   It's clearer and avoids piling every worker onto the single write lock (writes
   serialize regardless). The lock makes worker-thread writes *correct*, not *fast*.

2. **Prefer parameterized SQL.** `DataController.select_rows(..., where={...})`
   binds parameters. Building `conditions=f'name="{value}"'` with
   caller-supplied values (bucket names, emails, role names, project ids) is the
   current pattern in places but is brittle (a `"` breaks the query) and an
   injection surface. New code should use bound parameters; migrating old call
   sites is welcome.

3. **All service tables are workspace-scoped.** Rows carry a `workspace_id`;
   `session.get_data`/`insert_data` add it automatically. Don't query service
   tables without it.

4. **Permissions are recorded as evidence, not booleans.** `insert_actions`
   merges discovered permissions into per-credential trees tagged with
   provenance (`direct_api` vs `test_iam_permissions`). See `action_schema.py`
   and `db._merge_action_*`. Use the right `evidence_type` when you record a
   `testIamPermissions` result.

## Conventions

- Output goes through `gcpwn.core.console.UtilityTools` (colors, `summary_wrapup`,
  the `print_403/404/500` helpers). Don't hand-roll ANSI codes.
- Handle Google API errors with `service_runtime.handle_service_error` /
  `handle_discovery_error` so "API disabled" vs "403 denied" vs "404" is
  reported consistently and short-circuits region fan-out.
- Keep non-Google runtime dependencies minimal (eases enterprise install
  approval). `boto3` is REQUIRED (HMAC/XML Cloud Storage access); `prettytable`
  and `xlsxwriter` are optional extras.

## Exploit module testing protocol

After bulk refactors to `exploit_helpers.py` or any service's `utilities/helpers.py`,
or when new exploit modules are added, run the full audit:

```
# Phase 1 — live test all *_as_sa modules (SA key + OAuth2 auth paths)
# Phase 2 — OpenGraph edge verification (process_og_attack_paths --json cross-ref)
```

The full protocol is in `.claude/agents/exploit_module_audit.md` — invoke it as a
Claude skill or read it directly. Key invariants it enforces:

- Every `*_as_sa` module imports shared helpers from `gcpwn.core.utils.exploit_helpers`
  (never re-implements `print_exploit_header`, `print_token_result`, `select_target_sa`).
- Atomic ops (create/delete/poll) live in the service `utilities/helpers.py`, not inline.
- `process_og_attack_paths --json` must parse as valid JSON with no stdout preamble.
- 0 false-positive edges: every reported path hop must exist as a raw graph edge.

## Lint/type-check roadmap

Ruff is intentionally limited to real-bug rules (`E9`, `F`) so it stays green
without restyling 60k LOC. Widen `[tool.ruff.lint] select` over time
(`B`, `UP`, `SIM`, `DTZ`, ...). Mypy is scoped to `gcpwn/core` and is currently
non-blocking — drive those errors to zero, then drop `continue-on-error` in
`.github/workflows/ci.yml` and widen `[tool.mypy] files` to `cli` and `modules`.
