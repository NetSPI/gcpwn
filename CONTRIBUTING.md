# Contributing

## Setup

1. Create a virtual environment.
2. Install the package in editable mode with dev tooling:
   `python -m pip install -e .[dev]`
3. Run tests:
   `python -m pytest -q -ra tests/unit tests/module_contracts`

## Guidelines

- Keep module behavior backwards compatible unless the change is explicitly a bug fix.
- Prefer shared helpers in `gcpwn/core/` over duplicating logic in individual modules.
- Add or update at least one focused test for new helpers, exports, or module wiring changes.
- If you add a new module, update `gcpwn/mappings/module_mappings.json` and `gcpwn/mappings/database_info.json` when needed.

## OpenGraph Allowlists

Starter OpenGraph allowlists live in `gcpwn/modules/opengraph/utilities/data/allowlists.json`.
Add new permission-to-edge and role-to-edge mappings there as coverage expands.
