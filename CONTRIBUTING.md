# Contributing to gcpwn

## How to contribute

The best way to contribute is through **GitHub Issues**. Issues are triaged regularly and directly shape the roadmap.

### Issue categories

| Template | Use it for |
|---|---|
| **Bug Report** | Something that doesn't work — wrong output, crash, API error |
| **New Service / Module Request** | A GCP service not yet covered by enumeration or exploit modules |
| **Feature Request** | Improvements to existing behavior, CLI UX, output format, or framework internals |
| **OpenGraph Priv-Esc Edge Request** | A privilege escalation path to add to the default OpenGraph attack edge set |

Good issues include: exact module command and flags used (with placeholder values for project IDs and credentials), observed vs. expected output, and gcpwn version.

### Pull requests

Pull requests are currently limited to a small group of approved contributors to keep review overhead manageable. If you'd like to contribute code, open an issue first — that's the best way to get involved and start a conversation about the approach.

---

## Development setup

1. Create a virtual environment.
2. Install in editable mode with dev tooling:
   ```
   python -m pip install -e .[dev]
   ```
3. Run tests:
   ```
   python -m pytest -q -ra tests/unit tests/module_contracts
   ```
4. Run the linter (required to pass CI):
   ```
   ruff check .
   ```
