"""A get_data-only session backed by a Cloud Asset Inventory export FILE.

`process_og --cai-file <export>` wraps the real session in a `CaiFileSource`: data
reads (`get_data(<table>)`) are served from the CAI export mapped via
`cai_records_to_tables`, while every other attribute/method (output-path resolution,
config, project_id, ...) delegates to the wrapped session. This lets the UNCHANGED,
golden-guarded OpenGraph pipeline build a graph straight from a client's CAI export
with no prior enumeration and no SQLite. See [[gcpwn-opengraph-is-sensitive]].
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gcpwn.core.utils.module_helpers import parse_json_value

from gcpwn.modules.gcp.assetinventory.utilities.cai_mapping import cai_records_to_tables


def load_cai_records(path: str | Path) -> list[dict[str, Any]]:
    """Parse a CAI export file into a list of asset record dicts.

    Accepts the common shapes: NDJSON (one Asset per line, the `gcloud asset export`
    / exportAssets-to-GCS format), a JSON array of records, or a JSON object wrapping
    a list under a known key (assets / results / ...).
    """
    text = Path(path).expanduser().read_text(encoding="utf-8").strip()
    if not text:
        return []
    # Whole-document JSON (array or wrapper object) first.
    obj = parse_json_value(text)
    if isinstance(obj, list):
        return [r for r in obj if isinstance(r, dict)]
    if isinstance(obj, dict):
        for key in ("assets", "results", "resourceSearchResults", "iamPolicyResults", "resource_search_results"):
            value = obj.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        return [obj]  # a single asset record
    # Fall back to NDJSON (one record per line).
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


class CaiFileSource:
    """Session shim: serve get_data from a CAI export, delegate everything else."""

    def __init__(self, session: Any, cai_file_path: str | Path):
        self._session = session
        self._records = load_cai_records(cai_file_path)
        self._tables = cai_records_to_tables(self._records)

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def table_summary(self) -> dict[str, int]:
        return {table: len(rows) for table, rows in self._tables.items() if rows}

    def get_data(self, table_name, columns="*", conditions=None, *, where=None, params=None):
        return [dict(row) for row in self._tables.get(str(table_name), [])]

    # CAI carries no live-credential session rows or recorded actions.
    def get_session_data(self, *args, **kwargs):
        return []

    def get_actions(self, *args, **kwargs):
        return {}

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes not defined above; delegate to the real session
        # (resolve_output_path, get_download_save_path, project_id, configs, ...).
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return getattr(self._session, name)
