from __future__ import annotations

from typing import Any

from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error
from gcpwn.modules.gcp.assetinventory.utilities.cai_mapping import CAI_TABLES, cai_records_to_tables


def build_asset_client(session):
    from google.cloud import asset_v1

    return asset_v1.AssetServiceClient(credentials=session.credentials)


def fetch_cai_records(session, *, scope: str, asset_types: list[str] | None = None) -> list[dict[str, Any]]:
    """Pull Cloud Asset Inventory assets at ``scope`` and return merged dict records.

    Calls ``list_assets`` once per content type (RESOURCE then IAM_POLICY) and merges
    by asset name, so each record carries both ``resource.data`` and ``iamPolicy`` --
    the shape ``cai_records_to_tables`` expects. ``scope`` is ``projects/<id>``,
    ``folders/<id>`` or ``organizations/<id>``. Errors (403 / API disabled / 404) are
    funneled through ``handle_service_error`` and yield an empty list.
    """
    from google.cloud import asset_v1

    client = build_asset_client(session)
    merged: dict[str, dict[str, Any]] = {}
    for content_type in (asset_v1.ContentType.RESOURCE, asset_v1.ContentType.IAM_POLICY):
        request = asset_v1.ListAssetsRequest(
            parent=scope,
            content_type=content_type,
            asset_types=list(asset_types or []),
        )
        try:
            for asset in client.list_assets(request=request):
                record = resource_to_dict(asset)
                name = str(record.get("name") or "").strip()
                if not name:
                    continue
                if name in merged:
                    merged[name].update({k: v for k, v in record.items() if v not in (None, "", [], {})})
                else:
                    merged[name] = record
        except Exception as exc:
            handle_service_error(
                exc,
                api_name="cloudasset.assets.list",
                resource_name=scope,
                service_label="Cloud Asset Inventory",
            )
            return []
    return list(merged.values())


def save_cai_tables(session, tables: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    """Upsert mapped CAI rows into the shared workspace tables; return counts saved."""
    saved: dict[str, int] = {}
    for table in CAI_TABLES:
        rows = tables.get(table) or []
        for row in rows:
            session.insert_data(table, row)
        if rows:
            saved[table] = len(rows)
    return saved


def write_cai_records_file(records: list[dict[str, Any]], output_file: str) -> int:
    """Write fetched CAI records to a portable JSON file usable with ``process_og --cai-file``.

    Writes a JSON array (the shape ``load_cai_records`` accepts) so the same scan that
    populates the workspace can also be handed off / built offline with no credentials.
    Returns the number of records written."""
    import json
    from pathlib import Path

    path = Path(str(output_file)).expanduser()
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(list(records or []), handle, ensure_ascii=False)
    return len(records or [])


def enumerate_asset_inventory(
    session, *, scope: str, asset_types: list[str] | None = None, output_file: str | None = None
) -> dict[str, int]:
    """Fetch CAI at scope, map to gcpwn tables, persist; return per-table saved counts.

    When ``output_file`` is given, the raw fetched records are ALSO written there as a
    portable CAI export (``process_og --cai-file``-ready) before mapping/persisting."""
    records = fetch_cai_records(session, scope=scope, asset_types=asset_types)
    if not records:
        return {}
    if output_file:
        count = write_cai_records_file(records, output_file)
        print(f"[*] Wrote {count} CAI records to {output_file} (use: process_og_gcpwn_data --cai-file {output_file}).")
    tables = cai_records_to_tables(records)
    return save_cai_tables(session, tables)
