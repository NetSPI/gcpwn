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


def enumerate_asset_inventory(session, *, scope: str, asset_types: list[str] | None = None) -> dict[str, int]:
    """Fetch CAI at scope, map to gcpwn tables, persist; return per-table saved counts."""
    records = fetch_cai_records(session, scope=scope, asset_types=asset_types)
    if not records:
        return {}
    tables = cai_records_to_tables(records)
    return save_cai_tables(session, tables)
