from __future__ import annotations

from typing import Any

from google.cloud import bigquery_datatransfer_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("bigquerydatatransfer", ("bigquerydatatransfer", "v1"))


class BigQueryDataTransferConfigsResource(GcpListResource):
    """List/get BigQuery Data Transfer Service transfer configs via the
    bigquery_datatransfer_v1 GAPIC client.

    A TransferConfig is recon-rich: ``data_source_id`` says what external data is
    being pulled, ``destination_dataset_id`` says where it lands, ``schedule`` and
    ``owner_info.email`` say when and as whom. There is no service-account field on
    a returned TransferConfig (the run-as SA is a create-time request parameter,
    not stored/returned), so none is extracted.

    The bigquery_datatransfer GAPIC client exposes no ``test_iam_permissions``
    method, so the component runs with ``supports_iam=False``.
    """

    SERVICE_LABEL = "BigQuery Data Transfer"
    TABLE_NAME = "bigquerydatatransfer_configs"
    COLUMNS = [
        "location",
        "config_id",
        "name",
        "display_name",
        "data_source_id",
        "destination_dataset_id",
        "schedule",
        "state",
        "disabled",
        "owner_email",
    ]
    ACTION_RESOURCE_TYPE = "transferConfigs"
    LIST_PERMISSION = "bigquery.transfers.get"
    GET_PERMISSION = "bigquery.transfers.get"
    ID_FIELD = "config_id"

    def _build_client(self, session):
        return bigquery_datatransfer_v1.DataTransferServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_transfer_configs(
            request=bigquery_datatransfer_v1.ListTransferConfigsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_transfer_config(
            request=bigquery_datatransfer_v1.GetTransferConfigRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        owner_info = raw.get("owner_info") if isinstance(raw.get("owner_info"), dict) else {}
        return {
            "config_id": extract_path_tail(str(raw.get("name", "") or "")),
            "owner_email": str((owner_info or {}).get("email", "") or "").strip(),
        }
