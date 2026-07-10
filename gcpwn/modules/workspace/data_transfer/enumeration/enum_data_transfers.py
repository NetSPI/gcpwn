"""enum_data_transfers: enumerate Google Workspace data-ownership transfer requests.

Admin SDK Data Transfer API ``transfers.list`` -> who transferred data to whom (the
offboarding trail: old owner -> new owner, per application, status). Tenant-scoped;
needs Workspace admin creds or service-account domain-wide delegation (--impersonate /
`configs set workspace_admin_subject`).
"""

from __future__ import annotations

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.workspace.common import (
    resolve_directory_customer_id,
    resolve_workspace_admin_subject,
)
from gcpwn.modules.workspace.data_transfer.utilities.data_transfers_helpers import (
    WorkspaceDataTransfersResource,
)


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--customer-id", required=False, help="Directory customer ID (e.g. C046psxkn)")
        parser.add_argument("--org-id", required=False, help="GCP organization ID used to resolve directoryCustomerId")
        parser.add_argument("--impersonate", required=False, help="Workspace admin email to impersonate (SA domain-wide delegation)")

    return parse_component_args(
        user_args,
        description="Enumerate Google Workspace data-ownership transfer requests",
        components=[],
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    customer_id = resolve_directory_customer_id(session, customer_id=args.customer_id, organization_id=args.org_id)
    subject = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))

    resource = WorkspaceDataTransfersResource(session, subject=subject)
    transfers = resource.list(customer=customer_id)
    if transfers:
        resource.save(transfers, customer_id=customer_id or "my_customer")

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Workspace Data Transfers",
        [
            {
                "transfer_id": str(transfer.get("id") or ""),
                "old_owner": str(transfer.get("oldOwnerUserId") or ""),
                "new_owner": str(transfer.get("newOwnerUserId") or ""),
                "status": str(transfer.get("overallTransferStatusCode") or ""),
            }
            for transfer in transfers
        ],
        ["transfer_id", "old_owner", "new_owner", "status"],
        primary_resource="Data Transfers",
        primary_sort_key="transfer_id",
    )
    return 1
