from __future__ import annotations

import json
from typing import Any

from google.cloud import billing_v1

from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def build_billing_client(session):
    return billing_v1.CloudBillingClient(credentials=session.credentials)


def _account_iam_members(client, account_name: str) -> str:
    """Best-effort: who can administer this billing account (priv-esc -- billing admins
    can attach projects / move billing). Returns a comma-joined member list or ''."""
    try:
        from google.iam.v1 import iam_policy_pb2

        policy = client.get_iam_policy(request=iam_policy_pb2.GetIamPolicyRequest(resource=account_name))
        members = sorted({member for binding in policy.bindings for member in binding.members})
        return ",".join(members)
    except Exception:
        return ""


def list_billing_accounts(session) -> list[dict[str, Any]]:
    """List all billing accounts the caller can see (global, not project-scoped)."""
    client = build_billing_client(session)
    rows: list[dict[str, Any]] = []
    try:
        for account in client.list_billing_accounts(request=billing_v1.ListBillingAccountsRequest()):
            data = resource_to_dict(account)
            name = str(data.get("name") or "")
            rows.append({
                "name": name,
                "account_id": extract_path_tail(name),
                "display_name": str(data.get("display_name") or data.get("displayName") or ""),
                "is_open": "yes" if (data.get("open") or data.get("open_") or data.get("isOpen")) else "no",
                "master_billing_account": str(data.get("master_billing_account") or data.get("masterBillingAccount") or ""),
                "iam_members": _account_iam_members(client, name),
                "raw_json": json.dumps(data, default=str),
            })
    except Exception as exc:
        handle_service_error(
            exc,
            api_name="cloudbilling.billingAccounts.list",
            resource_name="billingAccounts",
            service_label="Cloud Billing",
        )
        return []
    return rows


def get_project_billing_info(session, project_id: str) -> dict[str, Any] | None:
    """Which billing account funds ``project_id`` (and whether billing is enabled)."""
    client = build_billing_client(session)
    try:
        info = client.get_project_billing_info(
            request=billing_v1.GetProjectBillingInfoRequest(name=f"projects/{project_id}")
        )
        data = resource_to_dict(info)
        return {
            "name": str(data.get("name") or f"projects/{project_id}/billingInfo"),
            "billing_account_name": str(data.get("billing_account_name") or data.get("billingAccountName") or ""),
            "billing_enabled": "yes" if (data.get("billing_enabled") or data.get("billingEnabled")) else "no",
            "raw_json": json.dumps(data, default=str),
        }
    except Exception as exc:
        handle_service_error(
            exc,
            api_name="cloudbilling.projects.getBillingInfo",
            resource_name=f"projects/{project_id}",
            service_label="Cloud Billing",
        )
        return None
