from __future__ import annotations

import json

from gcpwn.core.console import UtilityTools


class WorkspaceConfig:
    # "std_output_format" is a single default output mode.
    # Supported values are table/text.
    ALLOWED_STD_OUTPUT_FORMATS = {"table", "text"}

    std_output_format: str = "text"
    preferred_project_ids: list[str] | None = None
    preferred_regions: list[str] | None = None
    preferred_zones: list[str] | None = None
    workspace_customer_id: str | None = None
    workspace_admin_subject: str | None = None  # Workspace admin email to impersonate for SA domain-wide delegation
    workspace_tenants: list[dict]  # registered Workspace tenants [{customer_id, domain?, admin_subject?, org_id?, credname?}]

    def __init__(self, json_data: str | None = None):
        self.std_output_format = "text"
        self.preferred_project_ids = None
        self.preferred_regions = None
        self.preferred_zones = None
        self.workspace_customer_id = None
        self.workspace_admin_subject = None
        self.workspace_tenants = []
        if json_data:
            self.from_json(json_data)

    def from_json(self, json_data: str) -> None:
        data = json.loads(json_data)
        raw_std = str(data.get("std_output_format") or "").strip().lower()
        self.std_output_format = raw_std if raw_std in self.ALLOWED_STD_OUTPUT_FORMATS else "text"

        self.preferred_project_ids = data.get("preferred_project_ids")
        self.preferred_regions = data.get("preferred_regions")
        self.preferred_zones = data.get("preferred_zones")
        self.workspace_customer_id = data.get("workspace_customer_id")
        self.workspace_admin_subject = data.get("workspace_admin_subject")
        raw_tenants = data.get("workspace_tenants")
        self.workspace_tenants = list(raw_tenants) if isinstance(raw_tenants, list) else []

    def to_json_string(self) -> str:
        return json.dumps(
            {
                "std_output_format": self.std_output_format,
                "preferred_project_ids": self.preferred_project_ids,
                "preferred_regions": self.preferred_regions,
                "preferred_zones": self.preferred_zones,
                "workspace_customer_id": self.workspace_customer_id,
                "workspace_admin_subject": self.workspace_admin_subject,
                "workspace_tenants": self.workspace_tenants,
            }
        )

    def print_json_formatted(self) -> None:
        data = json.loads(self.to_json_string())
        max_key_length = max(len(key) for key in data.keys())
        for key, value in data.items():
            key_str = f"{key.rjust(max_key_length)}:"
            if value is None or value == []:
                value_str = f"{UtilityTools.RED}[Not Set]{UtilityTools.RESET}"
            else:
                value_str = f"{UtilityTools.GREEN}{value}{UtilityTools.RESET}"
            print(f"{UtilityTools.BOLD}{key_str}{UtilityTools.RESET} {value_str}")

    def set_std_output_format(self, value: str) -> None:
        candidate = str(value or "").strip().lower()
        if candidate not in self.ALLOWED_STD_OUTPUT_FORMATS:
            raise ValueError(
                f"Invalid value '{value}'. Allowed values are: table, text."
            )
        self.std_output_format = candidate

    # --- Workspace tenant helpers ---

    def get_tenant(self, customer_id: str) -> dict | None:
        for tenant in (self.workspace_tenants or []):
            if tenant.get("customer_id") == customer_id:
                return dict(tenant)
        return None

    def add_or_update_tenant(self, tenant: dict) -> bool:
        """Add or update a tenant by customer_id. Returns True if added (new), False if updated."""
        customer_id = str(tenant.get("customer_id") or "").strip()
        if not customer_id:
            raise ValueError("customer_id is required")
        if self.workspace_tenants is None:
            self.workspace_tenants = []
        for i, existing in enumerate(self.workspace_tenants):
            if existing.get("customer_id") == customer_id:
                self.workspace_tenants[i] = {**existing, **{k: v for k, v in tenant.items() if v}}
                return False
        self.workspace_tenants.append({k: v for k, v in tenant.items() if v})
        return True

    def remove_tenant(self, customer_id: str) -> bool:
        """Remove a tenant by customer_id. Returns True if a tenant was removed."""
        if not self.workspace_tenants:
            return False
        before = len(self.workspace_tenants)
        self.workspace_tenants = [t for t in self.workspace_tenants if t.get("customer_id") != customer_id]
        return len(self.workspace_tenants) < before
