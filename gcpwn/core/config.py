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

    def __init__(self, json_data: str | None = None):
        self.std_output_format = "text"
        self.preferred_project_ids = None
        self.preferred_regions = None
        self.preferred_zones = None
        self.workspace_customer_id = None
        self.workspace_admin_subject = None
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

    def to_json_string(self) -> str:
        return json.dumps(
            {
                "std_output_format": self.std_output_format,
                "preferred_project_ids": self.preferred_project_ids,
                "preferred_regions": self.preferred_regions,
                "preferred_zones": self.preferred_zones,
                "workspace_customer_id": self.workspace_customer_id,
                "workspace_admin_subject": self.workspace_admin_subject,
            }
        )

    def print_json_formatted(self) -> None:
        data = json.loads(self.to_json_string())
        max_key_length = max(len(key) for key in data.keys())
        for key, value in data.items():
            key_str = f"{key.rjust(max_key_length)}:"
            if value is None:
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
