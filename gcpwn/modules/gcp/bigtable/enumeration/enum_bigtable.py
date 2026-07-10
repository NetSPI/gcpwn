from __future__ import annotations

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.bigtable.utilities.helpers import (
    BigtableAuthorizedViewsResource,
    BigtableBackupsResource,
    BigtableInstancesResource,
    BigtableTablesResource,
)


COMPONENTS = [
    Component("instances", BigtableInstancesResource, "Bigtable Instances", "Instances",
              help_text="Enumerate Bigtable instances", scope=PROJECT, primary_sort_key="instance_id"),
    Component("tables", BigtableTablesResource, "Bigtable Tables", "Tables",
              help_text="Enumerate Bigtable tables (per instance)", scope=NESTED, parent_key="instances",
              dependency_label="Instances", save_parent_kwarg="instance_name", primary_sort_key="table_id"),
    Component("backups", BigtableBackupsResource, "Bigtable Backups", "Backups",
              help_text="Enumerate Bigtable backups (per instance)", scope=NESTED, parent_key="instances",
              dependency_label="Instances", save_parent_kwarg="instance_name", primary_sort_key="backup_id",
              supports_iam=False),
    Component("authorized_views", BigtableAuthorizedViewsResource, "Bigtable Authorized Views", "Authorized Views",
              help_text="Enumerate Bigtable authorized views (per table)", scope=NESTED, parent_key="tables",
              dependency_label="Tables", save_parent_kwarg="table_name", primary_sort_key="authorized_view_id",
              supports_iam=False),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate Cloud Bigtable resources (read-only)",
        components=component_args(COMPONENTS),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on Bigtable instances and tables"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="bigtable_actions_allowed", module_name="enum_bigtable")
    return 1
