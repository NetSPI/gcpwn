from __future__ import annotations

from gcpwn.core.utils.enum_framework import NESTED, PROJECT, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.vmmigration.utilities.helpers import (
    VmMigrationGroupsResource,
    VmMigrationMigratingVmsResource,
    VmMigrationSourcesResource,
    VmMigrationTargetProjectsResource,
    resolve_locations,
)

COMPONENTS = [
    Component(
        "sources",
        VmMigrationSourcesResource,
        "VM Migration Sources",
        "Sources",
        help_text="Enumerate VM Migration sources (VMware/AWS/Azure connections)",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "migrating_vms",
        VmMigrationMigratingVmsResource,
        "VM Migration MigratingVMs",
        "MigratingVMs",
        help_text="Enumerate migrating VMs under each discovered source",
        scope=NESTED,
        parent_key="sources",
        dependency_label="sources",
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "groups",
        VmMigrationGroupsResource,
        "VM Migration Groups",
        "Groups",
        help_text="Enumerate VM Migration groups",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "target_projects",
        VmMigrationTargetProjectsResource,
        "VM Migration Target Projects",
        "Target Projects",
        help_text="Enumerate VM Migration target projects (always global)",
        scope=PROJECT,
        supports_get=False,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser):
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known VM Migration regions")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Comma-separated list of regions to query")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File with regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate VM Migration sources, migrating VMs, groups, and target projects.",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "iam"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args,
        components=COMPONENTS,
        column_name="vmmigration_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_vmmigration_resources",
    )
    return 1
