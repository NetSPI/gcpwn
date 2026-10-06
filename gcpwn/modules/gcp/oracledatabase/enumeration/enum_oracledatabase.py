from __future__ import annotations

from gcpwn.core.utils.enum_framework import (
    Component,
    REGION,
    parse_enum_args,
    run_components,
)
from gcpwn.modules.gcp.oracledatabase.utilities.helpers import (
    OracleAutonomousDatabasesResource,
    OracleExadataInfrastructuresResource,
    OracleVmClustersResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "autonomous_databases",
        OracleAutonomousDatabasesResource,
        "Oracle Autonomous Databases",
        "Autonomous Databases",
        help_text="REQUIRES: oracledatabase.autonomousDatabases.list",
        scope=REGION,
        supports_iam=False,
    ),
    Component(
        "exadata_infras",
        OracleExadataInfrastructuresResource,
        "Oracle Cloud Exadata Infrastructures",
        "Exadata Infrastructures",
        help_text="REQUIRES: oracledatabase.cloudExadataInfrastructures.list",
        scope=REGION,
        supports_iam=False,
    ),
    Component(
        "vm_clusters",
        OracleVmClustersResource,
        "Oracle Cloud VM Clusters",
        "VM Clusters",
        help_text="REQUIRES: oracledatabase.cloudVmClusters.list",
        scope=REGION,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Oracle Database Service resources: autonomous databases, Exadata infrastructures, and VM clusters",
        region_label="Oracle Database locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="oracledatabase_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_oracledatabase",
    )
    return 1
