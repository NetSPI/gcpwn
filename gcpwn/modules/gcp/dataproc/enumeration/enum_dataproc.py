from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.dataproc.utilities.helpers import (
    DataprocBatchesResource,
    DataprocClustersResource,
    DataprocWorkflowTemplatesResource,
    resolve_locations,
)


COMPONENTS = [
    Component("clusters", DataprocClustersResource, "Dataproc Clusters", "Clusters",
              help_text="Enumerate Dataproc clusters (and the SA each runs as)", scope=REGION,
              supports_get=False, supports_iam=False),
    Component("batches", DataprocBatchesResource, "Dataproc Serverless Batches", "Batches",
              help_text="Enumerate Dataproc Serverless batches (and the SA each runs as)", scope=REGION,
              supports_get=False, supports_iam=False),
    Component("workflow_templates", DataprocWorkflowTemplatesResource, "Dataproc Workflow Templates", "Workflow Templates",
              help_text="Enumerate Dataproc Workflow Templates (service_account = PE target)", scope=REGION,
              supports_get=False, supports_iam=False),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Dataproc resources",
        region_label="Dataproc regions",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="dataproc_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_dataproc",
    )
    return 1
