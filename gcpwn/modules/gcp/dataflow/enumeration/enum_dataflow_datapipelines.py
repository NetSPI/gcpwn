"""Enumerate Cloud Data Pipelines pipelines.

Cloud Data Pipelines (datapipelines.googleapis.com) is a managed scheduling
layer that dispatches Dataflow jobs on a cron. Pipelines that specify a non-default
workerServiceAccount are PE candidates: the dispatched Dataflow job runs as that SA
(GCE VMs → IMDS → ya29.*).

Required permission  : datapipelines.pipelines.list
Exploit follow-on    : exploit_dataflow_datapipeline_as_sa
  (datapipelines.pipelines.create + iam.serviceAccounts.actAs on the target SA)
"""

from __future__ import annotations


from gcpwn.core.utils.enum_framework import Component, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.dataflow.utilities.helpers import (
    DataPipelinesResource,
    resolve_dp_locations,
)


COMPONENTS = [
    Component(
        "pipelines", DataPipelinesResource,
        "Cloud Data Pipelines", "Pipelines",
        help_text="Enumerate Cloud Data Pipelines (PE candidates: non-default workerServiceAccount)",
        scope=REGION,
        supports_get=False,
        supports_iam=True,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Cloud Data Pipelines across regions",
        region_label="Data Pipelines regions",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS,
        column_name="dataflow_actions_allowed",
        region_resolver=resolve_dp_locations,
        module_name="enum_dataflow_datapipelines",
    )
    return 1
