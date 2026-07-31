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

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
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
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False,
                                   help="Try all known Data Pipelines regions")
        regions_group.add_argument("--regions-list", required=False,
                                   help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False,
                                   help="File containing regions per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Data Pipelines across regions",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "debug"),
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
