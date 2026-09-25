"""Dataflow + Data Pipelines enumeration shim for enum_all.

enum_all references this single module; it delegates to the two sub-modules so
that enum_all only needs one ServiceSpec entry while both resource types run:

  enum_dataflow_core        -- Dataflow jobs        (DataflowJobsResource)
  enum_dataflow_datapipelines -- Data Pipelines     (DataPipelinesResource)

Each sub-module parses user_args independently, so all standard flags
(--regions-list, --threads, --iam, etc.) are handled correctly.
"""
from __future__ import annotations

from gcpwn.modules.gcp.dataflow.enumeration.enum_dataflow_core import (
    run_module as _run_core,
)
from gcpwn.modules.gcp.dataflow.enumeration.enum_dataflow_datapipelines import (
    run_module as _run_pipelines,
)


def run_module(user_args, session):
    _run_core(user_args, session)
    _run_pipelines(user_args, session)
    return 1
