from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.vertex.utilities.helpers import (
    VertexCustomJobsResource,
    VertexDeploymentResourcePoolsResource,
    VertexEndpointsResource,
    VertexModelsResource,
    VertexPipelineJobsResource,
    VertexReasoningEnginesResource,
    VertexTuningJobsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "custom_jobs", VertexCustomJobsResource,
        "Vertex AI Custom Jobs", "Custom Jobs",
        help_text="Enumerate Vertex AI custom training jobs",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "pipeline_jobs", VertexPipelineJobsResource,
        "Vertex AI Pipeline Jobs", "Pipeline Jobs",
        help_text="Enumerate Vertex AI pipeline / KFP jobs",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "deployment_resource_pools", VertexDeploymentResourcePoolsResource,
        "Vertex AI Deployment Resource Pools", "Deployment Resource Pools",
        help_text="Enumerate Vertex AI deployment resource pools",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "tuning_jobs", VertexTuningJobsResource,
        "Vertex AI Tuning Jobs", "Tuning Jobs",
        help_text="Enumerate Vertex AI supervised fine-tuning jobs",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "reasoning_engines", VertexReasoningEnginesResource,
        "Vertex AI Reasoning Engines", "Reasoning Engines",
        help_text="Enumerate Vertex AI reasoning engines (v1beta1)",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "endpoints", VertexEndpointsResource,
        "Vertex AI Endpoints", "Endpoints",
        help_text="Enumerate Vertex AI prediction endpoints",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
        primary_sort_key="endpoint_id",
    ),
    Component(
        "models", VertexModelsResource,
        "Vertex AI Models", "Models",
        help_text="Enumerate Vertex AI registered models",
        scope=REGION,
        supports_get=False,
        supports_iam=False,
        primary_sort_key="model_id",
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument(
            "--region", default=None,
            help="Single region to query",
        )
        regions_group.add_argument(
            "--all-regions", action="store_true",
            help="Try all known Vertex AI regions",
        )
        regions_group.add_argument(
            "--regions-list",
            help="Comma-separated list of regions",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Vertex AI resources (custom jobs, pipeline jobs, DRPs, tuning jobs, reasoning engines, endpoints, models)",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args,
        components=COMPONENTS,
        column_name="vertex_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_vertex",
    )
    return 1
