from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.deploymentmanager.utilities.helpers import DeploymentManagerDeploymentResource


COMPONENTS = [
    Component(
        "deployments", DeploymentManagerDeploymentResource,
        "Cloud Deployment Manager Deployments", "Deployments",
        help_text="Enumerate Cloud Deployment Manager deployments",
        scope=PROJECT,
        supports_iam=False,
        primary_sort_key="name",
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--download", action="store_true",
            help="Download manifest YAML/Jinja2 template for each deployment to disk",
        )

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Deployment Manager deployments",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(
        session, args,
        components=COMPONENTS,
        column_name="deploymentmanager_actions_allowed",
        module_name="enum_deploymentmanager",
    )

    if getattr(args, "download", False):
        deployments = discovered.get("deployments", [])
        if deployments:
            DeploymentManagerDeploymentResource(session).download_all_manifests(
                session.project_id, deployments
            )

    return 1
