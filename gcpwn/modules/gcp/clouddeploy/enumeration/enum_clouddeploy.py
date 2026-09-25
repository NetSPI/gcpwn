from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.clouddeploy.utilities.helpers import (
    CloudDeployDeliveryPipelinesResource,
    CloudDeployReleasesResource,
    CloudDeployRolloutsResource,
    CloudDeployTargetsResource,
    resolve_locations,
)


COMPONENTS = [
    Component("delivery_pipelines", CloudDeployDeliveryPipelinesResource, "Cloud Deploy Delivery Pipelines", "Delivery Pipelines",
              help_text="Enumerate Cloud Deploy delivery pipelines", scope=REGION,
              manual_id_arg="pipeline_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "deliveryPipelines", 1),
              manual_error="Invalid delivery pipeline ID format. Use LOCATION/PIPELINE_ID or projects/PROJECT_ID/locations/LOCATION/deliveryPipelines/PIPELINE_ID.",
              manual_help="Delivery pipeline IDs as LOCATION/PIPELINE_ID or full projects/.../deliveryPipelines/... names."),
    Component("targets", CloudDeployTargetsResource, "Cloud Deploy Targets", "Targets",
              help_text="Enumerate Cloud Deploy targets", scope=REGION,
              manual_id_arg="target_ids",
              manual_template=("projects", "{project_id}", "locations", 0, "targets", 1),
              manual_error="Invalid target ID format. Use LOCATION/TARGET_ID or projects/PROJECT_ID/locations/LOCATION/targets/TARGET_ID.",
              manual_help="Target IDs as LOCATION/TARGET_ID or full projects/.../targets/... names."),
    Component("releases", CloudDeployReleasesResource, "Cloud Deploy Releases", "Releases",
              help_text="Enumerate Cloud Deploy releases (nested under each delivery pipeline)",
              scope=NESTED, parent_key="delivery_pipelines", dependency_label="Delivery Pipelines",
              primary_sort_key="release_id", supports_iam=False),
    Component("rollouts", CloudDeployRolloutsResource, "Cloud Deploy Rollouts", "Rollouts",
              help_text="Enumerate Cloud Deploy rollouts (nested under each release)",
              scope=NESTED, parent_key="releases", dependency_label="Releases",
              primary_sort_key="rollout_id", supports_iam=False),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try all known Cloud Deploy locations")
        regions_group.add_argument("--regions-list", required=False, help="Locations in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing locations per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Deploy resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "iam", "get"),
        standard_arg_overrides={
            "download": {
                "help": (
                    "Download user-uploaded Skaffold config archives from each release's "
                    "skaffold_config_uri (gs:// path) and extract the contained YAML files. "
                    "Requires storage.objects.get on the source bucket."
                ),
            },
        },
    )


def _download_skaffold_configs(session, discovered):
    project_id = session.project_id
    pipeline_rows = discovered.get("delivery_pipelines", [])
    if not pipeline_rows:
        print("[*] No delivery pipelines found — skipping Skaffold config download.")
        return

    releases_resource = CloudDeployReleasesResource(session)
    all_paths = []
    for row in pipeline_rows:
        if not isinstance(row, dict):
            continue
        pipeline_name = str(row.get("name") or "").strip()
        if not pipeline_name:
            continue
        paths = releases_resource.download_skaffold_configs(
            pipeline_name=pipeline_name, project_id=project_id
        )
        all_paths.extend(paths)

    if all_paths:
        for path in all_paths:
            print(f"[*] Wrote Skaffold config to {path}")
        print(f"[*] Downloaded {len(all_paths)} Skaffold config file(s) for project {project_id}.")
    else:
        print(f"[*] No Skaffold config archives found/accessible for project {project_id}.")


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.delivery_pipelines = True  # need pipeline names to list releases

    discovered = run_components(
        session, args, components=COMPONENTS, column_name="clouddeploy_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_clouddeploy",
    )

    if getattr(args, "download", False):
        _download_skaffold_configs(session, discovered)
    return 1
