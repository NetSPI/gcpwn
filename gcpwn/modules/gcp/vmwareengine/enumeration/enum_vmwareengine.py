from __future__ import annotations

from gcpwn.core.utils.enum_framework import Component, NESTED, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.vmwareengine.utilities.helpers import (
    VmwareEngineHcxActivationKeysResource,
    VmwareEnginePrivateCloudsResource,
    VmwareEngineClustersResource,
    resolve_locations,
)

COMPONENTS = [
    Component(
        "private_clouds",
        VmwareEnginePrivateCloudsResource,
        "VMware Engine Private Clouds",
        "Private Clouds",
        help_text="Enumerate VMware Engine private clouds. REQUIRES: vmwareengine.privateClouds.list",
        scope=REGION,
    ),
    Component(
        "clusters",
        VmwareEngineClustersResource,
        "VMware Engine Clusters",
        "Clusters",
        help_text="Enumerate clusters in each private cloud. REQUIRES: vmwareengine.clusters.list + --private-clouds",
        scope=NESTED,
        parent_key="private_clouds",
        dependency_label="Private Clouds",
        save_parent_kwarg="private_cloud",
        supports_get=False,
    ),
    Component(
        "hcx_activation_keys",
        VmwareEngineHcxActivationKeysResource,
        "VMware Engine HCX Activation Keys",
        "HCX Activation Keys",
        help_text=(
            "Enumerate HCX activation keys per private cloud. "
            "REQUIRES: vmwareengine.hcxActivationKeys.list + --private-clouds"
        ),
        scope=NESTED,
        parent_key="private_clouds",
        dependency_label="Private Clouds",
        save_parent_kwarg="private_cloud",
        supports_get=False,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate VMware Engine private clouds, clusters, and HCX activation keys",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="vmwareengine_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_vmwareengine",
    )
    return 1
