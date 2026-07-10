from __future__ import annotations

import argparse

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.kms.utilities.helpers import (
    KmsCryptoKeysResource,
    KmsCryptoKeyVersionsResource,
    KmsKeyRingsResource,
    resolve_regions,
)


COMPONENTS = [
    Component("keyrings", KmsKeyRingsResource, "Cloud KMS Keyrings", "Keyrings",
              help_text="Enumerate Cloud KMS keyrings", scope=REGION, supports_get=False),
    Component("keys", KmsCryptoKeysResource, "Cloud KMS Keys", "Keys",
              help_text="Enumerate Cloud KMS keys (per keyring)", scope=NESTED,
              parent_key="keyrings", dependency_label="Keyrings", save_parent_kwarg="keyring_name"),
    Component("versions", KmsCryptoKeyVersionsResource, "Cloud KMS Key Versions", "Key Versions",
              help_text="Enumerate Cloud KMS key versions (per key)", scope=NESTED,
              parent_key="keys", dependency_label="Keys", save_parent_kwarg="key_name", supports_iam=False),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Enumerate all available KMS locations")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud KMS resources",
        components=component_args(COMPONENTS),
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on KMS keyrings and keys"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="kms_actions_allowed",
        region_resolver=resolve_regions,
        module_name="enum_kms",
    )
    return 1
