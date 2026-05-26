from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.service_runtime import (
    get_cached_rows,
    map_regions_with_disabled_short_circuit,
    parallel_map,
    parse_component_args,
    print_missing_dependency,
    resolve_selected_components,
)
from gcpwn.modules.kms.utilities.helpers import KmsCryptoKeysResource, KmsCryptoKeyVersionsResource, KmsKeyRingsResource, resolve_regions


COMPONENTS = [
    ("keyrings", "Enumerate Cloud KMS keyrings"),
    ("keys", "Enumerate Cloud KMS keys (per keyring)"),
    ("versions", "Enumerate Cloud KMS key versions (per key)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument(
            "--all-regions",
            action="store_true",
            required=False,
            help="Enumerate all available KMS locations",
        )
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud KMS resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on KMS keyrings and keys"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    keyrings_resource = KmsKeyRingsResource(session)
    keys_resource = KmsCryptoKeysResource(session)
    versions_resource = KmsCryptoKeyVersionsResource(session)

    regions = resolve_regions(session, args)

    discovered_keyrings: list[str] = []
    discovered_keys: list[str] = []

    if selected.get("keyrings", False):
        all_keyrings = []
        listed_by_region = map_regions_with_disabled_short_circuit(
            regions,
            lambda region: keyrings_resource.list(
                project_id=project_id,
                location=region,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for region, listed in listed_by_region:
            if listed in ("Not Enabled", None):
                continue
            if listed:
                keyrings_resource.save(listed, project_id=project_id, location=region)
                all_keyrings.extend(listed)
        if args.iam:
            for row in all_keyrings:
                name = str(row.get("name") or "").strip()
                if name:
                    keyrings_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
        UtilityTools.summary_wrapup(
            project_id,
            "Cloud KMS Keyrings",
            all_keyrings,
            keyrings_resource.COLUMNS,
            primary_resource="Keyrings",
            primary_sort_key="location",
            )
        discovered_keyrings.extend([str(row.get("name") or "").strip() for row in all_keyrings if str(row.get("name") or "").strip()])

    if selected.get("keys", False) or selected.get("versions", False):
        if not discovered_keyrings and not selected.get("keyrings", False):
            cached = get_cached_rows(session, keyrings_resource.TABLE_NAME, project_id=project_id, columns=["name"]) or []
            discovered_keyrings = [row.get("name", "") for row in cached if row.get("name")]

    if selected.get("keys", False):
        if not discovered_keyrings:
            print_missing_dependency(
                component_name="Cloud KMS keys",
                dependency_name="Keyrings",
                module_name="enum_kms",
            )
        else:
            all_keys = []
            listed_by_keyring = parallel_map(
                discovered_keyrings,
                lambda keyring_name: (
                    keyring_name,
                    keys_resource.list(keyring_name=keyring_name, action_dict=scope_actions),
                ),
                threads=getattr(args, "threads", 3),
            )
            for keyring_name, listed in listed_by_keyring:
                if listed in ("Not Enabled", None):
                    continue
                if listed:
                    if args.get:
                        listed = [keys_resource.get(resource_id=row.get("name", ""), action_dict=api_actions) or row for row in listed]
                    if args.iam:
                        for row in listed:
                            name = str(row.get("name") or "").strip()
                            if name:
                                keys_resource.test_iam_permissions(resource_id=name, action_dict=iam_actions)
                    keys_resource.save(listed, project_id=project_id, keyring_name=keyring_name)
                    all_keys.extend(listed)
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud KMS Keys",
                all_keys,
                keys_resource.COLUMNS,
                primary_resource="Keys",
                primary_sort_key="location",
                )
            discovered_keys = [str(row.get("name") or "").strip() for row in all_keys if str(row.get("name") or "").strip()]

    if selected.get("versions", False):
        if not discovered_keys and not selected.get("keys", False):
            cached_keys = get_cached_rows(session, keys_resource.TABLE_NAME, project_id=project_id, columns=["name"]) or []
            discovered_keys = [row.get("name", "") for row in cached_keys if row.get("name")]
        if not discovered_keys:
            print_missing_dependency(
                component_name="Cloud KMS key versions",
                dependency_name="Keys",
                module_name="enum_kms",
            )
        else:
            all_versions = []
            listed_by_key = parallel_map(
                discovered_keys,
                lambda key_name: (key_name, versions_resource.list(key_name=key_name)),
                threads=getattr(args, "threads", 3),
            )
            for key_name, listed in listed_by_key:
                if listed in ("Not Enabled", None):
                    continue
                if listed:
                    if args.get:
                        listed = [versions_resource.get(resource_id=row.get("name", "")) or row for row in listed]
                    versions_resource.save(listed, project_id=project_id, key_name=key_name)
                    all_versions.extend(listed)
            UtilityTools.summary_wrapup(
                project_id,
                "Cloud KMS Key Versions",
                all_versions,
                versions_resource.COLUMNS,
                primary_resource="Key Versions",
                primary_sort_key="location",
                )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="kms_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="kms_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="kms_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
