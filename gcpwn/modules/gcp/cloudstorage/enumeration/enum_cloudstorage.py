from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, run_components
from gcpwn.core.utils.module_helpers import extract_path_segment
from gcpwn.core.utils.service_runtime import (
    parse_component_args,
    parse_csv_file_args,
    resolve_selected_components,
)
from gcpwn.modules.gcp.cloudstorage.utilities.helpers import (
    CloudStorageBlobsResource,
    CloudStorageBucketsResource,
    CloudStorageHmacKeysResource,
)


class _Ref:
    # Hashable bucket stand-in: summary_wrapup keys its bucket -> blobs map on objects
    # and reads .name/.location off them (SimpleNamespace is unhashable here).
    __slots__ = ("name", "location")

    def __init__(self, name: str, location: str = "") -> None:
        self.name = name
        self.location = location

    def __hash__(self) -> int:
        return hash((self.name, self.location))

    def __eq__(self, other) -> bool:
        return isinstance(other, _Ref) and (self.name, self.location) == (other.name, other.location)


def _access_kwargs(args) -> dict:
    # Forwarded to bucket/blob list(): the standard-vs-HMAC/XML branch lives inside
    # the resource, so the enum module stays access-mode agnostic.
    return {
        "access_mode": getattr(args, "access_mode", "standard"),
        "access_id": getattr(args, "access_id", None),
        "hmac_secret": getattr(args, "hmac_secret", None),
    }


def _blob_name_filter(blob_name_inputs):
    # --blob-names restricts which listed blobs are kept (and saved); runs as the
    # NESTED enrich step before save/summary.
    allowed = {str(name).strip() for name in blob_name_inputs if str(name).strip()}

    def _enrich(rows, *, resource, args, api_actions):
        if not allowed:
            return rows
        return [row for row in rows if str(row.get("name") or "") in allowed]

    return _enrich


COMPONENTS = [
    Component(
        "hmac_keys", CloudStorageHmacKeysResource, "Cloud Storage HMAC Keys", "HMAC Keys",
        help_text="Enumerate Cloud Storage HMAC keys", scope=PROJECT, supports_iam=False,
        columns=["access_id", "secret", "state", "service_account_email"],
        primary_sort_key="service_account_email",
        manual_id_arg="access_keys",
        manual_help="HMAC access IDs (or projects/<project>/hmacKeys/<id> paths).",
    ),
    Component(
        "buckets", CloudStorageBucketsResource, "Cloud Storage Buckets", "Buckets",
        help_text="Enumerate Cloud Storage buckets", scope=PROJECT,
        columns=["name", "location"], primary_sort_key="name", summarize=False,
        list_kwargs=_access_kwargs,
        manual_id_arg="bucket_names",
        manual_help="Bucket names in comma-separated format.",
    ),
    # blobs are the children of buckets -> the uniform NESTED pattern. The framework
    # lists + saves them (per bucket, including manual --bucket-names targets); the
    # module only renders the bucket->blobs map and drives downloads.
    Component(
        "blobs", CloudStorageBlobsResource, "Cloud Storage Blobs", "Buckets",
        help_text="Enumerate Cloud Storage blobs", scope=NESTED, parent_key="buckets",
        dependency_label="Buckets", supports_get=False, supports_iam=False, summarize=False,
        list_kwargs=_access_kwargs,
    ),
]
ALL_KEYS = ["hmac_keys", "buckets", "blobs"]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        blob_group = parser.add_mutually_exclusive_group(required=False)
        blob_group.add_argument("--blob-names", type=str, help="Blob names in comma-separated format")
        blob_group.add_argument("--blob-names-file", type=str, help="File containing blob names, one per line")
        parser.add_argument("--output", type=str, required=False, help="Output folder for downloaded files")
        parser.add_argument("--file-size", type=int, required=False, help="Blob size filter in bytes")
        parser.add_argument("--good-regex", type=str, required=False, help="Regex filter for blob downloads")
        parser.add_argument("--time-limit", type=str, required=False, help="Per-bucket time limit in seconds")
        parser.add_argument("--access-id", type=str, help="HMAC access ID")
        parser.add_argument("--hmac-secret", type=str, help="HMAC secret")
        parser.add_argument("--threads", type=int, default=1, help="Number of download worker threads")
        parser.add_argument("--list-hmac-secrets", action="store_true", help="List saved HMAC secrets")

    return parse_component_args(
        user_args,
        description="Enumerate Cloud Storage resources",
        components=[
            ("hmac_keys", "Enumerate Cloud Storage HMAC keys"),
            ("buckets", "Enumerate Cloud Storage buckets"),
            ("blobs", "Enumerate Cloud Storage blobs"),
        ],
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("download", "iam", "get", "debug"),
        standard_arg_overrides={
            "download": {"help": "Attempt to download enumerated blobs"},
            "iam": {"help": "Run bucket TestIamPermissions checks"},
        },
    )


def _summarize_buckets(project_id, bucket_rows, manual_requested, args) -> None:
    # Bespoke bucket view: each bucket with an (empty, at this stage) blobs column.
    if bucket_rows or not manual_requested:
        keyed = {
            _Ref(str(row.get("name") or "").strip(), str(row.get("location") or "").strip()): []
            for row in bucket_rows
        }
        UtilityTools.summary_wrapup(
            project_id, "Cloud Storage Buckets", keyed, ["name", "location"],
            primary_resource="Buckets", secondary_title_name="blobs",
        )
    elif getattr(args, "get", False):
        print("[*] No Cloud Storage buckets found for the supplied --bucket-names.")
    else:
        print("[*] Manual --bucket-names supplied without --get; skipping bucket summary.")


def _blob_target_buckets(session, discovered, bucket_name_inputs) -> list[str]:
    if bucket_name_inputs:
        names = list(bucket_name_inputs)
    elif discovered.get("buckets"):
        names = [str(row.get("name") or "").strip() for row in discovered["buckets"] if row.get("name")]
    else:
        names = [str(bucket.name) for bucket in CloudStorageBlobsResource(session).resolve_cached_buckets(project_id=session.project_id)]
    return [name for name in names if name]


def _blobs_tail(session, args, project_id, discovered, bucket_name_inputs, blob_name_inputs,
                access_mode, credname_override, dependency) -> None:
    # The framework (NESTED) already listed + saved blobs; render the bucket->blobs
    # map (incl. empty buckets) and drive downloads off the listed names.
    target_bucket_names = _blob_target_buckets(session, discovered, bucket_name_inputs)
    if not target_bucket_names:
        return  # run_components already printed the missing-Buckets dependency

    bucket_blob_map: dict = {_Ref(name): [] for name in target_bucket_names}
    for blob in discovered.get("blobs", []) or []:
        bucket_name = str(blob.get("bucket_name") or "").strip()
        blob_name = str(blob.get("name") or "")
        if not bucket_name or not blob_name or blob_name.endswith("/"):
            continue
        bucket_blob_map.setdefault(_Ref(bucket_name), []).append(blob_name)

    if not dependency:
        UtilityTools.summary_wrapup(
            project_id, "Cloud Storage Blobs", bucket_blob_map, ["name", "location"],
            primary_resource="Buckets", secondary_title_name="blobs",
        )

    if getattr(args, "download", False):
        blob_actions = CloudStorageBlobsResource(session).download_blobs(
            project_id=project_id, bucket_names=target_bucket_names, blob_name_inputs=blob_name_inputs,
            output=args.output, good_regex=args.good_regex, file_size=args.file_size,
            time_limit=args.time_limit, threads=args.threads, access_mode=access_mode,
            access_id=args.access_id, hmac_secret=args.hmac_secret,
        )
        if has_recorded_actions(blob_actions):
            session.insert_actions(blob_actions, project_id, column_name="storage_actions_allowed", credname_override=credname_override)


def run_module(user_args, session, dependency=False):
    args = _parse_args(user_args)
    if bool(args.access_id) ^ bool(args.hmac_secret):
        print("[X] --access-id and --hmac-secret must be supplied together.")
        return -1

    project_id = session.project_id
    access_mode = "hmac" if (args.access_id and args.hmac_secret) else "standard"
    args.access_mode = access_mode

    bucket_name_inputs = parse_csv_file_args(getattr(args, "bucket_names", None), getattr(args, "bucket_names_file", None))
    blob_name_inputs = parse_csv_file_args(getattr(args, "blob_names", None), getattr(args, "blob_names_file", None))
    access_key_inputs = parse_csv_file_args(getattr(args, "access_keys", None), getattr(args, "access_keys_file", None))

    hmac_resource = CloudStorageHmacKeysResource(session)
    hmac_action_crednames = (
        hmac_resource.resolve_action_crednames(project_id=project_id, access_id=args.access_id)
        if access_mode == "hmac"
        else None
    )

    if args.list_hmac_secrets:
        hmac_secrets = hmac_resource.list_saved_secrets()
        if hmac_secrets:
            print("[*] The following HMAC keys have saved secrets:")
            for secret in hmac_secrets:
                print(f"   - {secret['secret']} \n      - {secret['access_id']} @ {secret['service_account_email']}")
        return 1

    if access_key_inputs:
        args.hmac_keys = True
    if bucket_name_inputs:
        args.buckets = True
    if blob_name_inputs:
        args.blobs = True
    selected = resolve_selected_components(args, ALL_KEYS)
    for key in ALL_KEYS:
        setattr(args, key, selected[key])

    # --access-keys may be full paths; the HMAC get() keys on access_id, so reduce them.
    if access_key_inputs:
        access_ids = [extract_path_segment(token, "hmacKeys") or str(token).strip() for token in access_key_inputs]
        args.access_keys = ",".join([access_id for access_id in access_ids if access_id])
        args.access_keys_file = None

    # --blob-names filters the NESTED blob children before save/summary.
    for component in COMPONENTS:
        if component.key == "blobs":
            component.enrich_fn = _blob_name_filter(blob_name_inputs)

    discovered: dict = {}
    if selected["hmac_keys"] or selected["buckets"] or selected["blobs"]:
        discovered = run_components(
            session, args, components=COMPONENTS, column_name="storage_actions_allowed",
            credname_override=hmac_action_crednames, module_name="enum_cloudstorage",
        )

    if selected["buckets"]:
        _summarize_buckets(project_id, discovered.get("buckets", []), bool(bucket_name_inputs), args)

    if selected["blobs"]:
        _blobs_tail(session, args, project_id, discovered, bucket_name_inputs, blob_name_inputs,
                    access_mode, hmac_action_crednames, dependency)

    return 1
