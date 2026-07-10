from __future__ import annotations

from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.storagetransfer.utilities.helpers import StorageTransferJobsResource


COMPONENTS = [
    Component("transfer_jobs", StorageTransferJobsResource, "Storage Transfer Jobs", "Transfer Jobs",
              help_text="Enumerate Storage Transfer jobs", scope=PROJECT, primary_sort_key="name",
              supports_iam=False,
              manual_id_arg="transfer_job_ids",
              manual_template=("projects", "{project_id}", "transferJobs", 0),
              manual_help="Transfer job IDs (short `my-job` or full projects/PID/transferJobs/my-job)."),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate Storage Transfer resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS),
        standard_args=("download", "get", "debug"),
        standard_arg_overrides={"download": {"help": "Reserved for future transfer job content downloads"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    discovered = run_components(session, args, components=COMPONENTS, column_name=None, module_name="enum_storagetransfer")
    if getattr(args, "download", False) and discovered.get("transfer_jobs"):
        print("[*] Transfer job download is not yet implemented for this module.")
    return 1
