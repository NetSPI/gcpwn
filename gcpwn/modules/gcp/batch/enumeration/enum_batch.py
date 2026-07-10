from __future__ import annotations

import argparse

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import REGION, Component, component_args, run_components
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.batch.utilities.helpers import BatchJobsResource, resolve_locations


COMPONENTS = [
    Component("jobs", BatchJobsResource, "Batch Jobs", "Jobs",
              help_text="Enumerate Batch jobs", scope=REGION, supports_iam=False),
]


def _job_id_from_row(row: dict) -> str:
    return str((row or {}).get("job_id") or "").strip() or extract_path_tail(str((row or {}).get("name") or "").strip(), default="")


def _task_group_script_texts(job_row: dict) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    task_groups = job_row.get("task_groups") if isinstance(job_row, dict) else None
    if not isinstance(task_groups, list):
        return results
    for task_group_index, task_group in enumerate(task_groups):
        if not isinstance(task_group, dict):
            continue
        task_spec = task_group.get("task_spec")
        if not isinstance(task_spec, dict):
            continue
        runnables = task_spec.get("runnables")
        if not isinstance(runnables, list):
            continue
        script_texts = [
            str(((runnable.get("script") or {}) if isinstance(runnable, dict) else {}).get("text") or "").strip()
            for runnable in runnables
            if isinstance(runnable, dict)
        ]
        script_texts = [text for text in script_texts if text]
        if script_texts:
            results.append((task_group_index, "\n\n".join(script_texts)))
    return results


def _download_scripts(session, *, project_id: str, job_rows: list[dict]) -> None:
    downloaded_paths: list[str] = []
    download_count = 0
    budget = DownloadBudget(session, label="batch scripts")
    for job_row in job_rows:
        if budget.exceeded():  # per --download-timeout: stop and move on
            break
        if not isinstance(job_row, dict):
            continue
        job_id = _job_id_from_row(job_row)
        if not job_id:
            continue
        for task_group_index, script_text in _task_group_script_texts(job_row):
            filename = f"{job_id}_{task_group_index}_script_commands.txt"
            download_path = resolve_download_path(session, service_name="batch", project_id=project_id, filename=filename)
            download_path.write_text(script_text, encoding="utf-8")
            downloaded_paths.append(str(download_path))
            download_count += 1

    for download_path in downloaded_paths:
        print(f"[*] Wrote Batch script commands to {download_path}")
    if download_count:
        print(f"[*] Downloaded {download_count} Batch script command file(s) for project {project_id}.")
    elif job_rows:
        print(f"[*] No Batch runnable script text was present on the retrieved jobs for project {project_id}.")
    else:
        print(f"[*] No Batch jobs were available to download script commands from in project {project_id}.")


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try wildcard location (-) when supported")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Batch resources (read-only)",
        components=component_args(COMPONENTS),
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    if getattr(args, "download", False):
        args.get = True  # downloading script commands requires the full per-job payload

    discovered = run_components(
        session, args, components=COMPONENTS, column_name="batch_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_batch",
    )

    if getattr(args, "download", False):
        _download_scripts(session, project_id=session.project_id, job_rows=discovered.get("jobs", []))
    return 1
