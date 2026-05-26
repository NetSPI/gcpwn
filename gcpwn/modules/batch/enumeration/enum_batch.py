from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    resolve_selected_components,
)
from gcpwn.modules.batch.utilities.helpers import BatchJobsResource, resolve_locations


COMPONENTS = [
    ("jobs", "Enumerate Batch jobs"),
]


def _job_id_from_row(row: dict) -> str:
    return str((row or {}).get("job_id") or "").strip() or extract_path_tail(str((row or {}).get("name") or "").strip(), default="")


def _resolve_script_download_path(session, *, project_id: str, filename: str) -> Path:
    if hasattr(session, "get_download_save_path"):
        return Path(
            session.get_download_save_path(
                service_name="batch",
                filename=filename,
                project_id=project_id,
            )
        )
    fallback = Path.cwd() / "gcpwn_output" / "downloads" / "batch" / project_id / filename
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return fallback


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


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try wildcard location (-) when supported")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")

    return parse_component_args(
        user_args,
        description="Enumerate Batch resources (read-only)",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("download", "get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id
    locations = resolve_locations(session, args)

    jobs_resource = BatchJobsResource(session)
    job_rows: list[dict] = []
    downloaded_paths: list[str] = []
    download_message = ""
    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    if selected.get("jobs", False):
        rows = []
        listed_by_location = map_regions_with_disabled_short_circuit(
            locations,
            lambda location: jobs_resource.list(
                project_id=project_id,
                location=location,
                action_dict=scope_actions,
            ),
            threads=getattr(args, "threads", 3),
        )
        for location, listed in listed_by_location:
            if listed in ("Not Enabled", None):
                continue
            batch = listed or []
            if (args.get or args.download) and batch:
                batch = [
                    jobs_resource.get(
                        resource_id=row.get("name", ""),
                        action_dict=api_actions,
                    )
                    or row
                    for row in batch
                ]
            if batch:
                jobs_resource.save(batch, project_id=project_id, location=location)
                rows.extend(batch)
        job_rows = rows
        UtilityTools.summary_wrapup(
            project_id,
            "Batch Jobs",
            rows,
            jobs_resource.COLUMNS,
            primary_resource="Jobs",
            primary_sort_key="location",
        )

    if args.download:
        download_count = 0
        for job_row in job_rows:
            if not isinstance(job_row, dict):
                continue
            job_id = _job_id_from_row(job_row)
            if not job_id:
                continue
            for task_group_index, script_text in _task_group_script_texts(job_row):
                filename = f"{job_id}_{task_group_index}_script_commands.txt"
                download_path = _resolve_script_download_path(session, project_id=project_id, filename=filename)
                download_path.parent.mkdir(parents=True, exist_ok=True)
                download_path.write_text(script_text, encoding="utf-8")
                downloaded_paths.append(str(download_path))
                download_count += 1

        if download_count:
            download_message = f"[*] Downloaded {download_count} Batch script command file(s) for project {project_id}."
        elif job_rows:
            download_message = f"[*] No Batch runnable script text was present on the retrieved jobs for project {project_id}."
        else:
            download_message = f"[*] No Batch jobs were available to download script commands from in project {project_id}."

        for download_path in downloaded_paths:
            print(f"[*] Wrote Batch script commands to {download_path}")
        if download_message:
            print(download_message)

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="batch_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="batch_actions_allowed")

    return 1
