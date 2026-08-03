from __future__ import annotations

import argparse

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.utils.enum_framework import NESTED, PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.bigquery.utilities.helpers import (
    BigQueryDatasetsResource,
    BigQueryRoutinesResource,
    BigQueryTablesResource,
)


COMPONENTS = [
    Component("datasets", BigQueryDatasetsResource, "BigQuery Datasets", "Datasets",
              help_text="Enumerate BigQuery datasets", scope=PROJECT, primary_sort_key="full_dataset_id",
              supports_iam=False, manual_id_arg="dataset_ids",
              manual_help="Dataset IDs as `project.dataset`."),
    Component("tables", BigQueryTablesResource, "BigQuery Tables", "Tables",
              help_text="Enumerate BigQuery tables (per dataset)", scope=NESTED, parent_key="datasets",
              dependency_label="Datasets", primary_sort_key="full_table_id",
              manual_id_arg="table_ids", manual_help="Table IDs as `project.dataset.table`."),
    Component("routines", BigQueryRoutinesResource, "BigQuery Routines", "Routines",
              help_text="Enumerate BigQuery routines (per dataset)", scope=NESTED, parent_key="datasets",
              dependency_label="Datasets", primary_sort_key="full_routine_id",
              manual_id_arg="routine_ids", manual_help="Routine IDs as `project.dataset.routine`."),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--download", nargs="?", const="table", default=None,
                            help="Download BigQuery table data. Optional scope: table.")
        parser.add_argument("--download-limit", type=int, default=0,
                            help="Limit downloaded tables (0 = unlimited).")

    return parse_component_args(
        user_args,
        description="Enumerate BigQuery resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on tables and routines"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    download_requested = getattr(args, "download", None) is not None
    if download_requested:
        args.tables = True
        args.routines = True
        args.get = True  # downloading table/routine data needs the hydrated payload

    discovered = run_components(session, args, components=COMPONENTS, column_name="bigquery_actions_allowed",
                                module_name="enum_bigquery")

    if download_requested:
        project_id = session.project_id or ""
        table_resource = BigQueryTablesResource(session)
        limit = int(getattr(args, "download_limit", 0) or 0)
        rows = discovered.get("tables", [])
        if limit > 0:
            rows = rows[:limit]
        downloaded = []
        budget = DownloadBudget(session, label="bigquery table data")

        for table in rows:
            if budget.exceeded():
                break
            table_dict = table if isinstance(table, dict) else {}
            # Write view / materialized-view definition to a .sql loot file
            view_query = (table_dict.get("view_query") or table_dict.get("mview_query")
                          or table_dict.get("view", {}).get("query", "")) if table_dict else ""
            if view_query:
                full_id = table_dict.get("full_table_id", "unknown.unknown.unknown")
                parts = full_id.replace(":", ".").split(".")
                proj_part, ds_part, tbl_part = (parts + ["", "", ""])[:3]
                dest = resolve_download_path(
                    session, service_name="bigquery", project_id=project_id,
                    subdirs=["views", f"{proj_part}_{ds_part}"], filename=f"{tbl_part}.sql",
                )
                dest.write_text(view_query, encoding="utf-8")
                downloaded.append(str(dest))
                continue  # view tables have no rows to download
            # Download row data for non-view tables
            path = table_resource.download_table_data(row=table, project_id=project_id)
            if path is not None:
                downloaded.append(str(path))

        # Write routine bodies (SQL/Python UDFs, procedures) to .sql / .py loot files
        for routine in discovered.get("routines", []):
            if budget.exceeded():
                break
            routine_dict = routine if isinstance(routine, dict) else {}
            body = routine_dict.get("body") or ""
            if not body:
                continue
            full_id = routine_dict.get("full_routine_id", "unknown.unknown.unknown")
            parts = full_id.split(".")
            proj_part, ds_part, rtn_part = (parts + ["", "", ""])[:3]
            lang = str(routine_dict.get("language", "sql") or "sql").lower()
            ext = "py" if lang == "python" else "sql"
            dest = resolve_download_path(
                session, service_name="bigquery", project_id=project_id,
                subdirs=["routines", f"{proj_part}_{ds_part}"], filename=f"{rtn_part}.{ext}",
            )
            dest.write_text(body, encoding="utf-8")
            downloaded.append(str(dest))

        for path in downloaded:
            print(f"[*] Wrote BigQuery loot to {path}")
        if downloaded:
            print(f"[*] Downloaded {len(downloaded)} BigQuery file(s) for project {project_id}.")
        elif discovered.get("tables") or discovered.get("routines"):
            print(f"[*] No BigQuery data/definitions found to download for project {project_id}.")
    return 1
