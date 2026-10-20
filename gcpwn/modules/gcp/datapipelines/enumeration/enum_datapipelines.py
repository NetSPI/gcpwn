"""Enumerate Cloud Data Pipelines pipelines and their Dataflow worker SA settings.

Offensively interesting: a pipeline with a non-default workerServiceAccount
means any Dataflow job dispatched by it runs as that SA (GCE VMs → IMDS → ya29.*).
"""

from __future__ import annotations

import argparse

import requests as _rlib

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import get_bearer_token, static_locations

_DP_BASE = "https://datapipelines.googleapis.com/v1"
_DP_PERMISSIONS = permissions_with_prefixes("datapipelines.pipelines.")


def _test_iam_rest(tok: str, resource_name: str, permissions: tuple) -> list[str]:
    try:
        resp = _rlib.post(
            f"{_DP_BASE}/{resource_name}:testIamPermissions",
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json={"permissions": list(permissions)},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("permissions", [])
    except Exception:
        pass
    return []

_DEFAULT_REGIONS = static_locations("datapipelines")


def _list_pipelines(tok: str, project: str, region: str) -> list[dict]:
    parent = f"projects/{project}/locations/{region}"
    url = f"{_DP_BASE}/{parent}/pipelines"
    r = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, timeout=20)
    if r.status_code == 200:
        return r.json().get("pipelines", [])
    return []


def _extract_worker_sa(pipeline: dict) -> str:
    workload = pipeline.get("workload", {})
    for key in ("dataflowFlexTemplateRequest", "dataflowLaunchTemplateRequest"):
        sub = workload.get(key, {})
        lp = sub.get("launchParameter") or sub.get("launchParameters") or {}
        env = lp.get("environment", {})
        sa = env.get("serviceAccountEmail", "")
        if sa:
            return sa
    return ""


def run_module(user_args, session):
    parser = argparse.ArgumentParser(
        description="Enumerate Cloud Data Pipelines and flag non-default workerServiceAccount settings.",
        allow_abbrev=False,
    )
    parser.add_argument("--region", default=None,
                        help="Single region (default: all common regions)")
    parser.add_argument("--regions-list", default=None,
                        help="Comma-separated regions to enumerate")
    parser.add_argument("--iam", action="store_true",
                        help="Run testIamPermissions on each discovered pipeline")
    args = parser.parse_args(user_args)

    project = session.project_id
    if not project:
        print(f"{UtilityTools.RED}[!] No project context.{UtilityTools.RESET}")
        return -1

    if args.region:
        regions = [args.region]
    elif args.regions_list:
        regions = [r.strip() for r in args.regions_list.split(",") if r.strip()]
    else:
        regions = _DEFAULT_REGIONS

    tok = get_bearer_token(session)
    found_any = False
    pe_candidates: list[tuple[str, str, str]] = []
    action_dict: dict = {}
    iam_names: list[str] = []

    for region in regions:
        pipelines = _list_pipelines(tok, project, region)
        if not pipelines:
            continue

        found_any = True
        print(f"\n{UtilityTools.CYAN}[*] {region} — {len(pipelines)} pipeline(s){UtilityTools.RESET}")
        for p in pipelines:
            name = p.get("name", "")
            pipeline_id = name.split("/")[-1] if "/" in name else name
            state = p.get("state", "")
            schedule = (p.get("scheduleInfo") or {}).get("schedule", "")
            worker_sa = _extract_worker_sa(p)

            sa_label = f"  workerSA={worker_sa}" if worker_sa else ""
            flag = f" {UtilityTools.YELLOW}[PE candidate]{UtilityTools.RESET}" if worker_sa else ""
            print(f"  {pipeline_id:<40s} state={state:<15s} sched={schedule}{sa_label}{flag}")

            if worker_sa:
                pe_candidates.append((region, pipeline_id, worker_sa))
            if name:
                iam_names.append(name)

    if pe_candidates:
        print(f"\n{UtilityTools.YELLOW}[!] {len(pe_candidates)} PE candidate(s) found "
              f"(pipelines with non-default workerServiceAccount):{UtilityTools.RESET}")
        for region, pid, sa in pe_candidates:
            print(f"  {region}/{pid} → workerServiceAccount={sa}")
        print("\n    Exploit: modules exploit exploit_datapipelines_pipeline_as_sa "
              "--target-sa <SA>")

    if args.iam and iam_names and _DP_PERMISSIONS:
        print(f"\n{UtilityTools.CYAN}[*] Running testIamPermissions on {len(iam_names)} pipeline(s)...{UtilityTools.RESET}")
        tok = get_bearer_token(session)
        for res_name in iam_names:
            granted = _test_iam_rest(tok, res_name, _DP_PERMISSIONS)
            if granted:
                pid = res_name.split("/")[-1] if "/" in res_name else res_name
                print(f"  {pid}: {UtilityTools.GREEN}{granted}{UtilityTools.RESET}")
                proj = project
                record_permissions(
                    action_dict, permissions=granted,
                    project_id=proj,
                    resource_type="pipelines",
                    resource_label=res_name,
                )

    if not found_any:
        print("[*] No Data Pipelines found in any enumerated region.")

    if action_dict:
        session.insert_actions(action_dict, project)

    return 1 if found_any else 0
