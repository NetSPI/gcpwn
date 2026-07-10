from __future__ import annotations

import argparse

from gcpwn.core.utils.service_runtime import parse_csv_arg
from gcpwn.modules.gcp.logging.utilities.helpers import (
    DEFAULT_DOWNLOAD_LIMIT,
    download_log_entries,
    list_buckets,
    list_log_names,
    list_metrics,
    list_sinks,
)


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate Cloud Logging sinks/buckets/logs/metrics; optionally download recent entries",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download recent log entries (capped PER log) to JSON files instead of just listing the log groups.",
    )
    parser.add_argument(
        "--download-limit",
        dest="download_limit",
        type=int,
        default=DEFAULT_DOWNLOAD_LIMIT,
        help=f"Max entries downloaded per log (default {DEFAULT_DOWNLOAD_LIMIT}); keeps 50+ logs from holding everything up.",
    )
    parser.add_argument("--logs", required=False, help="Comma-separated log names to download (default: all discovered).")
    parser.add_argument("--output", required=False, help="Output directory for downloaded log entries.")
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")
    return parser.parse_args(user_args)


def run_module(user_args, session):
    """List the log 'groups' (sinks/buckets/log names/metrics) by default; download entries only on --download.

    Default is lightweight metadata (sinks expose export destinations + their writer SA;
    metrics + buckets round out the picture). --download fetches the newest entries per log,
    capped at --download-limit (default 1000) so projects with many logs stay bounded.
    """
    args = _parse_args(user_args)
    project_id = session.project_id

    sinks = list_sinks(session, project_id)
    buckets = list_buckets(session, project_id)
    logs = list_log_names(session, project_id)
    metrics = list_metrics(session, project_id)
    for row in sinks:
        session.insert_data("logging_sinks", {"project_id": project_id, **row})
    for row in buckets:
        session.insert_data("logging_buckets", {"project_id": project_id, **row})
    for row in logs:
        session.insert_data("logging_logs", {"project_id": project_id, **row})
    for row in metrics:
        session.insert_data("logging_metrics", {"project_id": project_id, **row})
    print(f"[*] Cloud Logging {project_id}: sinks={len(sinks)} buckets={len(buckets)} "
          f"logs={len(logs)} metrics={len(metrics)}.")

    if args.download:
        targets = parse_csv_arg(args.logs) or [r["log_name"] for r in logs]
        if not targets:
            print("[*] No logs available to download entries from.")
            return 1
        print(f"[*] Downloading up to {max(1, int(args.download_limit))} entries/log for {len(targets)} log(s)...")
        written = download_log_entries(
            session, project_id, log_names=targets, per_log_limit=args.download_limit, output=args.output
        )
        for path in written:
            print(f"[*] Wrote {path}")
        print(f"[*] Downloaded entries for {len(written)}/{len(targets)} log(s) (the rest were empty or denied).")
    return 1
