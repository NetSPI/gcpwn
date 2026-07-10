from __future__ import annotations

import argparse

from gcpwn.modules.gcp.cloudshell.utilities.helpers import get_environment


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate the caller's Cloud Shell environment (SSH keys, image, hosts)",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--environment",
        required=False,
        default="users/me/environments/default",
        help="Environment resource name (default: users/me/environments/default).",
    )
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")
    return parser.parse_args(user_args)


def run_module(user_args, session):
    """Fetch the caller's Cloud Shell environment and persist it.

    Cloud Shell is per-user (no list); with a service-account credential there is usually
    no environment and the API returns 404/403, handled gracefully.
    """
    args = _parse_args(user_args)
    env = get_environment(session, environment_name=args.environment)
    if not env:
        print("[*] Cloud Shell: no accessible environment (no Cloud Shell for this principal, API disabled, or denied).")
        return 1
    session.insert_data("cloudshell_environments", {"project_id": session.project_id, **env})
    keys = [k for k in (env.get("public_keys") or "[]").strip("[]").split(",") if k.strip()]
    print(f"[*] Cloud Shell environment {env['name']} state={env['state']} "
          f"image={env['docker_image'] or '(default)'} public_keys={len(keys)}.")
    return 1
