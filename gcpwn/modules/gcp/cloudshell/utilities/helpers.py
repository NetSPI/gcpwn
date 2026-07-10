from __future__ import annotations

import json
from typing import Any

from google.cloud import shell_v1

from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def build_cloudshell_client(session):
    return shell_v1.CloudShellServiceClient(credentials=session.credentials)


def get_environment(session, *, environment_name: str = "users/me/environments/default") -> dict[str, Any] | None:
    """Fetch a Cloud Shell environment (default: the caller's).

    Cloud Shell is per-USER (no list), so this targets ``users/me/environments/default``.
    Offensively interesting: ``public_keys`` (authorized SSH keys), ``docker_image`` (a
    custom image can persist tooling), and ``ssh_host``/``web_host`` of the running box.
    With a service-account credential there is usually no Cloud Shell -> 404/403 (graceful).
    """
    client = build_cloudshell_client(session)
    try:
        env = client.get_environment(request=shell_v1.GetEnvironmentRequest(name=environment_name))
        data = resource_to_dict(env)
        name = str(data.get("name") or environment_name)
        public_keys = data.get("public_keys") or data.get("publicKeys") or []
        return {
            "name": name,
            "env_id": str(data.get("id") or (name.split("/")[-1] if "/" in name else name)),
            "state": str(data.get("state") or ""),
            "docker_image": str(data.get("docker_image") or data.get("dockerImage") or ""),
            "ssh_username": str(data.get("ssh_username") or data.get("sshUsername") or ""),
            "ssh_host": str(data.get("ssh_host") or data.get("sshHost") or ""),
            "ssh_port": str(data.get("ssh_port") or data.get("sshPort") or ""),
            "web_host": str(data.get("web_host") or data.get("webHost") or ""),
            "public_keys": json.dumps(list(public_keys), default=str),
            "raw_json": json.dumps(data, default=str),
        }
    except Exception as exc:
        handle_service_error(
            exc,
            api_name="cloudshell.environments.get",
            resource_name=environment_name,
            service_label="Cloud Shell",
        )
        return None
