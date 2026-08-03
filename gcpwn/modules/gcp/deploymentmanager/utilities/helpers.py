from __future__ import annotations

import time
from typing import Any

from gcpwn.core.resource import DiscoveryListResource


class DeploymentManagerDeploymentResource(DiscoveryListResource):
    """List/get Cloud Deployment Manager deployments via the discovery client.

    Offensively interesting: a DM deployment containing GCE VMs can specify
    which service account those VMs run as.  Any principal with
    deploymentmanager.deployments.create + iam.serviceAccounts.actAs(TARGET_SA)
    can abuse this to run VMs as TARGET_SA.
    """

    SERVICE_LABEL = "Cloud Deployment Manager"
    TABLE_NAME = "deploymentmanager_deployments"
    COLUMNS = [
        "location",
        "deployment_id",
        "name",
        "state",
        "service_accounts",
        "manifest_url",
        "description",
    ]
    ACTION_RESOURCE_TYPE = "deployments"
    LIST_PERMISSION = "deploymentmanager.deployments.list"
    GET_PERMISSION = "deploymentmanager.deployments.get"
    LIST_API_NAME = "deploymentmanager.deployments.list"
    GET_API_NAME = "deploymentmanager.deployments.get"
    DISCOVERY_API = "deploymentmanager"
    DISCOVERY_VERSION = "v2"
    ID_FIELD = "deployment_id"

    def _list_request(self, *, project_id: str, parent: str | None, page_token: str | None = None, **_):
        return self.service.deployments().list(project=project_id, pageToken=page_token)

    def _get_request(self, *, project_id: str, resource_id: str, **_):
        return self.service.deployments().get(project=project_id, deployment=resource_id)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = raw.get("name", "")
        # deployment_id is the last path segment of the resource name, or the name itself
        deployment_id = name.rsplit("/", 1)[-1] if "/" in name else name

        # state from update.state (steady-state) or operation.status (in-progress)
        update = raw.get("update") or {}
        operation = raw.get("operation") or {}
        state = update.get("state") or operation.get("status") or ""

        # service_accounts: scan target.config.content for serviceAccount: lines
        target = raw.get("target") or {}
        config = target.get("config") or {}
        content = config.get("content") or ""
        sa_lines = [
            line.strip().split("serviceAccount:", 1)[1].strip()
            for line in content.splitlines()
            if "serviceAccount:" in line
        ]
        # deduplicate preserving order
        service_accounts = ", ".join(dict.fromkeys(sa_lines))

        return {
            "location": "global",
            "deployment_id": deployment_id,
            "state": state,
            "service_accounts": service_accounts,
            "manifest_url": raw.get("manifest", ""),
            "description": raw.get("description", ""),
        }

    def download_all_manifests(self, project_id: str, deployments: list[dict]) -> None:
        """Download manifest YAML content for each deployment row to disk."""
        from gcpwn.core.console import UtilityTools
        from gcpwn.core.output_paths import resolve_download_path
        from gcpwn.core.utils.service_runtime import DownloadBudget
        budget = DownloadBudget(self.session, label="DM manifest templates")
        for dep in deployments:
            if budget.exceeded():
                break
            name = dep.get("name", "")
            manifest_url = dep.get("manifest_url", "")
            if not (name and manifest_url):
                continue
            content = self.download_manifest_content(
                project_id=project_id,
                deployment_name=name,
                manifest_url=manifest_url,
            )
            if content:
                path = resolve_download_path(
                    self.session, service_name="deploymentmanager", project_id=project_id,
                    filename=f"{name}_manifest.yaml",
                )
                path.write_text(content, encoding="utf-8")
                print(f"{UtilityTools.GREEN}[+] Manifest saved → {path}{UtilityTools.RESET}")

    def download_manifest_content(
        self, *, project_id: str, deployment_name: str, manifest_url: str
    ) -> str | None:
        """Fetch the config.content string from a deployment manifest.

        Uses the manifests.get discovery method so no extra HTTP client is needed.
        Returns the YAML/Jinja2 content string, or None on error.
        """
        if not manifest_url:
            return None
        manifest_id = manifest_url.rsplit("/", 1)[-1]
        try:
            resp = self.service.manifests().get(
                project=project_id,
                deployment=deployment_name,
                manifest=manifest_id,
            ).execute()
            return (resp.get("config") or {}).get("content")
        except Exception:
            return None

    # ── Exploit helpers ──────────────────────────────────────────────────────────

    def create(self, project_id: str, name: str, config_content: str) -> dict:
        """Create a DM deployment. Returns the insert operation dict."""
        body = {
            "name": name,
            "target": {
                "config": {
                    "content": config_content,
                }
            },
        }
        return self.service.deployments().insert(project=project_id, body=body).execute()

    def delete(self, project_id: str, name: str) -> dict:
        """Delete a DM deployment (auto-deletes contained resources). Returns the operation dict."""
        return self.service.deployments().delete(project=project_id, deployment=name).execute()

    def poll_operation(
        self, project_id: str, op_name: str, *, timeout: int = 300, interval: int = 10
    ) -> tuple[str, dict | None, dict | None]:
        """Poll a DM operation until DONE or timeout.

        Returns (final_status, op_dict, error_dict).  final_status is "DONE" on
        success or "TIMEOUT" when the budget expires.
        """
        deadline = time.time() + timeout
        last_op: dict | None = None
        while time.time() < deadline:
            try:
                op = self.service.operations().get(
                    project=project_id, operation=op_name
                ).execute()
                last_op = op
                status = op.get("status", "UNKNOWN")
                print(f"  [dm-op] {op_name}: {status}")
                if status == "DONE":
                    return "DONE", op, op.get("error")
            except Exception as exc:
                print(f"  [dm-op] Error polling operation: {exc}")
            time.sleep(interval)
        return "TIMEOUT", last_op, None
