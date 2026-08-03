from __future__ import annotations

import json

import requests as _rlib

from gcpwn.core.console import UtilityTools
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import get_bearer_token

_COMPUTE_BASE = "https://compute.googleapis.com/compute/v1"
_IAP_FW_RANGE = "35.235.240.0/20"


def _req(tok: str, url: str, params=None) -> dict:
    try:
        r = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, params=params, timeout=20)
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception:
        return {}


def _list_paged(tok: str, url: str, key: str) -> list[dict]:
    results: list[dict] = []
    pt = None
    while True:
        params: dict = {"maxResults": 500}
        if pt:
            params["pageToken"] = pt
        data = _req(tok, url, params)
        results.extend(data.get(key, []))
        pt = data.get("nextPageToken")
        if not pt:
            break
    return results


def _normalize_instance(inst: dict, zone: str, *, iap_fw_rules: list[str]) -> dict:
    """Produce a DB-ready row from a raw GCE instance dict."""
    name = inst.get("name", "")
    sa_list = inst.get("serviceAccounts", [])
    sa_email = sa_list[0].get("email", "") if sa_list else ""

    nics = inst.get("networkInterfaces", [])
    has_external = any(nic.get("accessConfigs") for nic in nics)

    metadata_items = inst.get("metadata", {}).get("items", [])
    oslogin_enabled = any(
        item.get("key") == "enable-oslogin" and item.get("value", "").lower() == "true"
        for item in metadata_items
    )

    iap_candidate = not has_external or oslogin_enabled or bool(iap_fw_rules)

    # Derive region from zone (e.g. "us-central1-a" -> "us-central1")
    parts = zone.rsplit("-", 1)
    region = parts[0] if len(parts) == 2 else zone

    return {
        "name": name,
        "instance_id": name,
        "zone": zone,
        "location": region,
        "state": inst.get("status", ""),
        "iap_enabled": "true" if iap_candidate else "false",
        "service_account": sa_email,
    }


class IAPTunnelInstancesResource(GcpListResource):
    """Enumerate GCE instances that are candidates for IAP tunnel access.

    Offensively relevant: holding iap.tunnelInstances.accessViaIAP +
    compute.instances.osAdminLogin allows SSH into any IAP-enabled GCE VM
    via ``gcloud compute ssh --tunnel-through-iap``. The metadata server
    inside the VM then exposes the attached SA's OAuth2 token.

    Since the IAP API itself has no GAPIC client for tunnel enumeration,
    this class uses the Compute REST API directly.
    """

    SERVICE_LABEL = "IAP Tunnel Instances"
    TABLE_NAME = "iap_instances"
    COLUMNS = [
        "project_id",
        "location",
        "instance_id",
        "name",
        "zone",
        "state",
        "iap_enabled",
        "service_account",
    ]
    ACTION_RESOURCE_TYPE = "iap_instances"
    LIST_PERMISSION = "compute.instances.list"
    ID_FIELD = "instance_id"
    # Caller passes parent= directly (not constructed from project/location).
    PARENT_FROM_PROJECT_LOCATION = False
    PARENT_FROM_PROJECT = False

    def _build_client(self, session):
        return None  # REST-only; no GAPIC client needed

    def check_iap_firewall(self, project_id: str) -> list[str]:
        """Return names of firewall rules that allow 35.235.240.0/20 on tcp:22."""
        tok = get_bearer_token(self.session)
        rules = _list_paged(
            tok,
            f"{_COMPUTE_BASE}/projects/{project_id}/global/firewalls",
            "items",
        )
        iap_rules: list[str] = []
        for rule in rules:
            if rule.get("direction", "") == "EGRESS":
                continue
            for allowed in rule.get("allowed", []):
                if allowed.get("IPProtocol") not in ("tcp", "all"):
                    continue
                ports = allowed.get("ports", [])
                if ports and "22" not in ports and "0-65535" not in ports:
                    continue
                src_ranges = rule.get("sourceRanges", [])
                if _IAP_FW_RANGE in src_ranges or not src_ranges:
                    iap_rules.append(rule.get("name", ""))
        return iap_rules

    def list(
        self,
        *,
        project_id: str | None = None,
        location: str | None = None,
        parent: str | None = None,
        action_dict=None,
        zone: str | None = None,
        **_,
    ) -> list[dict]:
        """List GCE instances for the project, optionally filtered by ``zone``.

        Internally checks project-level IAP firewall rules and uses them to
        set the ``iap_enabled`` field on each returned row. Records
        ``compute.instances.list`` once on success.
        """
        tok = get_bearer_token(self.session)
        iap_fw_rules = self.check_iap_firewall(project_id or "")

        if zone:
            url = f"{_COMPUTE_BASE}/projects/{project_id}/zones/{zone}/instances"
            raw_instances = _list_paged(tok, url, "items")
            pairs: list[tuple[str, dict]] = [(zone, inst) for inst in raw_instances]
        else:
            agg = _req(
                tok,
                f"{_COMPUTE_BASE}/projects/{project_id}/aggregated/instances",
                params={"maxResults": 500},
            )
            pairs = []
            for zone_key, zone_data in agg.get("items", {}).items():
                z = zone_key.replace("zones/", "")
                for inst in zone_data.get("instances", []):
                    pairs.append((z, inst))

        rows = [_normalize_instance(inst, z, iap_fw_rules=iap_fw_rules) for z, inst in pairs]

        if rows and self.LIST_PERMISSION:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )

        return rows

    @staticmethod
    def parse_and_display(output: str, instance_name: str) -> None:
        """Parse metadata server response and display the recovered token."""
        lines = output.strip().split("\n")
        tok = None
        email = None
        for line in lines:
            line = line.strip()
            if line.startswith("{") and "access_token" in line:
                try:
                    d = json.loads(line)
                    tok = d.get("access_token", "")
                    continue
                except Exception:
                    pass
            if "@" in line and "gserviceaccount" in line:
                email = line.strip()
        if tok and email:
            print(f"\n{UtilityTools.GREEN}{UtilityTools.BOLD}[+] TOKEN RECOVERED VIA IAP SSH{UtilityTools.RESET}")
            print(f"{UtilityTools.GREEN}    VM     : {instance_name}{UtilityTools.RESET}")
            print(f"{UtilityTools.GREEN}    Email  : {email}{UtilityTools.RESET}")
            print(f"{UtilityTools.GREEN}    Token  : {tok[:50]}...{UtilityTools.RESET}")
            print(f"{UtilityTools.GREEN}    Add    : creds add <name> --type OAuth2 --token {tok}{UtilityTools.RESET}")
        elif output:
            print(f"{UtilityTools.YELLOW}[!] Could not parse token from output:{UtilityTools.RESET}")
            print(output[:500])
        else:
            print(f"{UtilityTools.YELLOW}[!] No output received from SSH command.{UtilityTools.RESET}")

    def check_iap_access(self, project_id: str, instance_name: str, zone: str) -> bool:
        """Return True if ``instance_name`` in ``zone`` appears accessible via IAP tunnel.

        Checks no-external-IP and OS Login signals on the live instance metadata.
        Does NOT verify that firewall rules allow the IAP source range.
        """
        tok = get_bearer_token(self.session)
        url = f"{_COMPUTE_BASE}/projects/{project_id}/zones/{zone}/instances/{instance_name}"
        data = _req(tok, url)
        if not data:
            return False
        nics = data.get("networkInterfaces", [])
        has_external = any(nic.get("accessConfigs") for nic in nics)
        metadata_items = data.get("metadata", {}).get("items", [])
        oslogin_enabled = any(
            item.get("key") == "enable-oslogin" and item.get("value", "").lower() == "true"
            for item in metadata_items
        )
        return not has_external or oslogin_enabled
