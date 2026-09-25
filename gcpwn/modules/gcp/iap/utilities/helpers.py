from __future__ import annotations

import json

from google.cloud import compute_v1

from gcpwn.core.console import UtilityTools
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions

_IAP_FW_RANGE = "35.235.240.0/20"


def _normalize_instance(inst, zone: str, *, iap_fw_rules: list[str]) -> dict:
    """Produce a DB-ready row from a compute_v1.Instance protobuf."""
    name = inst.name or ""
    sa_email = inst.service_accounts[0].email if inst.service_accounts else ""

    has_external = any(nic.access_configs for nic in inst.network_interfaces)

    metadata_items = (inst.metadata.items if inst.metadata else [])
    oslogin_enabled = any(
        item.key == "enable-oslogin" and item.value.lower() == "true"
        for item in metadata_items
    )

    iap_candidate = not has_external or oslogin_enabled or bool(iap_fw_rules)

    parts = zone.rsplit("-", 1)
    region = parts[0] if len(parts) == 2 else zone

    return {
        "name": name,
        "instance_id": name,
        "zone": zone,
        "location": region,
        "state": inst.status or "",
        "iap_enabled": "true" if iap_candidate else "false",
        "service_account": sa_email,
    }


class IAPTunnelInstancesResource(GcpListResource):
    """Enumerate GCE instances that are candidates for IAP tunnel access.

    Offensively relevant: holding iap.tunnelInstances.accessViaIAP +
    compute.instances.osAdminLogin allows SSH into any IAP-enabled GCE VM
    via ``gcloud compute ssh --tunnel-through-iap``. The metadata server
    inside the VM then exposes the attached SA's OAuth2 token.
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
    PARENT_FROM_PROJECT_LOCATION = False
    PARENT_FROM_PROJECT = False

    def _build_client(self, session):
        return compute_v1.InstancesClient(credentials=session.credentials)

    def _firewalls_client(self):
        return compute_v1.FirewallsClient(credentials=self.session.credentials)

    def check_iap_firewall(self, project_id: str) -> list[str]:
        """Return names of firewall rules that allow 35.235.240.0/20 on tcp:22."""
        iap_rules: list[str] = []
        try:
            for rule in self._firewalls_client().list(project=project_id):
                if rule.direction == "EGRESS":
                    continue
                for allowed in rule.allowed:
                    proto = allowed.I_p_protocol
                    if proto not in ("tcp", "all"):
                        continue
                    ports = list(allowed.ports)
                    if ports and "22" not in ports and "0-65535" not in ports:
                        continue
                    if _IAP_FW_RANGE in list(rule.source_ranges) or not rule.source_ranges:
                        iap_rules.append(rule.name)
        except Exception:
            pass
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
        """List GCE instances for the project, optionally filtered by ``zone``."""
        iap_fw_rules = self.check_iap_firewall(project_id or "")

        pairs: list[tuple[str, object]] = []
        if zone:
            for inst in self.client.list(project=project_id, zone=zone):
                pairs.append((zone, inst))
        else:
            for zone_key, scope in self.client.aggregated_list(project=project_id):
                z = zone_key.replace("zones/", "")
                for inst in scope.instances:
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
        """Return True if ``instance_name`` in ``zone`` appears accessible via IAP tunnel."""
        try:
            inst = self.client.get(project=project_id, zone=zone, instance=instance_name)
        except Exception:
            return False
        has_external = any(nic.access_configs for nic in inst.network_interfaces)
        metadata_items = inst.metadata.items if inst.metadata else []
        oslogin_enabled = any(
            item.key == "enable-oslogin" and item.value.lower() == "true"
            for item in metadata_items
        )
        return not has_external or oslogin_enabled
