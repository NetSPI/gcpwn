from __future__ import annotations

import argparse

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.iap.utilities.helpers import IAPTunnelInstancesResource


COMPONENTS = [
    Component(
        "instances", IAPTunnelInstancesResource,
        "IAP Tunnel Instances", "Instances",
        help_text="Enumerate GCE instances accessible via IAP tunnel",
        scope=PROJECT,
        supports_get=False,
        supports_iam=False,
        summarize=False,
        list_kwargs=lambda args: {"zone": getattr(args, "zone", None)},
    ),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--zone", default=None,
            help="Specific zone to enumerate (default: all zones)",
        )

    return parse_component_args(
        user_args,
        description=(
            "Find GCE instances accessible via IAP TCP tunnel and flag those with "
            "non-default service accounts. Identifies candidates for the IAP tunnel "
            "privilege escalation path (ACCESS_VM_VIA_IAP_TUNNEL)."
        ),
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS, extra=_add_extra_args),
        standard_args=("iam", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)

    project = session.project_id
    if not project:
        print(f"{UtilityTools.RED}[!] No project context.{UtilityTools.RESET}")
        return -1

    # Check firewall rules at the project level for display purposes.
    resource = IAPTunnelInstancesResource(session)
    iap_fw_rules = resource.check_iap_firewall(project)
    if iap_fw_rules:
        print(f"\n{UtilityTools.GREEN}[+] IAP firewall rules found (35.235.240.0/20 -> tcp:22):{UtilityTools.RESET}")
        for r in iap_fw_rules:
            print(f"  {r}")
    else:
        print(
            f"\n{UtilityTools.YELLOW}[!] No IAP-specific firewall rules found. "
            f"IAP tunnel may still work if a broader 0.0.0.0/0 rule exists.{UtilityTools.RESET}"
        )

    run_components(
        session, args, components=COMPONENTS,
        column_name="iap_actions_allowed",
        module_name="enum_iap",
    )

    return 1
