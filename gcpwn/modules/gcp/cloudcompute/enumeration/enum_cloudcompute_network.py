from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.service_runtime import get_cached_rows, parse_component_args, resolve_selected_components
from gcpwn.modules.gcp.cloudcompute.enumeration.enum_cloudcompute_resources import (
    _process_discovery_resource,
    _process_existing_resource,
    _resolve_regions,
)
from gcpwn.modules.gcp.cloudcompute.utilities.helpers import (
    CLOUDCOMPUTE_DISCOVERY_RESOURCE_SPECS,
    CloudComputeDiscoveryResource,
    CloudComputeInterconnectAttachmentGroupsResource,
    CloudComputeInterconnectGroupsResource,
    cloudcompute_gapic_resource,
)
from gcpwn.modules.gcp.cloudcompute.utilities.network_helpers import (
    VpcFirewallsResource,
    VpcNetworksResource,
    VpcRouterNatsResource,
    VpcRoutersResource,
    VpcRoutesResource,
    VpcSubnetworksResource,
    VpcTargetVpnGatewaysResource,
    VpcVpnGatewaysResource,
    VpcVpnTunnelsResource,
)


_NETWORK_DISCOVERY_COMPONENTS = {"service_attachments"}
_NETWORK_DISCOVERY_SPECS = tuple(
    spec for spec in CLOUDCOMPUTE_DISCOVERY_RESOURCE_SPECS if spec.component_key in _NETWORK_DISCOVERY_COMPONENTS
)

COMPONENTS = [
    ("networks", "Enumerate VPC networks"),
    ("subnetworks", "Enumerate VPC subnetworks"),
    ("firewalls", "Enumerate VPC firewall rules"),
    ("routes", "Enumerate VPC routes"),
    ("routers", "Enumerate Cloud Routers"),
    ("router_nats", "Enumerate Cloud NAT configs (per router)"),
    ("vpn_gateways", "Enumerate HA VPN Gateways"),
    ("target_vpn_gateways", "Enumerate Classic Target VPN Gateways"),
    ("vpn_tunnels", "Enumerate VPN Tunnels"),
    ("network_attachments", "Enumerate Compute network attachments"),
    ("service_attachments", "Enumerate Compute service attachments"),
    ("interconnect_attachment_groups", "Enumerate Compute interconnect attachment groups"),
    ("interconnect_groups", "Enumerate Compute interconnect groups"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try every known region")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument("--threads", type=int, default=3, help="Worker threads for region fan-out (default: 3)")

    return parse_component_args(
        user_args,
        description="Enumerate Compute Engine network and connectivity resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on supported Compute network resources"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id

    networks_resource = VpcNetworksResource(session)
    subnetworks_resource = VpcSubnetworksResource(session)
    firewalls_resource = VpcFirewallsResource(session)
    routes_resource = VpcRoutesResource(session)
    routers_resource = VpcRoutersResource(session)
    router_nats_resource = VpcRouterNatsResource(session)
    vpn_gateways_resource = VpcVpnGatewaysResource(session)
    target_vpn_gateways_resource = VpcTargetVpnGatewaysResource(session)
    vpn_tunnels_resource = VpcVpnTunnelsResource(session)
    network_attachments_resource = (
        cloudcompute_gapic_resource(session, "network_attachments") if selected.get("network_attachments", False) else None
    )
    interconnect_attachment_groups_resource = (
        CloudComputeInterconnectAttachmentGroupsResource(session)
        if selected.get("interconnect_attachment_groups", False)
        else None
    )
    interconnect_groups_resource = (
        CloudComputeInterconnectGroupsResource(session) if selected.get("interconnect_groups", False) else None
    )
    discovery_resources = {
        spec.component_key: CloudComputeDiscoveryResource(session, spec)
        for spec in _NETWORK_DISCOVERY_SPECS
        if selected.get(spec.component_key, False)
    }

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    discovery_rows_by_key: dict[str, list[dict]] = {}

    regional_components = {
        "service_attachments",
    }
    regions = _resolve_regions(
        args,
        session,
        project_id=project_id,
        require_all=any(selected.get(key, False) for key in regional_components),
    )

    routers = _process_existing_resource(
        selected_key="routers",
        title="Cloud Routers",
        primary_resource="Routers",
        enumeration_label="Cloud Routers",
        resource=routers_resource,
        list_callback=lambda action_dict: routers_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    ) if selected.get("routers", False) else []

    _process_existing_resource(
        selected_key="networks",
        title="VPC Networks",
        primary_resource="Networks",
        enumeration_label="VPC Networks",
        resource=networks_resource,
        list_callback=lambda action_dict: networks_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="subnetworks",
        title="VPC Subnetworks",
        primary_resource="Subnetworks",
        enumeration_label="VPC Subnetworks",
        resource=subnetworks_resource,
        list_callback=lambda action_dict: subnetworks_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )
    _process_existing_resource(
        selected_key="firewalls",
        title="VPC Firewall Rules",
        primary_resource="Firewalls",
        enumeration_label="VPC Firewall Rules",
        resource=firewalls_resource,
        list_callback=lambda action_dict: firewalls_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="routes",
        title="VPC Routes",
        primary_resource="Routes",
        enumeration_label="VPC Routes",
        resource=routes_resource,
        list_callback=lambda action_dict: routes_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="vpn_gateways",
        title="HA VPN Gateways",
        primary_resource="HA VPN Gateways",
        enumeration_label="HA VPN Gateways",
        resource=vpn_gateways_resource,
        list_callback=lambda action_dict: vpn_gateways_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )
    _process_existing_resource(
        selected_key="target_vpn_gateways",
        title="Target VPN Gateways",
        primary_resource="Target VPN Gateways",
        enumeration_label="Target VPN Gateways",
        resource=target_vpn_gateways_resource,
        list_callback=lambda action_dict: target_vpn_gateways_resource.list(
            project_id=project_id,
            action_dict=action_dict,
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )
    _process_existing_resource(
        selected_key="vpn_tunnels",
        title="VPN Tunnels",
        primary_resource="Tunnels",
        enumeration_label="VPN Tunnels",
        resource=vpn_tunnels_resource,
        list_callback=lambda action_dict: vpn_tunnels_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )
    _process_existing_resource(
        selected_key="network_attachments",
        title="Compute Network Attachments (PSC Interfaces)",
        primary_resource="Network Attachments (PSC Interfaces)",
        enumeration_label="Compute Network Attachments (PSC Interfaces)",
        resource=network_attachments_resource,
        list_callback=lambda action_dict: network_attachments_resource.list(
            project_id=project_id,
            action_dict=action_dict,
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )

    for spec in _NETWORK_DISCOVERY_SPECS:
        resource = discovery_resources.get(spec.component_key)
        if resource is None:
            continue
        display_spec = spec
        if spec.component_key == "service_attachments":
            display_spec = spec.__class__(
                **{
                    **spec.__dict__,
                    "summary_title": "Compute Service Attachments (PSC Producers)",
                    "primary_resource": "Service Attachments (PSC Producers)",
                }
            )
        _process_discovery_resource(
            resource=resource,
            spec=display_spec,
            args=args,
            selected=selected,
            session=session,
            project_id=project_id,
            zones=[],
            regions=regions,
            scope_actions=scope_actions,
            api_actions=api_actions,
            iam_actions=iam_actions,
            discovery_rows_by_key=discovery_rows_by_key,
        )

    _process_existing_resource(
        selected_key="interconnect_attachment_groups",
        title="Compute Interconnect Attachment Groups",
        primary_resource="Interconnect Attachment Groups",
        enumeration_label="Compute Interconnect Attachment Groups",
        resource=interconnect_attachment_groups_resource,
        list_callback=lambda action_dict: interconnect_attachment_groups_resource.list(
            project_id=project_id,
            action_dict=action_dict,
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="interconnect_groups",
        title="Compute Interconnect Groups",
        primary_resource="Interconnect Groups",
        enumeration_label="Compute Interconnect Groups",
        resource=interconnect_groups_resource,
        list_callback=lambda action_dict: interconnect_groups_resource.list(
            project_id=project_id,
            action_dict=action_dict,
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )

    if selected.get("router_nats", False):
        use_cache = not args.get and not args.iam
        all_nats = (
            get_cached_rows(session, router_nats_resource.TABLE_NAME, project_id=project_id, columns=router_nats_resource.COLUMNS) or []
        ) if use_cache else []

        if not all_nats:
            if not routers:
                routers = get_cached_rows(
                    session,
                    routers_resource.TABLE_NAME,
                    project_id=project_id,
                    columns=routers_resource.COLUMNS,
                ) or []
            if not routers:
                listed = routers_resource.list(project_id=project_id, action_dict=scope_actions)
                routers = [] if listed in ("Not Enabled", None) else list(listed or [])
                if routers:
                    routers_resource.save(routers, project_id=project_id)

            all_nats = []
            total_routers = len(routers)
            print(f"[*] Enumerating Cloud NAT configs from {total_routers} router(s)")
            for index, router in enumerate(routers, start=1):
                router_ref = routers_resource.reference_from_row(router)
                router_name = str(router_ref.get("router") or "").strip()
                region = str(router_ref.get("region") or "").strip()
                if not router_name or not region:
                    if total_routers <= 50 or index in (1, total_routers) or index % max(5, total_routers // 20 or 1) == 0:
                        print(f"[*] Cloud NAT progress: {index}/{total_routers} routers checked")
                    continue
                nats = router_nats_resource.list_for_router(
                    project_id=project_id,
                    region=region,
                    router_name=router_name,
                    action_dict=api_actions,
                ) or []
                if nats:
                    router_nats_resource.save(nats, project_id=project_id, region=region, router_name=router_name)
                    all_nats.extend(nats)
                if total_routers <= 50 or index in (1, total_routers) or index % max(5, total_routers // 20 or 1) == 0:
                    print(f"[*] Cloud NAT progress: {index}/{total_routers} routers checked")

        UtilityTools.summary_wrapup(
            project_id,
            "Cloud NATs",
            all_nats,
            router_nats_resource.COLUMNS,
            primary_resource="NATs",
            primary_sort_key="region",
        )
        if not all_nats:
            print(f"[*] No NATs found in project {project_id}.")

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="compute_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="compute_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="compute_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
