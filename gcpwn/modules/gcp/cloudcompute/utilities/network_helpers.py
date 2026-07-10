"""VPC networking enumeration helpers for Compute (networks, subnets, firewalls, routers, VPN).

Each Vpc*Resource wraps a compute_v1 GAPIC client and exposes the uniform
list/get[/get_iam_permissions]/save/reference_from_row contract the enum framework drives.
Scope varies: networks/firewalls/routes are global; subnetworks/routers/VPN are regional;
router NATs are nested under a parent router. Errors funnel through handle_service_error so a
disabled API yields the "Not Enabled" sentinel that short-circuits region fan-out.
"""

from __future__ import annotations

from typing import Any, Iterable

from google.cloud import compute_v1

from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


def _global_resource_label(project_id: str, collection: str, resource_id: str) -> str:
    return f"projects/{project_id}/global/{collection}/{resource_id}"


def _regional_resource_label(project_id: str, region: str, collection: str, resource_id: str) -> str:
    return f"projects/{project_id}/regions/{region}/{collection}/{resource_id}"


def _router_nat_label(project_id: str, region: str, router_name: str, nat_name: str) -> str:
    return f"projects/{project_id}/regions/{region}/routers/{router_name}/nats/{nat_name}"


def _record_list_permission(action_dict, *, permission: str, project_id: str) -> None:
    record_permissions(
        action_dict,
        permissions=permission,
        scope_key="project_permissions",
        scope_label=project_id,
    )


def _record_resource_permission(
    action_dict,
    *,
    permission: str,
    project_id: str,
    resource_type: str,
    resource_label: str,
) -> None:
    record_permissions(
        action_dict,
        permissions=permission,
        project_id=project_id,
        resource_type=resource_type,
        resource_label=resource_label,
    )


def _stringify_sequence(values: Any) -> str:
    if values is None:
        return ""
    if isinstance(values, str):
        return values
    rendered = [str(value).strip() for value in values or [] if str(value).strip()]
    return ", ".join(rendered)


def _format_firewall_rule_entries(entries: Any) -> str:
    """Render firewall allow/deny entries as a compact ``proto:port1,port2`` summary string."""
    output: list[str] = []
    for entry in entries or []:
        protocol = str(getattr(entry, "IP_protocol", "") or getattr(entry, "ip_protocol", "") or "").strip()
        ports = [str(port).strip() for port in getattr(entry, "ports", None) or [] if str(port).strip()]
        if protocol and ports:
            output.append(f"{protocol}:{','.join(ports)}")
        elif protocol:
            output.append(protocol)
        elif ports:
            output.append(",".join(ports))
    return ", ".join(output)


def _compute_test_iam_permissions(
    *,
    client,
    project_id: str,
    api_name: str,
    resource_label: str,
    permissions: tuple[str, ...],
    region: str | None = None,
    resource_id: str,
) -> list[str]:
    """Run testIamPermissions for a regional VPC resource via the compute_v1 client; return granted perms."""
    return call_test_iam_permissions(
        client=client,
        resource_name=resource_label,
        permissions=permissions,
        api_name=api_name,
        service_label="Compute",
        project_id=project_id,
        request_builder=lambda _resource_name, granted_permissions: list(granted_permissions),
        caller=lambda granted_permissions: client.test_iam_permissions(
            project=project_id,
            region=region,
            resource=resource_id,
            test_permissions_request_resource={"permissions": list(granted_permissions)},
        ),
    )


class _VpcBaseResource:
    """Base for VPC resources: shared session, error ladder, and the reference_from_row contract.

    Subclasses build their own compute_v1 client and implement reference_from_row (raises
    NotImplementedError here). SUPPORTS_GET/SUPPORTS_IAM gate the framework's get/IAM follow-ups.
    """

    SERVICE_LABEL = "Compute"
    ACTION_RESOURCE_TYPE = ""
    LIST_API_NAME = ""
    GET_API_NAME = ""
    SUPPORTS_GET = True
    SUPPORTS_IAM = False
    TEST_IAM_API_NAME = ""
    TEST_IAM_PERMISSIONS: tuple[str, ...] = ()

    def __init__(self, session) -> None:
        self.session = session

    def _handle_error(self, exc: Exception, *, api_name: str, resource_name: str, project_id: str) -> str | None:
        return handle_service_error(
            exc,
            api_name=api_name,
            resource_name=resource_name,
            service_label=self.SERVICE_LABEL,
            project_id=project_id,
        )

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        raise NotImplementedError


class VpcNetworksResource(_VpcBaseResource):
    """Enumerate global VPC networks into ``vpc_networks`` (auto-subnet mode, routing, peerings)."""

    TABLE_NAME = "vpc_networks"
    COLUMNS = ["name", "auto_create_subnetworks", "routing_mode", "peerings"]
    ACTION_RESOURCE_TYPE = "networks"
    LIST_API_NAME = "compute.networks.list"
    GET_API_NAME = "compute.networks.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.NetworksClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        network = field_from_row(row, payload, "name")
        return {"network": network, "resource_id": network}

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(project=project_id))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, network: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, network=network)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_global_resource_label(project_id, "networks", network),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=network, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class VpcSubnetworksResource(_VpcBaseResource):
    """Enumerate regional subnetworks into ``vpc_subnetworks`` (CIDR, purpose); supports testIamPermissions."""

    TABLE_NAME = "vpc_subnetworks"
    COLUMNS = ["name", "region", "network", "ip_cidr_range", "purpose"]
    ACTION_RESOURCE_TYPE = "subnetworks"
    LIST_API_NAME = "compute.subnetworks.list"
    GET_API_NAME = "compute.subnetworks.get"
    SUPPORTS_IAM = True
    TEST_IAM_API_NAME = "compute.subnetworks.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.subnetworks.",
        exclude_permissions=("compute.subnetworks.create","compute.subnetworks.list"),
    )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.SubnetworksClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        subnetwork = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "subnetwork": subnetwork,
            "resource_id": subnetwork,
        }

    def list(self, *, project_id: str, action_dict=None):
        out = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                out.extend(list(getattr(scoped, "subnetworks", None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return out
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, subnetwork: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, subnetwork=subnetwork)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, "subnetworks", subnetwork),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=subnetwork, project_id=project_id)
        return None

    def test_iam_permissions(self, *, project_id: str, region: str, subnetwork: str, action_dict=None) -> list[str]:
        if not region or not subnetwork:
            return []
        resource_label = _regional_resource_label(project_id, region, "subnetworks", subnetwork)
        permissions = _compute_test_iam_permissions(
            client=self.client,
            project_id=project_id,
            api_name=self.TEST_IAM_API_NAME,
            resource_label=resource_label,
            permissions=self.TEST_IAM_PERMISSIONS,
            region=region,
            resource_id=subnetwork,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_label,
            )
        return permissions

    def get_iam_permissions(self, *, project_id: str, region: str, subnetwork: str, action_dict=None) -> list[str]:
        return self.test_iam_permissions(
            project_id=project_id,
            region=region,
            subnetwork=subnetwork,
            action_dict=action_dict,
        )

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_tail(str(raw.get("region", "") or "")),
                },
            )


class VpcFirewallsResource(_VpcBaseResource):
    """Enumerate global firewall rules into ``vpc_firewalls`` (allow/deny proto:ports, direction, ranges)."""

    TABLE_NAME = "vpc_firewalls"
    COLUMNS = ["name", "network", "direction", "priority", "disabled", "source_ranges", "target_tags", "allowed", "denied"]
    ACTION_RESOURCE_TYPE = "firewalls"
    LIST_API_NAME = "compute.firewalls.list"
    GET_API_NAME = "compute.firewalls.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.FirewallsClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        firewall = field_from_row(row, payload, "name")
        return {"firewall": firewall, "resource_id": firewall}

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(project=project_id))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, firewall: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, firewall=firewall)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_global_resource_label(project_id, "firewalls", firewall),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=firewall, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def normalize_summary_rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for row in rows or []:
            payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
            normalized.append(
                {
                    "name": field_from_row(row, payload, "name"),
                    "network": extract_path_tail(field_from_row(row, payload, "network")),
                    "direction": field_from_row(row, payload, "direction"),
                    "priority": field_from_row(row, payload, "priority"),
                    "disabled": field_from_row(row, payload, "disabled"),
                    "source_ranges": _stringify_sequence(field_from_row(row, payload, "source_ranges", "sourceRanges")),
                    "target_tags": _stringify_sequence(field_from_row(row, payload, "target_tags", "targetTags")),
                    "allowed": _format_firewall_rule_entries(field_from_row(row, payload, "allowed")),
                    "denied": _format_firewall_rule_entries(field_from_row(row, payload, "denied")),
                }
            )
        return normalized


class VpcRoutesResource(_VpcBaseResource):
    """Enumerate global VPC routes into ``vpc_routes`` (dest range, next hop)."""

    TABLE_NAME = "vpc_routes"
    COLUMNS = ["name", "network", "dest_range", "next_hop_ip", "next_hop_instance", "next_hop_vpn_tunnel", "priority"]
    ACTION_RESOURCE_TYPE = "routes"
    LIST_API_NAME = "compute.routes.list"
    GET_API_NAME = "compute.routes.get"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.RoutesClient(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        route = field_from_row(row, payload, "name")
        return {"route": route, "resource_id": route}

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(project=project_id))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, route: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, route=route)
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_global_resource_label(project_id, "routes", route),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=route, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class _RegionalVpcResource(_VpcBaseResource):
    """Shared implementation for the region-scoped VPC resources (Cloud Routers, VPN
    tunnels, VPN gateways, target VPN gateways). They differ only in the compute_v1
    client (``_CLIENT_CLASS``), the aggregatedList scoped attribute (``_AGG_ATTR``), the
    ``client.get`` id kwarg (``_ID_KEY``), and the label path segment (``_GET_COLLECTION``);
    list/get/save/reference_from_row are otherwise identical.

    get() takes ``resource_id`` rather than the per-resource kwarg name: the enum
    framework calls it via ``_method_kwargs`` (matches by parameter name) and
    reference_from_row returns ``resource_id``, so this stays call-compatible with the
    old per-class signatures while collapsing four copies of each method into one.
    """

    _CLIENT_CLASS: str = ""    # compute_v1.<_CLIENT_CLASS>
    _AGG_ATTR: str = ""        # aggregated scoped_list.<_AGG_ATTR>
    _ID_KEY: str = ""          # client.get(<_ID_KEY>=...)
    _GET_COLLECTION: str = ""  # label path segment, e.g. "vpnTunnels"

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = getattr(compute_v1, self._CLIENT_CLASS)(credentials=session.credentials)

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row)
        resource_id = field_from_row(row, payload, "name")
        return {
            "region": extract_path_tail(field_from_row(row, payload, "region"))
            or extract_path_segment(field_from_row(row, payload, "self_link", "selfLink"), "regions"),
            "resource_id": resource_id,
        }

    def list(self, *, project_id: str, action_dict=None):
        rows: list[Any] = []
        try:
            aggregated = self.client.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                rows.extend(list(getattr(scoped, self._AGG_ATTR, None) or []))
            _record_list_permission(action_dict, permission=self.LIST_API_NAME, project_id=project_id)
            return rows
        except Exception as exc:
            result = self._handle_error(exc, api_name=self.LIST_API_NAME, resource_name=project_id, project_id=project_id)
            return "Not Enabled" if result == "Not Enabled" else []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, region=region, **{self._ID_KEY: resource_id})
            _record_resource_permission(
                action_dict,
                permission=self.GET_API_NAME,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_regional_resource_label(project_id, region, self._GET_COLLECTION, resource_id),
            )
            return row
        except Exception as exc:
            self._handle_error(exc, api_name=self.GET_API_NAME, resource_name=resource_id, project_id=project_id)
        return None

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": extract_path_segment(
                        raw.get("region", "") or raw.get("self_link") or raw.get("selfLink") or "",
                        "regions",
                    ),
                },
            )


class VpcRoutersResource(_RegionalVpcResource):
    """Enumerate regional Cloud Routers into ``vpc_routers``; parent for router NAT enumeration."""

    TABLE_NAME = "vpc_routers"
    COLUMNS = ["name", "region", "network", "bgp"]
    ACTION_RESOURCE_TYPE = "routers"
    LIST_API_NAME = "compute.routers.list"
    GET_API_NAME = "compute.routers.get"
    _CLIENT_CLASS = "RoutersClient"
    _AGG_ATTR = "routers"
    _ID_KEY = "router"
    _GET_COLLECTION = "routers"


class VpcRouterNatsResource(_VpcBaseResource):
    """Enumerate Cloud NAT configs (nested under each router) into ``vpc_router_nats``."""

    TABLE_NAME = "vpc_router_nats"
    COLUMNS = ["router_name", "region", "name", "nat_ip_allocate_option", "source_subnetwork_ip_ranges_to_nat", "nat_ips", "log_config"]
    SUPPORTS_GET = False

    def __init__(self, session) -> None:
        super().__init__(session)
        self.client = compute_v1.RoutersClient(credentials=session.credentials)

    def list_for_router(self, *, project_id: str, region: str, router_name: str, action_dict=None):
        try:
            router = self.client.get(project=project_id, region=region, router=router_name)
            _record_resource_permission(
                action_dict,
                permission="compute.routers.get",
                project_id=project_id,
                resource_type="routers",
                resource_label=_regional_resource_label(project_id, region, "routers", router_name),
            )
            return list(getattr(router, "nats", None) or [])
        except Exception as exc:
            self._handle_error(exc, api_name="compute.routers.get", resource_name=router_name, project_id=project_id)
        return []

    def save(self, rows: Iterable[Any], *, project_id: str, region: str, router_name: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "region": region, "router_name": router_name},
            )


class VpcVpnTunnelsResource(_RegionalVpcResource):
    """Enumerate regional VPN tunnels into ``vpc_vpn_tunnels`` (peer IP, status)."""

    TABLE_NAME = "vpc_vpn_tunnels"
    COLUMNS = ["name", "region", "status", "target_vpn_gateway", "vpn_gateway", "router", "peer_ip", "ike_version"]
    ACTION_RESOURCE_TYPE = "vpn_tunnels"
    LIST_API_NAME = "compute.vpnTunnels.list"
    GET_API_NAME = "compute.vpnTunnels.get"
    _CLIENT_CLASS = "VpnTunnelsClient"
    _AGG_ATTR = "vpn_tunnels"
    _ID_KEY = "vpn_tunnel"
    _GET_COLLECTION = "vpnTunnels"


class VpcVpnGatewaysResource(_RegionalVpcResource):
    """Enumerate regional HA VPN gateways into ``vpc_vpn_gateways``."""

    TABLE_NAME = "vpc_vpn_gateways"
    COLUMNS = ["name", "region", "network"]
    ACTION_RESOURCE_TYPE = "vpn_gateways"
    LIST_API_NAME = "compute.vpnGateways.list"
    GET_API_NAME = "compute.vpnGateways.get"
    _CLIENT_CLASS = "VpnGatewaysClient"
    _AGG_ATTR = "vpn_gateways"
    _ID_KEY = "vpn_gateway"
    _GET_COLLECTION = "vpnGateways"
    SUPPORTS_IAM = True
    TEST_IAM_API_NAME = "compute.vpnGateways.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("compute.vpnGateways.")

    def test_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None) -> list[str]:
        if not region or not resource_id:
            return []
        resource_label = _regional_resource_label(project_id, region, self._GET_COLLECTION, resource_id)
        permissions = _compute_test_iam_permissions(
            client=self.client,
            project_id=project_id,
            api_name=self.TEST_IAM_API_NAME,
            resource_label=resource_label,
            permissions=self.TEST_IAM_PERMISSIONS,
            region=region,
            resource_id=resource_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_label,
            )
        return permissions

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None) -> list[str]:
        return self.test_iam_permissions(
            project_id=project_id,
            region=region,
            resource_id=resource_id,
            action_dict=action_dict,
        )


class VpcTargetVpnGatewaysResource(_RegionalVpcResource):
    """Enumerate legacy (Classic) regional target VPN gateways into ``vpc_target_vpn_gateways``."""

    TABLE_NAME = "vpc_target_vpn_gateways"
    COLUMNS = ["name", "region", "network"]
    ACTION_RESOURCE_TYPE = "target_vpn_gateways"
    LIST_API_NAME = "compute.targetVpnGateways.list"
    GET_API_NAME = "compute.targetVpnGateways.get"
    _CLIENT_CLASS = "TargetVpnGatewaysClient"
    _AGG_ATTR = "target_vpn_gateways"
    _ID_KEY = "target_vpn_gateway"
    _GET_COLLECTION = "targetVpnGateways"
