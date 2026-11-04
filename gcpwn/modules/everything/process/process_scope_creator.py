"""
process_scope_creator – collect all external-facing URLs / IPs from the workspace DB.

Outputs
-------
1. scope_creator.csv  — one row per URL/IP found across service tables.
   Columns: resource_type, resource_id, url_or_ip, is_public,
            dns_zone, dns_record_type, points_to_gcp_asset

2. dangling_dns.csv   — DNS A/CNAME records where the target IP/hostname is not
   present anywhere else in this workspace's DB (stdout section + optional file).

Excludes bucket URLs and allUsers/allAuthenticatedUsers IAM entries.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
from dataclasses import dataclass
from typing import Any

from gcpwn.core.console import UtilityTools


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ScopeEntry:
    resource_type: str
    resource_id: str
    url_or_ip: str
    is_public: str          # "y" / "n" / "?"
    dns_zone: str = ""
    dns_record_type: str = ""
    points_to_gcp_asset: str = "N/A"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RFC1918_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # shared address space
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _is_public_ip(value: str) -> bool | None:
    """Return True if value is a routable public IP, False if private, None if not an IP."""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    for net in _RFC1918_RANGES:
        if addr in net:
            return False
    return True


_GCP_URL_SUFFIXES = (
    ".run.app",
    ".a.run.app",
    ".cloudfunctions.net",
    ".appspot.com",
    ".web.app",
    ".firebaseapp.com",
    ".gateway.dev",
    ".datafusion.googleusercontent.com",
    ".cloudshell.dev",
    ".workstations.dev",
    ".notebooks.googleusercontent.com",
    ".composer.googleusercontent.com",
)


def _is_gcp_url(hostname: str) -> bool:
    h = hostname.lower().rstrip(".")
    return any(h.endswith(s) for s in _GCP_URL_SUFFIXES)


def _parse_json(val: Any) -> Any:
    if val is None or val == "":
        return None
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return None


def _truthy(val: Any) -> bool:
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "t")


def _get(session, table: str, columns: str = "*") -> list[dict]:
    """Silently return [] if the table does not exist."""
    try:
        rows = session.get_data(table, columns=columns) or []
        return rows
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Per-table extractors
# ---------------------------------------------------------------------------

def _extract_cloudrun_services(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "cloudrun_services"):
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        ingress = str(row.get("ingress") or "").strip()
        is_pub = "y" if (not ingress or ingress in (
            "INGRESS_TRAFFIC_ALL", "all", "",
        )) else "n"
        entries.append(ScopeEntry(
            resource_type="cloudrun_service",
            resource_id=str(row.get("name") or row.get("service_id") or ""),
            url_or_ip=url,
            is_public=is_pub,
        ))
    return entries


def _extract_cloudfunctions(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "cloudfunctions_functions"):
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        entries.append(ScopeEntry(
            resource_type="cloud_function",
            resource_id=str(row.get("name") or ""),
            url_or_ip=url,
            is_public="y",
        ))
    return entries


def _extract_appengine(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "appengine_apps"):
        raw = _parse_json(row.get("raw_json"))
        hostname = ""
        if isinstance(raw, dict):
            hostname = str(raw.get("defaultHostname") or "").strip()
        if not hostname:
            pid = str(row.get("project_id") or "").strip()
            if pid:
                hostname = f"{pid}.appspot.com"
        if not hostname:
            continue
        is_pub = "y" if str(row.get("serving_status") or "").upper() == "SERVING" else "n"
        entries.append(ScopeEntry(
            resource_type="appengine_app",
            resource_id=str(row.get("name") or row.get("project_id") or ""),
            url_or_ip=hostname,
            is_public=is_pub,
        ))
    return entries


def _extract_gke(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "gke_clusters"):
        endpoint = str(row.get("endpoint") or "").strip()
        if not endpoint:
            continue
        is_private = _truthy(row.get("private_cluster"))
        entries.append(ScopeEntry(
            resource_type="gke_cluster_endpoint",
            resource_id=str(row.get("name") or row.get("cluster_id") or ""),
            url_or_ip=endpoint,
            is_public="n" if is_private else "y",
        ))
    return entries


def _extract_cloudsql(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "cloudsql_instances"):
        ip_addresses = _parse_json(row.get("ip_addresses")) or []
        if not isinstance(ip_addresses, list):
            continue
        ipv4_enabled = _truthy(row.get("settings_ip_configuration_ipv4_enabled"))
        for ip_entry in ip_addresses:
            if not isinstance(ip_entry, dict):
                continue
            addr = str(ip_entry.get("ipAddress") or ip_entry.get("ip_address") or "").strip()
            itype = str(ip_entry.get("type") or "").upper()
            if not addr:
                continue
            if itype == "PRIMARY":
                is_pub = "y" if ipv4_enabled else "n"
            elif itype == "OUTGOING":
                is_pub = "y"
            else:
                public = _is_public_ip(addr)
                is_pub = "y" if public else ("n" if public is False else "?")
            entries.append(ScopeEntry(
                resource_type=f"cloudsql_instance/{itype.lower() or 'ip'}",
                resource_id=str(row.get("name") or ""),
                url_or_ip=addr,
                is_public=is_pub,
            ))
    return entries


def _extract_lb_forwarding_rules(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "lb_forwarding_rules"):
        ip = str(row.get("ip_address") or "").strip()
        if not ip:
            continue
        scheme = str(row.get("load_balancing_scheme") or "").upper()
        is_pub = "y" if scheme in ("EXTERNAL", "EXTERNAL_MANAGED") else "n"
        entries.append(ScopeEntry(
            resource_type="lb_forwarding_rule",
            resource_id=str(row.get("name") or ""),
            url_or_ip=ip,
            is_public=is_pub,
        ))
    return entries


def _extract_alloydb(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "alloydb_instances"):
        pub_ip = str(row.get("public_ip_address") or "").strip()
        if pub_ip:
            entries.append(ScopeEntry(
                resource_type="alloydb_instance/public",
                resource_id=str(row.get("name") or row.get("instance_id") or ""),
                url_or_ip=pub_ip,
                is_public="y",
            ))
        priv_ip = str(row.get("ip_address") or "").strip()
        if priv_ip:
            entries.append(ScopeEntry(
                resource_type="alloydb_instance/private",
                resource_id=str(row.get("name") or row.get("instance_id") or ""),
                url_or_ip=priv_ip,
                is_public="n",
            ))
    return entries


def _extract_apigateway(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "apigateway_gateways"):
        host = str(row.get("default_hostname") or "").strip()
        if not host:
            continue
        entries.append(ScopeEntry(
            resource_type="apigateway_gateway",
            resource_id=str(row.get("name") or ""),
            url_or_ip=host,
            is_public="y",
        ))
    return entries


def _extract_datafusion(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "datafusion_instances"):
        for col, label in (
            ("service_endpoint", "service"),
            ("api_endpoint", "api"),
        ):
            val = str(row.get(col) or "").strip()
            if val:
                entries.append(ScopeEntry(
                    resource_type=f"datafusion_instance/{label}",
                    resource_id=str(row.get("name") or row.get("instance_id") or ""),
                    url_or_ip=val,
                    is_public="y",
                ))
    return entries


def _extract_managedkafka(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "managedkafka_clusters"):
        addr = str(row.get("bootstrap_address") or "").strip()
        if not addr:
            continue
        host = addr.split(":")[0]
        public = _is_public_ip(host)
        is_pub = "y" if public else ("n" if public is False else "?")
        entries.append(ScopeEntry(
            resource_type="managedkafka_cluster",
            resource_id=str(row.get("name") or row.get("cluster_id") or ""),
            url_or_ip=addr,
            is_public=is_pub,
        ))
    return entries


def _extract_cloudshell(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "cloudshell_environments"):
        for col, label in (
            ("ssh_host", "ssh"),
            ("web_host", "web"),
        ):
            val = str(row.get(col) or "").strip()
            if val:
                entries.append(ScopeEntry(
                    resource_type=f"cloudshell_env/{label}",
                    resource_id=str(row.get("name") or row.get("env_id") or ""),
                    url_or_ip=val,
                    is_public="y",
                ))
    return entries


def _extract_workstations(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "workstations_workstations"):
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        entries.append(ScopeEntry(
            resource_type="workstation",
            resource_id=str(row.get("name") or row.get("workstation_id") or ""),
            url_or_ip=host,
            is_public="n",  # accessed via IAP, not directly public
        ))
    return entries


def _extract_service_directory(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "servicedirectory_endpoints"):
        addr = str(row.get("address") or "").strip()
        if not addr:
            continue
        public = _is_public_ip(addr)
        is_pub = "y" if public else ("n" if public is False else "?")
        entries.append(ScopeEntry(
            resource_type="service_directory_endpoint",
            resource_id=str(row.get("name") or row.get("endpoint_id") or ""),
            url_or_ip=addr,
            is_public=is_pub,
        ))
    return entries


def _extract_vpn_tunnels(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "vpc_vpn_tunnels"):
        peer = str(row.get("peer_ip") or "").strip()
        if not peer:
            continue
        entries.append(ScopeEntry(
            resource_type="vpn_tunnel_peer",
            resource_id=str(row.get("name") or ""),
            url_or_ip=peer,
            is_public="y",
        ))
    return entries


def _extract_router_nat_ips(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "vpc_router_nats"):
        nat_ips = _parse_json(row.get("nat_ips"))
        if not isinstance(nat_ips, list):
            # could be a comma-separated string
            raw = str(row.get("nat_ips") or "").strip()
            nat_ips = [x.strip() for x in raw.split(",") if x.strip()] if raw else []
        rid = f"{row.get('router_name') or ''}/{row.get('name') or ''}".strip("/")
        for ip in nat_ips:
            ip = str(ip).strip()
            if ip:
                entries.append(ScopeEntry(
                    resource_type="router_nat_ip",
                    resource_id=rid,
                    url_or_ip=ip,
                    is_public="y",
                ))
    return entries


def _extract_memorystore_redis(session: Any) -> list[ScopeEntry]:
    entries = []
    for row in _get(session, "memorystore-redis"):
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        public = _is_public_ip(host)
        is_pub = "y" if public else ("n" if public is False else "?")
        entries.append(ScopeEntry(
            resource_type="memorystore_redis",
            resource_id=str(row.get("name") or ""),
            url_or_ip=host,
            is_public=is_pub,
        ))
    return entries


def _extract_compute_instances(session: Any) -> list[ScopeEntry]:
    """Extract external (natIP) addresses from Compute instances."""
    entries = []
    for row in _get(session, "cloudcompute_instances"):
        name = str(row.get("name") or row.get("id") or "")
        ifaces = _parse_json(row.get("network_interfaces"))
        if not isinstance(ifaces, list):
            continue
        for iface in ifaces:
            if not isinstance(iface, dict):
                continue
            for ac in (iface.get("accessConfigs") or iface.get("access_configs") or []):
                if not isinstance(ac, dict):
                    continue
                nat_ip = str(ac.get("natIP") or ac.get("nat_ip") or "").strip()
                if nat_ip:
                    entries.append(ScopeEntry(
                        resource_type="compute_instance_external_ip",
                        resource_id=name,
                        url_or_ip=nat_ip,
                        is_public="y",
                    ))
    return entries


# ---------------------------------------------------------------------------
# DNS extractors + cross-reference
# ---------------------------------------------------------------------------

def _build_gcp_asset_sets(non_dns_entries: list[ScopeEntry]) -> tuple[set[str], set[str]]:
    """Build sets of known GCP IPs and hostnames from non-DNS entries."""
    known_ips: set[str] = set()
    known_hosts: set[str] = set()
    for e in non_dns_entries:
        val = e.url_or_ip.strip()
        if not val:
            continue
        if _is_public_ip(val) is not None:
            known_ips.add(val)
        else:
            # strip scheme
            host = val.lower().lstrip("https://").lstrip("http://").split("/")[0].split(":")[0]
            known_hosts.add(host)
    return known_ips, known_hosts


def _normalise_cname_target(target: str) -> str:
    return target.lower().rstrip(".")


def _extract_dns(session: Any, known_ips: set[str], known_hosts: set[str]) -> list[ScopeEntry]:
    """
    Extract DNS record entries.  For public zones only we include the records.
    For each A/AAAA/CNAME record:
      - is_public = y if the zone is public, n if private
      - points_to_gcp_asset = y if any rrdata IP/hostname is in the GCP DB,
        or if target matches a GCP URL suffix
    """
    # Build zone visibility map
    zone_visibility: dict[str, str] = {}  # zone_name -> "PUBLIC" / "PRIVATE"
    for row in _get(session, "clouddns_managed_zones"):
        zname = str(row.get("name") or "")
        viz = str(row.get("visibility") or "").upper()
        zone_visibility[zname] = viz

    entries = []
    for row in _get(session, "clouddns_record_sets"):
        rtype = str(row.get("type") or "").upper()
        if rtype not in ("A", "AAAA", "CNAME"):
            continue
        zone = str(row.get("zone_name") or "")
        dns_name = str(row.get("name") or "")
        viz = zone_visibility.get(zone, "PUBLIC")
        is_pub = "n" if viz == "PRIVATE" else "y"

        rrdatas_raw = _parse_json(row.get("rrdatas"))
        if isinstance(rrdatas_raw, list):
            rrdatas = [str(r).strip() for r in rrdatas_raw if str(r).strip()]
        elif isinstance(rrdatas_raw, str) and rrdatas_raw:
            rrdatas = [rrdatas_raw.strip()]
        else:
            rrdatas = []

        for rrdata in rrdatas:
            if not rrdata:
                continue
            # Determine points_to_gcp_asset
            if rtype in ("A", "AAAA"):
                pta = "y" if rrdata in known_ips else "n"
            else:  # CNAME
                target = _normalise_cname_target(rrdata)
                if _is_gcp_url(target) or target in known_hosts:
                    pta = "y"
                else:
                    pta = "n"

            entries.append(ScopeEntry(
                resource_type="dns_record",
                resource_id=dns_name,
                url_or_ip=rrdata,
                is_public=is_pub,
                dns_zone=zone,
                dns_record_type=rtype,
                points_to_gcp_asset=pta,
            ))
    return entries


# ---------------------------------------------------------------------------
# CSV / output helpers
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "resource_type", "resource_id", "url_or_ip", "is_public",
    "dns_zone", "dns_record_type", "points_to_gcp_asset",
]


def _write_csv(entries: list[ScopeEntry], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for e in entries:
            writer.writerow({
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "url_or_ip": e.url_or_ip,
                "is_public": e.is_public,
                "dns_zone": e.dns_zone,
                "dns_record_type": e.dns_record_type,
                "points_to_gcp_asset": e.points_to_gcp_asset,
            })


# ---------------------------------------------------------------------------
# run_module
# ---------------------------------------------------------------------------

_EXTRACTORS = [
    ("Cloud Run Services",         _extract_cloudrun_services),
    ("Cloud Functions",            _extract_cloudfunctions),
    ("App Engine Apps",            _extract_appengine),
    ("GKE Cluster Endpoints",      _extract_gke),
    ("Cloud SQL Instances",        _extract_cloudsql),
    ("Compute Instance Ext. IPs",  _extract_compute_instances),
    ("LB Forwarding Rules",        _extract_lb_forwarding_rules),
    ("AlloyDB Instances",          _extract_alloydb),
    ("API Gateway Gateways",       _extract_apigateway),
    ("Data Fusion Instances",      _extract_datafusion),
    ("Managed Kafka Clusters",     _extract_managedkafka),
    ("Cloud Shell Environments",   _extract_cloudshell),
    ("Cloud Workstations",         _extract_workstations),
    ("Service Directory Endpoints",_extract_service_directory),
    ("VPN Tunnel Peers",           _extract_vpn_tunnels),
    ("Router NAT IPs",             _extract_router_nat_ips),
    ("Memorystore Redis",          _extract_memorystore_redis),
]


def run_module(user_args, session):
    parser = argparse.ArgumentParser(
        description="Extract external-facing URLs / IPs from the workspace DB",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Directory to write scope_creator.csv and dangling_dns.csv (default: .)",
    )
    parser.add_argument(
        "--no-dangling",
        action="store_true",
        help="Skip dangling DNS analysis",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress stdout summary (CSV files are still written)",
    )
    args = parser.parse_args(user_args)

    out_dir = os.path.expanduser(args.output)
    os.makedirs(out_dir, exist_ok=True)

    # --- collect non-DNS entries ---
    all_entries: list[ScopeEntry] = []
    if not args.silent:
        print(f"\n{UtilityTools.CYAN}[*] Scope Creator — scanning DB tables...{UtilityTools.RESET}")

    for label, extractor in _EXTRACTORS:
        try:
            found = extractor(session)
        except Exception as exc:
            if not args.silent:
                print(f"  {UtilityTools.YELLOW}[!] {label}: {exc}{UtilityTools.RESET}")
            found = []
        all_entries.extend(found)
        if found and not args.silent:
            print(f"  {UtilityTools.GREEN}[+]{UtilityTools.RESET} {label}: {len(found)} entries")

    # --- build GCP asset sets for DNS cross-reference ---
    known_ips, known_hosts = _build_gcp_asset_sets(all_entries)

    # --- DNS entries ---
    dns_entries: list[ScopeEntry] = []
    try:
        dns_entries = _extract_dns(session, known_ips, known_hosts)
    except Exception as exc:
        if not args.silent:
            print(f"  {UtilityTools.YELLOW}[!] Cloud DNS records: {exc}{UtilityTools.RESET}")
    if dns_entries and not args.silent:
        print(f"  {UtilityTools.GREEN}[+]{UtilityTools.RESET} Cloud DNS Records (A/AAAA/CNAME): {len(dns_entries)} entries")

    all_entries.extend(dns_entries)

    # --- write main CSV ---
    scope_csv = os.path.join(out_dir, "scope_creator.csv")
    _write_csv(all_entries, scope_csv)
    if not args.silent:
        pub  = sum(1 for e in all_entries if e.is_public == "y")
        priv = sum(1 for e in all_entries if e.is_public == "n")
        unk  = sum(1 for e in all_entries if e.is_public == "?")
        print(
            f"\n{UtilityTools.GREEN}[+] scope_creator.csv written → {scope_csv}{UtilityTools.RESET}"
        )
        print(f"    Total entries : {len(all_entries)}")
        print(f"    Public        : {pub}")
        print(f"    Private       : {priv}")
        print(f"    Unknown       : {unk}")

    # --- dangling DNS ---
    if not args.no_dangling:
        dangling = [e for e in dns_entries if e.points_to_gcp_asset == "n"]
        if not args.silent:
            print(
                f"\n{UtilityTools.CYAN}[*] Dangling DNS check "
                f"({len(dangling)} suspicious record(s) of {len(dns_entries)} DNS entries)"
                f"{UtilityTools.RESET}"
            )
        if dangling:
            dangling_csv = os.path.join(out_dir, "dangling_dns.csv")
            _write_csv(dangling, dangling_csv)
            if not args.silent:
                print(
                    f"{UtilityTools.YELLOW}[!] dangling_dns.csv written → "
                    f"{dangling_csv}{UtilityTools.RESET}"
                )
                print(
                    "    These A/AAAA/CNAME records point to IPs or hostnames not found "
                    "in any other GCP resource in this workspace."
                )
                _SHOW_LIMIT = 25
                for entry in dangling[:_SHOW_LIMIT]:
                    print(
                        f"      {entry.dns_record_type:<5}  "
                        f"{entry.resource_id:<40}  → {entry.url_or_ip}"
                    )
                if len(dangling) > _SHOW_LIMIT:
                    print(f"      ... and {len(dangling) - _SHOW_LIMIT} more (see CSV)")
        elif not args.silent:
            print(
                f"  {UtilityTools.GREEN}[+] No dangling DNS records found "
                f"(all A/CNAME targets matched known GCP assets).{UtilityTools.RESET}"
            )

    return 1
