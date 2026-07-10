from __future__ import annotations

from typing import Any, Iterable

from google.cloud import compute_v1

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_segment
from gcpwn.core.utils.persistence import save_to_table


def _scope_from_self_link(self_link: str) -> str:
    token = str(self_link or "")
    if "/regions/" in token:
        return extract_path_segment(token, "regions")
    return "global"


def _dedupe_rows(rows: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    output: list[Any] = []
    for row in rows or []:
        key = str(getattr(row, "self_link", "") or getattr(row, "name", "") or id(row))
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


class LbForwardingRulesResource:
    TABLE_NAME = "lb_forwarding_rules"
    COLUMNS = [
        "scope",
        "name",
        "ip_address",
        "ip_protocol",
        "port_range",
        "load_balancing_scheme",
        "target",
        "network_tier"
    ]
    SUPPORTS_GET = False
    SUPPORTS_IAM = False

    def __init__(self, session) -> None:
        self.session = session
        self._global = compute_v1.GlobalForwardingRulesClient(credentials=session.credentials)
        self._regional = compute_v1.ForwardingRulesClient(credentials=session.credentials)

    def list(self, *, project_id: str):
        rows: list[Any] = []
        try:
            rows.extend(list(self._global.list(project=project_id)))
        except Exception as exc:
            UtilityTools.print_500(project_id, "compute.globalForwardingRules.list", exc)
        try:
            aggregated = self._regional.aggregated_list(project=project_id)
            for _scope, scoped in aggregated:
                rows.extend(list(getattr(scoped, "forwarding_rules", None) or []))
        except Exception as exc:
            UtilityTools.print_500(project_id, "compute.forwardingRules.aggregatedList", exc)
        return _dedupe_rows(rows)

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "scope": _scope_from_self_link(raw.get("self_link") or raw.get("selfLink") or ""),
                },
            )


class LbUrlMapsResource:
    TABLE_NAME = "lb_url_maps"
    COLUMNS = ["name", "default_service", "host_rules", "path_matchers"]
    SUPPORTS_GET = False
    SUPPORTS_IAM = False

    def __init__(self, session) -> None:
        self.session = session
        self.client = compute_v1.UrlMapsClient(credentials=session.credentials)

    def list(self, *, project_id: str):
        try:
            return list(self.client.list(project=project_id))
        except Exception as exc:
            UtilityTools.print_500(project_id, "compute.urlMaps.list", exc)
            return []

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class LbTargetProxiesResource:
    TABLE_NAME = "lb_target_proxies"
    COLUMNS = ["proxy_type", "name", "service", "url_map"]
    SUPPORTS_GET = False
    SUPPORTS_IAM = False

    def __init__(self, session) -> None:
        self.session = session
        self._http = compute_v1.TargetHttpProxiesClient(credentials=session.credentials)
        self._https = compute_v1.TargetHttpsProxiesClient(credentials=session.credentials)
        self._tcp = compute_v1.TargetTcpProxiesClient(credentials=session.credentials)
        self._ssl = compute_v1.TargetSslProxiesClient(credentials=session.credentials)
        self._grpc = compute_v1.TargetGrpcProxiesClient(credentials=session.credentials)

    def list(self, *, project_id: str):
        rows: list[tuple[str, Any]] = []
        for proxy_type, client, api_name in (
            ("http", self._http, "compute.targetHttpProxies.list"),
            ("https", self._https, "compute.targetHttpsProxies.list"),
            ("tcp", self._tcp, "compute.targetTcpProxies.list"),
            ("ssl", self._ssl, "compute.targetSslProxies.list"),
            ("grpc", self._grpc, "compute.targetGrpcProxies.list"),
        ):
            try:
                rows.extend([(proxy_type, item) for item in client.list(project=project_id)])
            except Exception as exc:
                UtilityTools.print_500(project_id, api_name, exc)
        return rows

    def save(self, rows: Iterable[Any], *, project_id: str) -> None:
        for row in rows or []:
            if isinstance(row, tuple) and len(row) == 2:
                proxy_type, obj = row
            else:
                proxy_type, obj = "", row
            save_to_table(
                self.session,
                self.TABLE_NAME,
                obj,
                defaults={"project_id": project_id},
                extras={"proxy_type": proxy_type},
                extra_builder=lambda _obj, raw: {
                    "service": raw.get("service") or raw.get("backend_service") or raw.get("backendService") or "",
                    "url_map": raw.get("url_map") or raw.get("urlMap") or "",
                },
            )
