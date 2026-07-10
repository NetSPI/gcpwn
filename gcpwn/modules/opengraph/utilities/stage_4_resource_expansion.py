from __future__ import annotations

import re
import sys
from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail, parse_json_value
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    canonical_target_node_ref,
    gcp_resource_node_type,
    normalize_resource_type_token,
    principal_member_properties,
    principal_node_id,
    principal_type,
    resource_display_label,
    resource_leaf_name,
    resource_location_token,
    resource_node_id,
)

_WIF_SUBJECT_PRINCIPAL_RE = re.compile(
    r"^principal://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/subject/(.+)$"
)
_WIF_POOL_PRINCIPAL_SET_RE = re.compile(
    r"^principalSet://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/\*$"
)
_WIF_GROUP_PRINCIPAL_SET_RE = re.compile(
    r"^principalSet://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/group/(.+)$"
)
_WIF_ATTRIBUTE_PRINCIPAL_SET_RE = re.compile(
    r"^principalSet://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/attribute\.([^/]+)/(.+)$"
)
_WIF_GKE_SERVICE_ACCOUNT_UID_PRINCIPAL_RE = re.compile(
    r"^principal://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/kubernetes\.serviceaccount\.uid/(.+)$"
)
_WIF_GKE_NAMESPACE_PRINCIPAL_SET_RE = re.compile(
    r"^principalSet://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/namespace/(.+)$"
)
_WIF_GKE_CLUSTER_PRINCIPAL_SET_RE = re.compile(
    r"^principalSet://iam\.googleapis\.com/projects/([^/]+)/locations/([^/]+)/workloadIdentityPools/([^/]+)/kubernetes\.cluster/(.+)$"
)
_WIF_GKE_LEGACY_SERVICE_ACCOUNT_RE = re.compile(
    r"^serviceAccount:([a-z0-9-]+)\.svc\.id\.goog\[([^/\]]+)/([^\]]+)\]$",
    re.IGNORECASE,
)
_WIF_GKE_SUBJECT_SELECTOR_RE = re.compile(r"^ns/([^/]+)/sa/([^/]+)$")
_WIF_GKE_CLUSTER_SELECTOR_RE = re.compile(
    r"^https://container\.googleapis\.com/v1/projects/([^/]+)/locations/([^/]+)/clusters/(.+)$"
)


def _progress_interval(total: int) -> int:
    if total <= 0:
        return 1
    return max(1, total // 100)


def _should_emit_progress(processed: int, total: int) -> bool:
    if total <= 0 or processed <= 0:
        return False
    step = _progress_interval(total)
    return processed == 1 or processed == total or processed % step == 0


def _print_inline_progress(label: str, processed: int, total: int, *, force: bool = False) -> None:
    if total <= 0:
        return
    if not force and not _should_emit_progress(processed, total):
        return
    message = f"[*] {label}: {processed}/{total} (remaining {max(0, total - processed)})"
    if sys.stdout.isatty():
        print(f"\r{message}", end="", flush=True)
        if force:
            print("")
        return
    print(message)


def _print_stage4_section_progress(
    *,
    processed_sections: int,
    total_sections: int,
    section_label: str,
    force: bool = False,
) -> None:
    message = f"[*] Stage 4 sections: {processed_sections}/{total_sections} ({section_label})"
    if sys.stdout.isatty():
        print(f"\r{message}", end="", flush=True)
        if force:
            print("")
        return
    print(message)


def _normalize_graph_scalar(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    text = str(value).strip()
    if not text:
        return None
    return text


def _row_resourcedata_payload(
    row: dict[str, Any],
    *,
    skip_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Build nested row payload to later export as flattened `resourcedata.*`."""
    output: dict[str, Any] = {}
    if not isinstance(row, dict):
        return output

    effective_skip_keys = {str(key or "").strip() for key in (skip_keys or set())}
    for raw_key, raw_value in row.items():
        key = str(raw_key or "").strip()
        if not key or key in effective_skip_keys or key.startswith("resourcedata."):
            continue
        parsed = parse_json_value(raw_value, default=None)
        if key == "raw_json" and isinstance(parsed, dict):
            # Unwrap raw_json object payloads into top-level resourcedata keys
            # so exports read as resourcedata.<field> instead of
            # resourcedata.raw_json.<field>.
            for child_key, child_value in parsed.items():
                child_token = str(child_key or "").strip()
                if not child_token or child_token in output:
                    continue
                output[child_token] = child_value
            continue
        if isinstance(parsed, (dict, list)):
            output[key] = parsed
            continue
        normalized = _normalize_graph_scalar(raw_value)
        if normalized is not None:
            output[key] = normalized
    return output


def _compute_instance_resourcedata_payload(row: dict[str, Any]) -> dict[str, Any]:
    """
    Preserve cached `cloudcompute_instances` row data as nested `resourcedata`
    so export-time flattening can emit `resourcedata.*` keys.
    """
    return _row_resourcedata_payload(row, skip_keys={"workspace_id"})


def _compute_instance_resource_name(row: dict[str, Any]) -> str:
    project_id = str(row.get("project_id") or "").strip()
    name = str(row.get("name") or "").strip()
    zone = str(row.get("zone") or "").strip()
    zone = extract_path_tail(zone)
    if project_id and name and zone:
        return f"projects/{project_id}/zones/{zone}/instances/{name}"
    self_link = str(row.get("self_link") or "").strip()
    if self_link:
        return self_link
    return name


def _extract_compute_instance_service_accounts(row: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    candidates.append(parse_json_value(row.get("service_accounts"), default=None))
    raw_json = parse_json_value(row.get("raw_json"), default=None)
    if isinstance(raw_json, dict):
        candidates.append(raw_json.get("service_accounts"))

    emails: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, list):
            continue
        for item in candidate:
            if isinstance(item, str):
                email = item.strip().lower()
                if "@" in email:
                    emails.add(email)
                continue
            if isinstance(item, dict):
                email = str(item.get("email") or "").strip().lower()
                if "@" in email:
                    emails.add(email)
    return sorted(emails)


def _project_scope_name(project_id: str, project_scope_by_project_id: dict[str, str]) -> str:
    token = str(project_id or "").strip()
    if not token:
        return ""
    mapped = str(project_scope_by_project_id.get(token) or "").strip()
    if mapped:
        return mapped
    return token if token.startswith("projects/") else f"projects/{token}"


# "Relevant services" for default project->resource topology mode.
_DEFAULT_PROJECT_EDGE_RESOURCE_TYPES = frozenset(
    {
        "computeinstance",
        "cloudfunction",
        "cloudrunservice",
        "cloudrunjob",
        "workloadidentitypool",
        "workloadidentityprovider",
        "bucket",
        "secrets",
        "cloudtasksqueue",
        "artifactregistryrepo",
        "service-account",
    }
)

_RESOURCE_ENRICHMENT_SKIP_TABLES = frozenset(
    {
        "iam_allow_policies",
        "iam_unauth_permissions",
        "iam_roles",
        "iam_group_memberships",
        "workspace_users",
        "workspace_groups",
        "workspace_group_memberships",
        "member_permissions_summary",
        "opengraph_nodes",
        "opengraph_edges",
    }
)
_RESOURCE_ENRICHMENT_NAME_COLUMNS = ("resource_name", "name", "self_link")

_RESOURCE_EXPANSION_ROW_TABLES: tuple[str, ...] = (
    "iam_service_accounts",
    "iam_sa_keys",
    "cloudcompute_instances",
    "cloudfunctions_functions",
    "cloudrun_services",
    "cloudrun_jobs",
    "workload_identity_pools",
    "workload_identity_providers",
)

_RESOURCE_EXPANSION_STAGE_STAT_KEYS: tuple[str, ...] = (
    "service_account_nodes_added",
    "service_account_key_nodes_added",
    "service_account_key_edges_added",
    "project_resource_edges_added",
    "compute_executes_with_edges_added",
    "wif_provider_pool_edges_added",
    "wif_principal_pool_edges_added",
    "wif_provider_external_edges_added",
)


def _merge_nested_payload_missing(destination: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    merged = dict(destination or {})
    for key, value in (source or {}).items():
        if key not in merged:
            if value not in (None, "", [], {}):
                merged[key] = value
            continue
        existing_child = merged.get(key)
        if isinstance(existing_child, dict) and isinstance(value, dict):
            merged[key] = _merge_nested_payload_missing(existing_child, value)
    return merged


def _resource_name_aliases(value: str) -> set[str]:
    token = str(value or "").strip()
    if not token:
        return set()
    aliases = {token}
    tail = extract_path_tail(token, default="")
    if tail:
        aliases.add(tail)
    if "/buckets/" in token:
        bucket_tail = token.split("/buckets/", 1)[1].strip()
        if bucket_tail:
            aliases.add(bucket_tail)
    return {alias for alias in aliases if str(alias or "").strip()}


def _resource_enrichment_payloads_by_name(
    context,
    *,
    target_resource_names: set[str],
    candidate_project_by_name: dict[str, str],
) -> dict[str, dict[str, Any]]:
    if not target_resource_names:
        return {}

    alias_to_targets: dict[str, set[str]] = {}
    for resource_name in target_resource_names:
        for alias_token in _resource_name_aliases(resource_name):
            alias_to_targets.setdefault(alias_token, set()).add(resource_name)

    output: dict[str, dict[str, Any]] = {}
    for table_name in context.service_table_names():
        table_token = str(table_name or "").strip()
        if (
            not table_token
            or table_token in _RESOURCE_ENRICHMENT_SKIP_TABLES
            or table_token.startswith("opengraph_")
        ):
            continue
        table_columns = {str(col or "").strip().lower() for col in context.service_table_columns(table_token)}
        if "workspace_id" not in table_columns:
            continue
        name_columns = [column for column in _RESOURCE_ENRICHMENT_NAME_COLUMNS if column in table_columns]
        if not name_columns:
            continue

        for row in context.service_rows(table_token):
            row_dict = dict(row or {})
            row_project_id = str(row_dict.get("project_id") or "").strip()
            matched_names: set[str] = set()
            for column in name_columns:
                token = str(row_dict.get(column) or "").strip()
                if not token:
                    continue
                if token in target_resource_names:
                    matched_names.add(token)
                for alias_token in _resource_name_aliases(token):
                    alias_matches = alias_to_targets.get(alias_token, set())
                    if not alias_matches:
                        continue
                    if row_project_id:
                        alias_matches = {
                            name
                            for name in alias_matches
                            if str(candidate_project_by_name.get(name) or "").strip() == row_project_id
                        }
                    if len(alias_matches) == 1:
                        matched_names.update(alias_matches)
            if not matched_names:
                continue

            row_payload = _row_resourcedata_payload(row_dict, skip_keys={"workspace_id"})
            if not row_payload:
                continue
            for resource_name in matched_names:
                existing = output.setdefault(resource_name, {})
                output[resource_name] = _merge_nested_payload_missing(existing, row_payload)

    return output


def _collect_project_resource_candidates(
    *,
    indexes,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None,
    cloudfunctions_functions_rows: Iterable[dict[str, Any]] | None,
    cloudrun_services_rows: Iterable[dict[str, Any]] | None,
    cloudrun_jobs_rows: Iterable[dict[str, Any]] | None,
    workload_identity_pools_rows: Iterable[dict[str, Any]] | None,
    workload_identity_providers_rows: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Build candidate resources used for project -> resource topology edges.

    Sources:
    1) `scope_resource_indexes.allow_resources` (IAM-discovered resources)
    2) explicit cached service tables for high-value runtime services
       (compute instances, cloud functions, cloud run services/jobs)
    """
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for row in indexes.allow_resources or []:
        project_id = str(row.get("project_id") or "").strip()
        resource_name = str(row.get("resource_name") or "").strip()
        resource_type = normalize_resource_type_token(str(row.get("resource_type") or ""))
        if not project_id or not resource_name or not resource_type:
            continue
        key = (project_id, resource_type, resource_name)
        if key in seen:
            continue
        seen.add(key)
        region = resource_location_token(resource_name)
        candidates.append(
            {
                "project_id": project_id,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "display_name": str(row.get("display_name") or "").strip() or extract_path_tail(resource_name, default=resource_name),
                "region": region,
                "status": str(row.get("status") or row.get("state") or "").strip().upper(),
                "source": "iam_allow_policies",
                "resourcedata": _row_resourcedata_payload(dict(row), skip_keys={"workspace_id"}),
            }
        )

    def _append_explicit_rows(rows: Iterable[dict[str, Any]], *, resource_type: str, name_builder) -> None:
        for row in rows or []:
            project_id = str(row.get("project_id") or "").strip()
            resource_name = str(name_builder(row) or "").strip()
            if not project_id or not resource_name:
                continue
            normalized_type = normalize_resource_type_token(resource_type)
            key = (project_id, normalized_type, resource_name)
            if key in seen:
                continue
            seen.add(key)
            region = (
                str(row.get("region_val") or row.get("region") or row.get("location") or "").strip()
                or resource_location_token(resource_name)
            )
            candidates.append(
                {
                    "project_id": project_id,
                    "resource_type": normalized_type,
                    "resource_name": resource_name,
                    "display_name": extract_path_tail(resource_name, default=resource_name),
                    "region": region,
                    "status": str(row.get("status") or row.get("state") or "").strip().upper(),
                    "source": "service_cache",
                    "resourcedata": _row_resourcedata_payload(dict(row), skip_keys={"workspace_id"}),
                }
            )

    _append_explicit_rows(
        cloudcompute_instances_rows,
        resource_type="computeinstance",
        name_builder=lambda row: _compute_instance_resource_name(row),
    )
    _append_explicit_rows(
        cloudfunctions_functions_rows,
        resource_type="cloudfunction",
        name_builder=lambda row: row.get("name"),
    )
    _append_explicit_rows(
        cloudrun_services_rows,
        resource_type="cloudrunservice",
        name_builder=lambda row: row.get("name"),
    )
    _append_explicit_rows(
        cloudrun_jobs_rows,
        resource_type="cloudrunjob",
        name_builder=lambda row: row.get("name"),
    )
    _append_explicit_rows(
        workload_identity_pools_rows,
        resource_type="workloadidentitypool",
        name_builder=lambda row: row.get("name"),
    )
    _append_explicit_rows(
        workload_identity_providers_rows,
        resource_type="workloadidentityprovider",
        name_builder=lambda row: row.get("name"),
    )

    return candidates


def _add_project_resource_membership_edges(
    context,
    *,
    candidates: list[dict[str, Any]],
    indexes,
    resource_enrichment_by_name: dict[str, dict[str, Any]] | None = None,
) -> int:
    """
    Add:
      project -> EXISTS_IN_PROJECT -> resource

    Mode behavior:
    - default: emit only "relevant services" (compute/function/run + selected high-value services)
    - include_all: emit for every known resource candidate
    """
    include_all = bool(getattr(context.options, "include_all", False))
    edges_added = 0
    enrichment_by_name = dict(resource_enrichment_by_name or {})

    for resource in candidates:
        project_id = str(resource.get("project_id") or "").strip()
        resource_type = normalize_resource_type_token(str(resource.get("resource_type") or ""))
        resource_name = str(resource.get("resource_name") or "").strip()
        if not project_id or not resource_type or not resource_name:
            continue
        if resource_type in {"org", "folder", "project"}:
            continue
        should_emit_membership_edge = bool(include_all or resource_type in _DEFAULT_PROJECT_EDGE_RESOURCE_TYPES)

        # Service-account resources collapse onto their serviceAccount:<email> principal
        # node so a SA is ONE graph node (actor + object), not a separate
        # resource:projects/.../serviceAccounts/<email> duplicate.
        resource_node, resource_node_kind = canonical_target_node_ref(resource_name, resource_type)
        resource_label = resource_leaf_name(resource_name) or str(resource.get("display_name") or "").strip() or resource_name
        resource_region = str(resource.get("region") or "").strip() or resource_location_token(resource_name)
        resource_status = str(resource.get("status") or resource.get("state") or "").strip().upper()
        resource_resourcedata = resource.get("resourcedata") if isinstance(resource.get("resourcedata"), dict) else {}
        enriched_payload = enrichment_by_name.get(resource_name)
        if isinstance(enriched_payload, dict) and enriched_payload:
            resource_resourcedata = _merge_nested_payload_missing(resource_resourcedata, enriched_payload)
            if not resource_status:
                resource_status = (
                    str(resource_resourcedata.get("status") or "").strip()
                    or str(resource_resourcedata.get("state") or "").strip()
                    or str(resource_resourcedata.get("primary_state") or "").strip()
                ).upper()
        context.builder.add_node(
            resource_node,
            resource_node_kind,
            name=resource_label,
            display_name=resource_label,
            resource_name=resource_name,
            region=resource_region,
            project_id=project_id,
            resource_type=resource_type,
            status=resource_status or None,
            source=str(resource.get("source") or "resource_expansion"),
            resourcedata=resource_resourcedata or None,
        )

        if not should_emit_membership_edge:
            continue

        project_scope_name = _project_scope_name(project_id, indexes.project_scope_by_project_id)
        if not project_scope_name or resource_name == project_scope_name:
            continue

        project_node_id = resource_node_id(project_scope_name)
        project_label = resource_display_label(
            project_scope_name,
            resource_type="project",
            project_id=project_id,
        )
        context.builder.add_node(
            project_node_id,
            gcp_resource_node_type("project"),
            name=project_label,
            display_name=project_label,
            resource_name=project_scope_name,
            project_id=project_id,
            resource_type="project",
            source="resource_expansion",
        )

        edge_key = (project_node_id, "EXISTS_IN_PROJECT", resource_node)
        if edge_key in context.builder.edge_map:
            continue
        context.builder.add_edge(
            project_node_id,
            resource_node,
            "EXISTS_IN_PROJECT",
            source="resource_expansion",
            project_id=project_id,
            resource_type=resource_type,
            membership_mode="include_all" if include_all else "default",
        )
        edges_added += 1

    return edges_added


def _add_compute_executes_with_edges(
    context,
    *,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None,
) -> int:
    """
    Add:
      compute_instance -> EXECUTES_WITH -> serviceAccount:<email>
    """
    edges_added = 0
    row_list = [row for row in (cloudcompute_instances_rows or []) if isinstance(row, dict)]
    total_rows = len(row_list)
    for index, row in enumerate(row_list, start=1):
        project_id = str(row.get("project_id") or "").strip()
        instance_name = _compute_instance_resource_name(row)
        if not project_id or not instance_name:
            _print_inline_progress("Stage 4 compute instances processed", index, total_rows)
            continue
        instance_label = resource_leaf_name(instance_name) or instance_name
        instance_region = str(row.get("region_val") or row.get("region") or row.get("location") or "").strip() or resource_location_token(instance_name)
        instance_status = str(row.get("status") or row.get("state") or "").strip().upper()
        instance_resourcedata = _compute_instance_resourcedata_payload(row)

        instance_node_id = resource_node_id(instance_name)
        context.builder.add_node(
            instance_node_id,
            gcp_resource_node_type("computeinstance"),
            name=instance_label,
            display_name=instance_label,
            resource_name=instance_name,
            region=instance_region,
            project_id=project_id,
            resource_type="computeinstance",
            status=instance_status or None,
            source="cloudcompute_instances",
            resourcedata=instance_resourcedata or None,
        )

        for email in _extract_compute_instance_service_accounts(row):
            member = f"serviceAccount:{email}"
            principal_id = principal_node_id(member)
            if not principal_id:
                continue
            context.builder.add_node(
                principal_id,
                principal_type(member),
                **principal_member_properties(member),
                source="cloudcompute_instances",
            )

            edge_key = (instance_node_id, "EXECUTES_WITH", principal_id)
            if edge_key in context.builder.edge_map:
                continue
            context.builder.add_edge(
                instance_node_id,
                principal_id,
                "EXECUTES_WITH",
                source="cloudcompute_instances",
                project_id=project_id,
                instance_resource=instance_name,
                service_account_email=email,
            )
            edges_added += 1
        _print_inline_progress("Stage 4 compute instances processed", index, total_rows)
    _print_inline_progress("Stage 4 compute instances processed", total_rows, total_rows, force=True)
    return edges_added


def _add_wif_provider_pool_edges(
    context,
    *,
    workload_identity_pools_rows: Iterable[dict[str, Any]] | None,
    workload_identity_providers_rows: Iterable[dict[str, Any]] | None,
) -> int:
    """
    Add:
      workload identity provider -> WIF_PROVIDER_IN_POOL -> workload identity pool
    """
    edges_added = 0
    pool_rows_by_name: dict[str, dict[str, Any]] = {}
    for row in workload_identity_pools_rows or []:
        pool_name = str(row.get("name") or "").strip()
        if pool_name:
            pool_rows_by_name[pool_name] = dict(row)

    for row in workload_identity_providers_rows or []:
        provider_name = str(row.get("name") or "").strip()
        pool_name = str(row.get("pool_name") or "").strip()
        project_id = str(row.get("project_id") or "").strip()
        if not provider_name or not pool_name:
            continue

        provider_node_id = resource_node_id(provider_name)
        provider_label = str(row.get("provider_id") or "").strip() or resource_leaf_name(provider_name) or provider_name
        provider_region = (
            str(row.get("region_val") or row.get("region") or row.get("location") or "").strip()
            or resource_location_token(provider_name)
        )
        provider_status = str(row.get("status") or row.get("state") or "").strip().upper()
        provider_resourcedata = _row_resourcedata_payload(dict(row), skip_keys={"workspace_id"})
        context.builder.add_node(
            provider_node_id,
            gcp_resource_node_type("workloadidentityprovider"),
            name=provider_label,
            display_name=provider_label,
            resource_name=provider_name,
            region=provider_region,
            project_id=project_id or None,
            resource_type="workloadidentityprovider",
            status=provider_status or None,
            source="workload_identity_providers",
            resourcedata=provider_resourcedata or None,
        )

        pool_row = pool_rows_by_name.get(pool_name, {})
        pool_project_id = str(pool_row.get("project_id") or "").strip() or project_id
        pool_node_id = resource_node_id(pool_name)
        pool_label = str(pool_row.get("pool_id") or "").strip() or resource_leaf_name(pool_name) or pool_name
        pool_region = (
            str(pool_row.get("region_val") or pool_row.get("region") or pool_row.get("location") or "").strip()
            or resource_location_token(pool_name)
        )
        pool_status = str(pool_row.get("status") or pool_row.get("state") or "").strip().upper()
        pool_resourcedata = _row_resourcedata_payload(dict(pool_row), skip_keys={"workspace_id"})
        context.builder.add_node(
            pool_node_id,
            gcp_resource_node_type("workloadidentitypool"),
            name=pool_label,
            display_name=pool_label,
            resource_name=pool_name,
            region=pool_region,
            project_id=pool_project_id or None,
            resource_type="workloadidentitypool",
            status=pool_status or None,
            source="workload_identity_pools" if pool_row else "workload_identity_providers",
            resourcedata=pool_resourcedata or None,
        )

        edge_key = (provider_node_id, "WIF_PROVIDER_IN_POOL", pool_node_id)
        if edge_key in context.builder.edge_map:
            continue
        context.builder.add_edge(
            provider_node_id,
            pool_node_id,
            "WIF_PROVIDER_IN_POOL",
            source="resource_expansion",
            project_id=pool_project_id or project_id or None,
            provider_name=provider_name,
            provider_id=str(row.get("provider_id") or "").strip() or None,
            pool_name=pool_name,
            pool_id=str(pool_row.get("pool_id") or row.get("pool_id") or "").strip() or None,
        )
        edges_added += 1
    return edges_added

def _wif_pool_resource_name(project_number: str, location: str, pool_id: str) -> str:
    return (
        f"projects/{str(project_number or '').strip()}/locations/{str(location or '').strip()}"
        f"/workloadIdentityPools/{str(pool_id or '').strip()}"
    )


def _is_gke_wif_pool_id(pool_id: str) -> bool:
    return str(pool_id or "").strip().lower().endswith(".svc.id.goog")


def _parse_gke_cluster_selector(selector_value: str) -> dict[str, str]:
    token = str(selector_value or "").strip()
    if not token:
        return {}
    match = _WIF_GKE_CLUSTER_SELECTOR_RE.match(token)
    if not match:
        return {"cluster_uri": token}
    cluster_project_id, cluster_location, cluster_name = match.groups()
    return {
        "cluster_uri": token,
        "cluster_project_id": cluster_project_id,
        "cluster_location": cluster_location,
        "cluster_name": cluster_name,
    }


def _wif_base_principal_payload(
    *,
    scheme: str,
    project_number: str,
    location: str,
    pool_id: str,
) -> dict[str, Any]:
    return {
        "scheme": scheme,
        "project_number": project_number,
        "location": location,
        "pool_id": pool_id,
        "pool_name": _wif_pool_resource_name(project_number, location, pool_id),
    }


def _wif_selector_payload(
    *,
    scheme: str,
    project_number: str,
    location: str,
    pool_id: str,
    kind: str,
    selector: str,
    selector_value: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = _wif_base_principal_payload(
        scheme=scheme,
        project_number=project_number,
        location=location,
        pool_id=pool_id,
    )
    payload.update(
        {
            "kind": kind,
            "selector": selector,
            "selector_value": selector_value,
        }
    )
    if isinstance(extra, dict) and extra:
        payload.update(extra)
    return payload


def _build_wif_gke_cluster_selector_payload(
    project_number: str,
    location: str,
    pool_id: str,
    cluster_selector: str,
) -> dict[str, Any]:
    cluster_info = _parse_gke_cluster_selector(cluster_selector)
    return _wif_selector_payload(
        scheme="principalSet",
        project_number=project_number,
        location=location,
        pool_id=pool_id,
        kind="gke_cluster",
        selector="kubernetes.cluster",
        selector_value=cluster_selector,
        extra={
            "gke_selector_type": "cluster",
            "gke_cluster_uri": cluster_info.get("cluster_uri"),
            "gke_cluster_project_id": cluster_info.get("cluster_project_id"),
            "gke_cluster_location": cluster_info.get("cluster_location"),
            "gke_cluster_name": cluster_info.get("cluster_name"),
        },
    )


def _build_wif_pool_selector_payload(project_number: str, location: str, pool_id: str) -> dict[str, Any]:
    return _wif_selector_payload(
        scheme="principalSet",
        project_number=project_number,
        location=location,
        pool_id=pool_id,
        kind="pool",
        selector="pool",
        selector_value="*",
    )


def _build_wif_gke_uid_selector_payload(
    project_number: str,
    location: str,
    pool_id: str,
    service_account_uid: str,
) -> dict[str, Any]:
    return _wif_selector_payload(
        scheme="principal",
        project_number=project_number,
        location=location,
        pool_id=pool_id,
        kind="gke_service_account_uid",
        selector="kubernetes.serviceaccount.uid",
        selector_value=service_account_uid,
        extra={
            "gke_service_account_uid": service_account_uid,
            "gke_selector_type": "serviceaccount_uid",
        },
    )


def _build_wif_gke_namespace_selector_payload(
    project_number: str,
    location: str,
    pool_id: str,
    namespace: str,
) -> dict[str, Any]:
    return _wif_selector_payload(
        scheme="principalSet",
        project_number=project_number,
        location=location,
        pool_id=pool_id,
        kind="gke_namespace",
        selector="kubernetes.namespace",
        selector_value=namespace,
        extra={
            "gke_namespace": namespace,
            "gke_selector_type": "namespace",
        },
    )


def _build_wif_group_selector_payload(
    project_number: str,
    location: str,
    pool_id: str,
    group: str,
) -> dict[str, Any]:
    return _wif_selector_payload(
        scheme="principalSet",
        project_number=project_number,
        location=location,
        pool_id=pool_id,
        kind="group",
        selector="group",
        selector_value=group,
        extra={"group": group},
    )


def _build_wif_attribute_selector_payload(
    project_number: str,
    location: str,
    pool_id: str,
    attribute_name: str,
    attribute_value: str,
) -> dict[str, Any]:
    return _wif_selector_payload(
        scheme="principalSet",
        project_number=project_number,
        location=location,
        pool_id=pool_id,
        kind="attribute",
        selector=f"attribute.{attribute_name}",
        selector_value=attribute_value,
        extra={
            "attribute_name": attribute_name,
            "attribute_value": attribute_value,
        },
    )


_WIF_SELECTOR_PAYLOAD_SPECS: tuple[tuple[re.Pattern[str], Any], ...] = (
    (_WIF_POOL_PRINCIPAL_SET_RE, _build_wif_pool_selector_payload),
    (_WIF_GKE_SERVICE_ACCOUNT_UID_PRINCIPAL_RE, _build_wif_gke_uid_selector_payload),
    (_WIF_GKE_NAMESPACE_PRINCIPAL_SET_RE, _build_wif_gke_namespace_selector_payload),
    (_WIF_GKE_CLUSTER_PRINCIPAL_SET_RE, _build_wif_gke_cluster_selector_payload),
    (_WIF_GROUP_PRINCIPAL_SET_RE, _build_wif_group_selector_payload),
    (_WIF_ATTRIBUTE_PRINCIPAL_SET_RE, _build_wif_attribute_selector_payload),
)


def _parse_wif_workload_principal(member: str) -> dict[str, Any] | None:
    token = str(member or "").strip()
    if not token:
        return None

    subject_match = _WIF_SUBJECT_PRINCIPAL_RE.match(token)
    if subject_match:
        project_number, location, pool_id, subject = subject_match.groups()
        parsed_subject: dict[str, Any] = _wif_selector_payload(
            scheme="principal",
            project_number=project_number,
            location=location,
            pool_id=pool_id,
            kind="subject",
            selector="subject",
            selector_value=subject,
            extra={"subject": subject},
        )
        if _is_gke_wif_pool_id(pool_id):
            gke_subject_match = _WIF_GKE_SUBJECT_SELECTOR_RE.match(subject)
            if gke_subject_match:
                namespace, service_account = gke_subject_match.groups()
                parsed_subject.update(
                    {
                        "kind": "gke_service_account_name",
                        "selector": "kubernetes.serviceaccount.name",
                        "selector_value": f"{namespace}/{service_account}",
                        "gke_namespace": namespace,
                        "gke_service_account": service_account,
                        "gke_selector_type": "serviceaccount_name",
                    }
                )
        return parsed_subject

    for pattern, builder in _WIF_SELECTOR_PAYLOAD_SPECS:
        match = pattern.match(token)
        if match:
            groups = match.groups()
            return builder(*groups)

    legacy_gke_match = _WIF_GKE_LEGACY_SERVICE_ACCOUNT_RE.match(token)
    if legacy_gke_match:
        project_id, namespace, service_account = legacy_gke_match.groups()
        pool_id = f"{project_id}.svc.id.goog"
        return {
            "scheme": "serviceAccountLegacy",
            "project_number": "",
            "location": "global",
            "pool_id": pool_id,
            "kind": "gke_service_account_name",
            "selector": "kubernetes.serviceaccount.name",
            "selector_value": f"{namespace}/{service_account}",
            "subject": f"ns/{namespace}/sa/{service_account}",
            "gke_project_id": project_id,
            "gke_namespace": namespace,
            "gke_service_account": service_account,
            "gke_selector_type": "serviceaccount_name",
            "pool_name": "",
        }

    return None


def _classify_wif_provider_source_kind(provider_row: dict[str, Any]) -> str:
    if not isinstance(provider_row, dict):
        return "unknown"

    if isinstance(provider_row.get("aws"), dict):
        return "aws"
    if isinstance(provider_row.get("saml"), dict):
        return "saml"

    oidc = provider_row.get("oidc")
    issuer_uri = ""
    if isinstance(oidc, dict):
        issuer_uri = str(oidc.get("issuerUri") or oidc.get("issuer_uri") or "").strip().lower()

    if issuer_uri:
        if "token.actions.githubusercontent.com" in issuer_uri:
            return "github"
        if "gitlab" in issuer_uri:
            return "gitlab"
        if "app.terraform.io" in issuer_uri:
            return "terraform"
        if "sts.windows.net" in issuer_uri or "login.microsoftonline.com" in issuer_uri:
            return "azure"
        return "oidc"

    if isinstance(oidc, dict):
        return "oidc"
    return "unknown"


def _provider_attribute_mapping(provider_row: dict[str, Any]) -> dict[str, str]:
    if not isinstance(provider_row, dict):
        return {}
    raw_mapping = parse_json_value(
        provider_row.get("attributeMapping")
        or provider_row.get("attribute_mapping"),
        default=None,
    )
    if not isinstance(raw_mapping, dict):
        return {}
    output: dict[str, str] = {}
    for raw_key, raw_value in raw_mapping.items():
        key = str(raw_key or "").strip()
        value = str(raw_value or "").strip()
        if key and value:
            output[key] = value
    return output


def _wif_selector_support_for_pool(
    *,
    parsed_principal: dict[str, Any],
    provider_rows: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    kind = str(parsed_principal.get("kind") or "").strip().lower()
    attribute_name = str(parsed_principal.get("attribute_name") or "").strip()
    pool_id = str(parsed_principal.get("pool_id") or "").strip()
    is_gke_pool = _is_gke_wif_pool_id(pool_id)
    provider_list = [dict(row) for row in (provider_rows or []) if isinstance(row, dict)]
    gke_selector_kinds = {
        "gke_service_account_name",
        "gke_service_account_uid",
        "gke_namespace",
        "gke_cluster",
    }

    if is_gke_pool and kind in gke_selector_kinds:
        return {
            "supported": True,
            "status": "supported",
            "support_reason": "gke_managed_pool_selector",
            "matching_provider_names": [],
        }

    if kind == "pool":
        return {
            "supported": True,
            "status": "supported",
            "support_reason": "pool_wide_selector",
            "matching_provider_names": [],
        }

    if not provider_list:
        return {
            "supported": False,
            "status": "unsupported",
            "support_reason": "no_providers_discovered_in_pool",
            "matching_provider_names": [],
        }

    required_mapping = ""
    if kind == "subject":
        required_mapping = "google.subject"
    elif kind == "group":
        required_mapping = "google.groups"
    elif kind == "attribute" and attribute_name:
        required_mapping = f"attribute.{attribute_name}"

    if not required_mapping:
        return {
            "supported": False,
            "status": "unsupported",
            "support_reason": "unsupported_selector_kind",
            "matching_provider_names": [],
        }

    matching_provider_names: list[str] = []
    for provider_row in provider_list:
        mapping = _provider_attribute_mapping(provider_row)
        if required_mapping not in mapping:
            continue
        provider_name = str(provider_row.get("name") or "").strip()
        if provider_name:
            matching_provider_names.append(provider_name)

    if matching_provider_names:
        return {
            "supported": True,
            "status": "supported",
            "support_reason": f"mapped_by_{required_mapping}",
            "matching_provider_names": sorted(set(matching_provider_names)),
        }

    return {
        "supported": False,
        "status": "unsupported",
        "support_reason": f"missing_provider_mapping:{required_mapping}",
        "matching_provider_names": [],
    }


def _no_condition_external_source_display(source_kind: str) -> str:
    return {
        "github": "GitHubNoCondition",
        "gitlab": "GitLabNoCondition",
        "terraform": "TerraformNoCondition",
        "aws": "AWSNoCondition",
        "azure": "AzureNoCondition",
        "saml": "SAMLNoCondition",
        "oidc": "OIDCNoCondition",
        "unknown": "ProviderNoCondition",
    }.get(str(source_kind or "").strip().lower(), "ProviderNoCondition")


def _add_wif_principal_pool_edges(
    context,
    *,
    workload_identity_pools_rows: Iterable[dict[str, Any]] | None,
    workload_identity_providers_rows: Iterable[dict[str, Any]] | None,
) -> int:
    """
    Add workload identity pool membership/context edges for WIF principal members seen in IAM bindings:
      principal://... or principalSet://... -> WIF_PRINCIPAL_IN_POOL -> workload identity pool
    """
    edges_added = 0
    simplified_base = context.simplified_hierarchy_permissions(include_inferred_permissions=False)
    member_binding_index = dict(simplified_base.get("member_binding_index") or {})
    member_tokens = {
        str(member or "").strip()
        for member in member_binding_index.keys()
        if str(member or "").strip()
    }
    pool_rows_by_name = {
        str(row.get("name") or "").strip(): dict(row)
        for row in workload_identity_pools_rows or []
        if str(row.get("name") or "").strip()
    }
    provider_rows_by_pool_name: dict[str, list[dict[str, Any]]] = {}
    for row in workload_identity_providers_rows or []:
        pool_name = str(row.get("pool_name") or "").strip()
        if not pool_name:
            continue
        provider_rows_by_pool_name.setdefault(pool_name, []).append(dict(row))

    for member_token in sorted(member_tokens):
        parsed = _parse_wif_workload_principal(member_token)
        if not parsed:
            continue
        principal_id = principal_node_id(member_token)
        if not principal_id:
            continue

        context.builder.add_node(
            principal_id,
            principal_type(member_token),
            **principal_member_properties(member_token),
            source="resource_expansion",
            wif_member=True,
            wif_scheme=str(parsed.get("scheme") or ""),
            wif_project_number=str(parsed.get("project_number") or ""),
            wif_location=str(parsed.get("location") or ""),
            wif_pool_id=str(parsed.get("pool_id") or ""),
            wif_pool_name=str(parsed.get("pool_name") or ""),
            wif_principal_kind=str(parsed.get("kind") or ""),
            wif_selector=str(parsed.get("selector") or ""),
            wif_selector_value=str(parsed.get("selector_value") or ""),
            wif_subject=str(parsed.get("subject") or "") or None,
            wif_group=str(parsed.get("group") or "") or None,
            wif_attribute_name=str(parsed.get("attribute_name") or "") or None,
            wif_attribute_value=str(parsed.get("attribute_value") or "") or None,
            wif_gke_selector_type=str(parsed.get("gke_selector_type") or "") or None,
            wif_gke_project_id=str(parsed.get("gke_project_id") or "") or None,
            wif_gke_namespace=str(parsed.get("gke_namespace") or "") or None,
            wif_gke_service_account=str(parsed.get("gke_service_account") or "") or None,
            wif_gke_service_account_uid=str(parsed.get("gke_service_account_uid") or "") or None,
            wif_gke_cluster_uri=str(parsed.get("gke_cluster_uri") or "") or None,
            wif_gke_cluster_project_id=str(parsed.get("gke_cluster_project_id") or "") or None,
            wif_gke_cluster_location=str(parsed.get("gke_cluster_location") or "") or None,
            wif_gke_cluster_name=str(parsed.get("gke_cluster_name") or "") or None,
        )

        pool_name = str(parsed.get("pool_name") or "").strip()
        if not pool_name:
            pool_id = str(parsed.get("pool_id") or "").strip()
            if pool_id:
                gke_project_id = str(parsed.get("gke_project_id") or "").strip()
                for row in workload_identity_pools_rows or []:
                    row_pool_id = str(row.get("pool_id") or "").strip()
                    row_project_id = str(row.get("project_id") or "").strip()
                    row_name = str(row.get("name") or "").strip()
                    if not row_name or row_pool_id != pool_id:
                        continue
                    if gke_project_id and row_project_id and row_project_id != gke_project_id:
                        continue
                    pool_name = row_name
                    parsed["pool_name"] = row_name
                    parsed["project_number"] = str(parsed.get("project_number") or "").strip() or str(
                        extract_path_segment(row_name, "projects")
                    ).strip()
                    break

        selector_support = _wif_selector_support_for_pool(
            parsed_principal=parsed,
            provider_rows=provider_rows_by_pool_name.get(pool_name, []) if pool_name else [],
        )

        if not pool_name:
            continue

        context.builder.add_node(
            principal_id,
            principal_type(member_token),
            wif_selector_supported=bool(selector_support.get("supported")),
            wif_selector_support_status=str(selector_support.get("status") or ""),
            wif_selector_support_reason=str(selector_support.get("support_reason") or ""),
            wif_supporting_provider_names=list(selector_support.get("matching_provider_names") or []),
        )
        pool_row = pool_rows_by_name.get(pool_name, {})
        pool_node_id = resource_node_id(pool_name)
        pool_label = str(pool_row.get("pool_id") or parsed.get("pool_id") or "").strip() or resource_leaf_name(pool_name) or pool_name
        pool_project_id = str(pool_row.get("project_id") or "").strip() or None
        pool_region = (
            str(pool_row.get("region_val") or pool_row.get("region") or pool_row.get("location") or "").strip()
            or resource_location_token(pool_name)
        )
        pool_status = str(pool_row.get("status") or pool_row.get("state") or "").strip().upper()
        pool_resourcedata = _row_resourcedata_payload(dict(pool_row), skip_keys={"workspace_id"})
        context.builder.add_node(
            pool_node_id,
            gcp_resource_node_type("workloadidentitypool"),
            name=pool_label,
            display_name=pool_label,
            resource_name=pool_name,
            region=pool_region,
            project_id=pool_project_id,
            resource_type="workloadidentitypool",
            status=pool_status or None,
            source="workload_identity_pools" if pool_row else "resource_expansion",
            project_number=str(parsed.get("project_number") or "") or None,
            resourcedata=pool_resourcedata or None,
        )

        edge_key = (principal_id, "WIF_PRINCIPAL_IN_POOL", pool_node_id)
        if edge_key in context.builder.edge_map:
            continue
        context.builder.add_edge(
            principal_id,
            pool_node_id,
            "WIF_PRINCIPAL_IN_POOL",
            source="resource_expansion",
            wif_scheme=str(parsed.get("scheme") or ""),
            wif_project_number=str(parsed.get("project_number") or ""),
            wif_location=str(parsed.get("location") or ""),
            wif_pool_id=str(parsed.get("pool_id") or ""),
            wif_principal_kind=str(parsed.get("kind") or ""),
            wif_selector=str(parsed.get("selector") or ""),
            wif_selector_value=str(parsed.get("selector_value") or ""),
            wif_selector_supported=bool(selector_support.get("supported")),
            wif_selector_support_status=str(selector_support.get("status") or ""),
            wif_selector_support_reason=str(selector_support.get("support_reason") or ""),
            wif_supporting_provider_names=list(selector_support.get("matching_provider_names") or []),
        )
        edges_added += 1

    return edges_added


def _enrich_wif_provider_nodes(
    context,
    *,
    workload_identity_providers_rows: Iterable[dict[str, Any]] | None,
) -> int:
    """
    Enrich workload identity provider nodes with provider metadata and emit
    anonymous external-source nodes for providers that have no attribute condition.
    """
    edges_added = 0
    for row in workload_identity_providers_rows or []:
        provider_name = str(row.get("name") or "").strip()
        if not provider_name:
            continue
        provider_node_id = resource_node_id(provider_name)
        raw_payload = parse_json_value(row.get("raw_json"), default=None)
        provider_payload = dict(raw_payload) if isinstance(raw_payload, dict) else dict(row)

        attribute_condition = str(
            provider_payload.get("attributeCondition")
            or provider_payload.get("attribute_condition")
            or row.get("attributeCondition")
            or row.get("attribute_condition")
            or ""
        ).strip()
        attribute_mapping = parse_json_value(
            provider_payload.get("attributeMapping")
            or provider_payload.get("attribute_mapping")
            or row.get("attributeMapping")
            or row.get("attribute_mapping"),
            default=None,
        )
        oidc_payload = provider_payload.get("oidc")
        aws_payload = provider_payload.get("aws")
        saml_payload = provider_payload.get("saml")
        issuer_uri = ""
        allowed_audiences = None
        aws_account_id = None
        if isinstance(oidc_payload, dict):
            issuer_uri = str(oidc_payload.get("issuerUri") or oidc_payload.get("issuer_uri") or "").strip()
            audiences = oidc_payload.get("allowedAudiences") or oidc_payload.get("allowed_audiences")
            if isinstance(audiences, list):
                allowed_audiences = list(audiences)
        if isinstance(aws_payload, dict):
            aws_account_id = str(aws_payload.get("accountId") or aws_payload.get("account_id") or "").strip() or None

        provider_source_kind = _classify_wif_provider_source_kind(provider_payload)
        has_attribute_condition = bool(attribute_condition)
        context.builder.add_node(
            provider_node_id,
            gcp_resource_node_type("workloadidentityprovider"),
            provider_source_kind=provider_source_kind,
            provider_type=(
                "aws"
                if isinstance(aws_payload, dict)
                else "saml"
                if isinstance(saml_payload, dict)
                else "oidc"
                if isinstance(oidc_payload, dict)
                else "unknown"
            ),
            issuer_uri=issuer_uri or None,
            allowed_audiences=allowed_audiences,
            aws_account_id=aws_account_id,
            attribute_condition=attribute_condition or None,
            has_attribute_condition=has_attribute_condition,
            attribute_mapping=attribute_mapping if isinstance(attribute_mapping, dict) else None,
            conditionals_added=has_attribute_condition,
        )

        if has_attribute_condition:
            continue

        external_display = _no_condition_external_source_display(provider_source_kind)
        external_node_id = f"external_identity_source:{external_display}@{provider_name}"
        context.builder.add_node(
            external_node_id,
            "GCPExternalIdentitySource",
            name=external_display,
            display_name=external_display,
            source="resource_expansion",
            provider_name=provider_name,
            provider_source_kind=provider_source_kind,
            issuer_uri=issuer_uri or None,
            conditionals_added=False,
        )

        edge_key = (external_node_id, "GCP_FEDERATION_POSSIBLE", provider_node_id)
        if edge_key in context.builder.edge_map:
            continue
        context.builder.add_edge(
            external_node_id,
            provider_node_id,
            "GCP_FEDERATION_POSSIBLE",
            source="resource_expansion",
            provider_name=provider_name,
            provider_source_kind=provider_source_kind,
            issuer_uri=issuer_uri or None,
            conditionals_added=False,
        )
        edges_added += 1

    return edges_added


def _section_seed_service_account_principals(
    context,
    *,
    iam_service_accounts_rows: Iterable[dict[str, Any]] | None,
) -> int:
    nodes_added = 0
    row_list = [row for row in (iam_service_accounts_rows or []) if isinstance(row, dict)]
    total_rows = len(row_list)
    for index, row in enumerate(row_list, start=1):
        principal_type_token = str(row.get("type") or "").strip().lower()
        if "service" not in principal_type_token:
            _print_inline_progress("Stage 4 service accounts processed", index, total_rows)
            continue
        email = str(row.get("email") or "").strip()
        if not email:
            _print_inline_progress("Stage 4 service accounts processed", index, total_rows)
            continue
        member = f"serviceAccount:{email}"
        node_id = principal_node_id(member)
        existed = node_id in context.builder.node_map
        props = dict(principal_member_properties(member))
        row_name = str(row.get("name") or "").strip()
        row_display_name = str(row.get("display_name") or "").strip()
        if row_name:
            props["name"] = row_name
        if row_display_name:
            props["display_name"] = row_display_name
        context.builder.add_node(
            node_id,
            principal_type(member),
            **props,
            source="iam_service_accounts",
        )
        if not existed:
            nodes_added += 1
        _print_inline_progress("Stage 4 service accounts processed", index, total_rows)
    _print_inline_progress("Stage 4 service accounts processed", total_rows, total_rows, force=True)
    return nodes_added


def _section_expand_service_account_keys(
    context,
    *,
    iam_sa_keys_rows: Iterable[dict[str, Any]] | None,
) -> tuple[int, int]:
    key_nodes_added = 0
    key_edges_added = 0
    row_list = [row for row in (iam_sa_keys_rows or []) if isinstance(row, dict)]
    total_rows = len(row_list)
    for index, row in enumerate(row_list, start=1):
        key_name = str(row.get("name") or "").strip()
        if not key_name:
            _print_inline_progress("Stage 4 service account keys processed", index, total_rows)
            continue
        service_account_email = extract_path_segment(key_name, "serviceAccounts")
        key_id = extract_path_segment(key_name, "keys")
        if not service_account_email or not key_id:
            _print_inline_progress("Stage 4 service account keys processed", index, total_rows)
            continue

        key_node_id = f"service_account_key:{key_name}"
        key_existed = key_node_id in context.builder.node_map
        context.builder.add_node(
            key_node_id,
            "GCPServiceAccountKey",
            name=key_id,
            display_name=key_id,
            resource_name=key_name,
            key_id=key_id,
            service_account_email=service_account_email,
            disabled=row.get("disabled"),
            key_type=row.get("key_type"),
            key_origin=row.get("key_origin"),
            valid_after_time=row.get("valid_after_time"),
            valid_before_time=row.get("valid_before_time"),
            source="iam_sa_keys",
        )
        if not key_existed:
            key_nodes_added += 1

        service_account_member = f"serviceAccount:{service_account_email}"
        service_account_id = principal_node_id(service_account_member)
        sa_props = principal_member_properties(service_account_member)
        context.builder.add_node(
            service_account_id,
            principal_type(service_account_member),
            **sa_props,
            source="iam_sa_keys",
        )

        edge_key = (key_node_id, "GCP_SERVICE_ACCOUNT_KEY_FOR", service_account_id)
        edge_existed = edge_key in context.builder.edge_map
        context.builder.add_edge(
            key_node_id,
            service_account_id,
            "GCP_SERVICE_ACCOUNT_KEY_FOR",
            source="iam_sa_keys",
            key_name=key_name,
            key_id=key_id,
            service_account_email=service_account_email,
        )
        if not edge_existed:
            key_edges_added += 1
        _print_inline_progress("Stage 4 service account keys processed", index, total_rows)
    _print_inline_progress("Stage 4 service account keys processed", total_rows, total_rows, force=True)
    return key_nodes_added, key_edges_added


def _section_expand_project_resource_topology(
    context,
    *,
    scope_resource_indexes,
    cloudcompute_instances_rows: Iterable[dict[str, Any]] | None,
    cloudfunctions_functions_rows: Iterable[dict[str, Any]] | None,
    cloudrun_services_rows: Iterable[dict[str, Any]] | None,
    cloudrun_jobs_rows: Iterable[dict[str, Any]] | None,
    workload_identity_pools_rows: Iterable[dict[str, Any]] | None,
    workload_identity_providers_rows: Iterable[dict[str, Any]] | None,
) -> int:
    project_resource_candidates = _collect_project_resource_candidates(
        indexes=scope_resource_indexes,
        cloudcompute_instances_rows=cloudcompute_instances_rows,
        cloudfunctions_functions_rows=cloudfunctions_functions_rows,
        cloudrun_services_rows=cloudrun_services_rows,
        cloudrun_jobs_rows=cloudrun_jobs_rows,
        workload_identity_pools_rows=workload_identity_pools_rows,
        workload_identity_providers_rows=workload_identity_providers_rows,
    )
    candidate_resource_names = {
        str(candidate.get("resource_name") or "").strip()
        for candidate in project_resource_candidates
        if str(candidate.get("resource_name") or "").strip()
    }
    candidate_project_by_name = {
        str(candidate.get("resource_name") or "").strip(): str(candidate.get("project_id") or "").strip()
        for candidate in project_resource_candidates
        if str(candidate.get("resource_name") or "").strip()
    }
    resource_enrichment_by_name = _resource_enrichment_payloads_by_name(
        context,
        target_resource_names=candidate_resource_names,
        candidate_project_by_name=candidate_project_by_name,
    )
    return _add_project_resource_membership_edges(
        context,
        candidates=project_resource_candidates,
        indexes=scope_resource_indexes,
        resource_enrichment_by_name=resource_enrichment_by_name,
    )


def build_resource_expansion_graph(context) -> dict[str, int | bool]:
    """
    Expand graph with additional derived resource nodes.

    Current pass:
    - GCPServiceAccount nodes from `iam_service_accounts`
    - GCPServiceAccountKey nodes from `iam_sa_keys`
    - key -> service account relationship edges
    - project -> resource topology edges (EXISTS_IN_PROJECT)
    - compute instance -> attached service account edges (EXECUTES_WITH)
    """

    before_nodes, before_edges = context.counts()
    source_rows: dict[str, Any] = {
        table_name: context.rows(table_name) for table_name in _RESOURCE_EXPANSION_ROW_TABLES
    }
    scope_resource_indexes = context.scope_resource_indexes()

    iam_service_accounts_rows = source_rows["iam_service_accounts"]
    iam_sa_keys_rows = source_rows["iam_sa_keys"]
    cloudcompute_instances_rows = source_rows["cloudcompute_instances"]
    cloudfunctions_functions_rows = source_rows["cloudfunctions_functions"]
    cloudrun_services_rows = source_rows["cloudrun_services"]
    cloudrun_jobs_rows = source_rows["cloudrun_jobs"]
    workload_identity_pools_rows = source_rows["workload_identity_pools"]
    workload_identity_providers_rows = source_rows["workload_identity_providers"]
    print(
        "[*] Stage 4 tally: "
        f"iam_service_accounts={len(iam_service_accounts_rows or [])}, "
        f"iam_sa_keys={len(iam_sa_keys_rows or [])}, "
        f"cloudcompute_instances={len(cloudcompute_instances_rows or [])}, "
        f"cloudfunctions_functions={len(cloudfunctions_functions_rows or [])}, "
        f"cloudrun_services={len(cloudrun_services_rows or [])}, "
        f"cloudrun_jobs={len(cloudrun_jobs_rows or [])}, "
        f"workload_identity_pools={len(workload_identity_pools_rows or [])}, "
        f"workload_identity_providers={len(workload_identity_providers_rows or [])}"
    )
    total_sections = 3
    processed_sections = 0
    _print_stage4_section_progress(
        processed_sections=processed_sections,
        total_sections=total_sections,
        section_label="starting",
    )

    section_stats: dict[str, int] = {}

    # ---------------------------------------------------------------------
    # SECTION 10: Base expansion (project -> resource topology)
    # ---------------------------------------------------------------------
    section_stats["project_resource_edges_added"] = _section_expand_project_resource_topology(
        context,
        scope_resource_indexes=scope_resource_indexes,
        cloudcompute_instances_rows=cloudcompute_instances_rows,
        cloudfunctions_functions_rows=cloudfunctions_functions_rows,
        cloudrun_services_rows=cloudrun_services_rows,
        cloudrun_jobs_rows=cloudrun_jobs_rows,
        workload_identity_pools_rows=workload_identity_pools_rows,
        workload_identity_providers_rows=workload_identity_providers_rows,
    )
    processed_sections += 1
    _print_stage4_section_progress(
        processed_sections=processed_sections,
        total_sections=total_sections,
        section_label="project/resource topology complete",
    )

    # ---------------------------------------------------------------------
    # SECTION 20: Identity workflows (WIF pools/providers/principals)
    # ---------------------------------------------------------------------
    section_stats["wif_provider_pool_edges_added"] = _add_wif_provider_pool_edges(
        context,
        workload_identity_pools_rows=workload_identity_pools_rows,
        workload_identity_providers_rows=workload_identity_providers_rows,
    )
    section_stats["wif_principal_pool_edges_added"] = _add_wif_principal_pool_edges(
        context,
        workload_identity_pools_rows=workload_identity_pools_rows,
        workload_identity_providers_rows=workload_identity_providers_rows,
    )
    section_stats["wif_provider_external_edges_added"] = _enrich_wif_provider_nodes(
        context,
        workload_identity_providers_rows=workload_identity_providers_rows,
    )
    processed_sections += 1
    _print_stage4_section_progress(
        processed_sections=processed_sections,
        total_sections=total_sections,
        section_label="wif identity workflows complete",
    )

    # ---------------------------------------------------------------------
    # SECTION 30: Attached service accounts (SA principals/keys/runtime attach)
    # ---------------------------------------------------------------------
    section_stats["service_account_nodes_added"] = _section_seed_service_account_principals(
        context,
        iam_service_accounts_rows=iam_service_accounts_rows,
    )
    key_nodes_added, key_edges_added = _section_expand_service_account_keys(
        context,
        iam_sa_keys_rows=iam_sa_keys_rows,
    )
    section_stats["service_account_key_nodes_added"] = key_nodes_added
    section_stats["service_account_key_edges_added"] = key_edges_added
    section_stats["compute_executes_with_edges_added"] = _add_compute_executes_with_edges(
        context,
        cloudcompute_instances_rows=cloudcompute_instances_rows,
    )
    processed_sections += 1
    _print_stage4_section_progress(
        processed_sections=processed_sections,
        total_sections=total_sections,
        section_label="service accounts/keys/runtime complete",
        force=True,
    )

    after_nodes, after_edges = context.counts()
    payload = {key: int(section_stats.get(key, 0)) for key in _RESOURCE_EXPANSION_STAGE_STAT_KEYS}
    payload.update(
        {
            "nodes_added": max(0, after_nodes - before_nodes),
            "edges_added": max(0, after_edges - before_edges),
            "total_nodes": after_nodes,
            "total_edges": after_edges,
        }
    )
    return payload
