from __future__ import annotations

"""
OpenGraph pipeline orchestrator.

Reader map:
1) Parse CLI/runtime options.
2) Choose stages and run in fixed order.
3) Apply end-of-pipeline trim pass (default mode).
4) Persist OpenGraph rows and export JSON snapshot.

Stage map:
- 1: principal + membership topology
- 2: IAM policy-binding prep + dangerous-edge emit
- 3: inferred-permission paths
- 4: resource/identity expansion
- 5: final trim
"""

import argparse
import json
import time
from pathlib import Path
from typing import Any, TypedDict

from gcpwn.core.console import UtilityTools
from gcpwn.modules.opengraph.utilities.stage_2_policy_bindings import (
    build_resolved_binding_entries,
)
from gcpwn.modules.opengraph.utilities.stage_3_inferred_permissions import (
    build_iam_inferred_permissions_graph,
)
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import build_resource_expansion_graph
from gcpwn.modules.opengraph.utilities.stage_5_allowlist_trim import apply_final_allowlist_trims
from gcpwn.modules.opengraph.utilities.helpers.graph.context import OpenGraphBuildContext, OpenGraphBuildOptions
from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    OpenGraphEdge,
    OpenGraphNode,
    edge_to_opengraph,
    node_to_opengraph,
    persist_opengraph,
)

class _StageSpec(TypedDict):
    id: str
    key: str
    title: str


_STAGE_REGISTRY: tuple[_StageSpec, ...] = (
    {
        "id": "1",
        "key": "users_groups",
        "title": "Users/Groups graph",
    },
    {
        "id": "2",
        "key": "iam_bindings",
        "title": "IAM policy bindings graph",
    },
    {
        "id": "3",
        "key": "inferred_permissions",
        "title": "Inferred permissions graph",
    },
    {
        "id": "4",
        "key": "resource_expansion",
        "title": "Resource expansion graph",
    },
)

_SPLIT_SECTION_KEYS: tuple[str, ...] = (
    "users_groups",
    "iam_bindings",
    "inferred_permissions",
    "resource_expansion",
)
_SPLIT_SECTION_ALIASES: dict[str, str] = {
    "users_groups": "users_groups",
    "users-groups": "users_groups",
    "users/groups": "users_groups",
    "usersgroups": "users_groups",
    "groups": "users_groups",
    "iam_bindings": "iam_bindings",
    "iam-bindings": "iam_bindings",
    "iam_policies": "iam_bindings",
    "iam-policies": "iam_bindings",
    "iampolicies": "iam_bindings",
    "inferred_permissions": "inferred_permissions",
    "inferred-permissions": "inferred_permissions",
    "inferredpermissions": "inferred_permissions",
    "resource_expansion": "resource_expansion",
    "resource-expansion": "resource_expansion",
    "resourceexpansion": "resource_expansion",
}
_USERS_GROUPS_SOURCE_HINTS: tuple[str, ...] = (
    "workspace_users",
    "workspace_groups",
    "workspace_group_memberships",
    "domain_wide_memberships",
    "iam_members",
    "stage_1_principals",
)
_RESOURCE_EXPANSION_SOURCE_HINTS: tuple[str, ...] = (
    "resource_expansion",
    "service_cache",
    "cloudcompute_instances",
    "workload_identity",
    "iam_sa_keys",
)
_PRINCIPAL_NODE_KINDS: set[str] = {
    "gcpallusers",
    "gcpallauthenticatedusers",
    "googleuser",
    "googlegroup",
    "gcpserviceaccount",
    "gcpdomainprincipal",
    "gcpconveniencemember",
    "gcpprincipal",
}


def _parse_split_sections(raw_value: str | None) -> list[str]:
    if raw_value is None or not str(raw_value).strip():
        return list(_SPLIT_SECTION_KEYS)

    selected: list[str] = []
    for token in str(raw_value).split(","):
        normalized = _SPLIT_SECTION_ALIASES.get(str(token or "").strip().lower())
        if not normalized:
            raise ValueError(
                f"Unsupported split section '{token}'. Supported values: "
                f"{', '.join(_SPLIT_SECTION_KEYS)}"
            )
        if normalized not in selected:
            selected.append(normalized)
    return selected or list(_SPLIT_SECTION_KEYS)


def _source_to_section(source_value: str) -> str | None:
    source = str(source_value or "").strip().lower()
    if not source:
        return None
    if source == "credential_permission_summary" or "inferred" in source:
        return "inferred_permissions"
    if source == "iam_allow_policies" or "iam_bindings" in source:
        return "iam_bindings"
    if source.startswith("workspace_") or source in _USERS_GROUPS_SOURCE_HINTS:
        return "users_groups"
    if any(hint in source for hint in _RESOURCE_EXPANSION_SOURCE_HINTS):
        return "resource_expansion"
    if source == "iam_service_accounts":
        return "users_groups"
    return None


def _edge_section(edge: dict[str, Any]) -> str:
    props = edge.get("properties")
    if isinstance(props, dict):
        source_section = _source_to_section(str(props.get("source") or ""))
        if source_section:
            return source_section

    kind = str(edge.get("kind") or "").strip().upper()
    if kind.startswith("INFERRED_"):
        return "inferred_permissions"
    if "BINDING" in kind:
        return "iam_bindings"
    return "resource_expansion"


def _node_section(node: dict[str, Any]) -> str:
    props = node.get("properties")
    if isinstance(props, dict):
        source_section = _source_to_section(str(props.get("source") or ""))
        if source_section:
            return source_section

    kind_tokens = {str(kind or "").strip().lower() for kind in (node.get("kinds") or []) if str(kind or "").strip()}
    if kind_tokens & _PRINCIPAL_NODE_KINDS:
        return "users_groups"
    if any("iambinding" in token for token in kind_tokens):
        return "iam_bindings"
    if any("key" in token or "workloadidentity" in token for token in kind_tokens):
        return "resource_expansion"
    return "resource_expansion"


def _build_graph_payload(*, metadata: dict[str, Any], nodes: list[dict[str, Any]], edges: list[dict[str, Any]], section: str | None = None) -> dict[str, Any]:
    metadata_payload = dict(metadata or {})
    if section:
        metadata_payload["split_section"] = section
    return {
        "metadata": metadata_payload,
        "graph": {
            "nodes": list(nodes or []),
            "edges": list(edges or []),
        },
        "summary": {
            "nodes": len(nodes or []),
            "edges": len(edges or []),
        },
    }


def _payload_size_bytes(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _write_split_outputs(
    *,
    base_output_path: str,
    payload: dict[str, Any],
    selected_sections: list[str],
    max_size_mb: float,
    debug: bool = False,
) -> tuple[list[str], str]:
    max_size_bytes = max(1, int(float(max_size_mb) * 1024 * 1024))
    metadata = dict(payload.get("metadata") or {})
    graph = dict(payload.get("graph") or {})
    all_nodes = [node for node in (graph.get("nodes") or []) if isinstance(node, dict)]
    all_edges = [edge for edge in (graph.get("edges") or []) if isinstance(edge, dict)]
    node_index = {
        str(node.get("id") or "").strip(): node
        for node in all_nodes
        if str(node.get("id") or "").strip()
    }

    section_edges: dict[str, list[dict[str, Any]]] = {key: [] for key in _SPLIT_SECTION_KEYS}
    section_node_ids: dict[str, set[str]] = {key: set() for key in _SPLIT_SECTION_KEYS}

    for node in all_nodes:
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            continue
        section_node_ids[_node_section(node)].add(node_id)

    for edge in all_edges:
        section_edges[_edge_section(edge)].append(edge)

    base_path = Path(base_output_path)
    output_dir = base_path.parent
    stem = base_path.stem
    written_files: list[str] = []
    manifest_sections: dict[str, Any] = {}
    section_chunk_payloads: dict[str, list[dict[str, Any]]] = {}

    for section in selected_sections:
        edges = list(section_edges.get(section) or [])
        seeded_node_ids = set(section_node_ids.get(section) or set())

        if not edges and not seeded_node_ids:
            continue

        referenced_node_ids: set[str] = set()
        for edge in edges:
            start = str((((edge.get("start") or {}) if isinstance(edge.get("start"), dict) else {}).get("value") or "")).strip()
            end = str((((edge.get("end") or {}) if isinstance(edge.get("end"), dict) else {}).get("value") or "")).strip()
            if start:
                referenced_node_ids.add(start)
            if end:
                referenced_node_ids.add(end)
        seeded_node_ids.update(referenced_node_ids)
        seeded_nodes = [
            node_index[node_id]
            for node_id in sorted(seeded_node_ids)
            if node_id in node_index
        ]

        chunks: list[dict[str, Any]] = []
        current_edges: list[dict[str, Any]] = []
        current_edge_node_ids: set[str] = set()

        def _flush_chunk(extra_nodes: list[dict[str, Any]] | None = None) -> None:
            edge_nodes = [
                node_index[node_id]
                for node_id in sorted(current_edge_node_ids)
                if node_id in node_index
            ]
            nodes_for_chunk = edge_nodes
            if extra_nodes:
                seen = {str(node.get("id") or "").strip() for node in edge_nodes}
                for node in extra_nodes:
                    node_id = str(node.get("id") or "").strip()
                    if not node_id or node_id in seen:
                        continue
                    seen.add(node_id)
                    nodes_for_chunk.append(node)
            chunk_payload = _build_graph_payload(
                metadata=metadata,
                nodes=nodes_for_chunk,
                edges=list(current_edges),
                section=section,
            )
            chunks.append(chunk_payload)

        for edge in edges:
            start = str((((edge.get("start") or {}) if isinstance(edge.get("start"), dict) else {}).get("value") or "")).strip()
            end = str((((edge.get("end") or {}) if isinstance(edge.get("end"), dict) else {}).get("value") or "")).strip()
            trial_edges = [*current_edges, edge]
            trial_edge_node_ids = set(current_edge_node_ids)
            if start:
                trial_edge_node_ids.add(start)
            if end:
                trial_edge_node_ids.add(end)
            trial_nodes = [
                node_index[node_id]
                for node_id in sorted(trial_edge_node_ids)
                if node_id in node_index
            ]
            trial_payload = _build_graph_payload(
                metadata=metadata,
                nodes=trial_nodes,
                edges=trial_edges,
                section=section,
            )
            if current_edges and _payload_size_bytes(trial_payload) > max_size_bytes:
                _flush_chunk()
                current_edges = []
                current_edge_node_ids = set()
                trial_edges = [edge]
                trial_edge_node_ids = set()
                if start:
                    trial_edge_node_ids.add(start)
                if end:
                    trial_edge_node_ids.add(end)

            current_edges = trial_edges
            current_edge_node_ids = trial_edge_node_ids

        standalone_nodes = [
            node
            for node in seeded_nodes
            if str(node.get("id") or "").strip() not in current_edge_node_ids
        ]

        if current_edges:
            _flush_chunk(extra_nodes=standalone_nodes)
        elif standalone_nodes:
            chunk_nodes: list[dict[str, Any]] = []
            for node in standalone_nodes:
                trial_nodes = [*chunk_nodes, node]
                trial_payload = _build_graph_payload(
                    metadata=metadata,
                    nodes=trial_nodes,
                    edges=[],
                    section=section,
                )
                if chunk_nodes and _payload_size_bytes(trial_payload) > max_size_bytes:
                    chunks.append(
                        _build_graph_payload(
                            metadata=metadata,
                            nodes=list(chunk_nodes),
                            edges=[],
                            section=section,
                        )
                    )
                    chunk_nodes = [node]
                else:
                    chunk_nodes = trial_nodes
            if chunk_nodes:
                chunks.append(
                    _build_graph_payload(
                        metadata=metadata,
                        nodes=list(chunk_nodes),
                        edges=[],
                        section=section,
                    )
                )
        if chunks:
            section_chunk_payloads[section] = chunks

    planned_sections_with_data = len(section_chunk_payloads)
    planned_split_files = sum(len(chunks) for chunks in section_chunk_payloads.values())
    print(
        "[*] Split planner: "
        f"selected_sections={len(selected_sections)}, "
        f"sections_with_data={planned_sections_with_data}, "
        f"planned_json_files={planned_split_files}"
    )

    written_split_files = 0
    for section in selected_sections:
        chunks = list(section_chunk_payloads.get(section) or [])
        if not chunks:
            continue
        section_file_paths: list[str] = []
        total_section_parts = len(chunks)
        for index, chunk in enumerate(chunks, start=1):
            suffix = f"_part{index}" if total_section_parts > 1 else ""
            section_filename = f"{stem}_{section}{suffix}.json"
            section_path = output_dir / section_filename
            with section_path.open("w", encoding="utf-8") as handle:
                json.dump(chunk, handle, ensure_ascii=False, indent=2)
            section_file_paths.append(str(section_path))
            written_files.append(str(section_path))
            written_split_files += 1
            print(
                f"[*] Split write progress: {written_split_files}/{planned_split_files} "
                f"(section={section}, part={index}/{total_section_parts}) -> {section_path}"
            )

        manifest_sections[section] = {
            "parts": len(section_file_paths),
            "files": section_file_paths,
            "nodes": sum(int((chunk.get("summary") or {}).get("nodes") or 0) for chunk in chunks),
            "edges": sum(int((chunk.get("summary") or {}).get("edges") or 0) for chunk in chunks),
        }
        UtilityTools.dlog(
            debug,
            "opengraph split section complete",
            section=section,
            parts=len(section_file_paths),
            files=section_file_paths,
        )

    manifest_payload = {
        "metadata": {
            **metadata,
            "source_file": str(base_path),
            "max_target_size_mb": float(max_size_mb),
            "selected_sections": list(selected_sections),
        },
        "sections": manifest_sections,
        "summary": {
            "files_written": len(written_files),
            "sections_written": len([section for section in selected_sections if section in manifest_sections]),
        },
    }
    manifest_path = output_dir / f"{stem}_split_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest_payload, handle, ensure_ascii=False, indent=2)
    written_files.append(str(manifest_path))
    return written_files, str(manifest_path)


def export_opengraph_json(nodes_in_memory, edges_in_memory, *, debug: bool = False):
    UtilityTools.dlog(
        debug,
        "export: loaded graph objects",
        nodes=len(nodes_in_memory or []),
        edges=len(edges_in_memory or []),
    )

    nodes = [node_to_opengraph(r) for r in (nodes_in_memory or [])]
    edges = [edge_to_opengraph(r) for r in (edges_in_memory or [])]

    nodes = sorted(nodes, key=lambda n: str(n["id"] or ""))
    edges = sorted(
        edges,
        key=lambda e: (
            str(e["start"]["value"] or ""),
            str(e["end"]["value"] or ""),
            str(e["kind"] or ""),
        ),
    )

    UtilityTools.dlog(debug, "export: final graph", unique_nodes=len(nodes), unique_edges=len(edges))
    payload = {
        "metadata": {
            "source_kind": "GCPBase",
        },
        "graph": {"nodes": nodes, "edges": edges},
        "summary": {"nodes": len(nodes), "edges": len(edges)},
    }
    return payload


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Build GCP OpenGraph data offline from cached SQLite tables",
        allow_abbrev=False,
    )

    # Logging
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")

    # Output / persistence
    parser.add_argument("--out", required=False, help="Optional JSON export path for the generated graph")
    parser.add_argument("--reset", action="store_true", help="Delete existing OpenGraph rows for this workspace before rebuilding")
    parser.add_argument(
        "--use-existing-opengraph-db",
        action="store_true",
        help=(
            "Skip graph rebuild and use existing opengraph_nodes/opengraph_edges from the current workspace. "
            "Useful for re-exporting graph JSON without rebuilding."
        ),
    )
    parser.add_argument(
        "--split-json-output",
        action="store_true",
        help=(
            "Additionally write sectioned/chunked OpenGraph JSON files for easier BloodHound uploads. "
            "Base single-file export is still written."
        ),
    )
    parser.add_argument(
        "--split-json-sections",
        required=False,
        default="users_groups,iam_bindings,inferred_permissions,resource_expansion",
        help=(
            "Comma list of split sections to emit. Supported: "
            "users_groups, iam_bindings, inferred_permissions, resource_expansion"
        ),
    )
    parser.add_argument(
        "--split-json-max-size-mb",
        type=float,
        default=50.0,
        required=False,
        help="Target max size (MB) per split JSON part (best-effort, give-or-take).",
    )

    # IAM graph behavior
    parser.add_argument("--include-all", action="store_true", help="Include generic IAM binding edges (not only dangerous built-in edges)")
    parser.add_argument("--expand-inherited", action="store_true", help="Expand inherited IAM bindings from org/folder down to child folders/projects")
    parser.add_argument(
        "--cond-eval",
        action="store_true",
        help="Run IAM conditional workflow in pass-through mode (currently no-op filtering)",
    )

    # Step selection
    parser.add_argument("--groups", action="store_true", help="Run users/groups mapping step")
    parser.add_argument("--iam-bindings", action="store_true", help="Run IAM bindings graph step")
    parser.add_argument("--inferred-permissions", action="store_true", help="Run inferred credential-permissions graph step")
    parser.add_argument("--resource-expansion", action="store_true", help="Run resource expansion graph step")

    return parser.parse_args(user_args)


def _decode_json_field(raw_value) -> dict:
    token = str(raw_value or "").strip()
    if not token:
        return {}
    try:
        decoded = json.loads(token)
    except Exception:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _load_existing_opengraph_from_db(session) -> tuple[list[OpenGraphNode], list[OpenGraphEdge]]:
    node_rows = session.get_data("opengraph_nodes") or []
    edge_rows = session.get_data("opengraph_edges") or []

    nodes: list[OpenGraphNode] = []
    for row in node_rows:
        if not isinstance(row, dict):
            continue
        node_id = str(row.get("node_id") or "").strip()
        node_type = str(row.get("node_type") or "").strip()
        if not node_id or not node_type:
            continue
        props = _decode_json_field(row.get("properties_json"))
        if not props.get("name"):
            props["name"] = str(row.get("name") or "").strip() or node_id
        if not props.get("display_name"):
            props["display_name"] = str(row.get("display_name") or "").strip() or props["name"]
        nodes.append(OpenGraphNode(node_id=node_id, node_type=node_type, properties=props))

    edges: list[OpenGraphEdge] = []
    for row in edge_rows:
        if not isinstance(row, dict):
            continue
        source_id = str(row.get("source_id") or "").strip()
        destination_id = str(row.get("destination_id") or "").strip()
        edge_type = str(row.get("edge_type") or "").strip()
        if not source_id or not destination_id or not edge_type:
            continue
        props = _decode_json_field(row.get("properties_json"))
        edges.append(
            OpenGraphEdge(
                source_id=source_id,
                destination_id=destination_id,
                edge_type=edge_type,
                properties=props,
            )
        )
    return nodes, edges


def _emit_binding_coverage_warnings(context) -> None:
    binding_coverage = dict(context.get_artifact("binding_permission_map_coverage") or {})
    unsupported_rules = list(binding_coverage.get("unsupported_rules") or [])
    unmapped_permissions = list(binding_coverage.get("unmapped_permissions") or [])
    if not unsupported_rules:
        return
    print(
        "[!] IAM binding rule coverage warning: some dangerous-edge rules reference permissions that are "
        "not mapped in og_permission_to_roles_map.json. Those rules will be skipped for IAM-binding graphing."
    )
    if unmapped_permissions:
        print(f"    Unmapped permissions: {', '.join(sorted(set(str(p) for p in unmapped_permissions if str(p))))}")
    for record in unsupported_rules:
        rule_name = str(record.get("rule_name") or "").strip() or "<unknown_rule>"
        rule_variant = str(record.get("rule_variant_id") or "").strip()
        missing = [str(permission or "").strip() for permission in (record.get("missing_permissions") or []) if str(permission or "").strip()]
        label = f"{rule_name} ({rule_variant})" if rule_variant else rule_name
        print(f"    Skipping rule {label}: unmapped permissions -> {', '.join(missing)}")


def _run_iam_bindings_stage(context) -> dict[str, object]:
    build_resolved_binding_entries(context)
    step_stats = dict(context.get_artifact("iam_policy_bindings_stage_stats") or {})
    _emit_binding_coverage_warnings(context)
    return step_stats


def _selected_stage_keys(*, args, run_all_steps: bool, has_allow_bindings: bool) -> set[str]:
    """Resolve selected stage keys from CLI switches + available source artifacts."""
    selection_rules: tuple[tuple[bool, str], ...] = (
        (run_all_steps or args.groups, "users_groups"),
        ((run_all_steps or args.iam_bindings) and has_allow_bindings, "iam_bindings"),
        (run_all_steps or args.inferred_permissions, "inferred_permissions"),
        (run_all_steps or args.resource_expansion, "resource_expansion"),
    )
    return {stage_key for enabled, stage_key in selection_rules if enabled}


def _print_trim_summary(trim_stats: dict[str, dict[str, int]]) -> None:
    """Render user-facing trim summaries for non-zero trim results."""
    trim_messages: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        (
            "service_account_binding_islands",
            "[*] Pruned isolated service-account IAM-binding islands",
            ("pairs", "key_islands", "nodes", "edges"),
        ),
        (
            "orphan_implied_bindings",
            "[*] Pruned orphan implied-IAM-binding nodes",
            ("implied_bindings", "nodes", "edges"),
        ),
        (
            "isolated_service_accounts",
            "[*] Pruned isolated service-account nodes",
            ("service_accounts", "nodes", "edges"),
        ),
    )
    for stat_key, prefix, output_keys in trim_messages:
        stat = dict(trim_stats.get(stat_key) or {})
        if not any(int(value or 0) > 0 for value in stat.values()):
            continue
        details = []
        for output_key in output_keys:
            if output_key == "pairs":
                details.append(f"pairs={int(stat.get('pairs_removed', 0))}")
            elif output_key == "key_islands":
                details.append(f"key_islands={int(stat.get('key_islands_removed', 0))}")
            elif output_key == "implied_bindings":
                details.append(f"implied_bindings={int(stat.get('implied_bindings_removed', 0))}")
            elif output_key == "service_accounts":
                details.append(f"service_accounts={int(stat.get('isolated_service_accounts_removed', 0))}")
            elif output_key == "nodes":
                details.append(f"nodes={int(stat.get('nodes_removed', 0))}")
            elif output_key == "edges":
                details.append(f"edges={int(stat.get('edges_removed', 0))}")
        print(f"{prefix} ({', '.join(details)}).")


def run_module(user_args, session):
    # Phase 1: parse args + mode selection.
    args = _parse_args(user_args)

    should_run_graph_build = True
    use_existing_opengraph_db = bool(args.use_existing_opengraph_db)
    if use_existing_opengraph_db:
        should_run_graph_build = False

    nodes: list[OpenGraphNode] = []
    edges: list[OpenGraphEdge] = []
    exported_path = ""

    if should_run_graph_build:
        run_all_steps = not any([args.groups, args.iam_bindings, args.inferred_permissions, args.resource_expansion])
        if args.cond_eval:
            print("[*] --cond-eval enabled in pass-through mode; condition filters currently return input scopes unchanged.")

        raw_allow_bindings = session.get_data("iam_allow_policies") or []
        if args.iam_bindings and not raw_allow_bindings:
            print("[X] No IAM policy data was found in SQLite (iam_allow_policies). Run enum_policy_bindings first.")
            return -1
        if run_all_steps and not raw_allow_bindings:
            print("[*] No IAM policy data was found in SQLite (iam_allow_policies). Skipping IAM bindings step.")

        # Phase 2: build shared context used by all stages.
        context = OpenGraphBuildContext(
            session=session,
            options=OpenGraphBuildOptions(
                include_all=args.include_all,
                expand_inheritance=args.expand_inherited,
                conditional_evaluation=bool(args.cond_eval),
                debug=args.debug,
            ),
        )

        UtilityTools.dlog(
            args.debug,
            "opengraph explicit steps selected",
            groups=bool(args.groups),
            iam_bindings=bool(args.iam_bindings),
            inferred_permissions=bool(args.inferred_permissions),
            resource_expansion=bool(args.resource_expansion),
        )
        UtilityTools.dlog(args.debug, "opengraph run all steps", enabled=run_all_steps)

        # Phase 3: stage selection and execution (fixed stage order from _STAGE_REGISTRY).
        stage_runners = {
            "users_groups": build_users_groups_graph,
            "iam_bindings": _run_iam_bindings_stage,
            "inferred_permissions": build_iam_inferred_permissions_graph,
            "resource_expansion": build_resource_expansion_graph,
        }
        selected_stage_keys = _selected_stage_keys(
            args=args,
            run_all_steps=run_all_steps,
            has_allow_bindings=bool(raw_allow_bindings),
        )
        selected_stages = [stage for stage in _STAGE_REGISTRY if stage["key"] in selected_stage_keys]

        UtilityTools.dlog(
            args.debug,
            "opengraph stage registry",
            stages=[
                {
                    "id": stage["id"],
                    "key": stage["key"],
                    "title": stage["title"],
                }
                for stage in _STAGE_REGISTRY
            ],
        )

        for step_index, stage in enumerate(selected_stages, start=1):
            step, step_id, step_title = stage["key"], stage["id"], stage["title"]

            before_nodes, before_edges = context.counts()
            print(f"[*] Step {step_index} [{step_id}]: {step} ({step_title})")

            runner = stage_runners[step]
            step_stats = runner(context) or {}

            context.record_step(step, step_stats)
            after_nodes, after_edges = context.counts()
            print(
                f"[*] Completed {step}: +{max(0, after_nodes - before_nodes)} nodes, "
                f"+{max(0, after_edges - before_edges)} edges"
            )
            UtilityTools.dlog(args.debug, "opengraph step stats", step=step, stats=step_stats)

        # Phase 4: apply default-mode trim passes.
        nodes = list(context.builder.node_map.values())
        edges = list(context.builder.edge_map.values())
        if args.include_all:
            trim_stats = {
                "service_account_binding_islands": {"pairs_removed": 0, "key_islands_removed": 0, "nodes_removed": 0, "edges_removed": 0},
                "orphan_implied_bindings": {"implied_bindings_removed": 0, "nodes_removed": 0, "edges_removed": 0},
                "isolated_service_accounts": {"isolated_service_accounts_removed": 0, "nodes_removed": 0, "edges_removed": 0},
            }
        else:
            nodes, edges, trim_stats = apply_final_allowlist_trims(nodes, edges)
        _print_trim_summary(trim_stats)

        # Phase 5: persist generated graph snapshot.
        persist_opengraph(session, nodes, edges, clear_existing=args.reset)
    elif use_existing_opengraph_db:
        nodes, edges = _load_existing_opengraph_from_db(session)
        if not nodes and not edges:
            print("[X] No existing OpenGraph data found in SQLite (opengraph_nodes/opengraph_edges).")
            print("    Run process_og_gcpwn_data without --use-existing-opengraph-db first.")
            return -1
        print(f"[*] Loaded existing OpenGraph graph from SQLite: {len(nodes)} nodes, {len(edges)} edges.")

    should_export_graph_json = bool(nodes or edges)
    if should_export_graph_json:
        output_path = str(
            session.resolve_output_path(
                requested_path=args.out,
                service_name="reports",
                filename=f"opengraph_{int(time.time())}.json",
                subdirs=["snapshots"],
                target="export",
            )
        )
        payload = export_opengraph_json(
            nodes,
            edges,
            debug=args.debug,
        )
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        exported_path = output_path

        if args.split_json_output:
            try:
                selected_sections = _parse_split_sections(getattr(args, "split_json_sections", None))
                max_split_size_mb = float(getattr(args, "split_json_max_size_mb", 50.0) or 50.0)
                if max_split_size_mb <= 0:
                    raise ValueError("--split-json-max-size-mb must be greater than 0")
                split_files, manifest_path = _write_split_outputs(
                    base_output_path=output_path,
                    payload=payload,
                    selected_sections=selected_sections,
                    max_size_mb=max_split_size_mb,
                    debug=args.debug,
                )
                print(
                    f"[*] Wrote {len(split_files) - 1} split JSON graph file(s) "
                    f"across {len(selected_sections)} selected section(s)."
                )
                print(f"[*] Saved split manifest to {manifest_path}")
            except ValueError as exc:
                print(f"[X] Split-output configuration error: {exc}")
                return -1

    if should_run_graph_build:
        print(f"[*] OpenGraph generation complete. Nodes: {len(nodes)} | Edges: {len(edges)}")
    if exported_path:
        print(f"[*] Saved graph JSON to {exported_path}")
    return 1
