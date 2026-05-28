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
import re
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
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


def _write_json_payload(path: Path, payload: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def _json_value_size_bytes(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _write_graph_json_with_progress(output_path: str, payload: dict[str, Any]) -> None:
    metadata = dict(payload.get("metadata") or {})
    graph = dict(payload.get("graph") or {})
    nodes = [node for node in (graph.get("nodes") or []) if isinstance(node, dict)]
    edges = [edge for edge in (graph.get("edges") or []) if isinstance(edge, dict)]
    summary = dict(payload.get("summary") or {"nodes": len(nodes), "edges": len(edges)})
    total_records = len(nodes) + len(edges)

    print(f"[*] Main JSON write tally: nodes={len(nodes)}, edges={len(edges)}, total_records={total_records}")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("{\n")
        handle.write('  "metadata": ')
        json.dump(metadata, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write(",\n")
        handle.write('  "graph": {\n')
        handle.write('    "nodes": [')
        for index, node in enumerate(nodes, start=1):
            if index > 1:
                handle.write(",")
            json.dump(node, handle, ensure_ascii=False, separators=(",", ":"))
            _print_inline_progress("Main JSON write (nodes)", index, len(nodes))
        _print_inline_progress("Main JSON write (nodes)", len(nodes), len(nodes), force=True)
        handle.write("],\n")
        handle.write('    "edges": [')
        for index, edge in enumerate(edges, start=1):
            if index > 1:
                handle.write(",")
            json.dump(edge, handle, ensure_ascii=False, separators=(",", ":"))
            overall = len(nodes) + index
            _print_inline_progress("Main JSON write (overall)", overall, total_records)
        _print_inline_progress("Main JSON write (overall)", total_records, total_records, force=True)
        handle.write("]\n")
        handle.write("  },\n")
        handle.write('  "summary": ')
        json.dump(summary, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write("\n}\n")


def _write_split_outputs(
    *,
    base_output_path: str,
    payload: dict[str, Any],
    selected_sections: list[str],
    max_size_mb: float,
    size_tolerance_mb: float = 25.0,
    split_threads: int = 1,
    split_output_dir: str | None = None,
    debug: bool = False,
) -> tuple[list[str], str]:
    max_size_bytes = max(1, int(float(max_size_mb) * 1024 * 1024))
    tolerance_bytes = max(0, int(float(size_tolerance_mb) * 1024 * 1024))
    soft_min_bytes = max(1, max_size_bytes - tolerance_bytes)
    soft_max_bytes = max_size_bytes + tolerance_bytes
    metadata = dict(payload.get("metadata") or {})
    graph = dict(payload.get("graph") or {})
    all_nodes = [node for node in (graph.get("nodes") or []) if isinstance(node, dict)]
    all_edges = [edge for edge in (graph.get("edges") or []) if isinstance(edge, dict)]
    node_index = {
        str(node.get("id") or "").strip(): node
        for node in all_nodes
        if str(node.get("id") or "").strip()
    }
    node_serialized_size = {
        node_id: _json_value_size_bytes(node)
        for node_id, node in node_index.items()
    }

    section_edges: dict[str, list[dict[str, Any]]] = {key: [] for key in _SPLIT_SECTION_KEYS}
    section_node_ids: dict[str, set[str]] = {key: set() for key in _SPLIT_SECTION_KEYS}

    for node in all_nodes:
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            continue
        section_node_ids[_node_section(node)].add(node_id)
    _print_inline_progress("Split planner classify nodes", len(all_nodes), len(all_nodes), force=True)

    total_all_edges = len(all_edges)
    for index, edge in enumerate(all_edges, start=1):
        section_edges[_edge_section(edge)].append(edge)
        _print_inline_progress("Split planner classify edges", index, total_all_edges)
    _print_inline_progress("Split planner classify edges", total_all_edges, total_all_edges, force=True)

    base_path = Path(base_output_path)
    output_dir = Path(split_output_dir).expanduser() if split_output_dir else base_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = base_path.stem
    written_files: list[str] = []
    manifest_sections: dict[str, Any] = {}
    selected_sections_with_data: list[str] = []
    written_split_files = 0
    section_estimated_parts: dict[str, int] = {}
    worker_count = max(1, int(split_threads or 1))
    print(
        "[*] Split size policy: "
        f"target={float(max_size_mb):g}MB, "
        f"tolerance=+/-{float(size_tolerance_mb):g}MB, "
        f"range={soft_min_bytes / (1024 * 1024):.2f}-{soft_max_bytes / (1024 * 1024):.2f}MB"
    )

    for section in selected_sections:
        edges = list(section_edges.get(section) or [])
        seeded_node_ids = set(section_node_ids.get(section) or set())

        if not edges and not seeded_node_ids:
            continue
        selected_sections_with_data.append(section)

        referenced_node_ids: set[str] = set()
        total_section_edges = len(edges)
        for edge_index, edge in enumerate(edges, start=1):
            start = str((((edge.get("start") or {}) if isinstance(edge.get("start"), dict) else {}).get("value") or "")).strip()
            end = str((((edge.get("end") or {}) if isinstance(edge.get("end"), dict) else {}).get("value") or "")).strip()
            if start:
                referenced_node_ids.add(start)
            if end:
                referenced_node_ids.add(end)
            _print_inline_progress(
                f"Split planner ({section}) map edge refs",
                edge_index,
                total_section_edges,
            )
        _print_inline_progress(
            f"Split planner ({section}) map edge refs",
            total_section_edges,
            total_section_edges,
            force=True,
        )
        seeded_node_ids.update(referenced_node_ids)
        seeded_nodes = [
            node_index[node_id]
            for node_id in sorted(seeded_node_ids)
            if node_id in node_index
        ]

        current_edges: list[dict[str, Any]] = []
        current_edge_node_ids: set[str] = set()
        current_edges_bytes = 0
        current_nodes_bytes = 0
        current_node_count = 0
        base_chunk_overhead_bytes = _payload_size_bytes(
            _build_graph_payload(
                metadata=metadata,
                nodes=[],
                edges=[],
                section=section,
            )
        )
        section_file_paths: list[str] = []
        section_nodes_written = 0
        section_edges_written = 0
        section_part_index = 0
        section_file_paths_by_part: dict[int, str] = {}
        pending_writes: list[tuple[Any, int, Path, int, int]] = []
        executor = ThreadPoolExecutor(max_workers=worker_count) if worker_count > 1 else None

        def _record_completed_writes(completed_items: list[tuple[Any, int, Path, int, int]]) -> None:
            nonlocal written_split_files, section_nodes_written, section_edges_written
            for future, part_index, part_path, node_count, edge_count in completed_items:
                future.result()
                section_file_paths_by_part[part_index] = str(part_path)
                written_files.append(str(part_path))
                written_split_files += 1
                section_nodes_written += node_count
                section_edges_written += edge_count
                print(
                    f"[*] Split write progress: files_written={written_split_files} "
                    f"(section={section}, part={part_index}) -> {part_path}"
                )

        def _drain_pending_writes(*, force: bool) -> None:
            nonlocal pending_writes
            if not pending_writes:
                return
            if force:
                completed_items = list(pending_writes)
                pending_writes = []
                _record_completed_writes(completed_items)
                return
            done_futures, _ = wait(
                [item[0] for item in pending_writes],
                return_when=FIRST_COMPLETED,
            )
            if not done_futures:
                return
            completed_items: list[tuple[Any, int, Path, int, int]] = []
            remaining_items: list[tuple[Any, int, Path, int, int]] = []
            for item in pending_writes:
                if item[0] in done_futures:
                    completed_items.append(item)
                else:
                    remaining_items.append(item)
            pending_writes = remaining_items
            _record_completed_writes(completed_items)

        def _flush_chunk(extra_nodes: list[dict[str, Any]] | None = None) -> bool:
            nonlocal section_part_index, written_split_files, section_nodes_written, section_edges_written
            if not current_edges and not extra_nodes:
                return False
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
            section_part_index += 1
            section_filename = f"{stem}_{section}_part{section_part_index}.json"
            section_path = output_dir / section_filename
            chunk_node_count = int((chunk_payload.get("summary") or {}).get("nodes") or 0)
            chunk_edge_count = int((chunk_payload.get("summary") or {}).get("edges") or 0)
            if executor is None:
                _write_json_payload(section_path, chunk_payload)
                section_file_paths_by_part[section_part_index] = str(section_path)
                written_files.append(str(section_path))
                written_split_files += 1
                section_nodes_written += chunk_node_count
                section_edges_written += chunk_edge_count
                print(
                    f"[*] Split write progress: files_written={written_split_files} "
                    f"(section={section}, part={section_part_index}) -> {section_path}"
                )
            else:
                future = executor.submit(_write_json_payload, section_path, chunk_payload)
                pending_writes.append((future, section_part_index, section_path, chunk_node_count, chunk_edge_count))
                if len(pending_writes) >= max(2, worker_count * 2):
                    _drain_pending_writes(force=False)
            return True

        for edge_index, edge in enumerate(edges, start=1):
            start = str((((edge.get("start") or {}) if isinstance(edge.get("start"), dict) else {}).get("value") or "")).strip()
            end = str((((edge.get("end") or {}) if isinstance(edge.get("end"), dict) else {}).get("value") or "")).strip()
            trial_edges = [*current_edges, edge]
            trial_edge_node_ids = set(current_edge_node_ids)
            new_node_ids: list[str] = []
            if start:
                if start not in trial_edge_node_ids and start in node_index:
                    new_node_ids.append(start)
                trial_edge_node_ids.add(start)
            if end:
                if end not in trial_edge_node_ids and end in node_index:
                    new_node_ids.append(end)
                trial_edge_node_ids.add(end)
            edge_size = _json_value_size_bytes(edge)
            new_node_bytes = sum(node_serialized_size.get(node_id, 0) for node_id in new_node_ids)
            trial_edges_bytes = current_edges_bytes + edge_size
            trial_nodes_bytes = current_nodes_bytes + new_node_bytes
            trial_node_count = current_node_count + len(new_node_ids)
            trial_edge_count = len(current_edges) + 1
            trial_estimated_bytes = (
                base_chunk_overhead_bytes
                + trial_edges_bytes
                + trial_nodes_bytes
                + max(0, trial_edge_count - 1)
                + max(0, trial_node_count - 1)
            )
            current_estimated_bytes = (
                base_chunk_overhead_bytes
                + current_edges_bytes
                + current_nodes_bytes
                + max(0, len(current_edges) - 1)
                + max(0, current_node_count - 1)
            )
            if current_edges and trial_estimated_bytes > soft_max_bytes and current_estimated_bytes >= soft_min_bytes:
                _flush_chunk()
                current_edges = []
                current_edge_node_ids = set()
                current_edges_bytes = 0
                current_nodes_bytes = 0
                current_node_count = 0
                trial_edges = [edge]
                trial_edge_node_ids = set()
                new_node_ids = []
                if start:
                    if start in node_index:
                        new_node_ids.append(start)
                    trial_edge_node_ids.add(start)
                if end:
                    if end in node_index and end not in new_node_ids:
                        new_node_ids.append(end)
                    trial_edge_node_ids.add(end)
                trial_edges_bytes = edge_size
                trial_nodes_bytes = sum(node_serialized_size.get(node_id, 0) for node_id in new_node_ids)
                trial_node_count = len(new_node_ids)

            current_edges = trial_edges
            current_edge_node_ids = trial_edge_node_ids
            current_edges_bytes = trial_edges_bytes
            current_nodes_bytes = trial_nodes_bytes
            current_node_count = trial_node_count
            _print_inline_progress(
                f"Split planner ({section}) chunk edges",
                edge_index,
                total_section_edges,
            )
        _print_inline_progress(
            f"Split planner ({section}) chunk edges",
            total_section_edges,
            total_section_edges,
            force=True,
        )

        standalone_nodes = [
            node
            for node in seeded_nodes
            if str(node.get("id") or "").strip() not in current_edge_node_ids
        ]

        if current_edges:
            _flush_chunk(extra_nodes=standalone_nodes)
        elif standalone_nodes:
            chunk_nodes: list[dict[str, Any]] = []
            chunk_nodes_bytes = 0
            for node in standalone_nodes:
                node_id = str(node.get("id") or "").strip()
                node_size = node_serialized_size.get(node_id, _json_value_size_bytes(node))
                trial_nodes_bytes = chunk_nodes_bytes + node_size
                trial_node_count = len(chunk_nodes) + 1
                trial_estimated_bytes = (
                    base_chunk_overhead_bytes
                    + trial_nodes_bytes
                    + max(0, trial_node_count - 1)
                )
                current_estimated_bytes = (
                    base_chunk_overhead_bytes
                    + chunk_nodes_bytes
                    + max(0, len(chunk_nodes) - 1)
                )
                if chunk_nodes and trial_estimated_bytes > soft_max_bytes and current_estimated_bytes >= soft_min_bytes:
                    current_edges = []
                    current_edge_node_ids = set()
                    _flush_chunk(extra_nodes=list(chunk_nodes))
                    chunk_nodes = [node]
                    chunk_nodes_bytes = node_size
                else:
                    chunk_nodes.append(node)
                    chunk_nodes_bytes = trial_nodes_bytes
            if chunk_nodes:
                current_edges = []
                current_edge_node_ids = set()
                _flush_chunk(extra_nodes=list(chunk_nodes))

        _drain_pending_writes(force=True)
        if executor is not None:
            executor.shutdown(wait=True)
        section_file_paths = [
            section_file_paths_by_part[index]
            for index in sorted(section_file_paths_by_part)
        ]
        section_estimated_parts[section] = section_part_index
        if len(section_file_paths) == 1:
            legacy_section_path = output_dir / f"{stem}_{section}.json"
            current_section_path = Path(section_file_paths[0])
            if current_section_path != legacy_section_path:
                current_section_path.replace(legacy_section_path)
                section_file_paths[0] = str(legacy_section_path)
                if written_files:
                    written_files[-1] = str(legacy_section_path)
        manifest_sections[section] = {
            "parts": len(section_file_paths),
            "files": section_file_paths,
            "nodes": section_nodes_written,
            "edges": section_edges_written,
        }
        UtilityTools.dlog(
            debug,
            "opengraph split section complete",
            section=section,
            parts=len(section_file_paths),
            files=section_file_paths,
        )

    planned_sections_with_data = len(selected_sections_with_data)
    planned_split_files = int(sum(section_estimated_parts.values()))
    print(
        "[*] Split planner: "
        f"selected_sections={len(selected_sections)}, "
        f"sections_with_data={planned_sections_with_data}, "
        f"planned_json_files={planned_split_files}"
    )

    manifest_payload = {
        "metadata": {
            **metadata,
            "source_file": str(base_path),
            "max_target_size_mb": float(max_size_mb),
            "size_tolerance_mb": float(size_tolerance_mb),
            "split_threads": worker_count,
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


def _safe_export_token(raw_value: str | None) -> str:
    token = str(raw_value or "").strip()
    if not token:
        return "export"
    normalized = re.sub(r"[^A-Za-z0-9_-]+", "_", token).strip("_")
    return normalized or "export"


def _resolve_export_paths(session, args) -> tuple[str, str | None]:
    # Custom output path mode:
    # - --out/-o is treated as an OUTPUT DIRECTORY, not a file path.
    # - Single JSON + split outputs are written directly in that directory.
    custom_out = str(getattr(args, "out", "") or "").strip()
    if custom_out:
        out_dir = Path(custom_out).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_name = _safe_export_token(out_dir.name)
        single_json_path = out_dir / f"opengraph_{out_name}.json"
        return str(single_json_path), str(out_dir)

    # Default output mode:
    # - Build snapshot name as before, then create a bundle directory:
    #   opengraph_<id>/single_json/<single.json>
    #   opengraph_<id>/split_json/<split files + manifest>
    default_single = Path(
        str(
            session.resolve_output_path(
                requested_path=None,
                service_name="reports",
                filename=f"opengraph_{int(time.time())}.json",
                subdirs=["snapshots"],
                target="export",
            )
        )
    )
    bundle_dir = default_single.parent / default_single.stem
    single_json_dir = bundle_dir / "single_json"
    split_json_dir = bundle_dir / "split_json"
    single_json_dir.mkdir(parents=True, exist_ok=True)
    split_json_dir.mkdir(parents=True, exist_ok=True)
    return str(single_json_dir / default_single.name), str(split_json_dir)


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Build GCP OpenGraph data offline from cached SQLite tables",
        allow_abbrev=False,
    )

    # Logging
    parser.add_argument("-v", "--debug", action="store_true", help="Verbose output")

    # Output / persistence
    parser.add_argument(
        "-o",
        "--out",
        required=False,
        help=(
            "Optional output directory for OpenGraph JSON exports. "
            "When provided, files are written into this folder as opengraph_<folder_name>.json "
            "and matching split outputs."
        ),
    )
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
        help=(
            "Target split-part size center (MB). Used with --split-json-size-tolerance-mb "
            "as an approximate +/- range. Default center: 50 MB."
        ),
    )
    parser.add_argument(
        "--split-json-size-tolerance-mb",
        type=float,
        default=25.0,
        required=False,
        help=(
            "Tolerance (MB) around --split-json-max-size-mb for faster chunking "
            "(approximate range, best-effort). Default: +/-25 MB."
        ),
    )
    parser.add_argument(
        "--split-json-threads",
        type=int,
        default=1,
        required=False,
        help=(
            "Thread count for writing split JSON output files. "
            "Default 1 (sequential); increase for parallel writes."
        ),
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
        output_path, split_output_dir = _resolve_export_paths(session, args)
        payload = export_opengraph_json(
            nodes,
            edges,
            debug=args.debug,
        )
        _write_graph_json_with_progress(output_path, payload)
        exported_path = output_path

        if args.split_json_output:
            try:
                selected_sections = _parse_split_sections(getattr(args, "split_json_sections", None))
                max_split_size_mb = float(getattr(args, "split_json_max_size_mb", 50.0) or 50.0)
                if max_split_size_mb <= 0:
                    raise ValueError("--split-json-max-size-mb must be greater than 0")
                split_size_tolerance_mb = float(getattr(args, "split_json_size_tolerance_mb", 25.0) or 0.0)
                if split_size_tolerance_mb < 0:
                    raise ValueError("--split-json-size-tolerance-mb cannot be negative")
                split_json_threads = int(getattr(args, "split_json_threads", 1) or 1)
                if split_json_threads <= 0:
                    raise ValueError("--split-json-threads must be greater than 0")
                split_files, manifest_path = _write_split_outputs(
                    base_output_path=output_path,
                    payload=payload,
                    selected_sections=selected_sections,
                    max_size_mb=max_split_size_mb,
                    size_tolerance_mb=split_size_tolerance_mb,
                    split_threads=split_json_threads,
                    split_output_dir=split_output_dir,
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
