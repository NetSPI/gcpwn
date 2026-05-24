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
from typing import TypedDict

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

    if should_run_graph_build:
        print(f"[*] OpenGraph generation complete. Nodes: {len(nodes)} | Edges: {len(edges)}")
    if exported_path:
        print(f"[*] Saved graph JSON to {exported_path}")
    return 1
