from __future__ import annotations

"""
Stage 5: final allowlist trim pass.

Read order:
1) `apply_final_allowlist_trims` (orchestrator)
2) `trim_service_account_binding_islands`
3) `trim_orphan_implied_bindings`
4) `trim_isolated_service_accounts`
"""

from collections import defaultdict

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphEdge, OpenGraphNode

IAM_BINDING_NODE_TYPES = {
    "GCPIamBinding",
    "GCPIamGrant",
    "GCPIamSimpleBinding",
    "GCPIamMultiBinding",
}


def _build_adjacency(
    edges: list[OpenGraphEdge] | None,
) -> tuple[dict[str, list[tuple[str, str, str]]], dict[str, list[tuple[str, str, str]]]]:
    incoming: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    outgoing: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for edge in edges or []:
        key = (str(edge.source_id), str(edge.edge_type), str(edge.destination_id))
        outgoing[key[0]].append(key)
        incoming[key[2]].append(key)
    return incoming, outgoing


def _apply_pruned_sets(
    nodes: list[OpenGraphNode],
    edges: list[OpenGraphEdge],
    *,
    nodes_to_remove: set[str],
    edges_to_remove: set[tuple[str, str, str]],
) -> tuple[list[OpenGraphNode], list[OpenGraphEdge]]:
    pruned_nodes = [node for node in nodes if str(node.node_id) not in nodes_to_remove]
    pruned_edges: list[OpenGraphEdge] = []
    for edge in edges:
        key = (str(edge.source_id), str(edge.edge_type), str(edge.destination_id))
        if key in edges_to_remove:
            continue
        if str(edge.source_id) in nodes_to_remove or str(edge.destination_id) in nodes_to_remove:
            continue
        pruned_edges.append(edge)
    return pruned_nodes, pruned_edges


def trim_service_account_binding_islands(
    nodes: list[OpenGraphNode],
    edges: list[OpenGraphEdge],
) -> tuple[list[OpenGraphNode], list[OpenGraphEdge], dict[str, int]]:
    """
    Trim disconnected service-account->binding islands and SA<->key-only islands.
    """
    node_by_id = {str(node.node_id): node for node in (nodes or [])}
    incoming, outgoing = _build_adjacency(edges)

    nodes_to_remove: set[str] = set()
    edges_to_remove: set[tuple[str, str, str]] = set()
    key_nodes_to_consider: set[str] = set()
    pairs_removed = 0
    key_islands_removed = 0

    for node in nodes or []:
        service_account_id = str(node.node_id)
        if str(node.node_type) != "GCPServiceAccount":
            continue
        sa_in = list(incoming.get(service_account_id, []))
        key_in_edges: list[tuple[str, str, str]] = []
        if sa_in:
            key_only = True
            for in_edge_key in sa_in:
                source_id, edge_type, _dest_id = in_edge_key
                source_node = node_by_id.get(source_id)
                if edge_type != "GCP_SERVICE_ACCOUNT_KEY_FOR" or not source_node or str(source_node.node_type) != "GCPServiceAccountKey":
                    key_only = False
                    break
                key_in_edges.append(in_edge_key)
            if not key_only:
                continue

        sa_out = outgoing.get(service_account_id, [])
        if len(sa_out) != 1:
            continue

        binding_edge_key = sa_out[0]
        if binding_edge_key[1] != "HAS_IAM_BINDING":
            continue

        binding_node_id = binding_edge_key[2]
        binding_node = node_by_id.get(binding_node_id)
        if not binding_node or str(binding_node.node_type) not in IAM_BINDING_NODE_TYPES:
            continue

        binding_out = outgoing.get(binding_node_id, [])
        if binding_out:
            continue
        binding_in = incoming.get(binding_node_id, [])
        if len(binding_in) != 1 or binding_in[0] != binding_edge_key:
            continue

        nodes_to_remove.add(service_account_id)
        nodes_to_remove.add(binding_node_id)
        edges_to_remove.add(binding_edge_key)
        for key_edge_key in key_in_edges:
            edges_to_remove.add(key_edge_key)
            key_nodes_to_consider.add(key_edge_key[0])
        pairs_removed += 1

    for node in nodes or []:
        service_account_id = str(node.node_id)
        if service_account_id in nodes_to_remove:
            continue
        if str(node.node_type) != "GCPServiceAccount":
            continue

        incident_keys = list(incoming.get(service_account_id, [])) + list(outgoing.get(service_account_id, []))
        active_incident_keys: list[tuple[str, str, str]] = []
        for edge_key in incident_keys:
            src_id, _edge_type, dst_id = edge_key
            if edge_key in edges_to_remove:
                continue
            if src_id in nodes_to_remove or dst_id in nodes_to_remove:
                continue
            active_incident_keys.append(edge_key)
        if not active_incident_keys:
            continue

        key_only = True
        connected_key_nodes: set[str] = set()
        for edge_key in active_incident_keys:
            src_id, edge_type, dst_id = edge_key
            if edge_type != "GCP_SERVICE_ACCOUNT_KEY_FOR":
                key_only = False
                break
            other_id = src_id if dst_id == service_account_id else dst_id
            other_node = node_by_id.get(other_id)
            if not other_node or str(other_node.node_type) != "GCPServiceAccountKey":
                key_only = False
                break
            connected_key_nodes.add(other_id)
        if not key_only:
            continue

        nodes_to_remove.add(service_account_id)
        for edge_key in active_incident_keys:
            edges_to_remove.add(edge_key)
        key_nodes_to_consider.update(connected_key_nodes)
        key_islands_removed += 1

    for key_node_id in key_nodes_to_consider:
        key_node = node_by_id.get(key_node_id)
        if not key_node or str(key_node.node_type) != "GCPServiceAccountKey":
            continue
        remaining_incident = False
        for edge_key in incoming.get(key_node_id, []) + outgoing.get(key_node_id, []):
            src_id, _edge_type, dst_id = edge_key
            if edge_key in edges_to_remove:
                continue
            if src_id in nodes_to_remove or dst_id in nodes_to_remove:
                continue
            remaining_incident = True
            break
        if not remaining_incident:
            nodes_to_remove.add(key_node_id)

    if not nodes_to_remove and not edges_to_remove:
        return nodes, edges, {"pairs_removed": 0, "key_islands_removed": 0, "nodes_removed": 0, "edges_removed": 0}

    pruned_nodes, pruned_edges = _apply_pruned_sets(
        nodes,
        edges,
        nodes_to_remove=nodes_to_remove,
        edges_to_remove=edges_to_remove,
    )
    return pruned_nodes, pruned_edges, {
        "pairs_removed": pairs_removed,
        "key_islands_removed": key_islands_removed,
        "nodes_removed": max(0, len(nodes) - len(pruned_nodes)),
        "edges_removed": max(0, len(edges) - len(pruned_edges)),
    }


def trim_orphan_implied_bindings(
    nodes: list[OpenGraphNode],
    edges: list[OpenGraphEdge],
) -> tuple[list[OpenGraphNode], list[OpenGraphEdge], dict[str, int]]:
    """
    Trim implied IAM binding nodes that no longer have outgoing inferred edges.
    """
    incoming, outgoing = _build_adjacency(edges)
    node_by_id = {str(node.node_id): node for node in (nodes or [])}
    nodes_to_remove: set[str] = set()
    edges_to_remove: set[tuple[str, str, str]] = set()
    implied_bindings_removed = 0

    for node_id, node in node_by_id.items():
        if str(node.node_type) not in IAM_BINDING_NODE_TYPES:
            continue
        props = dict(node.properties or {})
        role_name = str(props.get("role_name") or props.get("implied_role_name") or "").strip()
        inferred = bool(props.get("inferred"))
        is_implied = str(node_id).startswith("implied-iambinding:") or (
            inferred and role_name.startswith("IMPLIED_PERMISSIONS")
        )
        if not is_implied or outgoing.get(node_id):
            continue
        nodes_to_remove.add(node_id)
        for edge_key in incoming.get(node_id, []):
            edges_to_remove.add(edge_key)
        implied_bindings_removed += 1

    if not nodes_to_remove and not edges_to_remove:
        return nodes, edges, {"implied_bindings_removed": 0, "nodes_removed": 0, "edges_removed": 0}

    pruned_nodes, pruned_edges = _apply_pruned_sets(
        nodes,
        edges,
        nodes_to_remove=nodes_to_remove,
        edges_to_remove=edges_to_remove,
    )
    return pruned_nodes, pruned_edges, {
        "implied_bindings_removed": implied_bindings_removed,
        "nodes_removed": max(0, len(nodes) - len(pruned_nodes)),
        "edges_removed": max(0, len(edges) - len(pruned_edges)),
    }


def trim_isolated_service_accounts(
    nodes: list[OpenGraphNode],
    edges: list[OpenGraphEdge],
) -> tuple[list[OpenGraphNode], list[OpenGraphEdge], dict[str, int]]:
    """
    Trim GCP service-account nodes that have no remaining incident edges.
    """
    incident_counts: dict[str, int] = defaultdict(int)
    for edge in edges or []:
        source_id = str(edge.source_id or "").strip()
        destination_id = str(edge.destination_id or "").strip()
        if source_id:
            incident_counts[source_id] += 1
        if destination_id:
            incident_counts[destination_id] += 1

    nodes_to_remove: set[str] = set()
    for node in nodes or []:
        node_id = str(node.node_id or "").strip()
        if not node_id:
            continue
        if str(node.node_type or "").strip() != "GCPServiceAccount":
            continue
        if incident_counts.get(node_id, 0) == 0:
            nodes_to_remove.add(node_id)

    if not nodes_to_remove:
        return nodes, edges, {"isolated_service_accounts_removed": 0, "nodes_removed": 0, "edges_removed": 0}

    pruned_nodes, pruned_edges = _apply_pruned_sets(
        nodes,
        edges,
        nodes_to_remove=nodes_to_remove,
        edges_to_remove=set(),
    )
    return pruned_nodes, pruned_edges, {
        "isolated_service_accounts_removed": len(nodes_to_remove),
        "nodes_removed": max(0, len(nodes) - len(pruned_nodes)),
        "edges_removed": max(0, len(edges) - len(pruned_edges)),
    }


def trim_non_escalation_simple_bindings(
    nodes: list[OpenGraphNode],
    edges: list[OpenGraphEdge],
) -> tuple[list[OpenGraphNode], list[OpenGraphEdge], dict[str, int]]:
    """
    Trim simple IAM binding nodes that are not marked as privilege escalation.
    Default mode should focus on escalation paths; include-all keeps these.
    """
    nodes_to_remove: set[str] = set()
    for node in nodes or []:
        if str(node.node_type or "").strip() != "GCPIamSimpleBinding":
            continue
        props = dict(node.properties or {})
        if bool(props.get("privilege_escalation", False)):
            continue
        nodes_to_remove.add(str(node.node_id or "").strip())

    if not nodes_to_remove:
        return nodes, edges, {"non_escalation_simple_bindings_removed": 0, "nodes_removed": 0, "edges_removed": 0}

    pruned_nodes, pruned_edges = _apply_pruned_sets(
        nodes,
        edges,
        nodes_to_remove=nodes_to_remove,
        edges_to_remove=set(),
    )
    return pruned_nodes, pruned_edges, {
        "non_escalation_simple_bindings_removed": len(nodes_to_remove),
        "nodes_removed": max(0, len(nodes) - len(pruned_nodes)),
        "edges_removed": max(0, len(edges) - len(pruned_edges)),
    }


def apply_final_allowlist_trims(
    nodes: list[OpenGraphNode],
    edges: list[OpenGraphEdge],
) -> tuple[list[OpenGraphNode], list[OpenGraphEdge], dict[str, dict[str, int]]]:
    """
    Orchestrator:
    1) trim_service_account_binding_islands
    2) trim_orphan_implied_bindings
    3) trim_non_escalation_simple_bindings
    4) trim_isolated_service_accounts
    """
    nodes, edges, islands_stats = trim_service_account_binding_islands(nodes, edges)
    nodes, edges, implied_stats = trim_orphan_implied_bindings(nodes, edges)
    nodes, edges, non_escalation_simple_stats = trim_non_escalation_simple_bindings(nodes, edges)
    nodes, edges, isolated_sa_stats = trim_isolated_service_accounts(nodes, edges)
    return nodes, edges, {
        "service_account_binding_islands": islands_stats,
        "orphan_implied_bindings": implied_stats,
        "non_escalation_simple_bindings": non_escalation_simple_stats,
        "isolated_service_accounts": isolated_sa_stats,
    }
