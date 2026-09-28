"""In-memory attack graph built from an exported OpenGraph JSON payload.

This is a strictly READ-ONLY consumer of the BloodHound OpenGraph JSON that
``process_og_gcpwn_data`` emits -- it never re-derives anything from the DB and
never changes the emitted contract. Everything needed for path analysis (nodes,
edge kinds, roles, scopes, inheritance/conditional markers) is already present
in that JSON.

Graph shape, as emitted by the pipeline:

    principal --HAS_IAM_BINDING-----> iambinding:<role>@<scope> --CAN_*/ROLE_*--> target
    principal --HAS_COMBO_BINDING---> combo binding node       --CREATE_*_AS_SA-> target
    principal --HasImpliedPermissions-> iambinding node        --...------------> target

Binding nodes are *plumbing*: they carry the role and the attached scope, but a
human counts "hops" in identities, not in binding nodes. So traversal runs over
the raw graph while :mod:`.render` collapses each
``principal -> binding -> target`` triple into a single logical hop labelled
with the role.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

# Binding nodes are intermediates collapsed at render time.
BINDING_KINDS = frozenset({"GCPIamSimpleBinding", "GCPIamMultiBinding"})

# Edges that attach a principal to a binding node (the "has this role" half).
GRANT_EDGE_KINDS = frozenset({"HAS_IAM_BINDING", "HAS_COMBO_BINDING", "HasImpliedPermissions"})

# Top-down containment (Project -> child resource). Semantically true but it
# multiplies path counts enormously, so traversal skips it unless asked.
CONTAINMENT_EDGE_KINDS = frozenset({"ExistsInProject"})

# Node kinds that can start a path.
PRINCIPAL_KINDS = frozenset(
    {
        "GoogleUser",
        "GoogleGroup",
        "GCPGroup",
        "GCPWorkspaceUser",
        "GCPServiceAccount",
        "GCPPrincipalSet",
        "GCPAllUsers",
        "GCPAllAuthenticatedUsers",
        "GCPDomainPrincipal",
        "GCPExternalIdentitySource",
    }
)

# Fallback principal detection by canonical IAM member prefix on the node id.
PRINCIPAL_ID_PREFIXES = (
    "user:",
    "serviceAccount:",
    "group:",
    "domain:",
    "principalSet://",
    "principal://",
    "allUsers",
    "allAuthenticatedUsers",
)

_SA_EMAIL_SUFFIX = ".iam.gserviceaccount.com"


def _project_of(text: str) -> str | None:
    """Best-effort project id from an SA email or a ``projects/<id>/...`` path."""
    if not text:
        return None
    if _SA_EMAIL_SUFFIX in text:
        local = text.split("@", 1)[-1]
        return local[: -len(_SA_EMAIL_SUFFIX)] or None
    marker = "projects/"
    index = text.find(marker)
    if index != -1:
        return text[index + len(marker) :].split("/", 1)[0] or None
    return None


class AttackGraph:
    """Adjacency-indexed view of an OpenGraph export, built for path queries."""

    def __init__(self, nodes: dict[str, dict], edges: list[dict], *, sources_loaded: list[str] | None = None):
        self.nodes = nodes
        self.edges = edges
        self.sources_loaded = sources_loaded or []
        self._known_projects: set[str] | None = None

        # src -> [(dst, edge_index)], and the reverse, for backward BFS.
        self.adj: dict[str, list[tuple[str, int]]] = {}
        self.radj: dict[str, list[tuple[str, int]]] = {}
        for index, edge in enumerate(edges):
            start, end = edge["start"], edge["end"]
            self.adj.setdefault(start, []).append((end, index))
            self.radj.setdefault(end, []).append((start, index))

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_path(cls, path: str | Path) -> AttackGraph:
        """Load a single OpenGraph JSON file, or every JSON part in a directory.

        ``process_og --split-json-output`` writes one file per section plus a
        ``*_split_manifest.json``; a directory load merges the parts and skips
        the manifest, so single-file and split exports behave identically.
        """
        target = Path(path).expanduser()
        if not target.exists():
            raise FileNotFoundError(f"No such graph file or directory: {target}")

        files: list[Path]
        if target.is_dir():
            files = sorted(
                candidate
                for candidate in target.rglob("*.json")
                if not candidate.name.endswith("_split_manifest.json")
            )
            if not files:
                raise FileNotFoundError(f"No OpenGraph .json files found under {target}")
        else:
            files = [target]

        nodes: dict[str, dict] = {}
        edge_keys: set[tuple[str, str, str]] = set()
        edges: list[dict] = []

        for file_path in files:
            with file_path.open(encoding="utf-8") as handle:
                payload = json.load(handle)
            graph = payload.get("graph", payload) if isinstance(payload, dict) else {}

            for node in graph.get("nodes") or []:
                node_id = node.get("id")
                if not node_id or node_id in nodes:
                    continue
                kinds = node.get("kinds") or []
                nodes[node_id] = {
                    "id": node_id,
                    "kinds": kinds,
                    "kind": kinds[0] if kinds else "Unknown",
                    "properties": node.get("properties") or {},
                }

            for edge in graph.get("edges") or []:
                start = (edge.get("start") or {}).get("value")
                end = (edge.get("end") or {}).get("value")
                kind = edge.get("kind")
                if not (start and end and kind):
                    continue
                key = (start, end, kind)
                if key in edge_keys:
                    continue
                edge_keys.add(key)
                edges.append(
                    {
                        "start": start,
                        "end": end,
                        "kind": kind,
                        "properties": edge.get("properties") or {},
                    }
                )

        # Edges may reference nodes that were trimmed from the export; keep them
        # as placeholders so traversal does not have to special-case lookups.
        for edge in edges:
            for endpoint in (edge["start"], edge["end"]):
                if endpoint not in nodes:
                    nodes[endpoint] = {"id": endpoint, "kinds": [], "kind": "Unknown", "properties": {}}

        return cls(nodes, edges, sources_loaded=[str(f) for f in files])

    # ------------------------------------------------------------- classification

    def kind_of(self, node_id: str) -> str:
        return self.nodes.get(node_id, {}).get("kind", "Unknown")

    def props(self, node_id: str) -> dict[str, Any]:
        return self.nodes.get(node_id, {}).get("properties", {})

    def is_binding(self, node_id: str) -> bool:
        return self.kind_of(node_id) in BINDING_KINDS

    def is_capability(self, node_id: str) -> bool:
        """Synthetic ``CAP:`` node standing for a capability (e.g. "deploy a job as SA").

        The pipeline inserts these between a combo binding and the service account
        it yields. They reuse resource kinds, so the ``CAP:`` id prefix is the marker.
        """
        return node_id.startswith("CAP:")

    def is_synthetic(self, node_id: str) -> bool:
        """Graph plumbing rather than a real identity or resource."""
        return self.is_binding(node_id) or self.is_capability(node_id)

    def is_principal(self, node_id: str) -> bool:
        if self.kind_of(node_id) in PRINCIPAL_KINDS:
            return True
        return node_id.startswith(PRINCIPAL_ID_PREFIXES)

    def is_service_agent(self, node_id: str) -> bool:
        """Google-managed service agent, per the flag the pipeline already emits."""
        return bool(self.props(node_id).get("is_service_agent"))

    def known_project_ids(self) -> set[str]:
        """Project ids of the real project nodes in this graph.

        Capability (``CAP:``) nodes reuse resource kinds such as ``GCPProject`` but
        carry no ``project_id``, so keying on that property selects only real
        projects. Used to keep project comparisons honest: a project *number* or a
        Google-owned service-agent tenant (``gcp-sa-aiplatform``) is not a project
        in this graph and must not be compared as one.
        """
        if self._known_projects is None:
            self._known_projects = {
                str(node["properties"]["project_id"]).strip().lower()
                for node in self.nodes.values()
                if node["kind"] == "GCPProject" and node["properties"].get("project_id")
            }
        return self._known_projects

    def display_name(self, node_id: str) -> str:
        """Short human label for a node, preferring emitted display properties."""
        properties = self.props(node_id)
        for key in ("display_name", "name", "role_display_name"):
            value = properties.get(key)
            if value:
                return str(value)
        return node_id

    def role_of_binding(self, node_id: str) -> str | None:
        value = self.props(node_id).get("role_name")
        return str(value) if value else None

    def scope_of_binding(self, node_id: str) -> str | None:
        properties = self.props(node_id)
        for key in ("attached_scope_id", "effective_scope_id"):
            value = properties.get(key)
            if value:
                return str(value)
        return None

    def traversable_kinds(self, *, include_containment: bool = False) -> frozenset[str]:
        """Edge kinds traversal is allowed to follow."""
        kinds = {edge["kind"] for edge in self.edges}
        if not include_containment:
            kinds -= set(CONTAINMENT_EDGE_KINDS)
        return frozenset(kinds)

    def principals(self, *, exclude_service_agents: bool = False) -> list[str]:
        return [
            node_id
            for node_id in self.nodes
            if self.is_principal(node_id) and not (exclude_service_agents and self.is_service_agent(node_id))
        ]

    # -------------------------------------------------------------------- config

    def config_summary(self) -> dict[str, Any]:
        """Facts about how this graph was generated, inferred from its content.

        The export's ``metadata`` block only carries ``source_kind``, so the
        generation settings a defender cares about (was inheritance expanded? are
        there conditional bindings? any cross-project actAs?) are recovered from
        the node ids and edge properties that the pipeline already stamps.
        """
        inheritance = False
        conditional = False
        deny = False
        cross_project_pairs: set[tuple[str, str]] = set()

        for node_id in self.nodes:
            if "#src:" in node_id:
                inheritance = True
            if "#cond:" in node_id:
                conditional = True
            if inheritance and conditional:
                break

        for edge in self.edges:
            properties = edge["properties"]
            if properties.get("inherited"):
                inheritance = True
            if properties.get("conditional") or properties.get("condition_expr_raw"):
                conditional = True
            if "DENY" in edge["kind"].upper():
                deny = True

        # Cross-project actAs: a principal in project A holding a binding attached
        # to a service account in project B -- the observable effect of building the
        # graph with --cross-sa-project-allowed. Both sides must be project ids that
        # actually exist in this graph, otherwise a project *number* (same project,
        # different spelling) or a Google service-agent tenant would read as a
        # different project and report a path that does not exist.
        projects = self.known_project_ids()
        for edge in self.edges:
            if edge["kind"] not in GRANT_EDGE_KINDS:
                continue
            binding = edge["end"]
            if str(self.props(binding).get("attached_scope_type") or "") != "service-account":
                continue
            principal_project = (_project_of(edge["start"]) or "").lower()
            scope_project = (_project_of(str(self.scope_of_binding(binding) or "")) or "").lower()
            if principal_project not in projects or scope_project not in projects:
                continue
            if principal_project != scope_project:
                cross_project_pairs.add((principal_project, scope_project))

        kind_counts = Counter(node["kind"] for node in self.nodes.values())
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "files_loaded": self.sources_loaded,
            "inheritance_expanded": inheritance,
            "conditional_bindings": conditional,
            "deny_policies": deny,
            "cross_project_actas": bool(cross_project_pairs),
            "cross_project_actas_pairs": sorted(f"{a} -> {b}" for a, b in cross_project_pairs),
            "known_projects": sorted(self.known_project_ids()),
            "principal_count": sum(1 for node_id in self.nodes if self.is_principal(node_id)),
            "service_agent_count": sum(
                1 for node_id in self.nodes if self.is_principal(node_id) and self.is_service_agent(node_id)
            ),
            "binding_count": sum(count for kind, count in kind_counts.items() if kind in BINDING_KINDS),
            "distinct_edge_kinds": len({edge["kind"] for edge in self.edges}),
            "top_node_kinds": kind_counts.most_common(10),
            "edge_kind_counts": Counter(edge["kind"] for edge in self.edges).most_common(),
        }

    # ------------------------------------------------------------------ matching

    def scope_matches(self, node_id: str, scope: str) -> bool:
        """True when a node sits at/under ``scope`` (project/folder/org or any path)."""
        if not scope:
            return True
        needle = scope.lower()
        if needle in node_id.lower():
            return True
        properties = self.props(node_id)
        for key in ("attached_scope_id", "effective_scope_id", "project_id", "name", "effective_scope_ids"):
            value = properties.get(key)
            if isinstance(value, (list, tuple)):
                if any(needle in str(item).lower() for item in value):
                    return True
            elif value and needle in str(value).lower():
                return True
        return False

    def find_role_bindings(self, roles: Iterable[str]) -> list[str]:
        """Binding nodes whose role matches any of ``roles`` (exact or suffix)."""
        wanted = [role.strip().lower() for role in roles if role and role.strip()]
        if not wanted:
            return []
        matches = []
        for node_id, node in self.nodes.items():
            if node["kind"] not in BINDING_KINDS:
                continue
            role = str(node["properties"].get("role_name") or "").lower()
            if not role:
                continue
            short = role.rsplit("/", 1)[-1]
            if any(role == want or short == want.rsplit("/", 1)[-1] for want in wanted):
                matches.append(node_id)
        return matches
