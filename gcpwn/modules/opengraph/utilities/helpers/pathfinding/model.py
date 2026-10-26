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
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

# Heavy edge/node properties the exporter stamps that NOTHING in the pathfinding/render
# subsystem reads. Dropped from the retained in-memory attack graph (not from the exported
# JSON) so text analysis of a large graph needs far less RAM. Keep this a denylist of
# verified-unused HEAVY values only; traversal/display keys (inherited, conditional,
# condition_expr_raw, role_name, project_id, *scope*, permission_source_summary, …) are kept.
_UNUSED_HEAVY_PROPS = frozenset({"rule_description", "example_command", "permissions"})

# Binding nodes are intermediates collapsed at render time.
BINDING_KINDS = frozenset({"GCPIamSimpleBinding", "GCPIamMultiBinding"})

# Edges that attach a principal to a binding node (the "has this role" half).
GRANT_EDGE_KINDS = frozenset({"HAS_IAM_BINDING", "HAS_COMBO_BINDING", "HasImpliedPermissions"})

# Basic roles, ranked by privilege level (owner > editor > viewer).
BASIC_ROLE_RANK: dict[str, int] = {"roles/owner": 3, "roles/editor": 2, "roles/viewer": 1}

# Top-down containment (Project -> child resource). Semantically true but it
# multiplies path counts enormously, so traversal skips it unless asked.
CONTAINMENT_EDGE_KINDS = frozenset({"ExistsInProject"})

# Scope (hierarchy) resource node kinds.
SCOPE_RESOURCE_KINDS = frozenset({"GCPOrganization", "GCPFolder", "GCPProject"})

# Placeholder values that stand in for "no id" on a node (e.g. an org/folder has no
# project_id, stored as "N/A"). These are NOT scope identifiers and must never be
# tokenized -- splitting "N/A" on "/" yields the junk token "a", which would otherwise
# make every org/folder match every other under --at-scope.
_NON_SCOPE_VALUES = frozenset({"", "n/a", "na", "none", "null", "-"})

# Edges INTO a scope resource node that let the source set that scope's IAM -- i.e. grant
# itself (or anyone) ANY role at that scope. A principal reaching a binding with one of these
# is "effectively owner" of the scope even without a direct roles/owner binding.
# ROLE_EDITOR is deliberately NOT here: editor cannot setIamPolicy, so it cannot grant owner.
IAM_CONTROL_EDGE_KINDS = frozenset({
    "ROLE_OWNER",
    "CAN_MODIFY_ORG_IAM", "CAN_MODIFY_FOLDER_IAM", "CAN_MODIFY_PROJECT_IAM",
    "CAN_CREATE_ACCESS_POLICY_BINDING_ORG", "CAN_CREATE_ACCESS_POLICY_BINDING_FOLDER",
    "CAN_CREATE_ACCESS_POLICY_BINDING_PROJECT",
    "CAN_UPDATE_ACCESS_POLICY_BINDING_ORG", "CAN_UPDATE_ACCESS_POLICY_BINDING_FOLDER",
    "CAN_UPDATE_ACCESS_POLICY_BINDING_PROJECT",
})

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
        # Broadest-principal node for an open group (whoCanJoin=ALL_IN_DOMAIN_CAN_JOIN);
        # it originates CanJoin edges and must count as a traversal start vector.
        "PrincipalsInOrg",
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
    "principals_in_org:",
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
            cls._warn_if_partial_split(target, files)
        else:
            files = [target]

        nodes: dict[str, dict] = {}
        edge_keys: set[tuple[str, str, str]] = set()
        edges: list[dict] = []

        # Pathfinding/rendering never reads these properties (verified across the whole
        # pathfinding subsystem). They are the heaviest values the exporter stamps on every
        # dangerous/combo edge+node (a full rule description, an example command, the permission
        # list), so dropping them from the RETAINED in-memory graph cuts the text-analysis
        # footprint by roughly the combined size of those strings -- without changing any path,
        # edge, node, or displayed field. Split parts keep per-file json.load bounded; this keeps
        # the merged graph small too.
        drop = _UNUSED_HEAVY_PROPS

        def _slim(props: dict) -> dict:
            if not props:
                return {}
            return {k: v for k, v in props.items() if k not in drop}

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
                    "properties": _slim(node.get("properties") or {}),
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
                        "properties": _slim(edge.get("properties") or {}),
                    }
                )
            # Release this file's fully-parsed payload before the next part is read.
            del payload, graph

        # Edges may reference nodes that were trimmed from the export; keep them
        # as placeholders so traversal does not have to special-case lookups.
        for edge in edges:
            for endpoint in (edge["start"], edge["end"]):
                if endpoint not in nodes:
                    nodes[endpoint] = {"id": endpoint, "kinds": [], "kind": "Unknown", "properties": {}}

        return cls(nodes, edges, sources_loaded=[str(f) for f in files])

    @staticmethod
    def _warn_if_partial_split(directory: Path, loaded_files: list[Path]) -> None:
        """Warn (stderr) when a directory load is missing sections the split manifest expected.

        ``--split-json-output`` writes a ``*_split_manifest.json`` listing every section's part
        files. Loading a directory that holds only SOME of those parts (a hand-picked subset, an
        interrupted export) otherwise analyzes as if complete and silently UNDER-reports paths.
        Surfaces that instead of failing silently; absence of a manifest means a plain single-file
        or non-split directory, which is fine."""
        manifest = next(iter(sorted(directory.rglob("*_split_manifest.json"))), None)
        if manifest is None:
            return
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        sections = data.get("sections")
        if not isinstance(sections, dict) or not sections:
            return
        loaded_names = {p.name for p in loaded_files}
        missing = [
            str(section)
            for section, info in sections.items()
            if isinstance(info, dict)
            and (basenames := {Path(str(f)).name for f in (info.get("files") or [])})
            and not (basenames & loaded_names)
        ]
        if missing:
            print(
                f"[!] Partial split load: manifest lists {len(sections)} section(s) but "
                f"{len(missing)} are not present on disk ({', '.join(sorted(missing))}). "
                "Attack-path results will UNDER-report; load the full split export or re-run "
                "process_og_gcpwn_data.",
                file=sys.stderr,
            )

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
        return node_id.startswith("cap:new:")

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

    def scope_matches(self, node_id: str, scope: str, *, exact: bool = False) -> bool:
        """True when a node sits at or under ``scope`` (a project/folder/org).

        With ``exact=True``, match only nodes whose OWN scope is ``scope`` — not grants/resources
        inherited into descendants. The node's own scope is the effective-scope leaf in its node id
        (before any ``#src:`` inherited-source suffix), so an org's own binding
        (``...@org:123``) matches ``organizations/123`` while that same grant inherited into a
        project (``...@project:p1#src:org:123``) does not.

        Accepts any of the forms a user naturally types for the same scope:
        ``projects/my-proj`` (the documented form), the bare id ``my-proj``, the
        project number ``projects/799...``/``799...``, the node-id form
        ``project:my-proj``, and the folder/organization equivalents. Matching is
        segment-exact (not a raw substring), so ``my-proj`` does not spuriously
        match ``my-proj-2``, and a binding's own scope id in its node id is matched
        even when its stored ``attached_scope_id`` uses the numeric form.
        """
        if not scope or not scope.strip():
            return True
        want = scope.strip().lower()
        for prefix in (
            # Accept both the plural ("projects/") and the easy-to-mistype singular
            # ("project/") forms; the bare id and the node-id colon forms also work.
            "projects/", "project/", "folders/", "folder/",
            "organizations/", "organization/",
            "project:", "folder:", "org:", "organization:",
        ):
            if want.startswith(prefix):
                want = want[len(prefix):]
                break
        want = want.strip("/")
        if not want:
            return True

        # own_tokens identify the node's OWN scope; ancestor_tokens add the scopes it sits UNDER
        # (inherited-source ancestors, container project, etc.). Exact matching uses only own_tokens.
        own_tokens: set[str] = set()
        ancestor_tokens: set[str] = set()
        # The binding/resource node id carries its own scope as ``...@<type>:<leaf>``
        # (optionally ``#src:...`` for an inherited grant). The leaf is the scope id
        # (e.g. the project id), which is what a user types -- and is present even when
        # attached_scope_id stores the numeric form.
        lowered_id = node_id.lower()
        at_index = lowered_id.rfind("@")
        inherited = False
        if at_index != -1:
            tail_full = lowered_id[at_index + 1:]
            inherited = "#" in tail_full
            tail = tail_full.split("#", 1)[0]
            if ":" in tail:
                own_tokens.add(tail.split(":", 1)[1])
        # A resource node id is ``resource:<leaf>[@<project>]`` -- its leaf IS its own scope
        # (e.g. the org/folder/project id). Binding nodes use ``...@<type>:<leaf>`` and are handled
        # above; without this, exact matching never identifies a scope RESOURCE node (e.g. the org
        # node ``resource:358690432006``), so --exact-scope would skip it.
        if lowered_id.startswith("resource:"):
            own_tokens.add(lowered_id[len("resource:"):].split("@", 1)[0])
        # A scope RESOURCE node (org/folder/project) IS its own scope, so its id properties
        # (project_id/name, which carry the human id alongside the numeric leaf in the node id)
        # describe the node itself -- they belong in own_tokens so --exact-scope matches the
        # project by name, not only by number.
        is_scope_resource = lowered_id.startswith("resource:") or self.kind_of(node_id) in SCOPE_RESOURCE_KINDS
        properties = self.props(node_id)
        for key in ("attached_scope_id", "effective_scope_id", "effective_scope_ids", "project_id", "name"):
            value = properties.get(key)
            values = value if isinstance(value, (list, tuple)) else [value]
            for item in values:
                if not item or str(item).strip().lower() in _NON_SCOPE_VALUES:
                    continue
                for segment in str(item).lower().split("/"):
                    if not segment:
                        continue
                    # For a directly-attached grant (no inherited source), attached/effective
                    # scope IS the node's own scope (covers the numeric form of the id). For an
                    # inherited grant these keys point at ancestors/the source scope.
                    if is_scope_resource:
                        own_tokens.add(segment)
                    elif key in ("attached_scope_id", "effective_scope_id") and not inherited:
                        own_tokens.add(segment)
                    else:
                        ancestor_tokens.add(segment)
        tokens = own_tokens if exact else (own_tokens | ancestor_tokens)
        # A project/folder/org has two interchangeable ids -- its name (project_id) and its
        # number. Different node types record one or the other (a binding on an SA carries the
        # project name in its resource path; a project resource node carries the number in its
        # id), so a query by one form must also match tokens recorded in the other. Expand the
        # wanted scope to both forms via the graph's name<->number map.
        wants = {want} | self._scope_alias_map.get(want, frozenset())
        return bool(wants & tokens)

    @property
    def _scope_alias_map(self) -> dict[str, frozenset[str]]:
        """name <-> number aliases for every org/folder/project in the graph, so --at-scope by
        name and by number are equivalent. Built once from the scope resource nodes."""
        cached = getattr(self, "_scope_alias_cache", None)
        if cached is not None:
            return cached
        aliases: dict[str, set[str]] = {}
        for node_id, node in self.nodes.items():
            if node["kind"] not in SCOPE_RESOURCE_KINDS:
                continue
            forms: set[str] = set()
            if node_id.startswith("resource:"):
                forms.add(node_id[len("resource:"):].split("@", 1)[0].lower())
            for key in ("project_id", "attached_scope_id"):
                value = node["properties"].get(key)
                if value and str(value).strip().lower() not in _NON_SCOPE_VALUES:
                    forms.add(str(value).rsplit("/", 1)[-1].lower())
            for form in forms:
                aliases.setdefault(form, set()).update(forms - {form})
        frozen = {k: frozenset(v) for k, v in aliases.items()}
        self._scope_alias_cache = frozen
        return frozen

    def basic_roles_held(self, node_id: str) -> frozenset[tuple[str, str | None]]:
        """(role, scope) pairs for basic roles node_id directly holds via IAM binding edges."""
        held: set[tuple[str, str | None]] = set()
        for neighbor, edge_index in self.adj.get(node_id, []):
            if self.edges[edge_index]["kind"] not in GRANT_EDGE_KINDS:
                continue
            if not self.is_binding(neighbor):
                continue
            role = self.role_of_binding(neighbor)
            if role and role in BASIC_ROLE_RANK:
                held.add((role, self.scope_of_binding(neighbor)))
        return frozenset(held)

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

    def iam_control_sources(self, *, scope: str | None = None, exact: bool = False) -> set[str]:
        """Binding nodes that can SET a scope's IAM (and so grant themselves any role there).

        Returns the source node of every ``IAM_CONTROL_EDGE_KINDS`` edge pointing at a scope
        (org/folder/project) resource node, optionally restricted to ``scope`` (and ``exact``).
        Used so a ``--to-role roles/owner`` query also surfaces principals who reach the role
        indirectly via setIamPolicy / policy-binding, not only direct holders. ROLE_EDITOR is not
        an IAM-control edge, so editor-only holders are excluded.
        """
        sources: set[str] = set()
        for node_id in self.nodes:
            if self.kind_of(node_id) not in SCOPE_RESOURCE_KINDS:
                continue
            if scope and not self.scope_matches(node_id, scope, exact=exact):
                continue
            for predecessor, edge_index in self.radj.get(node_id, ()):
                if self.edges[edge_index]["kind"] in IAM_CONTROL_EDGE_KINDS:
                    sources.add(predecessor)
        return sources
