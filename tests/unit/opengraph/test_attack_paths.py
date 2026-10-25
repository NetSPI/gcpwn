"""Tests for the text-based attack-path analysis over exported OpenGraph JSON.

These exercise the consumer side only: the pathfinder reads the emitted JSON and
must never need the pipeline or DB. Fixtures below hand-build graphs in the exact
shape ``process_og_gcpwn_data`` emits (principal -> binding -> target, plus
synthetic ``CAP:`` capability nodes for combo rules).
"""

from __future__ import annotations

import json

import pytest

from gcpwn.modules.opengraph.utilities.helpers.pathfinding.model import AttackGraph
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.render import (
    collapse_path,
    describe_target,
    render_report,
)
from gcpwn.modules.opengraph.utilities.helpers.pathfinding.search import (
    enumerate_paths,
    path_signature,
    resolve_targets,
    shortest_paths,
)


def _node(node_id, kind, props=None):
    return {"id": node_id, "kinds": [kind, "GCPResource"], "properties": props or {}}


def _edge(start, end, kind, props=None):
    return {
        "start": {"match_by": "id", "value": start},
        "end": {"match_by": "id", "value": end},
        "kind": kind,
        "properties": props or {},
    }


def _binding(node_id, role, scope, scope_type="project", **extra):
    return _node(
        node_id,
        "GCPIamSimpleBinding",
        {"role_name": role, "attached_scope_id": scope, "attached_scope_type": scope_type, **extra},
    )


def _write(tmp_path, nodes, edges, name="graph.json"):
    payload = {"metadata": {"source_kind": "GCPBase"}, "graph": {"nodes": nodes, "edges": edges}}
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# alice --owner binding--> project   (direct — 0 attack hops; alice already holds the role)
# svc-a --tokenCreator--> svc-b --owner binding--> project   (1 attack hop)
@pytest.fixture
def chain_graph(tmp_path):
    nodes = [
        _node("user:alice@corp.com", "GoogleUser"),
        _node("serviceAccount:svc-a@proj.iam.gserviceaccount.com", "GCPServiceAccount"),
        _node("serviceAccount:svc-b@proj.iam.gserviceaccount.com", "GCPServiceAccount"),
        _node("resource:proj", "GCPProject", {"project_id": "proj", "name": "proj"}),
        _binding("iambinding:roles/owner@project:proj", "roles/owner", "projects/proj"),
        _binding(
            "iambinding:roles/iam.serviceAccountTokenCreator@sa:svc-b",
            "roles/iam.serviceAccountTokenCreator",
            "projects/proj/serviceAccounts/svc-b@proj.iam.gserviceaccount.com",
            scope_type="service-account",
        ),
    ]
    edges = [
        _edge("user:alice@corp.com", "iambinding:roles/owner@project:proj", "HAS_IAM_BINDING"),
        _edge("iambinding:roles/owner@project:proj", "resource:proj", "ROLE_OWNER"),
        _edge(
            "serviceAccount:svc-a@proj.iam.gserviceaccount.com",
            "iambinding:roles/iam.serviceAccountTokenCreator@sa:svc-b",
            "HAS_IAM_BINDING",
        ),
        _edge(
            "iambinding:roles/iam.serviceAccountTokenCreator@sa:svc-b",
            "serviceAccount:svc-b@proj.iam.gserviceaccount.com",
            "CAN_CREATE_SA_ACCESS_TOKEN",
        ),
        _edge(
            "serviceAccount:svc-b@proj.iam.gserviceaccount.com",
            "iambinding:roles/owner@project:proj",
            "HAS_IAM_BINDING",
        ),
    ]
    return AttackGraph.from_path(_write(tmp_path, nodes, edges))


class TestLoading:
    def test_loads_single_file(self, chain_graph):
        assert len(chain_graph.nodes) == 6
        assert len(chain_graph.edges) == 5

    def test_loads_and_merges_split_directory(self, tmp_path):
        """A split export is several files plus a manifest; the manifest is skipped."""
        part_dir = tmp_path / "split_json"
        part_dir.mkdir()
        _write(part_dir, [_node("user:a@x.com", "GoogleUser")], [], name="part_1.json")
        _write(
            part_dir,
            [_binding("iambinding:roles/owner@project:p", "roles/owner", "projects/p")],
            [_edge("user:a@x.com", "iambinding:roles/owner@project:p", "HAS_IAM_BINDING")],
            name="part_2.json",
        )
        (part_dir / "graph_split_manifest.json").write_text(
            json.dumps({"sections": {"bogus": "ignored"}}), encoding="utf-8"
        )

        graph = AttackGraph.from_path(part_dir)
        assert "user:a@x.com" in graph.nodes
        assert len(graph.edges) == 1
        assert len(graph.sources_loaded) == 2

    def test_deduplicates_repeated_nodes_and_edges(self, tmp_path):
        node = _node("user:a@x.com", "GoogleUser")
        edge = _edge("user:a@x.com", "user:a@x.com", "SELF")
        graph = AttackGraph.from_path(_write(tmp_path, [node, node], [edge, edge]))
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1

    def test_missing_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            AttackGraph.from_path(tmp_path / "nope.json")

    def test_edge_endpoint_missing_from_nodes_becomes_placeholder(self, tmp_path):
        """Trimmed exports can reference absent nodes; traversal must still work."""
        graph = AttackGraph.from_path(
            _write(tmp_path, [_node("user:a@x.com", "GoogleUser")], [_edge("user:a@x.com", "ghost", "X")])
        )
        assert graph.kind_of("ghost") == "Unknown"


class TestTargetResolution:
    def test_matches_role_exactly_and_by_short_name(self, chain_graph):
        assert len(resolve_targets(chain_graph, roles=["roles/owner"]).node_ids) == 1
        assert len(resolve_targets(chain_graph, roles=["owner"]).node_ids) == 1

    def test_unknown_role_matches_nothing(self, chain_graph):
        assert resolve_targets(chain_graph, roles=["roles/nope"]).node_ids == set()

    def test_service_account_substring(self, chain_graph):
        assert resolve_targets(chain_graph, service_accounts=["svc-b"]).node_ids == {
            "serviceAccount:svc-b@proj.iam.gserviceaccount.com"
        }

    def test_kind_selector(self, chain_graph):
        assert resolve_targets(chain_graph, kinds=["GCPProject"]).node_ids == {"resource:proj"}

    def test_scope_filter_narrows_targets(self, chain_graph):
        assert resolve_targets(chain_graph, roles=["roles/owner"], scope="projects/proj").node_ids
        assert not resolve_targets(chain_graph, roles=["roles/owner"], scope="projects/other").node_ids

    def test_scope_accepts_singular_project_prefix(self, chain_graph):
        """The easy-to-mistype singular 'project/' prefix works like 'projects/' and bare id."""
        for scope in ("projects/proj", "project/proj", "proj"):
            assert resolve_targets(chain_graph, roles=["roles/owner"], scope=scope).node_ids, scope

    def test_inherited_target_is_labeled_distinctly_from_direct(self, tmp_path):
        """A direct grant and an org-inherited grant on the same project are different nodes;
        the inherited one names its source so it isn't a confusing duplicate."""
        nodes = [
            _binding("iambinding:roles/owner@project:p1", "roles/owner", "projects/p1"),
            _binding("iambinding:roles/owner@project:p1#src:org:123", "roles/owner", "projects/p1",
                     inherited=True, source_scope_id="organizations/123"),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, []))
        direct = describe_target(graph, "iambinding:roles/owner@project:p1")
        inherited = describe_target(graph, "iambinding:roles/owner@project:p1#src:org:123")
        assert direct != inherited
        assert "inherited from organizations/123" in inherited
        assert "inherited" not in direct

    def test_scope_matches_project_by_name_and_number_equivalently(self, tmp_path):
        """A project's name and number are interchangeable: a query by either must return the
        same targets, even for bindings that record only one form (e.g. an SA-scoped binding whose
        path carries the project name, matched against a query by the project number)."""
        nodes = [
            _node("resource:999@999", "GCPProject", {"project_id": "my-proj"}),
            # binding on a service account -- its attached scope path carries the project NAME only
            _binding(
                "iambinding:roles/iam.serviceAccountAdmin@service-account:sa@my-proj.iam.gserviceaccount.com",
                "roles/iam.serviceAccountAdmin",
                "projects/my-proj/serviceAccounts/sa@my-proj.iam.gserviceaccount.com",
                scope_type="service-account",
            ),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, []))
        b = "iambinding:roles/iam.serviceAccountAdmin@service-account:sa@my-proj.iam.gserviceaccount.com"
        for exact in (False, True):
            assert graph.scope_matches(b, "my-proj", exact=exact) == graph.scope_matches(b, "999", exact=exact)
        # and it does match (by both forms)
        assert graph.scope_matches(b, "my-proj")
        assert graph.scope_matches(b, "999")

    def test_exact_scope_matches_project_resource_node_by_name(self, tmp_path):
        """--exact-scope on a project must match the project resource node by its id/name, not only
        its number -- otherwise iam_control_sources drops setIamPolicy bindings on it."""
        nodes = [
            _node("resource:12345@12345", "GCPProject", {"project_id": "my-proj-id"}),
            _binding("iambinding:roles/resourcemanager.projectIamAdmin@project:my-proj-id",
                     "roles/resourcemanager.projectIamAdmin", "projects/my-proj-id"),
        ]
        edges = [_edge("iambinding:roles/resourcemanager.projectIamAdmin@project:my-proj-id",
                       "resource:12345@12345", "CAN_MODIFY_PROJECT_IAM")]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        # Project node matches by name and number under exact.
        assert graph.scope_matches("resource:12345@12345", "my-proj-id", exact=True)
        assert graph.scope_matches("resource:12345@12345", "12345", exact=True)
        # So the setIamPolicy binding is surfaced under --exact-scope by name.
        assert graph.iam_control_sources(scope="my-proj-id", exact=True)

    def test_exact_scope_matches_only_own_scope(self, tmp_path):
        # An org-level owner binding, plus that same org grant inherited down into a project.
        nodes = [
            _node("user:a@x.com", "GoogleUser"),
            _binding("iambinding:roles/owner@org:123", "roles/owner", "organizations/123",
                     scope_type="organization"),
            _binding("iambinding:roles/owner@project:p2#src:org:123", "roles/owner", "projects/p2",
                     inherited=True, source_scope_id="organizations/123",
                     effective_scope_ids=["projects/p2", "organizations/123"]),
        ]
        edges = [
            _edge("user:a@x.com", "iambinding:roles/owner@org:123", "HAS_IAM_BINDING"),
            _edge("user:a@x.com", "iambinding:roles/owner@project:p2#src:org:123", "HAS_IAM_BINDING"),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        # default (at-or-under): the org's own binding AND the grant inherited into the project.
        broad = resolve_targets(graph, roles=["roles/owner"], scope="organizations/123").node_ids
        assert broad == {
            "iambinding:roles/owner@org:123",
            "iambinding:roles/owner@project:p2#src:org:123",
        }
        # --exact-scope: only the org's OWN binding, not the inherited-into-project one.
        exact = resolve_targets(
            graph, roles=["roles/owner"], scope="organizations/123", scope_exact=True
        ).node_ids
        assert exact == {"iambinding:roles/owner@org:123"}
        assert exact <= broad  # exact never matches more than the broad set

class TestShortestPaths:
    def test_finds_direct_and_chained_principals(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        paths = shortest_paths(chain_graph, targets)
        by_source = {p.source: p for p in paths}

        assert "user:alice@corp.com" in by_source
        assert "serviceAccount:svc-a@proj.iam.gserviceaccount.com" in by_source
        # alice holds owner directly; svc-a must pivot through svc-b first.
        assert len(collapse_path(chain_graph, by_source["user:alice@corp.com"])) == 1
        assert len(collapse_path(chain_graph, by_source["serviceAccount:svc-a@proj.iam.gserviceaccount.com"])) == 2

    def test_results_are_ordered_shortest_first(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        lengths = [len(p.edge_indices) for p in shortest_paths(chain_graph, targets)]
        assert lengths == sorted(lengths)

    def test_max_depth_excludes_longer_chains(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        sources = {p.source for p in shortest_paths(chain_graph, targets, max_depth=1)}
        # svc-a needs 3 raw edges; only the direct holder fits in depth 1.
        assert sources == {"user:alice@corp.com", "serviceAccount:svc-b@proj.iam.gserviceaccount.com"}

    def test_source_filter_restricts_results(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        paths = shortest_paths(chain_graph, targets, sources=["user:alice@corp.com"])
        assert [p.source for p in paths] == ["user:alice@corp.com"]

    def test_unreachable_target_yields_nothing(self, chain_graph):
        assert shortest_paths(chain_graph, {"resource:nonexistent"}) == []


class TestCollapse:
    def test_capability_nodes_do_not_inflate_hop_count(self, tmp_path):
        """A combo rule inserts a synthetic CAP: node; it is plumbing, not a hop."""
        nodes = [
            _node("serviceAccount:attacker@p.iam.gserviceaccount.com", "GCPServiceAccount"),
            _node("serviceAccount:victim@p.iam.gserviceaccount.com", "GCPServiceAccount"),
            _node("combo_iambinding:CREATE_CLOUDBUILD_BUILD_AS_SA@mixed#abc", "GCPIamMultiBinding",
                  {"role_name": "combo:CREATE_CLOUDBUILD_BUILD_AS_SA", "attached_scope_id": "projects/p"}),
            _node("cap:new:CloudBuildBuild@mixed#abc12345", "GCPIamCapability"),
        ]
        edges = [
            _edge("serviceAccount:attacker@p.iam.gserviceaccount.com",
                  "combo_iambinding:CREATE_CLOUDBUILD_BUILD_AS_SA@mixed#abc", "HAS_COMBO_BINDING"),
            _edge("combo_iambinding:CREATE_CLOUDBUILD_BUILD_AS_SA@mixed#abc",
                  "cap:new:CloudBuildBuild@mixed#abc12345", "CREATE_CLOUDBUILD_BUILD_AS_SA"),
            _edge("cap:new:CloudBuildBuild@mixed#abc12345",
                  "serviceAccount:victim@p.iam.gserviceaccount.com", "CREATE_CLOUDBUILD_BUILD_AS_SA"),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        paths = shortest_paths(graph, {"serviceAccount:victim@p.iam.gserviceaccount.com"})

        [path] = [p for p in paths if p.source.endswith("attacker@p.iam.gserviceaccount.com")]
        hops = collapse_path(graph, path)
        # 3 raw edges through binding + CAP collapse to a single identity hop.
        assert len(path.edge_indices) == 3
        assert len(hops) == 1
        assert hops[0].dst == "serviceAccount:victim@p.iam.gserviceaccount.com"
        assert hops[0].role == "combo:CREATE_CLOUDBUILD_BUILD_AS_SA"

    def test_terminal_binding_is_reported_as_acquiring_the_role(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        [path] = [p for p in shortest_paths(chain_graph, targets) if p.source == "user:alice@corp.com"]
        hops = collapse_path(chain_graph, path)
        assert hops[-1].acquires_role is True
        assert hops[-1].role == "roles/owner"

    def test_inherited_binding_records_its_origin(self, tmp_path):
        nodes = [
            _node("user:a@x.com", "GoogleUser"),
            _binding("iambinding:roles/owner@folder:1#src:org:9", "roles/owner", "folders/1",
                     scope_type="folder", inherited=True, source_scope_id="organizations/9"),
        ]
        edges = [_edge("user:a@x.com", "iambinding:roles/owner@folder:1#src:org:9", "HAS_IAM_BINDING")]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        targets = resolve_targets(graph, roles=["roles/owner"]).node_ids
        [path] = shortest_paths(graph, targets)
        assert collapse_path(graph, path)[-1].inherited_from == "organizations/9"


class TestEnumerate:
    def test_yields_paths_shortest_first(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        found, _ = enumerate_paths(chain_graph, targets, max_depth=8)
        lengths = [len(p.edge_indices) for p in found]
        assert lengths == sorted(lengths)

    def test_max_paths_truncates_and_flags_it(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        found, truncated = enumerate_paths(chain_graph, targets, max_depth=8, max_paths=1)
        assert len(found) == 1
        assert truncated is True

    def test_expansion_budget_terminates(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        _, truncated = enumerate_paths(chain_graph, targets, max_depth=8, max_expansions=0)
        assert truncated is True

    def test_cycles_do_not_hang(self, tmp_path):
        """Mutual impersonation is common in real orgs; paths must stay simple."""
        nodes = [
            _node("serviceAccount:a@p.iam.gserviceaccount.com", "GCPServiceAccount"),
            _node("serviceAccount:b@p.iam.gserviceaccount.com", "GCPServiceAccount"),
            _binding("iambinding:tc@sa:a", "roles/iam.serviceAccountTokenCreator",
                     "projects/p/serviceAccounts/a@p.iam.gserviceaccount.com", scope_type="service-account"),
            _binding("iambinding:tc@sa:b", "roles/iam.serviceAccountTokenCreator",
                     "projects/p/serviceAccounts/b@p.iam.gserviceaccount.com", scope_type="service-account"),
        ]
        edges = [
            _edge("serviceAccount:a@p.iam.gserviceaccount.com", "iambinding:tc@sa:b", "HAS_IAM_BINDING"),
            _edge("iambinding:tc@sa:b", "serviceAccount:b@p.iam.gserviceaccount.com", "CAN_IMPERSONATE_SA"),
            _edge("serviceAccount:b@p.iam.gserviceaccount.com", "iambinding:tc@sa:a", "HAS_IAM_BINDING"),
            _edge("iambinding:tc@sa:a", "serviceAccount:a@p.iam.gserviceaccount.com", "CAN_IMPERSONATE_SA"),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        found, _ = enumerate_paths(graph, {"serviceAccount:b@p.iam.gserviceaccount.com"}, max_depth=10)
        for path in found:
            assert len(set(path.nodes)) == len(path.nodes)

    def test_signature_collapses_equivalent_bindings(self, tmp_path):
        """Two bindings granting the same role at the same scope are one finding."""
        nodes = [
            _node("user:a@x.com", "GoogleUser"),
            _node("serviceAccount:t@p.iam.gserviceaccount.com", "GCPServiceAccount"),
            _binding("iambinding:dup-1", "roles/iam.serviceAccountTokenCreator", "projects/p",
                     scope_type="service-account"),
            _binding("iambinding:dup-2", "roles/iam.serviceAccountTokenCreator", "projects/p",
                     scope_type="service-account"),
        ]
        edges = [
            _edge("user:a@x.com", "iambinding:dup-1", "HAS_IAM_BINDING"),
            _edge("iambinding:dup-1", "serviceAccount:t@p.iam.gserviceaccount.com", "CAN_IMPERSONATE_SA"),
            _edge("user:a@x.com", "iambinding:dup-2", "HAS_IAM_BINDING"),
            _edge("iambinding:dup-2", "serviceAccount:t@p.iam.gserviceaccount.com", "CAN_IMPERSONATE_SA"),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        found, _ = enumerate_paths(graph, {"serviceAccount:t@p.iam.gserviceaccount.com"}, max_depth=6)
        assert len(found) == 2
        assert len({path_signature(graph, p) for p in found}) == 1


class TestContainment:
    @pytest.fixture
    def bucket_graph(self, tmp_path):
        nodes = [
            _node("user:a@x.com", "GoogleUser"),
            _node("resource:proj", "GCPProject", {"project_id": "proj"}),
            _node("resource:proj/buckets/data", "GCPBucket"),
            _binding("iambinding:roles/owner@project:proj", "roles/owner", "projects/proj"),
        ]
        edges = [
            _edge("user:a@x.com", "iambinding:roles/owner@project:proj", "HAS_IAM_BINDING"),
            _edge("iambinding:roles/owner@project:proj", "resource:proj", "ROLE_OWNER"),
            _edge("resource:proj", "resource:proj/buckets/data", "ExistsInProject"),
        ]
        return AttackGraph.from_path(_write(tmp_path, nodes, edges))

    def test_containment_not_followed_by_default(self, bucket_graph):
        assert shortest_paths(bucket_graph, {"resource:proj/buckets/data"}) == []

    def test_containment_followed_when_requested(self, bucket_graph):
        paths = shortest_paths(bucket_graph, {"resource:proj/buckets/data"}, include_containment=True)
        assert [p.source for p in paths] == ["user:a@x.com"]


class TestConfigSummary:
    def test_detects_inheritance_and_conditionals(self, tmp_path):
        nodes = [
            _node("user:a@x.com", "GoogleUser"),
            _binding("iambinding:roles/owner@folder:1#src:org:9#cond:abc123", "roles/owner", "folders/1",
                     inherited=True, conditional=True, source_scope_id="organizations/9"),
        ]
        edges = [_edge("user:a@x.com", "iambinding:roles/owner@folder:1#src:org:9#cond:abc123",
                       "HAS_IAM_BINDING", {"inherited": True, "conditional": True})]
        config = AttackGraph.from_path(_write(tmp_path, nodes, edges)).config_summary()
        assert config["inheritance_expanded"] is True
        assert config["conditional_bindings"] is True

    def test_clean_graph_reports_no_inheritance(self, chain_graph):
        config = chain_graph.config_summary()
        assert config["inheritance_expanded"] is False
        assert config["conditional_bindings"] is False
        assert config["cross_project_actas"] is False

    def test_cross_project_actas_detected_between_real_projects(self, tmp_path):
        nodes = [
            _node("serviceAccount:a@proj-one.iam.gserviceaccount.com", "GCPServiceAccount"),
            _node("resource:proj-one", "GCPProject", {"project_id": "proj-one"}),
            _node("resource:proj-two", "GCPProject", {"project_id": "proj-two"}),
            _binding("iambinding:tc@sa:b", "roles/iam.serviceAccountTokenCreator",
                     "projects/proj-two/serviceAccounts/b@proj-two.iam.gserviceaccount.com",
                     scope_type="service-account"),
        ]
        edges = [_edge("serviceAccount:a@proj-one.iam.gserviceaccount.com", "iambinding:tc@sa:b",
                       "HAS_IAM_BINDING")]
        config = AttackGraph.from_path(_write(tmp_path, nodes, edges)).config_summary()
        assert config["cross_project_actas"] is True
        assert config["cross_project_actas_pairs"] == ["proj-one -> proj-two"]

    def test_project_number_is_not_mistaken_for_another_project(self, tmp_path):
        """A principalSet keyed by project NUMBER is the same project, not a second one."""
        nodes = [
            _node("principalSet://iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/p/*",
                  "GCPPrincipalSet"),
            _node("resource:proj-one", "GCPProject", {"project_id": "proj-one"}),
            _binding("iambinding:tc@sa:b", "roles/iam.workloadIdentityUser",
                     "projects/proj-one/serviceAccounts/b@proj-one.iam.gserviceaccount.com",
                     scope_type="service-account"),
        ]
        edges = [_edge(
            "principalSet://iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/p/*",
            "iambinding:tc@sa:b", "HAS_IAM_BINDING")]
        config = AttackGraph.from_path(_write(tmp_path, nodes, edges)).config_summary()
        assert config["cross_project_actas"] is False

    def test_service_agent_tenant_is_not_mistaken_for_a_project(self, tmp_path):
        """gcp-sa-* is a Google-owned tenant domain, not a project in this graph."""
        nodes = [
            _node("serviceAccount:service-1@gcp-sa-aiplatform.iam.gserviceaccount.com",
                  "GCPServiceAccount", {"is_service_agent": True}),
            _node("resource:proj-one", "GCPProject", {"project_id": "proj-one"}),
            _binding("iambinding:tc@sa:b", "roles/aiplatform.serviceAgent",
                     "projects/proj-one/serviceAccounts/b@proj-one.iam.gserviceaccount.com",
                     scope_type="service-account"),
        ]
        edges = [_edge("serviceAccount:service-1@gcp-sa-aiplatform.iam.gserviceaccount.com",
                       "iambinding:tc@sa:b", "HAS_IAM_BINDING")]
        config = AttackGraph.from_path(_write(tmp_path, nodes, edges)).config_summary()
        assert config["cross_project_actas"] is False
        assert config["service_agent_count"] == 1

    def test_capability_nodes_are_not_counted_as_projects(self, tmp_path):
        """CAP: nodes reuse resource kinds such as GCPProject but are not projects."""
        nodes = [
            _node("CAP:SOME_RULE@mixed:hop_1#abc", "GCPProject", {"effective_scope_id": "MULTI_SCOPE"}),
            _node("resource:real-proj", "GCPProject", {"project_id": "real-proj"}),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, []))
        assert graph.known_project_ids() == {"real-proj"}


class TestServiceAgents:
    def test_service_agents_can_be_excluded_as_sources(self, tmp_path):
        nodes = [
            _node("serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com", "GCPServiceAccount",
                  {"is_service_agent": True}),
            _node("user:real@corp.com", "GoogleUser"),
            _binding("iambinding:roles/owner@project:p", "roles/owner", "projects/p"),
        ]
        edges = [
            _edge("serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com",
                  "iambinding:roles/owner@project:p", "HAS_IAM_BINDING"),
            _edge("user:real@corp.com", "iambinding:roles/owner@project:p", "HAS_IAM_BINDING"),
        ]
        graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
        targets = resolve_targets(graph, roles=["roles/owner"]).node_ids

        assert len(shortest_paths(graph, targets)) == 2
        filtered = shortest_paths(graph, targets, exclude_service_agents=True)
        assert [p.source for p in filtered] == ["user:real@corp.com"]


class TestRender:
    _RENDER_KWARGS = {
        "compact", "expand", "truncated", "detail_limit", "summary_only",
        "iam_control_targets", "iam_control_note",
    }

    def _report(self, graph, paths, **overrides):
        render_kwargs = {k: overrides.pop(k) for k in list(overrides) if k in self._RENDER_KWARGS}
        query = {
            "description": "role=roles/owner",
            "target_count": 1,
            "mode": "shortest-path per principal",
            "max_depth": 12,
            "include_containment": False,
            **overrides,
        }
        return render_report(graph, paths, config=graph.config_summary(), query=query, **render_kwargs)

    def test_report_contains_config_and_paths(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        report = self._report(chain_graph, shortest_paths(chain_graph, targets))
        assert "GRAPH CONFIGURATION" in report
        assert "Inheritance Expanded" in report
        assert "TARGET SUMMARY" in report
        assert "holds roles/owner" in report
        assert "user:alice@corp.com" in report

    def test_empty_result_explains_itself(self, chain_graph):
        report = self._report(chain_graph, [])
        assert "NO PATHS FOUND" in report
        assert "--max-depth" in report

    def test_detail_limit_reports_omitted_paths(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        paths = shortest_paths(chain_graph, targets)
        report = render_report(
            chain_graph, paths, config=chain_graph.config_summary(),
            query={"description": "x", "target_count": 1, "mode": "shortest-path per principal",
                   "max_depth": 12, "include_containment": False},
            detail_limit=1,
        )
        assert "further path(s) not shown" in report

    def test_summary_only_omits_individual_paths(self, chain_graph):
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        paths = shortest_paths(chain_graph, targets)
        report = render_report(
            chain_graph, paths, config=chain_graph.config_summary(),
            query={"description": "x", "target_count": 1, "mode": "shortest-path per principal",
                   "max_depth": 12, "include_containment": False},
            summary_only=True,
        )
        assert "TARGET SUMMARY" in report
        assert "ACQUIRES" not in report

    def test_short_id_shows_full_identifier(self):
        """Identifiers are shown in full (only prefixes/SA suffix stripped), so a long
        resource scope never loses its resource name."""
        from gcpwn.modules.opengraph.utilities.helpers.pathfinding.render import (
            _scope_label,
            short_id,
        )

        long_binding = (
            "iambinding:roles/secretmanager.secretAccessor@projects/"
            "my-production-project/secrets/prod-database-master-credentials"
        )
        # Full id, prefix stripped, nothing truncated.
        assert short_id(long_binding) == (
            "roles/secretmanager.secretAccessor@projects/"
            "my-production-project/secrets/prod-database-master-credentials"
        )

        gke = "projects/my-production-project/locations/us-central1/clusters/primary-gke-cluster-east"
        assert _scope_label(gke, None) == gke

        # An explicit limit still elides the MIDDLE (keeps both ends), never the tail.
        out = short_id(long_binding, limit=60)
        assert out.endswith("prod-database-master-credentials")
        assert "…" in out

        assert short_id("iambinding:roles/owner@org:123") == "roles/owner@org:123"

    def test_iam_control_target_terminal_gets_equivalence_note(self, chain_graph):
        """A path ending on an IAM-control binding (added for a basic-role query) spells out
        that the holder can grant themselves the queried role."""
        targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids
        paths = shortest_paths(chain_graph, targets)
        terminals = frozenset(p.target for p in paths)
        note = "can set this scope's IAM policy, thus able to grant themselves roles/owner (or any role)"

        with_note = self._report(chain_graph, paths, iam_control_targets=terminals, iam_control_note=note)
        assert note in with_note
        # Without declaring the terminals as IAM-control targets, the note is absent.
        without = self._report(chain_graph, paths)
        assert note not in without

    def test_service_account_email_is_shown_in_full(self, chain_graph):
        """SA emails render with their full ...gserviceaccount.com domain, so every SA
        (incl. @developer/@appspot legacy SAs) renders consistently."""
        targets = resolve_targets(chain_graph, service_accounts=["svc-b"]).node_ids
        report = self._report(chain_graph, shortest_paths(chain_graph, targets))
        assert "svc-a@proj.iam.gserviceaccount.com" in report


def test_exclude_node_drops_paths_through_it(chain_graph):
    """--exclude-node removes any path that starts at, ends at, or passes through a matched node.
    In chain_graph svc-a reaches roles/owner only via svc-b, so excluding svc-b drops svc-a's path
    while alice's direct path is untouched."""
    svc_a = "serviceAccount:svc-a@proj.iam.gserviceaccount.com"
    svc_b = "serviceAccount:svc-b@proj.iam.gserviceaccount.com"
    targets = resolve_targets(chain_graph, roles=["roles/owner"]).node_ids

    base = {p.source for p in shortest_paths(chain_graph, targets)}
    assert svc_a in base and "user:alice@corp.com" in base

    excl = frozenset({svc_b})
    pruned = {p.source for p in shortest_paths(chain_graph, targets, excluded_nodes=excl)}
    assert svc_a not in pruned          # its only route ran through svc-b
    assert "user:alice@corp.com" in pruned  # direct path unaffected

    found, _ = enumerate_paths(chain_graph, targets, excluded_nodes=excl)
    assert all(svc_b not in p.nodes for p in found)


def test_iam_control_sources_includes_setiampolicy_excludes_editor(tmp_path):
    """--to-role roles/owner must also find principals who can SET the scope's IAM (setIamPolicy /
    policy-binding = can grant themselves owner), while excluding editor-only (can't grant owner)."""
    nodes = [
        _node("resource:111", "GCPOrganization", {"name": "111"}),
        _binding("iambinding:roles/owner@org:111", "roles/owner", "organizations/111", scope_type="organization"),
        _binding("iambinding:orgiam@org:111", "projects/p/roles/orgiam", "organizations/111", scope_type="organization"),
        _binding("iambinding:roles/editor@org:111", "roles/editor", "organizations/111", scope_type="organization"),
    ]
    edges = [
        _edge("iambinding:roles/owner@org:111", "resource:111", "ROLE_OWNER"),
        _edge("iambinding:orgiam@org:111", "resource:111", "CAN_MODIFY_ORG_IAM"),
        _edge("iambinding:roles/editor@org:111", "resource:111", "ROLE_EDITOR"),
    ]
    graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
    sources = graph.iam_control_sources(scope="organizations/111")
    assert "iambinding:orgiam@org:111" in sources        # setIamPolicy -> can grant owner
    assert "iambinding:roles/owner@org:111" in sources    # ROLE_OWNER -> holds/grants owner
    assert "iambinding:roles/editor@org:111" not in sources  # editor cannot grant owner
    # scoped to a different org -> nothing
    assert graph.iam_control_sources(scope="organizations/999") == set()


def test_exact_scope_matches_a_scope_resource_node(tmp_path):
    """--exact-scope must identify a scope RESOURCE node (resource:<leaf>), not only binding nodes --
    otherwise iam_control_sources/targeting skips the scope entirely under --exact-scope."""
    nodes = [
        _node("resource:111", "GCPOrganization", {"name": "111"}),
        _node("resource:proj-a@proj-a", "GCPProject", {"name": "proj-a", "project_id": "proj-a"}),
    ]
    graph = AttackGraph.from_path(_write(tmp_path, nodes, []))
    assert graph.scope_matches("resource:111", "organizations/111", exact=True)
    assert graph.scope_matches("resource:proj-a@proj-a", "projects/proj-a", exact=True)
    assert not graph.scope_matches("resource:111", "organizations/999", exact=True)


def test_iam_control_sources_with_exact_scope(tmp_path):
    """iam_control_sources must work under exact scope matching (the --exact-scope path)."""
    nodes = [
        _node("resource:111", "GCPOrganization", {"name": "111"}),
        _binding("iambinding:roles/owner@org:111", "roles/owner", "organizations/111", scope_type="organization"),
        _binding("iambinding:orgadmin@org:111", "roles/resourcemanager.organizationAdmin", "organizations/111", scope_type="organization"),
    ]
    edges = [
        _edge("iambinding:roles/owner@org:111", "resource:111", "ROLE_OWNER"),
        _edge("iambinding:orgadmin@org:111", "resource:111", "CAN_MODIFY_ORG_IAM"),
    ]
    graph = AttackGraph.from_path(_write(tmp_path, nodes, edges))
    srcs = graph.iam_control_sources(scope="organizations/111", exact=True)
    assert "iambinding:orgadmin@org:111" in srcs
    assert "iambinding:roles/owner@org:111" in srcs
