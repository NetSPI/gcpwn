from __future__ import annotations

from gcpwn.modules.opengraph.processing.process_og_gcpwn_data import export_opengraph_json
from gcpwn.modules.opengraph.utilities.helpers.graph.context import OpenGraphBuildContext, OpenGraphBuildOptions
from gcpwn.modules.opengraph.utilities.stage_1_principals import build_users_groups_graph


class _FakeSession:
    def __init__(self, rows_by_table: dict[str, list[dict]]) -> None:
        self._rows_by_table = rows_by_table

    def get_data(self, table_name: str, *args, **kwargs):
        _ = (args, kwargs)
        rows = self._rows_by_table.get(table_name, [])
        return [dict(row) for row in rows]


def test_key_opengraph_example_users_groups_to_graph_json() -> None:
    session = _FakeSession(
        {
            "workspace_users": [
                {
                    "email": "alice@example.com",
                    "display_name": "Alice",
                    "user_id": "u-1",
                    "customer_id": "C-1",
                }
            ],
            "workspace_groups": [
                {
                    "email": "admins@example.com",
                    "display_name": "Admins",
                    "description": "Admin group",
                    "customer_id": "C-1",
                }
            ],
            "workspace_group_memberships": [
                {
                    "group_member": "group:admins@example.com",
                    "member": "user:alice@example.com",
                    "member_type": "user",
                    "source": "example_membership",
                }
            ],
            "iam_allow_policies": [],
            "abstract_tree_hierarchy": [],
        }
    )

    context = OpenGraphBuildContext(session=session, options=OpenGraphBuildOptions())
    stats = build_users_groups_graph(context)

    nodes = list(context.builder.node_map.values())
    edges = list(context.builder.edge_map.values())
    payload = export_opengraph_json(nodes, edges)

    assert stats["nodes_added"] == 2
    assert stats["edges_added"] == 1
    assert payload["summary"] == {"nodes": 2, "edges": 1}

    node_ids = [node["id"] for node in payload["graph"]["nodes"]]
    assert node_ids == ["group:admins@example.com", "user:alice@example.com"]

    edge = payload["graph"]["edges"][0]
    assert edge["kind"] == "GOOGLE_MEMBER_OF"
    assert edge["start"]["value"] == "user:alice@example.com"
    assert edge["end"]["value"] == "group:admins@example.com"


def test_key_opengraph_example_service_account_membership() -> None:
    session = _FakeSession(
        {
            "workspace_users": [],
            "workspace_groups": [],
            "workspace_group_memberships": [
                {
                    "group_member": "group:eng@example.com",
                    "member": "serviceAccount:build-bot@demo-project.iam.gserviceaccount.com",
                    "member_type": "service_account",
                    "source": "example_membership",
                }
            ],
            "iam_allow_policies": [],
            "abstract_tree_hierarchy": [],
        }
    )

    context = OpenGraphBuildContext(session=session, options=OpenGraphBuildOptions())
    build_users_groups_graph(context)

    payload = export_opengraph_json(
        list(context.builder.node_map.values()),
        list(context.builder.edge_map.values()),
    )

    assert payload["summary"] == {"nodes": 2, "edges": 1}
    edge = payload["graph"]["edges"][0]
    assert edge["start"]["value"] == "serviceAccount:build-bot@demo-project.iam.gserviceaccount.com"
    assert edge["end"]["value"] == "group:eng@example.com"
