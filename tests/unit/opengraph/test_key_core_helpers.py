from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import (
    OpenGraphEdge,
    OpenGraphNode,
    edge_to_opengraph,
    gcp_resource_node_type,
    node_to_opengraph,
    principal_member_properties,
    principal_node_id,
    principal_type,
)


def test_key_opengraph_principal_normalization() -> None:
    assert principal_node_id("users:alice@example.com") == "user:alice@example.com"
    assert principal_node_id("service_account:bot@demo.iam.gserviceaccount.com") == (
        "serviceAccount:bot@demo.iam.gserviceaccount.com"
    )
    assert principal_type("serviceAccount:bot@demo.iam.gserviceaccount.com") == "GCPServiceAccount"


def test_key_opengraph_service_agent_detection() -> None:
    props = principal_member_properties(
        "serviceAccount:service-111111111111@gcp-sa-cloudtasks.iam.gserviceaccount.com"
    )

    assert props["email"] == "service-111111111111@gcp-sa-cloudtasks.iam.gserviceaccount.com"
    assert props["is_service_agent"] is True
    assert props["service_agent_pattern"]


def test_key_opengraph_node_export_flattens_and_trims_principal_fields() -> None:
    exported = node_to_opengraph(
        OpenGraphNode(
            node_id="user:alice@example.com",
            node_type="GoogleUser",
            properties={
                "member": "user:alice@example.com",
                "display_name": "Alice",
                "name": "Alice",
                "labels": {"team": "platform"},
            },
        )
    )

    props = exported["properties"]
    assert props["display_name"] == "Alice"
    assert props["labels.team"] == "platform"
    assert "member" not in props
    assert "name" not in props


def test_key_opengraph_edge_export_single_permission_shape() -> None:
    exported = edge_to_opengraph(
        OpenGraphEdge(
            source_id="grant:roles/viewer@project:demo-project",
            destination_id="resource:projects/demo-project",
            edge_type="CAN_VIEW_PROJECT",
            properties={
                "matched_permissions": ["resourcemanager.projects.get"],
                "contributing_permissions": ["resourcemanager.projects.get"],
            },
        )
    )

    assert exported["kind"] == "CAN_VIEW_PROJECT"
    props = exported["properties"]
    # Moderate de-crowd: two readable permission fields only.
    assert props["permissions"] == ["resourcemanager.projects.get"]
    assert props["permission_source_summary"] == ["resourcemanager.projects.get"]
    for gone in ("single_permission", "permission", "permissions_required_by_rule",
                 "permissions_granted_from_bindings", "matched_permissions", "contributing_permissions"):
        assert gone not in props


def test_key_opengraph_multi_permission_attribution_is_glanceable() -> None:
    exported = node_to_opengraph(
        OpenGraphNode(
            node_id="combo_iambinding:user:alice@example.com:CAN_SOMETHING@project:demo#abc123",
            node_type="GCPIamBinding",
            properties={
                "contributing_binding_ids": [
                    "iambinding:roles/editor@project:demo#1",
                    "iambinding:roles/iam.serviceAccountTokenCreator@project:demo#2",
                ],
                "matched_permissions": [
                    "iam.serviceAccounts.getAccessToken",
                    "resourcemanager.projects.getIamPolicy",
                ],
                "contributing_permissions": [
                    "iam.serviceAccounts.getAccessToken",
                    "resourcemanager.projects.setIamPolicy",
                ],
                "contributing_binding_permission_map": {
                    "iambinding:roles/editor@project:demo#1": [
                        "resourcemanager.projects.setIamPolicy",
                    ],
                    "iambinding:roles/iam.serviceAccountTokenCreator@project:demo#2": [
                        "iam.serviceAccounts.getAccessToken",
                    ],
                },
            },
        )
    )

    props = exported["properties"]
    # Moderate de-crowd: `permissions` (effective) + readable role@scope attribution lines.
    assert props["permissions"] == [
        "iam.serviceAccounts.getAccessToken",
        "resourcemanager.projects.getIamPolicy",
    ]
    assert props["permission_source_summary"] == [
        "roles/editor @ project:demo: resourcemanager.projects.setIamPolicy",
        "roles/iam.serviceAccountTokenCreator @ project:demo: iam.serviceAccounts.getAccessToken",
    ]
    for gone in ("permissions_required_by_rule", "permissions_granted_from_bindings",
                 "permission_source_bindings", "contributing_binding_permission_map"):
        assert gone not in props


def test_key_opengraph_kmskey_resource_type_normalizes_to_crypto_key_node() -> None:
    assert gcp_resource_node_type("kmskey") == "GCPKmsCryptoKey"
