from __future__ import annotations

from gcpwn.modules.opengraph.utilities.helpers.graph.core_helpers import OpenGraphBuilder, OpenGraphNode, node_to_opengraph
from gcpwn.modules.opengraph.utilities.stage_4_resource_expansion import (
    _add_project_resource_membership_edges,
    _resource_enrichment_payloads_by_name,
    _row_resourcedata_payload,
)


def test_key_row_resourcedata_payload_parses_nested_json_values() -> None:
    row = {
        "workspace_id": "workspace-1",
        "name": "projects/demo-project/zones/us-central1-c/instances/i-1",
        "status": "RUNNING",
        "labels": '{"env":"dev"}',
        "metadata": '{"items":[{"key":"startup-script","value":"echo unit-test"}]}',
    }

    payload = _row_resourcedata_payload(row, skip_keys={"workspace_id"})

    assert payload["name"] == "projects/demo-project/zones/us-central1-c/instances/i-1"
    assert payload["status"] == "RUNNING"
    assert payload["labels"]["env"] == "dev"
    assert payload["metadata"]["items"][0]["key"] == "startup-script"
    assert "workspace_id" not in payload


def test_key_row_resourcedata_payload_unwraps_raw_json_object() -> None:
    row = {
        "name": "projects/demo/locations/global/keyRings/r/cryptoKeys/k",
        "raw_json": '{"versionTemplate":{"protectionLevel":"HSM"},"labels":{"a":"b"}}',
    }
    payload = _row_resourcedata_payload(row, skip_keys={"workspace_id"})

    assert payload["versionTemplate"]["protectionLevel"] == "HSM"
    assert payload["labels"]["a"] == "b"
    assert "raw_json" not in payload


def test_key_node_export_auto_generates_resourcedata_for_resource_nodes() -> None:
    exported = node_to_opengraph(
        OpenGraphNode(
            node_id="resource:projects/demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1",
            node_type="GCPKmsCryptoKey",
            properties={
                "name": "key-1",
                "display_name": "key-1",
                "resource_name": "projects/demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1",
                "resource_type": "kmskey",
                "project_id": "demo-project",
            },
        )
    )

    props = exported["properties"] or {}
    assert props["resourcedata.resource_type"] == "kmskey"
    assert props["resourcedata.resource_name"] == "projects/demo-project/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1"


def test_key_node_export_flattens_nested_resourcedata_dicts_and_lists() -> None:
    exported = node_to_opengraph(
        OpenGraphNode(
            node_id="resource:projects/demo-project/zones/us-central1-c/instances/i-1",
            node_type="GCPComputeInstance",
            properties={
                "name": "i-1",
                "resource_name": "projects/demo-project/zones/us-central1-c/instances/i-1",
                "resource_type": "computeinstance",
                "resourcedata": {
                    "status": "TERMINATED",
                    "metadata": {
                        "items": [
                            {
                                "key": "startup-script",
                                "value": "echo test",
                            }
                        ]
                    },
                },
            },
        )
    )

    props = exported["properties"] or {}
    assert props["resourcedata.status"] == "TERMINATED"
    assert "status" not in props
    assert props["resourcedata.metadata.items.0.key"] == "startup-script"
    assert props["resourcedata.metadata.items.0.value"] == "echo test"


def test_key_resource_node_merge_keeps_existing_and_adds_missing_resourcedata_fields() -> None:
    node_id = "resource:projects/demo-project/zones/us-central1-c/instances/i-1"
    builder = OpenGraphBuilder()

    builder.add_node(
        node_id,
        "GCPComputeInstance",
        resource_name="projects/demo-project/zones/us-central1-c/instances/i-1",
        resource_type="computeinstance",
        resourcedata={
            "project_id": "demo-project",
            "status": "RUNNING",
        },
    )
    builder.add_node(
        node_id,
        "GCPComputeInstance",
        resourcedata={
            "name": "i-1",
            "metadata": {
                "items": [
                    {
                        "key": "startup-script",
                        "value": "echo test",
                    }
                ]
            },
        },
    )

    exported = node_to_opengraph(builder.node_map[node_id])
    props = exported["properties"] or {}
    assert props["resourcedata.project_id"] == "demo-project"
    assert props["resourcedata.status"] == "RUNNING"
    assert props["resourcedata.name"] == "i-1"
    assert props["resourcedata.metadata.items.0.key"] == "startup-script"


def test_key_resource_enrichment_index_uses_generic_service_tables_for_kms() -> None:
    class _FakeContext:
        def service_table_names(self):
            return ["kms_keys", "opengraph_nodes"]

        def service_table_columns(self, table_name):
            if table_name == "kms_keys":
                return [
                    "project_id",
                    "location",
                    "keyring_name",
                    "key_id",
                    "name",
                    "purpose",
                    "primary_state",
                    "next_rotation_time",
                    "rotation_period",
                    "labels",
                    "raw_json",
                    "workspace_id",
                ]
            return ["workspace_id", "node_id"]

        def service_rows(self, table_name):
            if table_name != "kms_keys":
                return []
            return [
                {
                    "project_id": "example-project-a",
                    "location": "us-central1",
                    "keyring_name": "projects/example-project-a/locations/us-central1/keyRings/demo-key-ring",
                    "key_id": "gke-key",
                    "name": "projects/example-project-a/locations/us-central1/keyRings/demo-key-ring/cryptoKeys/demo-key",
                    "purpose": "ENCRYPT_DECRYPT",
                    "primary_state": "ENABLED",
                    "labels": '{"tier":"prod"}',
                    "raw_json": '{"versionTemplate":{"protectionLevel":"SOFTWARE"}}',
                    "workspace_id": "demo",
                }
            ]

    target_name = "projects/example-project-a/locations/us-central1/keyRings/demo-key-ring/cryptoKeys/demo-key"
    enrichment = _resource_enrichment_payloads_by_name(
        _FakeContext(),
        target_resource_names={target_name},
        candidate_project_by_name={target_name: "example-project-a"},
    )

    payload = enrichment[target_name]
    assert payload["purpose"] == "ENCRYPT_DECRYPT"
    assert payload["primary_state"] == "ENABLED"
    assert payload["labels"]["tier"] == "prod"
    assert payload["versionTemplate"]["protectionLevel"] == "SOFTWARE"
    assert "raw_json" not in payload


def test_key_resource_enrichment_alias_matches_short_secret_name_to_full_resource_path() -> None:
    class _FakeContext:
        def service_table_names(self):
            return ["secretsmanager_secrets"]

        def service_table_columns(self, table_name):
            return [
                "project_id",
                "name",
                "replication",
                "labels",
                "workspace_id",
            ]

        def service_rows(self, table_name):
            return [
                {
                    "project_id": "example-project-b",
                    "name": "projects/example-project-b/secrets/test-secret",
                    "replication": '{"automatic":{}}',
                    "labels": '{"env":"prod"}',
                    "workspace_id": "demo",
                }
            ]

    target_name = "test-secret"
    enrichment = _resource_enrichment_payloads_by_name(
        _FakeContext(),
        target_resource_names={target_name},
        candidate_project_by_name={target_name: "example-project-b"},
    )
    payload = enrichment[target_name]

    assert payload["name"] == "projects/example-project-b/secrets/test-secret"
    assert payload["labels"]["env"] == "prod"
    assert "replication" in payload


def test_key_nondefault_resource_type_still_emits_resource_node_with_resourcedata() -> None:
    class _FakeContext:
        def __init__(self):
            self.options = type("Opt", (), {"include_all": False})()
            self.builder = OpenGraphBuilder()

    class _FakeIndexes:
        project_scope_by_project_id = {"example-project-a": "projects/example-project-a"}

    context = _FakeContext()
    candidates = [
        {
            "project_id": "example-project-a",
            "resource_type": "kmskey",
            "resource_name": "projects/example-project-a/locations/us-central1/keyRings/demo-key-ring/cryptoKeys/demo-key",
            "display_name": "demo-key",
            "region": "us-central1",
            "status": "",
            "source": "iam_allow_policies",
            "resourcedata": {
                "resource_type": "kmskey",
            },
        }
    ]
    enrichment_by_name = {
        "projects/example-project-a/locations/us-central1/keyRings/demo-key-ring/cryptoKeys/demo-key": {
            "purpose": "ENCRYPT_DECRYPT",
            "primary_state": "ENABLED",
        }
    }

    edges_added = _add_project_resource_membership_edges(
        context,
        candidates=candidates,
        indexes=_FakeIndexes(),
        resource_enrichment_by_name=enrichment_by_name,
    )

    assert edges_added == 0
    node_id = "resource:projects/example-project-a/locations/us-central1/keyRings/demo-key-ring/cryptoKeys/demo-key"
    assert node_id in context.builder.node_map
    exported = node_to_opengraph(context.builder.node_map[node_id])
    props = exported["properties"] or {}
    assert props["resourcedata.purpose"] == "ENCRYPT_DECRYPT"
    assert props["resourcedata.primary_state"] == "ENABLED"
