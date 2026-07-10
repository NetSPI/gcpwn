from __future__ import annotations

from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.pubsub.utilities.helpers import (
    PubSubSchemasResource,
    PubSubSnapshotsResource,
    PubSubSubscriptionsResource,
    PubSubTopicsResource,
)


COMPONENTS = [
    Component("topics", PubSubTopicsResource, "Pub/Sub Topics", "Topics", help_text="Enumerate Pub/Sub topics",
              scope=PROJECT, columns=["name", "kms_key_name", "labels"], primary_sort_key="name",
              manual_id_arg="topic_names",
              manual_help="Topic names in comma-separated format using projects/PROJECT_ID/topics/TOPIC_ID."),
    Component("subscriptions", PubSubSubscriptionsResource, "Pub/Sub Subscriptions", "Subscriptions",
              help_text="Enumerate Pub/Sub subscriptions", scope=PROJECT,
              columns=["name", "topic", "filter", "state"], primary_sort_key="name",
              manual_id_arg="subscription_names",
              manual_help="Subscription names using projects/PROJECT_ID/subscriptions/SUBSCRIPTION_ID."),
    Component("schemas", PubSubSchemasResource, "Pub/Sub Schemas", "Schemas", help_text="Enumerate Pub/Sub schemas",
              scope=PROJECT, columns=["name", "schema_id", "type"], primary_sort_key="schema_id",
              manual_id_arg="schema_names",
              manual_help="Schema names using projects/PROJECT_ID/schemas/SCHEMA_ID."),
    Component("snapshots", PubSubSnapshotsResource, "Pub/Sub Snapshots", "Snapshots",
              help_text="Enumerate Pub/Sub snapshots", scope=PROJECT,
              columns=["name", "snapshot_id", "topic", "expire_time"], primary_sort_key="snapshot_id",
              manual_id_arg="snapshot_names",
              manual_help="Snapshot names using projects/PROJECT_ID/snapshots/SNAPSHOT_ID."),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate Pub/Sub resources",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on Pub/Sub topics, subscriptions, schemas, and snapshots"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="pubsub_actions_allowed", module_name="enum_pubsub")
    return 1
