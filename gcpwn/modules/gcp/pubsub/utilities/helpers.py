from __future__ import annotations

from google.cloud import pubsub_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes


class PubSubTopicsResource(GcpListResource):
    """Enumerate Pub/Sub topics for a project into the ``pubsub_topics`` table."""

    SERVICE_LABEL = "Pub/Sub"
    TABLE_NAME = "pubsub_topics"
    ACTION_RESOURCE_TYPE = "topics"
    LIST_PERMISSION = "pubsub.topics.list"
    GET_PERMISSION = "pubsub.topics.get"
    TEST_IAM_API_NAME = "pubsub.topics.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.topics.", exclude_permissions=("pubsub.topics.create", "pubsub.topics.list")
    )
    ID_FIELD = "topic_id"
    PARENT_FROM_PROJECT = True

    def _build_client(self, session):
        return pubsub_v1.PublisherClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return list(self.client.list_topics(request={"project": parent}))

    def _get_item(self, resource_id, **_):
        return self.client.get_topic(request={"topic": resource_id})


class PubSubSubscriptionsResource(GcpListResource):
    """Enumerate Pub/Sub subscriptions for a project into ``pubsub_subscriptions``."""

    SERVICE_LABEL = "Pub/Sub"
    TABLE_NAME = "pubsub_subscriptions"
    ACTION_RESOURCE_TYPE = "subscriptions"
    LIST_PERMISSION = "pubsub.subscriptions.list"
    GET_PERMISSION = "pubsub.subscriptions.get"
    TEST_IAM_API_NAME = "pubsub.subscriptions.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.subscriptions.", exclude_permissions=("pubsub.subscriptions.create", "pubsub.subscriptions.list")
    )
    ID_FIELD = "subscription_id"
    PARENT_FROM_PROJECT = True

    def _build_client(self, session):
        return pubsub_v1.SubscriberClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return list(self.client.list_subscriptions(request={"project": parent}))

    def _get_item(self, resource_id, **_):
        return self.client.get_subscription(request={"subscription": resource_id})


class PubSubSchemasResource(GcpListResource):
    """Enumerate Pub/Sub schemas for a project into ``pubsub_schemas`` (incl. type/definition)."""

    SERVICE_LABEL = "Pub/Sub"
    TABLE_NAME = "pubsub_schemas"
    ACTION_RESOURCE_TYPE = "schemas"
    LIST_PERMISSION = "pubsub.schemas.list"
    GET_PERMISSION = "pubsub.schemas.get"
    TEST_IAM_API_NAME = "pubsub.schemas.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.schemas.",
        exclude_permissions=("pubsub.schemas.create", "pubsub.schemas.list", "pubsub.schemas.validate"),
    )
    ID_FIELD = "schema_id"
    PARENT_FROM_PROJECT = True

    def _build_client(self, session):
        return pubsub_v1.SchemaServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return list(self.client.list_schemas(request={"parent": parent}))

    def _get_item(self, resource_id, **_):
        return self.client.get_schema(request={"name": resource_id})

    def _extra_save_fields(self, raw):
        """Persist the schema ``type``/``definition`` (handling the proto ``type_`` alias)."""
        return {
            "type": raw.get("type") or raw.get("type_") or "",
            "definition": raw.get("definition") or "",
        }


class PubSubSnapshotsResource(GcpListResource):
    """Enumerate Pub/Sub snapshots for a project into ``pubsub_snapshots``."""

    SERVICE_LABEL = "Pub/Sub"
    TABLE_NAME = "pubsub_snapshots"
    ACTION_RESOURCE_TYPE = "snapshots"
    LIST_PERMISSION = "pubsub.snapshots.list"
    GET_PERMISSION = "pubsub.snapshots.get"
    TEST_IAM_API_NAME = "pubsub.snapshots.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "pubsub.snapshots.", exclude_permissions=("pubsub.snapshots.create", "pubsub.snapshots.list")
    )
    ID_FIELD = "snapshot_id"
    PARENT_FROM_PROJECT = True

    def _build_client(self, session):
        return pubsub_v1.SubscriberClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return list(self.client.list_snapshots(request={"project": parent}))

    def _get_item(self, resource_id, **_):
        return self.client.get_snapshot(request={"snapshot": resource_id})
