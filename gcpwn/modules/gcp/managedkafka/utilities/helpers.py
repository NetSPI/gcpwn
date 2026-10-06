from __future__ import annotations

from typing import Any

from google.cloud import managedkafka_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    region_resolver_for,
)


resolve_locations = region_resolver_for("managedkafka", ("managedkafka", "v1"))


class ManagedKafkaClustersResource(GcpListResource):

    TABLE_NAME = "managedkafka_clusters"
    SERVICE_LABEL = "Managed Kafka Clusters"
    COLUMNS = ["location", "cluster_id", "name", "state", "bootstrap_address"]
    LIST_PERMISSION = "managedkafka.clusters.list"
    GET_PERMISSION = "managedkafka.clusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return managedkafka_v1.ManagedKafkaClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_clusters(parent=parent)

    def _get_item(self, resource_id, **_):
        return self.client.get_cluster(name=resource_id)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "cluster_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
            "bootstrap_address": str(
                (raw.get("bootstrap_config") or {}).get("bootstrap_address", "") or ""
            ),
        }


class ManagedKafkaTopicsResource(GcpListResource):

    TABLE_NAME = "managedkafka_topics"
    SERVICE_LABEL = "Managed Kafka Topics"
    COLUMNS = ["location", "topic_id", "name", "cluster", "partition_count", "replication_factor"]
    LIST_PERMISSION = "managedkafka.topics.list"
    GET_PERMISSION = "managedkafka.topics.get"
    ID_FIELD = "topic_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return managedkafka_v1.ManagedKafkaClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_topics(parent=parent)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = str(raw.get("name", "") or "")
        return {
            "topic_id": extract_path_tail(name),
            "cluster": extract_path_segment(name, "clusters"),
            "partition_count": str(raw.get("partition_count", 0) or 0),
            "replication_factor": str(raw.get("replication_factor", 0) or 0),
        }


class ManagedKafkaConsumerGroupsResource(GcpListResource):

    TABLE_NAME = "managedkafka_consumer_groups"
    SERVICE_LABEL = "Managed Kafka Consumer Groups"
    COLUMNS = ["location", "group_id", "name", "cluster"]
    LIST_PERMISSION = "managedkafka.consumerGroups.list"
    GET_PERMISSION = "managedkafka.consumerGroups.get"
    ID_FIELD = "group_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return managedkafka_v1.ManagedKafkaClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_consumer_groups(parent=parent)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        name = str(raw.get("name", "") or "")
        return {
            "group_id": extract_path_tail(name),
            "cluster": extract_path_segment(name, "clusters"),
        }
