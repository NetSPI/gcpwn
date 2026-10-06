from __future__ import annotations

from gcpwn.core.utils.enum_framework import (
    Component,
    NESTED,
    REGION,
    parse_enum_args,
    run_components,
)
from gcpwn.modules.gcp.managedkafka.utilities.helpers import (
    ManagedKafkaClustersResource,
    ManagedKafkaConsumerGroupsResource,
    ManagedKafkaTopicsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "clusters",
        ManagedKafkaClustersResource,
        "Managed Kafka Clusters",
        "Clusters",
        help_text=(
            "Enumerate Managed Kafka clusters. "
            "REQUIRES: managedkafka.clusters.list"
        ),
        scope=REGION,
        supports_iam=False,
    ),
    Component(
        "topics",
        ManagedKafkaTopicsResource,
        "Managed Kafka Topics",
        "Topics",
        help_text=(
            "Enumerate topics per cluster. "
            "REQUIRES: managedkafka.topics.list + --clusters"
        ),
        scope=NESTED,
        parent_key="clusters",
        dependency_label="Clusters",
        save_parent_kwarg="cluster",
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "consumer_groups",
        ManagedKafkaConsumerGroupsResource,
        "Managed Kafka Consumer Groups",
        "Consumer Groups",
        help_text=(
            "Enumerate consumer groups per cluster. "
            "REQUIRES: managedkafka.consumerGroups.list + --clusters first"
        ),
        scope=NESTED,
        parent_key="clusters",
        dependency_label="Clusters",
        save_parent_kwarg="cluster",
        supports_get=False,
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Managed Apache Kafka resources: clusters, topics, and consumer groups",
        region_label="Managed Kafka regions",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="managedkafka_actions_allowed",
        region_resolver=resolve_locations,
        module_name="enum_managedkafka",
    )
    return 1
