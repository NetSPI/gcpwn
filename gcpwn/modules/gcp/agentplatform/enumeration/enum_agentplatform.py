from __future__ import annotations

from gcpwn.core.utils.enum_framework import NESTED, REGION, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.agentplatform.utilities.helpers import (
    AgentPlatformDatasetsResource,
    AgentPlatformEndpointsResource,
    AgentPlatformEntityTypesResource,
    AgentPlatformFeatureGroupsResource,
    AgentPlatformFeatureOnlineStoresResource,
    AgentPlatformFeatureViewsResource,
    AgentPlatformFeaturestoresResource,
    AgentPlatformModelsResource,
    AgentPlatformNotebookRuntimeTemplatesResource,
    AgentPlatformReasoningEnginesResource,
)

_GLOBAL = ["global"]

COMPONENTS = [
    Component("datasets", AgentPlatformDatasetsResource, "AgentPlatform Datasets", "Datasets",
              help_text="Enumerate aiplatform datasets", scope=REGION, locations=_GLOBAL),
    Component("endpoints", AgentPlatformEndpointsResource, "AgentPlatform Endpoints", "Endpoints",
              help_text="Enumerate aiplatform endpoints", scope=REGION, locations=_GLOBAL, supports_iam=False,
              iam_unsupported_message="[!] Skipping aiplatform endpoint TestIamPermissions: endpoints do not support testIamPermissions."),
    Component("models", AgentPlatformModelsResource, "AgentPlatform Models", "Models",
              help_text="Enumerate aiplatform models", scope=REGION, locations=_GLOBAL),
    Component("featurestores", AgentPlatformFeaturestoresResource, "AgentPlatform Featurestores", "Featurestores",
              help_text="Enumerate aiplatform featurestores", scope=REGION, locations=_GLOBAL),
    Component("entity_types", AgentPlatformEntityTypesResource, "AgentPlatform Entity Types", "Entity Types",
              help_text="Enumerate aiplatform entity types", scope=NESTED, parent_key="featurestores",
              dependency_label="Featurestores", save_parent_kwarg="featurestore_name"),
    Component("feature_groups", AgentPlatformFeatureGroupsResource, "AgentPlatform Feature Groups", "Feature Groups",
              help_text="Enumerate aiplatform feature groups", scope=REGION, locations=_GLOBAL),
    Component("feature_online_stores", AgentPlatformFeatureOnlineStoresResource, "AgentPlatform Feature Online Stores", "Feature Online Stores",
              help_text="Enumerate aiplatform feature online stores", scope=REGION, locations=_GLOBAL),
    Component("feature_views", AgentPlatformFeatureViewsResource, "AgentPlatform Feature Views", "Feature Views",
              help_text="Enumerate aiplatform feature views", scope=NESTED, parent_key="feature_online_stores",
              dependency_label="Feature Online Stores", save_parent_kwarg="feature_online_store_name"),
    Component("reasoning_engines", AgentPlatformReasoningEnginesResource, "AgentPlatform Reasoning Engines", "Reasoning Engines",
              help_text="Enumerate aiplatform reasoning engines", scope=REGION, locations=_GLOBAL),
    Component("notebook_runtime_templates", AgentPlatformNotebookRuntimeTemplatesResource, "AgentPlatform Notebook Runtime Templates", "Notebook Runtime Templates",
              help_text="Enumerate aiplatform notebook runtime templates", scope=REGION, locations=_GLOBAL),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate aiplatform resources (read-only)",
        components=component_args(COMPONENTS),
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={"iam": {"help": "Run TestIamPermissions on enumerated aiplatform resources"}},
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(session, args, components=COMPONENTS, column_name="agentplatform_actions_allowed", module_name="enum_agentplatform")
    return 1
