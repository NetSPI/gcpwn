from __future__ import annotations

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes


def _vertex_test_iam_permissions(resource: str) -> tuple[str, ...]:
    """All aiplatform.<resource>.* permissions except the non-testable add/list."""
    return permissions_with_prefixes(
        f"aiplatform.{resource}.",
        exclude_permissions=(f"aiplatform.{resource}.add", f"aiplatform.{resource}.list"),
    )


class _AgentPlatformResource(GcpListResource):
    """Base for aiplatform resources: builds an aiplatform_v1 client by class name."""

    SERVICE_LABEL = "aiplatform"
    CLIENT_CLASS_NAME = ""  # attribute on google.cloud.aiplatform_v1

    def _build_client(self, session):
        try:
            from google.cloud import aiplatform_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "aiplatform enumeration requires the `google-cloud-aiplatform` package."
            ) from exc
        return getattr(aiplatform_v1, self.CLIENT_CLASS_NAME)(credentials=session.credentials)


class _FeatureOnlineStoreAdminResource(_AgentPlatformResource):
    """Resources served by the FeatureOnlineStoreAdmin sub-service client."""

    def _build_client(self, session):
        from google.cloud.aiplatform_v1.services import feature_online_store_admin_service  # type: ignore

        return feature_online_store_admin_service.FeatureOnlineStoreAdminServiceClient(
            credentials=session.credentials
        )


class AgentPlatformEndpointsResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_endpoints"
    COLUMNS = ["location", "endpoint_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "endpoints"
    LIST_PERMISSION = "aiplatform.endpoints.list"
    GET_PERMISSION = "aiplatform.endpoints.get"
    CLIENT_CLASS_NAME = "EndpointServiceClient"
    LIST_METHOD = "list_endpoints"
    GET_METHOD = "get_endpoint"
    ID_FIELD = "endpoint_id"
    # endpoints do not support testIamPermissions (TEST_IAM_PERMISSIONS stays empty)


class AgentPlatformDatasetsResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_datasets"
    COLUMNS = ["location", "dataset_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "datasets"
    LIST_PERMISSION = "aiplatform.datasets.list"
    GET_PERMISSION = "aiplatform.datasets.get"
    TEST_IAM_API_NAME = "aiplatform.datasets.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("datasets")
    CLIENT_CLASS_NAME = "DatasetServiceClient"
    LIST_METHOD = "list_datasets"
    GET_METHOD = "get_dataset"
    ID_FIELD = "dataset_id"


class AgentPlatformModelsResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_models"
    COLUMNS = ["location", "model_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "models"
    LIST_PERMISSION = "aiplatform.models.list"
    GET_PERMISSION = "aiplatform.models.get"
    TEST_IAM_API_NAME = "aiplatform.models.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("models")
    CLIENT_CLASS_NAME = "ModelServiceClient"
    LIST_METHOD = "list_models"
    GET_METHOD = "get_model"
    ID_FIELD = "model_id"


class AgentPlatformFeaturestoresResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_featurestores"
    COLUMNS = ["location", "featurestore_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "featurestores"
    LIST_PERMISSION = "aiplatform.featurestores.list"
    GET_PERMISSION = "aiplatform.featurestores.get"
    TEST_IAM_API_NAME = "aiplatform.featurestores.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("featurestores")
    CLIENT_CLASS_NAME = "FeaturestoreServiceClient"
    LIST_METHOD = "list_featurestores"
    GET_METHOD = "get_featurestore"
    ID_FIELD = "featurestore_id"


class AgentPlatformEntityTypesResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_entity_types"
    COLUMNS = ["location", "entity_type_id", "name", "featurestore_name", "labels"]
    ACTION_RESOURCE_TYPE = "entityTypes"
    LIST_PERMISSION = "aiplatform.entityTypes.list"
    GET_PERMISSION = "aiplatform.entityTypes.get"
    TEST_IAM_API_NAME = "aiplatform.entityTypes.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("entityTypes")
    CLIENT_CLASS_NAME = "FeaturestoreServiceClient"
    LIST_METHOD = "list_entity_types"
    GET_METHOD = "get_entity_type"
    ID_FIELD = "entity_type_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent featurestore


class AgentPlatformFeatureGroupsResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_feature_groups"
    COLUMNS = ["location", "feature_group_id", "name", "display_name", "labels"]
    ACTION_RESOURCE_TYPE = "featureGroups"
    LIST_PERMISSION = "aiplatform.featureGroups.list"
    GET_PERMISSION = "aiplatform.featureGroups.get"
    TEST_IAM_API_NAME = "aiplatform.featureGroups.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("featureGroups")
    CLIENT_CLASS_NAME = "FeatureRegistryServiceClient"
    LIST_METHOD = "list_feature_groups"
    GET_METHOD = "get_feature_group"
    ID_FIELD = "feature_group_id"


class AgentPlatformFeatureOnlineStoresResource(_FeatureOnlineStoreAdminResource):
    TABLE_NAME = "agentplatform_feature_online_stores"
    COLUMNS = ["location", "feature_online_store_id", "name", "display_name", "labels"]
    ACTION_RESOURCE_TYPE = "featureOnlineStores"
    LIST_PERMISSION = "aiplatform.featureOnlineStores.list"
    GET_PERMISSION = "aiplatform.featureOnlineStores.get"
    TEST_IAM_API_NAME = "aiplatform.featureOnlineStores.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("featureOnlineStores")
    LIST_METHOD = "list_feature_online_stores"
    GET_METHOD = "get_feature_online_store"
    ID_FIELD = "feature_online_store_id"


class AgentPlatformFeatureViewsResource(_FeatureOnlineStoreAdminResource):
    TABLE_NAME = "agentplatform_feature_views"
    COLUMNS = ["location", "feature_view_id", "name", "feature_online_store_name", "labels"]
    ACTION_RESOURCE_TYPE = "featureViews"
    LIST_PERMISSION = "aiplatform.featureViews.list"
    GET_PERMISSION = "aiplatform.featureViews.get"
    TEST_IAM_API_NAME = "aiplatform.featureViews.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("featureViews")
    LIST_METHOD = "list_feature_views"
    GET_METHOD = "get_feature_view"
    ID_FIELD = "feature_view_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent feature online store


class AgentPlatformReasoningEnginesResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_reasoning_engines"
    COLUMNS = ["location", "reasoning_engine_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "reasoningEngines"
    LIST_PERMISSION = "aiplatform.reasoningEngines.list"
    GET_PERMISSION = "aiplatform.reasoningEngines.get"
    TEST_IAM_API_NAME = "aiplatform.reasoningEngines.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("reasoningEngines")
    CLIENT_CLASS_NAME = "ReasoningEngineServiceClient"
    LIST_METHOD = "list_reasoning_engines"
    GET_METHOD = "get_reasoning_engine"
    ID_FIELD = "reasoning_engine_id"


class AgentPlatformNotebookRuntimeTemplatesResource(_AgentPlatformResource):
    TABLE_NAME = "agentplatform_notebook_runtime_templates"
    COLUMNS = ["location", "notebook_runtime_template_id", "name", "display_name", "create_time", "update_time"]
    ACTION_RESOURCE_TYPE = "notebookRuntimeTemplates"
    LIST_PERMISSION = "aiplatform.notebookRuntimeTemplates.list"
    GET_PERMISSION = "aiplatform.notebookRuntimeTemplates.get"
    TEST_IAM_API_NAME = "aiplatform.notebookRuntimeTemplates.testIamPermissions"
    TEST_IAM_PERMISSIONS = _vertex_test_iam_permissions("notebookRuntimeTemplates")
    CLIENT_CLASS_NAME = "NotebookServiceClient"
    LIST_METHOD = "list_notebook_runtime_templates"
    GET_METHOD = "get_notebook_runtime_template"
    ID_FIELD = "notebook_runtime_template_id"
