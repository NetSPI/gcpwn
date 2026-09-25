from __future__ import annotations


def _fa_icon(name: str, color: str) -> dict:
    return {"icon": {"type": "font-awesome", "name": name, "color": color}}


CUSTOM_NODE_TYPES = {
    # Principals
    "GCPAllUsers": _fa_icon("users", "#8E24AA"),
    "GCPAllAuthenticatedUsers": _fa_icon("user-check", "#5E35B1"),
    "GoogleUser": _fa_icon("user", "#43A047"),
    "GoogleGroup": _fa_icon("users", "#FB8C00"),
    "GoogleWorkspaceTenant": _fa_icon("google", "#4285F4"),
    "PrincipalsInOrg": _fa_icon("user-friends", "#7CB342"),
    "GoogleDriveFile": _fa_icon("file", "#FBBC04"),
    "GCPServiceAccount": _fa_icon("id-badge", "#1E88E5"),
    "GCPPrincipalSet": _fa_icon("sitemap", "#546E7A"),
    "GCPDomainPrincipal": _fa_icon("globe", "#607D8B"),
    "GCPConvenienceMember": _fa_icon("user-tag", "#7B1FA2"),
    "GCPPrincipal": _fa_icon("user-shield", "#546E7A"),
    "GCPExternalIdentitySource": _fa_icon("sign-in-alt", "#6D4C41"),

    # Graph internals
    "GCPIamBinding": _fa_icon("id-card", "#546E7A"),
    "GCPIamGrant": _fa_icon("id-card", "#546E7A"),
    "GCPIamSimpleBinding": _fa_icon("id-card", "#455A64"),
    "GCPIamMultiBinding": _fa_icon("layer-group", "#37474F"),
    "GCPIamCapability": _fa_icon("magic", "#6A1B9A"),
    "GCPResource": _fa_icon("cube", "#90A4AE"),
    "GCPUnknown": _fa_icon("circle-question", "#B0BEC5"),

    # Hierarchy / scope resources
    "GCPOrganization": _fa_icon("building", "#6D4C41"),
    "GCPFolder": _fa_icon("folder", "#8D6E63"),
    "GCPProject": _fa_icon("folder-open", "#5D4037"),

    # GCP resources
    "GCPBucket": _fa_icon("box-open", "#F57C00"),
    "GCPCloudFunction": _fa_icon("bolt", "#FF7043"),
    "GCPComputeInstance": _fa_icon("server", "#1E88E5"),
    "GCPCloudSQLInstance": _fa_icon("database", "#1976D2"),
    "GCPServiceAccountResource": _fa_icon("id-badge", "#1565C0"),
    "GCPArtifactRegistryRepo": _fa_icon("boxes", "#8E24AA"),
    "GCPBigQueryDataset": _fa_icon("database", "#1A73E8"),
    "GCPBigQueryTable": _fa_icon("table", "#1A73E8"),
    "GCPBigQueryRoutine": _fa_icon("terminal", "#1A73E8"),
    "GCPSpannerInstance": _fa_icon("database", "#0B57D0"),
    "GCPSpannerDatabase": _fa_icon("table", "#0B57D0"),
    "GCPCloudRunService": _fa_icon("play", "#00ACC1"),
    "GCPCloudRunJob": _fa_icon("gears", "#00ACC1"),
    "GCPWorkloadIdentityPool": _fa_icon("users", "#3949AB"),
    "GCPWorkloadIdentityProvider": _fa_icon("exchange-alt", "#5C6BC0"),
    "GCPCloudTasksQueue": _fa_icon("tasks", "#5E35B1"),
    "GCPServiceDirectoryNamespace": _fa_icon("folder-open", "#6A1B9A"),
    "GCPServiceDirectoryService": _fa_icon("compass", "#6A1B9A"),
    "GCPPubSubTopic": _fa_icon("bullhorn", "#8E24AA"),
    "GCPPubSubSubscription": _fa_icon("bell", "#8E24AA"),
    "GCPPubSubSchema": _fa_icon("file-code", "#8E24AA"),
    "GCPPubSubSnapshot": _fa_icon("camera", "#8E24AA"),

    # Secrets / KMS
    "GCPSecret": _fa_icon("lock", "#00695C"),
    "GCPKmsKeyRing": _fa_icon("archive", "#00796B"),
    "GCPKmsCryptoKey": _fa_icon("key", "#00796B"),
    "GCPKmsCryptoKeyVersion": _fa_icon("code-branch", "#00796B"),

    # App Engine
    "GCPAppEngineApp": _fa_icon("layer-group", "#1A73E8"),
    "GCPAppEngineVersion": _fa_icon("code-branch", "#1565C0"),

    # Cloud Build
    "GCPCloudBuildBuild": _fa_icon("hammer", "#E65100"),
    "GCPCloudBuildTrigger": _fa_icon("play-circle", "#BF360C"),

    # Cloud Deploy / Infra Manager
    "GCPCloudDeployRelease": _fa_icon("rocket", "#1976D2"),
    "GCPInfraManagerDeployment": _fa_icon("cube", "#546E7A"),

    # Cloud Scheduler / Tasks / Workflows
    "GCPCloudSchedulerJob": _fa_icon("clock", "#2E7D32"),
    "GCPCloudWorkflowsExecution": _fa_icon("project-diagram", "#6A1B9A"),

    # Data processing
    "GCPDataflowJob": _fa_icon("stream", "#0277BD"),
    "GCPDataflowDataPipeline": _fa_icon("stream", "#01579B"),
    "GCPDataprocBatch": _fa_icon("layer-group", "#E65100"),
    "GCPDataprocWorkflowTemplate": _fa_icon("clipboard-list", "#BF360C"),
    "GCPDataplexTask": _fa_icon("wave-square", "#00695C"),
    "GCPDataFusionInstance": _fa_icon("random", "#6A1B9A"),
    "GCPBQSparkProcedure": _fa_icon("fire", "#E65100"),
    "GCPComposerEnv": _fa_icon("wind", "#0288D1"),

    # Vertex AI / ML
    "GCPVertexCustomJob": _fa_icon("robot", "#4527A0"),
    "GCPVertexEndpoint": _fa_icon("plug", "#512DA8"),
    "GCPVertexPipelineJob": _fa_icon("code-branch", "#4527A0"),
    "GCPVertexReasoningEngine": _fa_icon("brain", "#311B92"),

    # Notebooks / Workbench
    "GCPNotebooksExecution": _fa_icon("book-open", "#388E3C"),
    "GCPNotebooksWorkbench": _fa_icon("laptop-code", "#2E7D32"),

    # Compute / TPU / Migration
    "GCPTpuNode": _fa_icon("microchip", "#4527A0"),
    "GCPVMMigrationMigratingVm": _fa_icon("truck-moving", "#546E7A"),
    "GCPInstances": _fa_icon("server", "#1565C0"),

    # Firebase
    "GCPFirebaseBackend": _fa_icon("fire-alt", "#F57C00"),

    # Deployment Manager
    "GCPDeploymentManagerDeployment": _fa_icon("boxes", "#546E7A"),

    # App Integration
    "GCPAppIntegration": _fa_icon("project-diagram", "#7B1FA2"),

    # Batch
    "GCPBatchJob": _fa_icon("list-ol", "#00695C"),

    # Cloud Workstations
    "GCPWorkstation": _fa_icon("desktop", "#0097A7"),

    # API Gateway
    "GCPApiGateway": _fa_icon("network-wired", "#F57C00"),

    # Expansion helpers
    "GCPServiceAccountKey": _fa_icon("file-signature", "#F9A825"),
}
