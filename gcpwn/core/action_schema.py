"""Canonical column model for the per-credential permission/provenance store.

Permissions in gcpwn are recorded as EVIDENCE with provenance, not booleans: each
discovered permission is tagged ``direct_api`` (proven by a successful read API
call) or ``test_iam_permissions`` (reported by testIamPermissions). The action
table has one column per scope tier (org/folder/project/workspace) and one per
service; this module is the single source of truth mapping those columns to their
resource types (and back), so db.py, iam_simplifier, and the process pipeline all
agree on column names and what each represents. Pure constants -- no logic.
"""

from __future__ import annotations

ACTION_EVIDENCE_DIRECT_API = "direct_api"
ACTION_EVIDENCE_TEST_IAM_PERMISSIONS = "test_iam_permissions"
ACTION_EVIDENCE_LABELS = {
    ACTION_EVIDENCE_DIRECT_API: "direct API",
    ACTION_EVIDENCE_TEST_IAM_PERMISSIONS: "testIamPermissions",
}

ACTION_SCOPE_SPECS = (
    {
        "scope_key": "organization_permissions",
        "action_column": "organization_actions_allowed",
        "resource_type": "org",
        "scope_type": "org",
    },
    {
        "scope_key": "folder_permissions",
        "action_column": "folder_actions_allowed",
        "resource_type": "folder",
        "scope_type": "folder",
    },
    {
        "scope_key": "project_permissions",
        "action_column": "project_actions_allowed",
        "resource_type": "project",
        "scope_type": "project",
    },
    {
        "scope_key": "workspace_permissions",
        "action_column": "workspace_actions_allowed",
        "resource_type": "googleworkspace",
        "scope_type": "workspace",
    },
)

ACTION_SERVICE_COLUMN_TO_RESOURCE_TYPE = {
    "apikeys_actions_allowed": "apikeys",
    "apigateway_actions_allowed": "apigateway",
    "appengine_actions_allowed": "appengine",
    "artifactregistry_actions_allowed": "artifactregistry",
    "batch_actions_allowed": "batch",
    "bigquery_actions_allowed": "bigquery",
    "bigtable_actions_allowed": "bigtable",
    "cloudbuild_actions_allowed": "cloudbuild",
    "cloudcomposer_actions_allowed": "composer",
    "cloudsql_actions_allowed": "cloudsql",
    "clouddns_actions_allowed": "clouddns",
    "firestore_actions_allowed": "firestore",
    "gke_actions_allowed": "gke",
    "cloudrun_actions_allowed": "cloudrun",
    "cloudtasks_actions_allowed": "cloudtasks",
    "kms_actions_allowed": "kms",
    "memorystore_actions_allowed": "redis",
    "loadbalancing_actions_allowed": "loadbalancing",
    "pubsub_actions_allowed": "pubsub",
    "servicedirectory_actions_allowed": "servicedirectory",
    "storage_actions_allowed": "bucket",
    "function_actions_allowed": "cloudfunction",
    "compute_actions_allowed": "computeinstance",
    "service_account_actions_allowed": "saaccounts",
    "secret_actions_allowed": "secrets",
    "agentplatform_actions_allowed": "aiplatform",
    "vpc_actions_allowed": "vpc",
}

ACTION_SCOPE_COLUMNS = tuple(
    (str(spec["scope_key"]), str(spec["action_column"]))
    for spec in ACTION_SCOPE_SPECS
)
ACTION_SCOPE_KEY_TO_SCOPE_TYPE = {
    str(spec["scope_key"]): str(spec["scope_type"])
    for spec in ACTION_SCOPE_SPECS
}
ACTION_SCOPE_COLUMN_TO_RESOURCE_TYPE = {
    str(spec["action_column"]): str(spec["resource_type"])
    for spec in ACTION_SCOPE_SPECS
}

ACTION_COLUMN_TO_RESOURCE_TYPE = {
    **ACTION_SCOPE_COLUMN_TO_RESOURCE_TYPE,
    **ACTION_SERVICE_COLUMN_TO_RESOURCE_TYPE,
}

RESOURCE_TYPE_TO_ACTION_COLUMN = {value: key for key, value in ACTION_COLUMN_TO_RESOURCE_TYPE.items()}

ACTION_PROVENANCE_COLUMN = "action_provenance"
ACTION_SCOPE_KEYS = {scope_key for scope_key, _ in ACTION_SCOPE_COLUMNS}
ACTION_COLUMNS = tuple(ACTION_COLUMN_TO_RESOURCE_TYPE)
