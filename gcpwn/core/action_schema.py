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
    # ── core ──────────────────────────────────────────────────────────────────
    "apikeys_actions_allowed": "apikeys",
    "apigateway_actions_allowed": "apigateway",
    "appengine_actions_allowed": "appengine",
    "appintegration_actions_allowed": "appintegration",
    "artifactregistry_actions_allowed": "artifactregistry",
    "batch_actions_allowed": "batch",
    "bigquery_actions_allowed": "bigquery",
    "bigquerydatatransfer_actions_allowed": "bigquerydatatransfer",
    "bigtable_actions_allowed": "bigtable",
    # ── cloud* ────────────────────────────────────────────────────────────────
    "cloudbuild_actions_allowed": "cloudbuild",
    "cloudcomposer_actions_allowed": "composer",
    "clouddeploy_actions_allowed": "clouddeploy",
    "clouddns_actions_allowed": "clouddns",
    "cloudrun_actions_allowed": "cloudrun",
    "cloudscheduler_actions_allowed": "cloudscheduler",
    "cloudsql_actions_allowed": "cloudsql",
    "cloudtasks_actions_allowed": "cloudtasks",
    "cloudworkflows_actions_allowed": "cloudworkflows",
    # ── compute / storage ─────────────────────────────────────────────────────
    "compute_actions_allowed": "computeinstance",
    "connectors_actions_allowed": "connectors",
    "datafusion_actions_allowed": "datafusion",
    "dataflow_actions_allowed": "dataflow",
    "dataform_actions_allowed": "dataform",
    "dataplex_actions_allowed": "dataplex",
    "dataproc_actions_allowed": "dataproc",
    "deploymentmanager_actions_allowed": "deploymentmanager",
    # ── E-F ───────────────────────────────────────────────────────────────────
    "eventarc_actions_allowed": "eventarc",
    "firebaseapphosting_actions_allowed": "firebaseapphosting",
    "firestore_actions_allowed": "firestore",
    "function_actions_allowed": "cloudfunction",
    # ── G-M ───────────────────────────────────────────────────────────────────
    "gke_actions_allowed": "gke",
    "iap_actions_allowed": "iap",
    "inframanager_actions_allowed": "inframanager",
    "kms_actions_allowed": "kms",
    "loadbalancing_actions_allowed": "loadbalancing",
    "memorystore_actions_allowed": "redis",
    # ── N-R ───────────────────────────────────────────────────────────────────
    "notebooks_actions_allowed": "notebooks",
    "orgpolicy_actions_allowed": "orgpolicy",
    "pubsub_actions_allowed": "pubsub",
    # ── S ─────────────────────────────────────────────────────────────────────
    "secret_actions_allowed": "secrets",
    "service_account_actions_allowed": "saaccounts",
    "servicedirectory_actions_allowed": "servicedirectory",
    "serviceusage_actions_allowed": "serviceusage",
    "spanner_actions_allowed": "spanner",
    "storage_actions_allowed": "bucket",
    # ── T-Z ───────────────────────────────────────────────────────────────────
    "agentplatform_actions_allowed": "aiplatform",
    "alloydb_actions_allowed": "alloydb",
    "tpu_actions_allowed": "tpu",
    "vertex_actions_allowed": "vertex",
    "vmmigration_actions_allowed": "vmmigration",
    "vpc_actions_allowed": "vpc",
    "workstations_actions_allowed": "workstations",
}

ACTION_SCOPE_COLUMNS = tuple(
    (str(spec["scope_key"]), str(spec["action_column"]))
    for spec in ACTION_SCOPE_SPECS
)
ACTION_SCOPE_KEY_TO_SCOPE_TYPE = {
    str(spec["scope_key"]): str(spec["scope_type"])
    for spec in ACTION_SCOPE_SPECS
}
_ACTION_SCOPE_COLUMN_TO_RESOURCE_TYPE = {
    str(spec["action_column"]): str(spec["resource_type"])
    for spec in ACTION_SCOPE_SPECS
}

ACTION_COLUMN_TO_RESOURCE_TYPE = {
    **_ACTION_SCOPE_COLUMN_TO_RESOURCE_TYPE,
    **ACTION_SERVICE_COLUMN_TO_RESOURCE_TYPE,
}

ACTION_PROVENANCE_COLUMN = "action_provenance"
ACTION_SCOPE_KEYS = {scope_key for scope_key, _ in ACTION_SCOPE_COLUMNS}
ACTION_COLUMNS = tuple(ACTION_COLUMN_TO_RESOURCE_TYPE)
