"""GCP permission/resource-type taxonomy for OpenGraph IAM-binding analysis.

A zero-dependency leaf: hand-maintained maps from permission prefixes and internal
resource-type tokens to Google API services / canonical IAM-Condition resource types,
plus the small lookup helpers over them. Extracted from iam_bindings_shared_helpers so
the taxonomy tables live next to the functions that read them; imported back there (and
nowhere else references these symbols directly).
"""

from __future__ import annotations

from typing import Iterable

# Permission prefix -> canonical Google API service (used by conditional narrowing).
_PERMISSION_SERVICE_PREFIX_MAP: tuple[tuple[str, str], ...] = (
    ("resourcemanager.", "cloudresourcemanager.googleapis.com"),
    ("compute.", "compute.googleapis.com"),
    ("storage.", "storage.googleapis.com"),
    ("cloudfunctions.", "cloudfunctions.googleapis.com"),
    ("iam.", "iam.googleapis.com"),
    ("secretmanager.", "secretmanager.googleapis.com"),
    ("cloudkms.", "cloudkms.googleapis.com"),
    ("run.", "run.googleapis.com"),
    ("artifactregistry.", "artifactregistry.googleapis.com"),
    ("pubsub.", "pubsub.googleapis.com"),
    ("servicedirectory.", "servicedirectory.googleapis.com"),
    ("spanner.", "spanner.googleapis.com"),
    ("cloudtasks.", "cloudtasks.googleapis.com"),
)

# Permission prefix -> canonical full resource type(s) used by IAM Conditions.
_PERMISSION_RESOURCE_TYPE_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("resourcemanager.organizations.", ("cloudresourcemanager.googleapis.com/Organization",)),
    ("resourcemanager.folders.", ("cloudresourcemanager.googleapis.com/Folder",)),
    ("resourcemanager.projects.", ("cloudresourcemanager.googleapis.com/Project",)),
    ("compute.instances.", ("compute.googleapis.com/Instance",)),
    ("storage.buckets.", ("storage.googleapis.com/Bucket",)),
    ("storage.objects.", ("storage.googleapis.com/Object",)),
    ("cloudfunctions.functions.", ("cloudfunctions.googleapis.com/CloudFunction",)),
    ("iam.serviceAccounts.", ("iam.googleapis.com/ServiceAccount",)),
    ("iam.serviceAccountKeys.", ("iam.googleapis.com/ServiceAccountKey",)),
    ("iam.roles.", ("iam.googleapis.com/Role",)),
    ("secretmanager.secrets.", ("secretmanager.googleapis.com/Secret",)),
    ("secretmanager.versions.", ("secretmanager.googleapis.com/SecretVersion",)),
    ("cloudkms.keyRings.", ("cloudkms.googleapis.com/KeyRing",)),
    ("cloudkms.cryptoKeys.", ("cloudkms.googleapis.com/CryptoKey",)),
    ("run.services.", ("run.googleapis.com/Service",)),
    ("run.jobs.", ("run.googleapis.com/Job",)),
    ("artifactregistry.repositories.", ("artifactregistry.googleapis.com/Repository",)),
    ("pubsub.topics.", ("pubsub.googleapis.com/Topic",)),
    ("pubsub.subscriptions.", ("pubsub.googleapis.com/Subscription",)),
    ("pubsub.snapshots.", ("pubsub.googleapis.com/Snapshot",)),
    ("pubsub.schemas.", ("pubsub.googleapis.com/Schema",)),
    ("servicedirectory.namespaces.", ("servicedirectory.googleapis.com/Namespace",)),
    ("servicedirectory.services.", ("servicedirectory.googleapis.com/Service",)),
    ("spanner.instances.", ("spanner.googleapis.com/Instance",)),
    ("spanner.databases.", ("spanner.googleapis.com/Database",)),
    ("cloudtasks.queues.", ("cloudtasks.googleapis.com/Queue",)),
    ("cloudbuild.builds.", ("cloudbuild.googleapis.com/Build",)),
)

# Internal resource_type token -> canonical full resource type(s).
_RESOURCE_TYPE_TO_FULL_TYPE: dict[str, tuple[str, ...]] = {
    "org": ("cloudresourcemanager.googleapis.com/Organization",),
    "folder": ("cloudresourcemanager.googleapis.com/Folder",),
    "project": ("cloudresourcemanager.googleapis.com/Project",),
    "computeinstance": ("compute.googleapis.com/Instance",),
    "bucket": ("storage.googleapis.com/Bucket",),
    "cloudfunction": ("cloudfunctions.googleapis.com/CloudFunction",),
    "service-account": ("iam.googleapis.com/ServiceAccount",),
    "secrets": ("secretmanager.googleapis.com/Secret",),
    "kmskeyring": ("cloudkms.googleapis.com/KeyRing",),
    "kmscryptokey": ("cloudkms.googleapis.com/CryptoKey",),
    "cloudrunservice": ("run.googleapis.com/Service",),
    "cloudrunjob": ("run.googleapis.com/Job",),
    "artifactregistryrepo": ("artifactregistry.googleapis.com/Repository",),
    "pubsubtopic": ("pubsub.googleapis.com/Topic",),
    "pubsubsubscription": ("pubsub.googleapis.com/Subscription",),
    "pubsubsnapshot": ("pubsub.googleapis.com/Snapshot",),
    "pubsubschema": ("pubsub.googleapis.com/Schema",),
    "servicedirectorynamespace": ("servicedirectory.googleapis.com/Namespace",),
    "servicedirectoryservice": ("servicedirectory.googleapis.com/Service",),
    "spannerinstance": ("spanner.googleapis.com/Instance",),
    "spannerdatabase": ("spanner.googleapis.com/Database",),
    "cloudtasksqueue": ("cloudtasks.googleapis.com/Queue",),
    "cloudbuildbuild": ("cloudbuild.googleapis.com/Build",),
}

# Internal resource_type token -> owning Google API service. Derived from the full-type map
# (the service is the prefix before "/"), so the two never drift out of sync.
_RESOURCE_TYPE_TO_SERVICE: dict[str, str] = {
    token: full_types[0].split("/")[0]
    for token, full_types in _RESOURCE_TYPE_TO_FULL_TYPE.items()
}

_PREFERRED_RULE_RESOURCE_TOKENS: frozenset[str] = frozenset(
    {
        "org",
        "folder",
        "project",
        "computeinstance",
        "bucket",
        "cloudfunction",
        "service-account",
        "secrets",
        "kmskeyring",
        "kmscryptokey",
        "kmskeyversion",
        "cloudrunservice",
        "cloudrunjob",
        "artifactregistryrepo",
        "pubsubtopic",
        "pubsubsubscription",
        "pubsubsnapshot",
        "pubsubschema",
        "servicedirectorynamespace",
        "servicedirectoryservice",
        "spannerinstance",
        "spannerdatabase",
        "cloudtasksqueue",
        "cloudsqlinstance",
        "bigquerydataset",
        "bigquerytable",
        "bigqueryroutine",
        "cloudbuildbuild",
        # GKE cluster and fleet membership targets for GKE/GKEHub PE edges.
        # Without these, rules with on="k8scluster"/"fleetmembership" silently
        # fall back to ALL project resources, generating thousands of false-positive edges.
        "k8scluster",
        "fleetmembership",
        # Cloud Composer environment target for UPDATE_COMPOSER_ENV_AS_SA /
        # EXEC_COMPOSER_ENV_AS_SA PE edges.
        "composerenv",
        # Sensitive-resource-access targets. Without these the rules reading a
        # token from a specific resource (on="workstation"/"apikey"/"gitrepolink")
        # silently fall back to ALL project resources, fanning the read edge out
        # to every resource in the project.
        "workstation",
        "apikey",
        "gitrepolink",
        # BigQuery Spark connection (DELEGATE_BQ_CONNECTION_AS_SA) and Cloud Run
        # worker pool (SSH_CLOUDRUN_WORKERPOOL_AS_SA) resource targets — same
        # fall-back-to-all-resources hazard as above when unregistered.
        "bigqueryconnection",
        "cloudrunworkerpool",
    }
)


def _permission_service(permission: str) -> str:
    token = str(permission or "").strip()
    if not token:
        return ""
    for prefix, service in _PERMISSION_SERVICE_PREFIX_MAP:
        if token.startswith(prefix):
            return service
    return ""


def _services_for_permissions(permissions: Iterable[str]) -> set[str]:
    return {
        service
        for permission in (permissions or ())
        if (service := _permission_service(str(permission or "")))
    }


def _permission_resource_types(permission: str) -> set[str]:
    token = str(permission or "").strip()
    if not token:
        return set()
    for prefix, resource_types in _PERMISSION_RESOURCE_TYPE_MAP:
        if token.startswith(prefix):
            return set(resource_types or ())
    return set()


def _resource_types_for_permissions(permissions: Iterable[str]) -> set[str]:
    return {
        resource_type
        for permission in (permissions or ())
        for resource_type in _permission_resource_types(str(permission or ""))
    }
