from __future__ import annotations

from collections.abc import Iterable
from typing import Any

_RESOURCE_TYPE_NORMALIZATION: dict[str, str] = {
    # Keep this intentionally small: canonical resource_type tokens should be emitted upstream.
    "organization": "org",
    "organizations": "org",
    "folders": "folder",
    "projects": "project",
    "service-accounts": "service-account",
    "workload-identity-pools": "workloadidentitypool",
    "workload-identity-providers": "workloadidentityprovider",
}

RESOURCE_TOKEN_TO_NODE_TYPE: dict[str, str] = {
    "org": "GCPOrganization",
    "folder": "GCPFolder",
    "project": "GCPProject",
    "bucket": "GCPBucket",
    "cloudfunction": "GCPCloudFunction",
    "computeinstance": "GCPComputeInstance",
    "service-account": "GCPServiceAccountResource",
    "kmskeyring": "GCPKmsKeyRing",
    "kmscryptokey": "GCPKmsCryptoKey",
    "kmskeyversion": "GCPKmsCryptoKeyVersion",
    "cloudrunservice": "GCPCloudRunService",
    "cloudrunjob": "GCPCloudRunJob",
    "workloadidentitypool": "GCPWorkloadIdentityPool",
    "workloadidentityprovider": "GCPWorkloadIdentityProvider",
    "cloudsqlinstance": "GCPCloudSQLInstance",
    "artifactregistryrepo": "GCPArtifactRegistryRepo",
    "pubsubtopic": "GCPPubSubTopic",
    "pubsubsubscription": "GCPPubSubSubscription",
    "pubsubschema": "GCPPubSubSchema",
    "pubsubsnapshot": "GCPPubSubSnapshot",
    "spannerinstance": "GCPSpannerInstance",
    "spannerdatabase": "GCPSpannerDatabase",
    "servicedirectorynamespace": "GCPServiceDirectoryNamespace",
    "servicedirectoryservice": "GCPServiceDirectoryService",
    "bigquerydataset": "GCPBigQueryDataset",
    "bigquerytable": "GCPBigQueryTable",
    "bigqueryroutine": "GCPBigQueryRoutine",
    "cloudtasksqueue": "GCPCloudTasksQueue",
    "secrets": "GCPSecret",
}


def normalize_scope_type_token(scope_type: str | None) -> str:
    return str(scope_type or "").strip().lower().replace("_", "-").replace(" ", "-")


def normalize_resource_type_token(resource_type: str | None) -> str:
    token = normalize_scope_type_token(resource_type)
    return _RESOURCE_TYPE_NORMALIZATION.get(token, token)


def canonical_scope_type(scope_type: str | None, scope_name: str | None = None) -> str:
    raw_token = normalize_scope_type_token(scope_type)
    scope_name_token = str(scope_name or "").strip().lower()
    if raw_token == "services":
        if "/namespaces/" in scope_name_token:
            return "servicedirectoryservice"
        return "cloudrunservice"
    token = normalize_resource_type_token(raw_token)
    if token and token not in {"resource", "abstract"}:
        return token
    if scope_name_token.startswith("organizations/"):
        return "org"
    if scope_name_token.startswith("folders/"):
        return "folder"
    if scope_name_token.startswith("projects/"):
        return "project"
    return token or "resource"


def normalized_token_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, dict):
        source_values: Iterable[Any] = values.keys()
    elif isinstance(values, (list, tuple, set, frozenset)):
        source_values = values
    elif isinstance(values, Iterable) and not isinstance(values, (str, bytes)):
        source_values = values
    else:
        source_values = [values]
    return sorted(
        {
            token
            for value in source_values
            if (token := str(value or "").strip())
        }
    )


def normalized_token_frozenset(values: Any) -> frozenset[str]:
    return frozenset(normalized_token_list(values))
