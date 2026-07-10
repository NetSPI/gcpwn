from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.contracts import HashableResourceProxy
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_tail, extract_project_id_from_resource
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


class HashableSecret(HashableResourceProxy):
    """Hashable wrapper around a Secret proto so secrets can live in sets/dicts (keyed by name)."""

    def __init__(self, secret, validated: bool = True):
        self._secret = secret
        super().__init__(
            secret,
            key_fields=("name",),
            validated=validated,
            repr_fields=("name",),
        )


def _normalize_resource_name(resource_name: str) -> str:
    return str(resource_name or "").strip()


def _safe_filename(value: str) -> str:
    token = str(value or "").strip()
    token = token.replace("/", "_")
    token = re.sub(r"[^A-Za-z0-9._-]+", "_", token)
    return token or "secret"


def _write_secret_value(
    session,
    *,
    project_id: str,
    secret_name: str,
    version_id: str,
    payload: bytes | bytearray | str,
) -> Path:
    """Write a decrypted secret payload to a per-secret/version loot file; return the path.

    Side effect: creates the download dir and writes bytes or text. This is the
    exfil of the actual secret value -- handle the returned file as sensitive.
    """
    filename = f"{_safe_filename(secret_name)}_{_safe_filename(version_id)}_value.txt"
    destination = session.get_download_save_path(
        service_name="secretmanager",
        filename=filename,
        project_id=project_id,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        destination.write_text(payload, encoding="utf-8")
    else:
        destination.write_bytes(bytes(payload))
    return destination


class _SecretsManagerBaseResource:
    """Base for Secret Manager resources: secretmanager_v1 client + shared IAM-test plumbing.

    Provides _test_iam_permissions (probe + record evidence with test_iam
    provenance) reused by both SecretsResource and SecretVersionsResource.
    """

    SERVICE_LABEL = "Secrets Manager"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import secretmanager_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Secret Manager enumeration requires the `google-cloud-secret-manager` package with `secretmanager_v1` support."
            ) from exc
        self._secretmanager_v1 = secretmanager_v1
        self.client = secretmanager_v1.SecretManagerServiceClient(credentials=session.credentials)

    def _resource_project_id(self, resource_name: str) -> str:
        fallback = str(getattr(self.session, "project_id", "") or "")
        return extract_project_id_from_resource(resource_name, fallback_project=fallback)

    def _record_test_iam_permissions(
        self,
        *,
        resource_id: str,
        permissions: list[str],
        action_dict: dict[str, Any] | None = None,
    ) -> list[str]:
        if permissions and action_dict is not None:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=self._resource_project_id(resource_id),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_normalize_resource_name(resource_id),
            )
        return permissions

    def _test_iam_permissions(
        self,
        *,
        resource_id: str,
        permission_hints: tuple[str, ...],
        api_name: str,
        action_dict: dict[str, Any] | None = None,
    ) -> list[str]:
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=_normalize_resource_name(resource_id),
            permissions=permission_hints,
            api_name=api_name,
            service_label=self.SERVICE_LABEL,
            project_id=self._resource_project_id(resource_id),
        )
        return self._record_test_iam_permissions(
            resource_id=_normalize_resource_name(resource_id),
            permissions=permissions,
            action_dict=action_dict,
        )


class SecretsResource(_SecretsManagerBaseResource):
    """List/get/testIamPermissions Secret Manager secrets (metadata only, not values)."""

    TABLE_NAME = "secretsmanager_secrets"
    COLUMNS = ["name", "expire_time", "labels"]
    LIST_PERMISSION = "secretmanager.secrets.list"
    GET_PERMISSION = "secretmanager.secrets.get"
    ACTION_RESOURCE_TYPE = "secrets"
    TEST_IAM_API_NAME = "secretmanager.secrets.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "secretmanager.secrets.",
        exclude_permissions=("secretmanager.secrets.create","secretmanager.secrets.list"),
    )

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        try:
            request = self._secretmanager_v1.ListSecretsRequest(parent=f"projects/{project_id}")
            rows = [resource_to_dict(secret) for secret in self.client.list_secrets(request=request)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="secretmanager.secrets.list",
                resource_name=f"projects/{project_id}",
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        normalized_name = _normalize_resource_name(resource_id)
        if not normalized_name:
            return None
        try:
            request = self._secretmanager_v1.GetSecretRequest(name=normalized_name)
            row = resource_to_dict(self.client.get_secret(request=request))
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=self._resource_project_id(normalized_name),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_name,
            )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="secretmanager.secrets.get",
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        return self._test_iam_permissions(
            resource_id=resource_id,
            permission_hints=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            action_dict=action_dict,
        )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_):
        normalized_project = _normalize_resource_name(project_id)
        for row in rows or []:
            normalized_row = resource_to_dict(row)
            project_token = extract_project_id_from_resource(
                normalized_row.get("name", ""),
                fallback_project=normalized_project,
            )
            save_to_table(
                self.session,
                self.TABLE_NAME,
                normalized_row,
                defaults={
                    "project_id": normalized_project,
                    "project_name": f"projects/{project_token}" if project_token else "",
                },
            )


class SecretVersionsResource(_SecretsManagerBaseResource):
    """List/get/access secret versions -- access_value() retrieves the cleartext payload.

    The high-value method is access_value() (secretmanager.versions.access),
    which returns the decrypted secret; download() then writes it to a loot file.
    """

    TABLE_NAME = "secretsmanager_secretversions"
    COLUMNS = ["name", "state", "etag", "secret_value"]
    LIST_PERMISSION = "secretmanager.versions.list"
    GET_PERMISSION = "secretmanager.versions.get"
    ACCESS_PERMISSION = "secretmanager.versions.access"
    ACTION_RESOURCE_TYPE = "secret version"
    TEST_IAM_API_NAME = "secretmanager.versions.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "secretmanager.versions.",
        exclude_permissions=(
            "secretmanager.versions.add",
            "secretmanager.versions.list"
        ),
    )

    @staticmethod
    def _version_label(resource_id: str) -> str:
        normalized_name = _normalize_resource_name(resource_id)
        if not normalized_name:
            return ""
        return f"{normalized_name.rpartition('/')[0]} (Version: {extract_path_tail(normalized_name, default=normalized_name)})"

    def list(self, *, secret_name: str = "", parent: str = "", location: str | None = None, action_dict=None):
        normalized_secret = _normalize_resource_name(secret_name or parent)
        if not normalized_secret:
            return []
        try:
            request = self._secretmanager_v1.ListSecretVersionsRequest(parent=normalized_secret)
            rows = [resource_to_dict(version) for version in self.client.list_secret_versions(request=request)]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=self._resource_project_id(normalized_secret),
                resource_type="secrets",
                resource_label=normalized_secret,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="secretmanager.versions.list",
                resource_name=normalized_secret,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        normalized_name = _normalize_resource_name(resource_id)
        if not normalized_name:
            return None
        try:
            request = self._secretmanager_v1.GetSecretVersionRequest(name=normalized_name)
            row = resource_to_dict(self.client.get_secret_version(request=request))
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=self._resource_project_id(normalized_name),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=self._version_label(normalized_name),
            )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="secretmanager.versions.get",
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def access_value(self, *, resource_id: str, action_dict=None):
        """Retrieve the decrypted payload of a secret version (the actual secret value).

        Records secretmanager.versions.access as evidence. Returns the SDK
        AccessSecretVersionResponse (payload under .payload.data), or None on
        error. This is the privileged read that exposes the cleartext secret.
        """
        normalized_name = _normalize_resource_name(resource_id)
        if not normalized_name:
            return None
        try:
            request = self._secretmanager_v1.AccessSecretVersionRequest(name=normalized_name)
            value = self.client.access_secret_version(request=request)
            record_permissions(
                action_dict,
                permissions=self.ACCESS_PERMISSION,
                project_id=self._resource_project_id(normalized_name),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=self._version_label(normalized_name),
            )
            return value
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="secretmanager.versions.access",
                resource_name=normalized_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        return self._test_iam_permissions(
            resource_id=resource_id,
            permission_hints=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            action_dict=action_dict,
        )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_):
        normalized_project = _normalize_resource_name(project_id)
        for row in rows or []:
            normalized_row = resource_to_dict(row)
            full_name = _normalize_resource_name(normalized_row.get("name", ""))
            version_num = extract_path_tail(full_name, default="") if full_name else ""
            project_token = extract_project_id_from_resource(
                full_name,
                fallback_project=normalized_project,
            )
            save_to_table(
                self.session,
                self.TABLE_NAME,
                normalized_row,
                defaults={
                    "project_id": normalized_project,
                    "project_name": f"projects/{project_token}" if project_token else "",
                    "version_num": version_num,
                },
            )

    def download(self, *, project_id: str, secret_name: str, version: str, payload):
        return _write_secret_value(
            self.session,
            project_id=project_id,
            secret_name=secret_name,
            version_id=version,
            payload=payload,
        )
