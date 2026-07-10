from __future__ import annotations

from typing import Any

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import region_resolver_for


resolve_regions = region_resolver_for("kms", ("cloudkms", "v1"))


def _kms_test_iam(resource: str) -> tuple[str, ...]:
    return permissions_with_prefixes(
        f"cloudkms.{resource}.",
        exclude_permissions=(f"cloudkms.{resource}.create", f"cloudkms.{resource}.list"),
    )


class _KmsResource(GcpListResource):
    SERVICE_LABEL = "Cloud KMS"

    def _build_client(self, session):
        try:
            from google.cloud import kms_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Cloud KMS enumeration requires the `google-cloud-kms` package."
            ) from exc
        return kms_v1.KeyManagementServiceClient(credentials=session.credentials)


class KmsKeyRingsResource(_KmsResource):
    """Enumerate Cloud KMS key rings per location into the ``kms_keyrings`` table."""

    TABLE_NAME = "kms_keyrings"
    COLUMNS = ["location", "keyring_id", "name", "create_time"]
    ACTION_RESOURCE_TYPE = "keyrings"
    LIST_PERMISSION = "cloudkms.keyRings.list"
    LIST_API_NAME = "cloudkms.projects.locations.keyRings.list"
    TEST_IAM_API_NAME = "cloudkms.keyRings.testIamPermissions"
    TEST_IAM_PERMISSIONS = _kms_test_iam("keyRings")
    LIST_METHOD = "list_key_rings"
    ID_FIELD = "keyring_id"


class KmsCryptoKeysResource(_KmsResource):
    """Enumerate KMS crypto keys (listed under each parent key ring) into ``kms_keys``.

    Listing is gated by ``cloudkms.cryptoKeys.list`` on the parent keyring
    (LIST_RESOURCE_TYPE='keyrings'), so the parent comes from enumerated key rings
    rather than project+location.
    """

    TABLE_NAME = "kms_keys"
    COLUMNS = ["location", "key_id", "name", "purpose", "primary_state", "next_rotation_time"]
    ACTION_RESOURCE_TYPE = "keys"
    LIST_PERMISSION = "cloudkms.cryptoKeys.list"
    LIST_RESOURCE_TYPE = "keyrings"  # listing keys is a permission on the parent keyring
    GET_PERMISSION = "cloudkms.cryptoKeys.get"
    TEST_IAM_API_NAME = "cloudkms.cryptoKeys.testIamPermissions"
    TEST_IAM_PERMISSIONS = _kms_test_iam("cryptoKeys")
    LIST_METHOD = "list_crypto_keys"
    GET_METHOD = "get_crypto_key"
    ID_FIELD = "key_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent keyring

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Flatten the nested ``primary.state`` into the row's ``primary_state`` column."""
        primary = raw.get("primary")
        return {"primary_state": primary.get("state") if isinstance(primary, dict) else ""}


class KmsCryptoKeyVersionsResource(_KmsResource):
    """Enumerate crypto key versions (under each parent crypto key) into ``kms_key_versions``.

    Versions intentionally record no permissions (LIST/GET_PERMISSION unset); only
    the error-message api_names are configured. Parent is a crypto key, not project+location.
    """

    TABLE_NAME = "kms_key_versions"
    COLUMNS = ["location", "version_id", "name", "state", "create_time", "destroy_time"]
    # Versions intentionally record no permissions (empty LIST/GET_PERMISSION);
    # only the error-message api_name is configured.
    LIST_API_NAME = "cloudkms.cryptoKeyVersions.list"
    GET_API_NAME = "cloudkms.cryptoKeyVersions.get"
    LIST_METHOD = "list_crypto_key_versions"
    GET_METHOD = "get_crypto_key_version"
    ID_FIELD = "version_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent crypto key
