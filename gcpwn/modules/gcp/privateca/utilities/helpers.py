from __future__ import annotations

from google.cloud.security import privateca_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, resolve_regions_args


resolve_locations = resolve_regions_args


class PrivateCAPoolsResource(GcpListResource):
    """List/get Private CA Service CA pools per project+location.

    A ``CaPool`` groups Certificate Authorities under a shared issuance policy.
    Pools with ``ENTERPRISE`` tier are typically signing internal mTLS certs;
    pools with ``DEVOPS`` tier issue short-lived workload certs. Access to a pool's
    IAM policy reveals who can request certificate issuance (``privateca.caPools.use``).
    """

    SERVICE_LABEL = "Certificate Authority Service"
    TABLE_NAME = "privateca_pools"
    COLUMNS = [
        "location",
        "pool_id",
        "name",
        "tier",
    ]
    ACTION_RESOURCE_TYPE = "caPools"
    LIST_PERMISSION = "privateca.caPools.list"
    GET_PERMISSION = "privateca.caPools.get"
    TEST_IAM_API_NAME = "privateca.caPools.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes("privateca.caPools.")
    ID_FIELD = "pool_id"

    def _build_client(self, session):
        return privateca_v1.CertificateAuthorityServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_ca_pools(
            request=privateca_v1.ListCaPoolsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_ca_pool(
            request=privateca_v1.GetCaPoolRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "caPools") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        return {
            "pool_id": extract_path_segment(str(raw.get("name", "") or ""), "caPools"),
            "tier": str(raw.get("tier", "") or ""),
        }


class PrivateCACertificateAuthoritiesResource(GcpListResource):
    """List/get Certificate Authorities under a parent CA pool.

    A ``CertificateAuthority`` is the actual signing key. Its ``state``
    (ENABLED, DISABLED, STAGED, AWAITING_USER_ACTIVATION, DELETED) shows
    whether it is currently issuing certs. ``key_spec.algorithm`` reveals the
    signing algorithm; ``access_urls`` exposes the CA bundle and CRL endpoints.

    CAs are listed per parent CA pool (``PARENT_FROM_PROJECT_LOCATION=False``).
    """

    SERVICE_LABEL = "Certificate Authority Service"
    TABLE_NAME = "privateca_certificate_authorities"
    COLUMNS = [
        "location",
        "pool_id",
        "ca_id",
        "name",
        "state",
        "type",
        "tier",
        "ca_certificate_description",
        "key_algorithm",
        "gcs_bucket",
    ]
    ACTION_RESOURCE_TYPE = "certificateAuthorities"
    LIST_PERMISSION = "privateca.certificateAuthorities.list"
    GET_PERMISSION = "privateca.certificateAuthorities.get"
    LIST_RESOURCE_TYPE = "caPools"
    ID_FIELD = "ca_id"
    PARENT_FROM_PROJECT_LOCATION = False

    def _build_client(self, session):
        return privateca_v1.CertificateAuthorityServiceClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_certificate_authorities(
            request=privateca_v1.ListCertificateAuthoritiesRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_certificate_authority(
            request=privateca_v1.GetCertificateAuthorityRequest(name=resource_id)
        )

    def _get_resource_id(self, item) -> str:
        name = getattr(item, "name", "") or ""
        return extract_path_segment(name, "certificateAuthorities") or name

    def _extra_save_fields(self, raw: dict) -> dict:
        key_spec = raw.get("key_spec") if isinstance(raw.get("key_spec"), dict) else {}
        # pem_ca_certificates is a list; take the leaf cert description if present.
        ca_descs = raw.get("ca_certificate_descriptions") or []
        leaf_desc = str((ca_descs[0] if ca_descs else {}).get("subject_description", {}).get("common_name", "") or "")
        return {
            "pool_id": extract_path_segment(str(raw.get("name", "") or ""), "caPools"),
            "ca_id": extract_path_segment(str(raw.get("name", "") or ""), "certificateAuthorities"),
            "state": str(raw.get("state", "") or ""),
            "type": str(raw.get("type_", "") or raw.get("type", "") or ""),
            "tier": str(raw.get("tier", "") or ""),
            "ca_certificate_description": leaf_desc,
            "key_algorithm": str(key_spec.get("algorithm", "") or ""),
            "gcs_bucket": str(raw.get("gcs_bucket", "") or ""),
        }
