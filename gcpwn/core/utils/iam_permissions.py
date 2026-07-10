from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

from google.iam.v1 import iam_policy_pb2

from gcpwn.core.utils.service_runtime import handle_discovery_error, handle_service_error


@lru_cache(maxsize=1)
def _all_unique_permissions() -> tuple[str, ...]:
    # parents[2] is the gcpwn package root (parents[0]=utils, [1]=core, [2]=gcpwn).
    permissions_path = (
        Path(__file__).resolve().parents[2]
        / "modules"
        / "gcp"
        / "resourcemanager"
        / "utilities"
        / "data"
        / "all_project_permissions.txt"
    )
    if not permissions_path.exists():
        permissions_path = Path(__file__).resolve().parents[3] / "scripts" / "all_unique_permissions.txt"
    if not permissions_path.exists():
        return ()
    return tuple(
        line.strip()
        for line in permissions_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )


def permissions_with_prefixes(
    *prefixes: str | Iterable[str],
    exclude_permissions: Iterable[str] | None = None,
) -> tuple[str, ...]:
    normalized_prefixes = tuple(cleaned for prefix in prefixes if (cleaned := str(prefix or "").strip()))
    if not normalized_prefixes:
        return ()

    excluded = {cleaned for permission in exclude_permissions or () if (cleaned := str(permission or "").strip())}

    return tuple(
        permission
        for permission in _all_unique_permissions()
        if any(permission.startswith(prefix) for prefix in normalized_prefixes)
        and permission not in excluded
    )


def call_test_iam_permissions(
    *,
    client: Any,
    resource_name: str,
    permissions: Iterable[str],
    api_name: str,
    service_label: str,
    project_id: str | None = None,
    request_builder: Callable[[str, list[str]], Any] | None = None,
    caller: Callable[[Any], Any] | None = None,
    not_found_label: str | None = None,
    quiet_not_found: bool = False,
    return_not_enabled: bool = False,
) -> list[str]:
    normalized_resource_name = str(resource_name or "").strip()
    normalized_permissions = [str(permission).strip() for permission in permissions or [] if str(permission).strip()]
    if not normalized_resource_name or not normalized_permissions:
        return []

    request = (
        request_builder(normalized_resource_name, normalized_permissions)
        if callable(request_builder)
        else iam_policy_pb2.TestIamPermissionsRequest(
            resource=normalized_resource_name,
            permissions=normalized_permissions,
        )
    )

    def _invoke():
        if callable(caller):
            return caller(request)
        return client.test_iam_permissions(request=request)

    try:
        response = _invoke()
        return list(getattr(response, "permissions", []) or [])
    except Exception as exc:
        result = handle_service_error(
            exc,
            api_name=api_name,
            resource_name=normalized_resource_name,
            service_label=service_label,
            project_id=project_id,
            return_not_enabled=return_not_enabled,
            not_found_label=not_found_label,
            quiet_not_found=quiet_not_found,
        )
        return [] if result in (None, "Not Enabled") else list(result or [])


def call_discovery_test_iam_permissions(
    *,
    session: Any,
    discovery_service: Any,
    resource_name: str,
    request_builder: Callable[[Any, str], Any],
    api_name: str,
    service_label: str,
) -> list[str]:
    """testIamPermissions over a googleapiclient DISCOVERY service; return granted perms.

    The discovery sibling of ``call_test_iam_permissions`` (which is for GAPIC clients),
    for services whose testIamPermissions only lives on the discovery API (apigateway,
    bigquery, clouddns, some compute). ``request_builder(discovery_service, resource_name)``
    builds the collection-specific request (e.g. ``svc.gateways().testIamPermissions(...)``);
    this runs ``.execute()``, extracts/strips ``response["permissions"]``, and funnels any
    error through ``handle_discovery_error`` (yielding ``[]``). Does NOT record evidence --
    the caller records the returned permissions with test_iam provenance.
    """
    normalized_resource_name = str(resource_name or "").strip()
    if not normalized_resource_name:
        return []
    try:
        response = request_builder(discovery_service, normalized_resource_name).execute()
        return [
            str(permission).strip()
            for permission in ((response or {}).get("permissions") or [])
            if str(permission).strip()
        ]
    except Exception as exc:
        result = handle_discovery_error(
            session,
            api_name,
            normalized_resource_name,
            exc,
            service_label=service_label,
        )
        return [] if result in (None, "Not Enabled") else list(result or [])
