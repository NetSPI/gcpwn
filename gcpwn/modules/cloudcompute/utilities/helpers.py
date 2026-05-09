from __future__ import annotations

import base64
import json
import re
import sys
import threading
import time
from importlib import import_module
from dataclasses import dataclass
from pathlib import Path

from collections import defaultdict
from typing import Any, Callable, List

from google.api_core.exceptions import (
    NotFound,
    Forbidden
)
from google.api_core.extended_operation import ExtendedOperation
from google.cloud import compute_v1

from gcpwn.modules.iam.utilities.helpers import compute_instance_get_iam_policy, instance_set_iam_policy
from gcpwn.core.console import UtilityTools
from gcpwn.core.contracts import HashableResourceProxy
from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import (
    build_discovery_service,
    handle_discovery_error,
    paged_list,
)
from gcpwn.core.utils.iam_permissions import call_test_iam_permissions, permissions_with_prefixes
from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error, is_api_disabled_error
from gcpwn.core.utils.service_runtime import parallel_map


def _is_insufficient_auth_scopes_error(exc: Exception) -> bool:
    return "insufficient authentication scopes" in str(exc or "").lower()


class HashableComputeProject(HashableResourceProxy):
    def __init__(self, compute_project, validated = True):
        self._compute_project = compute_project
        super().__init__(
            compute_project,
            key_fields=("id",),
            validated=validated,
            repr_fields=("id", "project_id"),
        )

class HashableInstance(HashableResourceProxy):

    network_interfaces_output = None
    metadata_output = None

    def __init__(self, instance, validated = True):
        self._instance = instance
        super().__init__(
            instance,
            key_fields=("id", "name"),
            validated=validated,
            repr_fields=("id", "name"),
        )

def _compute_download_path(
    session,
    *,
    project_id: str,
    filename: str,
    subdirs: list[str] | None = None,
    output: str | None = None,
) -> Path:
    safe_filename = compact_filename_component(filename)
    if output:
        destination = Path(output).expanduser() / safe_filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        return destination

    if hasattr(session, "get_download_save_path"):
        return Path(
            session.get_download_save_path(
                service_name="compute",
                filename=safe_filename,
                project_id=project_id,
                subdirs=subdirs,
            )
        )

    fallback = Path.cwd() / "gcpwn_output" / "downloads" / "compute" / project_id
    for part in subdirs or []:
        cleaned = str(part or "").strip()
        if cleaned:
            fallback /= cleaned
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback / safe_filename


def _write_compute_download(
    session,
    *,
    project_id: str,
    filename: str,
    payload: Any,
    subdirs: list[str] | None = None,
) -> Path:
    destination = _compute_download_path(
        session,
        project_id=project_id,
        filename=filename,
        subdirs=subdirs,
    )
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    return destination


def _metadata_only_payload(payload: dict[str, Any] | None, *, nested_key: str | None = None) -> Any:
    source = dict(payload or {})
    if nested_key:
        nested = source.get(nested_key)
        if isinstance(nested, dict):
            return nested.get("metadata") or {}
    return source.get("metadata") or {}


# Taken from code snippet at https://cloud.google.com/compute/docs/instances/stop-start-instance
def wait_for_extended_operation(
    operation: ExtendedOperation, verbose_name: str = "operation", timeout: int = 480
) -> Any:
    """
    Waits for the extended (long-running) operation to complete.

    If the operation is successful, it will return its result.
    If the operation ends with an error, an exception will be raised.
    If there were any warnings during the execution of the operation
    they will be printed to sys.stderr.

    Args:
        operation: a long-running operation you want to wait on.
        verbose_name: (optional) a more verbose name of the operation,
            used only during error and warning reporting.
        timeout: how long (in seconds) to wait for operation to finish.
            If None, wait indefinitely.

    Returns:
        Whatever the operation.result() returns.

    Raises:
        This method will raise the exception received from `operation.exception()`
        or RuntimeError if there is no exception set, but there is an `error_code`
        set for the `operation`.

        In case of an operation taking longer than `timeout` seconds to complete,
        a `concurrent.futures.TimeoutError` will be raised.
    """
    result = operation.result(timeout=timeout)

    if operation.error_code:
        print(
            f"Error during {verbose_name}: [Code: {operation.error_code}]: {operation.error_message}",
            file=sys.stderr,
            flush=True,
        )
        print(f"Operation ID: {operation.name}", file=sys.stderr, flush=True)
        raise operation.exception() or RuntimeError(operation.error_message)

    if operation.warnings:
        print(f"Warnings during {verbose_name}:\n", file=sys.stderr, flush=True)
        for warning in operation.warnings:
            print(f" - {warning.code}: {warning.message}", file=sys.stderr, flush=True)

    return result

def check_instance_format(instance_name: str) -> bool:
    return bool(
        re.fullmatch(
            r"projects/[^/]+/zones/[^/]+/instances/[^/]+",
            str(instance_name or "").strip(),
        )
    )


# https://cloud.google.com/compute/docs/instances/view-ip-address
def get_instance_ip_address(
    instance
) -> List[str]:
    """
    Retrieves the specified type of IP address (ipv6, internal or external) of a specified Compute Engine instance.

    Args:
        instance (compute_v1.Instance): instance to get
        ip_type (IPType): The type of IP address to retrieve (ipv6, internal or external).

    Returns:
        List[str]: Requested type IP addresses of the instance.
    """
    ips = []
    if not instance.network_interfaces:
        return ips
    for interface in instance.network_interfaces:

        for config in interface.access_configs:
            if config.type_ == "ONE_TO_ONE_NAT":
                ips.append(str(config.nat_i_p) + f" ({config.name})")

        for ipv6_config in getattr(interface, "ipv6_access_configs", []):
            if ipv6_config.type_ == "DIRECT_IPV6":
                ips.append(ipv6_config.external_ipv6)

        # Internal IP is directly available in the network interface.
        ips.append(interface.network_i_p)

    return ips


def _oslogin_enabled(raw: dict, *, metadata_key: str) -> str:
    metadata = raw.get(metadata_key) or {}
    items = metadata.get("items") if isinstance(metadata, dict) else None
    if not items:
        return "None"
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if "enable-oslogin" in str(item.get("key", "")):
            return "True" if str(item.get("value", "")).upper() == "TRUE" else "False"
    return "False"


def _compute_test_iam_permissions(
    *,
    client,
    resource_name: str,
    permissions: list[str] | tuple[str, ...],
    api_name: str,
    service_label: str,
    project_id: str,
    zone: str | None = None,
    region: str | None = None,
) -> list[str]:
    def _call(granted_permissions: list[str]):
        kwargs: dict[str, Any] = {
            "project": project_id,
            "resource": resource_name,
            "test_permissions_request_resource": {"permissions": list(granted_permissions)},
        }
        if zone:
            kwargs["zone"] = zone
        if region:
            kwargs["region"] = region
        return client.test_iam_permissions(**kwargs)

    return call_test_iam_permissions(
        client=client,
        resource_name=resource_name,
        permissions=permissions,
        api_name=api_name,
        service_label=service_label,
        project_id=project_id,
        request_builder=lambda _resource_name, granted_permissions: list(granted_permissions),
        caller=_call,
    )


def _merge_permissions(*collections: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    merged: list[str] = []
    seen: set[str] = set()
    for collection in collections:
        for permission in collection or ():
            token = str(permission or "").strip()
            if not token or token in seen:
                continue
            seen.add(token)
            merged.append(token)
    return tuple(merged)


def _manual_compute_iam_permissions(prefix: str) -> tuple[str, ...]:
    token = str(prefix or "").strip()
    if not token:
        return ()
    return (
        f"{token}get",
        f"{token}getIamPolicy",
        f"{token}list",
        f"{token}setIamPolicy",
    )


def _compute_permissions_with_fallback(
    *prefixes: str,
    exclude_permissions: tuple[str, ...] = (),
    extra_permissions: tuple[str, ...] = (),
) -> tuple[str, ...]:
    discovered = permissions_with_prefixes(*prefixes, exclude_permissions=exclude_permissions)
    return _merge_permissions(discovered, extra_permissions)


def _resource_self_link(raw: dict[str, Any]) -> str:
    return str(
        raw.get("self_link")
        or raw.get("self_link_with_id")
        or raw.get("selfLink")
        or raw.get("selfLinkWithId")
        or ""
    ).strip()


def _normalized_zone_from_raw(raw: dict[str, Any]) -> str:
    value = extract_path_tail(raw.get("zone"), default=str(raw.get("zone") or "").strip())
    if value:
        return value
    return extract_path_segment(_resource_self_link(raw), "zones")


def _normalized_region_from_raw(raw: dict[str, Any]) -> str:
    value = extract_path_tail(raw.get("region"), default=str(raw.get("region") or "").strip())
    if value:
        return value
    return extract_path_segment(_resource_self_link(raw), "regions")


def _reservation_name_from_raw(raw: dict[str, Any]) -> str:
    return extract_path_segment(_resource_self_link(raw), "reservations")


def _reservation_block_name_from_raw(raw: dict[str, Any]) -> str:
    return extract_path_segment(_resource_self_link(raw), "reservationBlocks")


def _reservation_parent_name_from_raw(raw: dict[str, Any]) -> str:
    reservation = str(raw.get("reservation") or raw.get("name") or "").strip() or _reservation_name_from_raw(raw)
    return f"reservations/{reservation}" if reservation else ""


def _reservation_block_parent_name_from_raw(raw: dict[str, Any]) -> str:
    reservation = str(raw.get("reservation") or "").strip() or _reservation_name_from_raw(raw)
    reservation_block = (
        str(raw.get("reservation_block") or raw.get("name") or "").strip()
        or _reservation_block_name_from_raw(raw)
    )
    if reservation and reservation_block:
        return f"reservations/{reservation}/reservationBlocks/{reservation_block}"
    return ""


def _compute_action_label(
    *,
    resource_id: str,
    zone: str | None = None,
    region: str | None = None,
    parent_name: str | None = None,
) -> str:
    parts: list[str] = []
    if zone:
        parts.extend(["zones", str(zone).strip()])
    if region:
        parts.extend(["regions", str(region).strip()])
    if parent_name:
        parts.append(str(parent_name).strip().strip("/"))
    parts.append(str(resource_id or "").strip())
    return "/".join([part for part in parts if part])


def _region_extra_builder(_obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
    return {"region": _normalized_region_from_raw(raw)}


def _zone_extra_builder(_obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "zone": _normalized_zone_from_raw(raw),
        "region": _normalized_region_from_raw(raw),
    }


def _aggregated_items(aggregated: Any, field_name: str) -> list[Any]:
    rows: list[Any] = []
    for _scope, scoped_list in aggregated:
        items = getattr(scoped_list, field_name, None) or []
        rows.extend(list(items))
    return rows


def _has_region(row: Any) -> bool:
    return bool(_normalized_region_from_raw(resource_to_dict(row)))


def _test_iam_permissions_without_project(
    *,
    client,
    resource_name: str,
    permissions: list[str] | tuple[str, ...],
    api_name: str,
    service_label: str,
    project_id: str | None = None,
) -> list[str]:
    return call_test_iam_permissions(
        client=client,
        resource_name=resource_name,
        permissions=permissions,
        api_name=api_name,
        service_label=service_label,
        project_id=project_id,
        request_builder=lambda _resource_name, granted_permissions: {
            "resource": _resource_name,
            "test_permissions_request_resource": {"permissions": list(granted_permissions)},
        },
    )


def _reservation_block_extra_builder(_obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "zone": _normalized_zone_from_raw(raw),
        "reservation": _reservation_name_from_raw(raw),
    }


def _reservation_sub_block_extra_builder(_obj: Any, raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "zone": _normalized_zone_from_raw(raw),
        "reservation": _reservation_name_from_raw(raw),
        "reservation_block": _reservation_block_name_from_raw(raw),
    }


@dataclass(frozen=True)
class CloudComputeDiscoveryResourceSpec:
    component_key: str
    help_text: str
    table_name: str
    summary_columns: tuple[str, ...]
    summary_title: str
    primary_resource: str
    collection_name: str
    action_resource_type: str
    list_permission: str
    test_iam_api_name: str
    test_iam_permissions: tuple[str, ...]
    location_scope: str = "global"
    primary_sort_key: str = "name"
    parent_dependency: str | None = None
    parent_param_name: str | None = None
    parent_name_extractor: Callable[[dict[str, Any]], str] | None = None
    save_extra_builder: Callable[[Any, dict[str, Any]], dict[str, Any]] | None = None
    get_param_name: str | None = None
    include_project_in_requests: bool = True


class CloudComputeDiscoveryResource:
    SERVICE_LABEL = "Compute"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    SUPPORTS_IAM = True

    def __init__(self, session, spec: CloudComputeDiscoveryResourceSpec):
        self.session = session
        self.spec = spec
        self.TABLE_NAME = spec.table_name
        self.COLUMNS = list(spec.summary_columns)
        self.ACTION_RESOURCE_TYPE = spec.action_resource_type
        self._discovery_service_local = threading.local()
        self._collection_available: bool | None = None

    @property
    def SUPPORTS_GET(self) -> bool:
        return bool(self.spec.get_param_name)

    def _service(self):
        service = getattr(self._discovery_service_local, "service", None)
        if service is None:
            service = build_discovery_service(
                getattr(self.session, "credentials", None),
                "compute",
                "v1",
                scopes=(self.CLOUD_PLATFORM_SCOPE,),
            )
            self._discovery_service_local.service = service
        return service

    def is_supported(self) -> bool:
        if self._collection_available is None:
            self._collection_available = hasattr(self._service(), self.spec.collection_name)
            if not self._collection_available:
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping {self.spec.summary_title}: "
                    f"compute discovery client does not expose `{self.spec.collection_name}`.{UtilityTools.RESET}"
                )
        return bool(self._collection_available)

    def _collection(self):
        if not self.is_supported():
            raise AttributeError(self.spec.collection_name)
        return getattr(self._service(), self.spec.collection_name)()

    def _request_kwargs(
        self,
        *,
        project_id: str,
        zone: str | None = None,
        region: str | None = None,
        parent_name: str | None = None,
        resource_id: str | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        if self.spec.include_project_in_requests:
            kwargs["project"] = project_id
        if self.spec.location_scope == "zone" and zone:
            kwargs["zone"] = zone
        if self.spec.location_scope == "region" and region:
            kwargs["region"] = region
        if self.spec.parent_param_name and parent_name:
            kwargs[self.spec.parent_param_name] = parent_name
        if resource_id:
            kwargs["resource"] = resource_id
        return kwargs

    def reference_from_row(self, row: Any) -> dict[str, Any]:
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        reference = {
            "resource_id": field_from_row(row, payload, "name"),
        }
        if self.spec.location_scope == "zone":
            reference["zone"] = _normalized_zone_from_raw(payload)
        elif self.spec.location_scope == "region":
            reference["region"] = _normalized_region_from_raw(payload)
        if callable(self.spec.parent_name_extractor):
            reference["parent_name"] = self.spec.parent_name_extractor(payload)
        return reference

    def list(
        self,
        *,
        project_id: str,
        zone: str | None = None,
        region: str | None = None,
        parent_name: str | None = None,
        action_dict=None,
    ):
        if not self.is_supported():
            return []
        request_kwargs = self._request_kwargs(
            project_id=project_id,
            zone=zone,
            region=region,
            parent_name=parent_name,
        )
        try:
            rows = paged_list(
                lambda page_token: self._collection().list(pageToken=page_token, **request_kwargs),
                items_key="items",
            )
            record_permissions(
                action_dict,
                permissions=self.spec.list_permission,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                self.spec.list_permission,
                parent_name or project_id,
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return "Not Enabled" if result == "Not Enabled" else []

    def get_iam_permissions(
        self,
        *,
        project_id: str,
        resource_id: str,
        zone: str | None = None,
        region: str | None = None,
        parent_name: str | None = None,
        action_dict=None,
    ) -> list[str]:
        if not self.is_supported():
            return []
        request_kwargs = self._request_kwargs(
            project_id=project_id,
            zone=zone,
            region=region,
            parent_name=parent_name,
            resource_id=resource_id,
        )
        try:
            response = self._collection().testIamPermissions(
                body={"permissions": list(self.spec.test_iam_permissions)},
                **request_kwargs,
            ).execute()
            permissions = [
                str(permission).strip()
                for permission in ((response or {}).get("permissions") or [])
                if str(permission).strip()
            ]
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                self.spec.test_iam_api_name,
                _compute_action_label(
                    resource_id=resource_id,
                    zone=zone,
                    region=region,
                    parent_name=parent_name,
                ),
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return [] if result in (None, "Not Enabled") else list(result or [])

        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(
                    resource_id=resource_id,
                    zone=zone,
                    region=region,
                    parent_name=parent_name,
                ),
            )
        return permissions

    def get(
        self,
        *,
        project_id: str,
        resource_id: str,
        zone: str | None = None,
        region: str | None = None,
        parent_name: str | None = None,
        action_dict=None,
    ) -> dict[str, Any] | None:
        if not self.SUPPORTS_GET:
            return None
        if not self.is_supported():
            return None

        request_kwargs = self._request_kwargs(
            project_id=project_id,
            zone=zone,
            region=region,
            parent_name=parent_name,
        )
        request_kwargs[str(self.spec.get_param_name)] = resource_id
        get_permission = self.spec.list_permission.rsplit(".", 1)[0] + ".get"
        try:
            row = self._collection().get(**request_kwargs).execute()
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                get_permission,
                _compute_action_label(
                    resource_id=resource_id,
                    zone=zone,
                    region=region,
                    parent_name=parent_name,
                ),
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return None if result in (None, "Not Enabled") else dict(result or {})

        if isinstance(row, dict) and row:
            record_permissions(
                action_dict,
                permissions=get_permission,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(
                    resource_id=resource_id,
                    zone=zone,
                    region=region,
                    parent_name=parent_name,
                ),
            )
        return row if isinstance(row, dict) else None

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=self.spec.save_extra_builder,
            )


CLOUDCOMPUTE_DISCOVERY_RESOURCE_SPECS: tuple[CloudComputeDiscoveryResourceSpec, ...] = (
    CloudComputeDiscoveryResourceSpec(
        component_key="region_network_firewall_policies",
        help_text="Enumerate Compute regional network firewall policies",
        table_name="cloudcompute_region_network_firewall_policies",
        summary_columns=("name", "region", "description"),
        summary_title="Compute Region Network Firewall Policies",
        primary_resource="Region Network Firewall Policies",
        collection_name="regionNetworkFirewallPolicies",
        action_resource_type="region_network_firewall_policies",
        list_permission="compute.regionFirewallPolicies.list",
        test_iam_api_name="compute.regionNetworkFirewallPolicies.testIamPermissions",
        test_iam_permissions=_compute_permissions_with_fallback(
            "compute.regionFirewallPolicies.",
            extra_permissions=_manual_compute_iam_permissions("compute.regionFirewallPolicies."),
        ),
        location_scope="region",
        save_extra_builder=_region_extra_builder,
        get_param_name="firewallPolicy",
    ),
    CloudComputeDiscoveryResourceSpec(
        component_key="service_attachments",
        help_text="Enumerate Compute service attachments",
        table_name="cloudcompute_service_attachments",
        summary_columns=("name", "region", "target_service", "connection_preference"),
        summary_title="Compute Service Attachments",
        primary_resource="Service Attachments",
        collection_name="serviceAttachments",
        action_resource_type="service_attachments",
        list_permission="compute.serviceAttachments.list",
        test_iam_api_name="compute.serviceAttachments.testIamPermissions",
        test_iam_permissions=_compute_permissions_with_fallback("compute.serviceAttachments."),
        location_scope="region",
        save_extra_builder=_region_extra_builder,
        get_param_name="serviceAttachment",
    ),
    CloudComputeDiscoveryResourceSpec(
        component_key="subnetworks",
        help_text="Enumerate Compute subnetworks",
        table_name="cloudcompute_subnetworks",
        summary_columns=("name", "region", "network", "ip_cidr_range"),
        summary_title="Compute Subnetworks",
        primary_resource="Subnetworks",
        collection_name="subnetworks",
        action_resource_type="subnetworks",
        list_permission="compute.subnetworks.list",
        test_iam_api_name="compute.subnetworks.testIamPermissions",
        test_iam_permissions=_compute_permissions_with_fallback("compute.subnetworks."),
        location_scope="region",
        save_extra_builder=_region_extra_builder,
        get_param_name="subnetwork",
    ),
)

########### Compute Instance API Calls

# Ref for arguments: https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation/blob/master/ExploitScripts/compute.instances.create.py
def create_instance(
        instance_client, 
        instance_name, 
        project_id, 
        instance_zone, 
        startup_script_data = None, 
        sa_email = None, 
        debug=False
    ):

    try:

        access = compute_v1.AccessConfig(type_=compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name, name="External NAT")

        body = {
            'name': instance_name,
            'machine_type': f'zones/{instance_zone}/machineTypes/e2-micro',
            'network_interfaces': [{
                'access_configs': [access],
                'network': 'global/networks/default'
            }],
            'disks': [{
                'auto_delete': True,
                'boot': True,
                'initialize_params': {
                    'source_image': 'projects/debian-cloud/global/images/family/debian-12'
                }
            }]
        }

        if sa_email:
            body['service_accounts'] = [{
                "email": sa_email,
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
            }]

        if startup_script_data:
            body['metadata'] = {
                'items': [{
                    'key': 'startup-script',
                    'value': startup_script_data
                }]
            }

        request = compute_v1.InsertInstanceRequest(
            project=project_id,
            zone=instance_zone,
            instance_resource=body
        )

        print(f"[*] Creating {instance_name} [{instance_zone}] in {project_id}. Note this might take a minute...")

        # Make the request
        operation = instance_client.insert(request=request)
        wait_for_extended_operation(operation, "instance creation")
     
        print(f"{UtilityTools.GREEN}[*] Instance {instance_name} created.{UtilityTools.RESET}")

        return 1

    except Forbidden as e:
        if "does not have compute.instances.create" in str(e):
            UtilityTools.print_403_api_denied("compute.instances.create permissions", project_id = project_id)

        elif is_api_disabled_error(e):
            UtilityTools.print_403_api_disabled("Compute", project_id)
            return "Not Enabled"
        
    except Exception as e:
        UtilityTools.print_500(instance_name, "compute.instances.create", e)
        return -1


def add_metadata(
        client, 
        action_dict,
        project_id, 
        added_metadata, 
        instance_name = None, 
        instance_zone= None, 
        type_of_resource = None, 
        overwrite_previous_key_values = False, 
        debug=False
    ):
    
    if type_of_resource == "instance":
        
        # Per google: You must always provide an up-to-date fingerprint hash in order to update or change metadata, otherwise the request will fail with error 412 conditionNotMet 
        current_instance = CloudComputeInstancesResource.get_with_client(
            client,
            instance_name,
            project_id,
            instance_zone,
            debug=debug,
        )

        if current_instance:
            
            current_metadata = current_instance.metadata
            fingerprint = current_metadata.fingerprint
 
            if not overwrite_previous_key_values:

                action_dict.setdefault(project_id, {}).setdefault("compute.instances.get", {}).setdefault("instances", set()).add(instance_name)


                starting_list  = list(current_metadata.items)
            
                # Append to existing values if key exists
                for new_entry in added_metadata:
                    key_exists = False
                    for item in starting_list:
                        if item.key == new_entry["key"]:
                            item.value = item.value + "\n"+new_entry["value"]
                            key_exists = True
                            break
                    if not key_exists:
                        starting_list.append(new_entry)
                
                final_metadata_list = starting_list

            else:

                final_metadata_list = added_metadata
                
        else:
            print("[X] Could not retrieve the fingerprint for the compute instance metadata. Thus no updates could be done. Exititng...")
            return None

        metadata_object = {
            "kind": "compute#metadata",
            "items":final_metadata_list
        }

        if fingerprint:
            metadata_object["fingerprint"] = fingerprint

        if debug:
            print(f"Setting Metadata to: {metadata_object}")

        output = CloudComputeInstancesResource.set_metadata_with_client(
            client,
            instance_name,
            project_id,
            instance_zone,
            metadata_object,
            debug=debug,
        )
        
        if output:
            action_dict.setdefault(project_id, {}).setdefault("compute.instances.setMetadata", {}).setdefault("instances", set()).add(instance_name)            

        return output

    elif type_of_resource == "project":
        
        current_project = CloudComputeProjectsResource.get_with_client(client, project_id, debug=debug)
        
        if current_project:

            current_metadata = current_project.common_instance_metadata
            fingerprint = current_metadata.fingerprint

            if not overwrite_previous_key_values:
                
                action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add("compute.projects.get")

                starting_list  = list(current_metadata.items)
                
                # Append to existing values if key exists
                for new_entry in added_metadata:
                    key_exists = False
                    for item in starting_list:
                        if item.key == new_entry["key"]:
                            item.value = item.value + "\n"+new_entry["value"]
                            key_exists = True
                            break
                    if not key_exists:
                        starting_list.append(new_entry)
                
                final_metadata_list = starting_list
        
            elif overwrite_previous_key_values:

                final_metadata_list = added_metadata

        else:
            print("[X] Could not retrieve the fingerprint for the compute project metadata. Thus no updates could be done. Exititng...")
            return None            

        metadata_object = {
        "kind": "compute#metadata",
        "items":final_metadata_list
        }

        if fingerprint:
            metadata_object["fingerprint"] = fingerprint

        output = CloudComputeProjectsResource.set_common_instance_metadata(
            client,
            project_id,
            metadata_object,
            debug=debug,
        )
        if output:
            action_dict.setdefault("project_permissions", {}).setdefault(project_id, set()).add("compute.projects.setCommonInstanceMetadata")            
        return output 

def add_instance_iam_member(instance_client, instance_name, project_id, zone, member, action_dict, brute = False, role = None, debug=False):
    
    additional_bind = {"role": role, "members": [member]}
    policy_dict = {}

    if brute:
        print(f"[*] Overwiting {instance_name} to just be {member}")

        policy_dict["bindings"] = []
        policy_dict["bindings"].append(additional_bind)
        policy_dict["version"] = 1
        policy = policy_dict

    else:

        print(f"[*] Fetching current policy for {instance_name}...")
        policy = compute_instance_get_iam_policy(instance_client, project_id, instance_name, zone, debug=debug)
    
        if policy:

            if policy == 404:

                print(f"{UtilityTools.RED}[X] Exiting the module as {instance_name} does not exist. Double check the name.{UtilityTools.RESET}")
                return -1

            else:

                action_dict.setdefault(project_id, {}).setdefault("compute.instances.getIamPolicy", {}).setdefault("instances", set()).add(instance_name)
                
                policy_dict["bindings"] = list(policy.bindings)
                policy_dict["bindings"].append(additional_bind)
                policy_dict["etag"] = policy.etag
                policy_dict["version"] = policy.version
                policy = policy_dict
        
        else:
            print(f"{UtilityTools.RED}[X] Exiting the module as current policy could not be retrieved to append. Try again and supply --brute to OVERWRITE entire bucket IAM policy if needed. NOTE THIS WILL OVERWRITE ALL PREVIOUS BINDINGS POTENTIALLY{UtilityTools.RESET}")
            return -1

    if policy is not None:
        policy_bindings = policy_dict["bindings"]
        print(f"[*] New policy below being added to {instance_name} \n{policy_bindings}")

    else:
        print(f"{UtilityTools.RED}[X] Exiting the module due to new policy not being created to add.{UtilityTools.RESET}")
        return -1

    status = instance_set_iam_policy(instance_client, instance_name, project_id, zone, policy, debug=debug)
    
    if status:
        if status == 404:
            print(
                f"{UtilityTools.RED}[X] Exiting the module as {instance_name} does not exist. "
                f"Double check the name.{UtilityTools.RESET}"
            )
            return -1

        else:
            action_dict.setdefault(project_id, {}).setdefault("compute.instances.setIamPolicy", {}).setdefault("instances", set()).add(instance_name)

    return status


class CloudComputeProjectsResource:
    TABLE_NAME = "cloudcompute_projects"
    COLUMNS = ["id", "project_id", "description", "metadata_enable_os_login"]
    LIST_PERMISSION = "compute.projects.get"

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.ProjectsClient(credentials=session.credentials)

    @staticmethod
    def get_with_client(compute_project_client, project_id, debug=False):
        if debug:
            print(f"[DEBUG] Getting compute project {project_id} ...")

        compute_project = None

        try:
            request = compute_v1.GetProjectRequest(project=project_id)
            compute_project = compute_project_client.get(request=request)
        except Forbidden as e:
            if "does not have compute.projects.get" in str(e):
                UtilityTools.print_403_api_denied("compute.projects.get permissions", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except NotFound as e:
            if f"{project_id}' was not found" in str(e):
                UtilityTools.print_404_resource(project_id)
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.projects.get", e)

        return compute_project

    @staticmethod
    def set_common_instance_metadata(instance_projects_client, project_id, metadata_object, debug=False):
        if debug:
            print(f"[DEBUG] Updating metadata for {project_id} ...")

        project_metadata = None

        try:
            request = compute_v1.SetCommonInstanceMetadataProjectRequest(
                project=project_id,
                metadata_resource=metadata_object,
            )
            project_metadata = instance_projects_client.set_common_instance_metadata(request=request)
        except Forbidden as e:
            if "does not have compute.projects.setCommonInstanceMetadata" in str(e):
                UtilityTools.print_403_api_denied("compute.projects.setCommonInstanceMetadata", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(project_id)
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.projects.setCommonInstanceMetadata", e)

        if debug:
            print("[DEBUG] Successfully completed instances update project metadata ..")

        return project_metadata

    def list(self, *, project_id: str, action_dict=None):
        project = self.get_with_client(self.client, project_id, debug=getattr(self.session, "debug", False))
        if project not in ("Not Enabled", None):
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return [project] if project not in ("Not Enabled", None) else []

    def get(self, *, resource_id: str, action_dict=None):
        row = self.get_with_client(self.client, resource_id, debug=getattr(self.session, "debug", False))
        if row:
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=str(resource_id or "").strip(),
            )
        return row

    def save(self, rows):
        for row in rows or []:
            save_to_table(
                self.session,
                "cloudcompute_projects",
                row,
                extra_builder=lambda _obj, raw: {
                    "project_id": raw.get("project_id") or raw.get("name") or getattr(row, "name", ""),
                    "metadata_enable_os_login": _oslogin_enabled(raw, metadata_key="common_instance_metadata"),
                },
            )
            project_id = ""
            if getattr(row, "name", None):
                project_id = extract_path_tail(str(row.name), default=str(row.name).strip())
            save_to_table(
                self.session,
                "abstract_tree_hierarchy",
                {"project_id": project_id, "name": "Unknown"},
                only_if_new_columns=["project_id"],
            )

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False

    def download_metadata(self, *, row: Any, project_id: str) -> Path | None:
        payload = resource_to_dict(row)
        if not payload:
            return None
        return _write_compute_download(
            self.session,
            project_id=project_id,
            filename=f"{project_id}_metadata.json",
            payload=payload,
            subdirs=["projects"],
        )


class CloudComputeInstancesResource:
    TABLE_NAME = "cloudcompute_instances"
    COLUMNS = ["name", "zone", "status", "network_interfaces_output", "metadata_output"]
    LIST_PERMISSION = "compute.instances.list"
    GET_PERMISSION = "compute.instances.get"
    START_PERMISSION = "compute.instances.start"
    STOP_PERMISSION = "compute.instances.stop"
    SET_METADATA_PERMISSION = "compute.instances.setMetadata"
    IAM_RESOURCE_TYPE = "instances"
    SCREENSHOT_PERMISSION = "compute.instances.getScreenshot"
    SERIAL_PERMISSION = "compute.instances.getSerialPortOutput"
    TEST_IAM_PERMISSIONS = _compute_permissions_with_fallback(
        "compute.instances.",
        exclude_permissions=(
            "compute.instances.create",
            "compute.instances.list",
        )
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.InstancesClient(credentials=session.credentials)
        self._zones_path = Path(__file__).resolve().parent / "data" / "zones.txt"

    @staticmethod
    def _handle_expected_artifact_error(exc: Exception, *, resource_id: str, artifact_label: str) -> bool:
        message = str(exc or "")
        if "Display device needs to be enabled for the instance" in message:
            UtilityTools.print_error(
                f"{artifact_label} unavailable for {resource_id}: display device is disabled on this VM."
            )
            return True
        if "is not ready" in message and "The resource" in message:
            UtilityTools.print_error(
                f"{artifact_label} unavailable for {resource_id}: the VM is not ready and may be stopped."
            )
            return True
        return False

    @staticmethod
    def list_zone_with_client(instances_client, project_id, zone, debug=False):
        if debug:
            print(f"[DEBUG] Listing instances for [{zone}] Project ID: {project_id}...")

        instance_list = []

        try:
            request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)
            instance_list = list(instances_client.list(request=request))
        except Forbidden as e:
            if "does not have compute.instances.list" in str(e):
                UtilityTools.print_403_api_denied("compute.instances.list permissions", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
            return None
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(project_id)
            return None
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.instances.list", e)
            return None

        return instance_list

    @staticmethod
    def list_aggregated_with_client(instances_client, project_id, debug=False):
        if debug:
            print(f"[DEBUG] Listing instances across all zones for Project ID: {project_id}...")

        all_instances = []

        try:
            request = compute_v1.AggregatedListInstancesRequest(project=project_id)
            agg_list = instances_client.aggregated_list(request=request)
            all_instances = defaultdict(list)

            for zone, response in agg_list:
                if response.instances:
                    all_instances[zone].extend(response.instances)
        except Forbidden as e:
            if "does not have compute.instances.list" in str(e):
                UtilityTools.print_403_api_denied("compute.instances.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
            return None
        except NotFound as e:
            if "was not found" in str(e) and f"{project_id}" in str(e):
                UtilityTools.print_404_resource(project_id)
            return None
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.instances.list", e)
            return None

        return all_instances

    @staticmethod
    def get_with_client(instances_client, instance_name, project_id, zone, debug=False):
        if debug:
            print(f"[DEBUG] Getting [{zone}] {instance_name} in {project_id}...")

        instance_metadata = None

        try:
            request = compute_v1.GetInstanceRequest(
                instance=instance_name,
                project=project_id,
                zone=zone,
            )
            instance_metadata = instances_client.get(request=request)
        except Forbidden as e:
            if "does not have compute.instances.get" in str(e):
                UtilityTools.print_403_api_denied("compute.instances.get", resource_name=instance_name)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(instance_name)
        except Exception as e:
            UtilityTools.print_500(instance_name, "compute.instances.get", e)

        if debug:
            print("[DEBUG] Successfully completed get_instance ...")

        return instance_metadata

    @classmethod
    def test_iam_permissions_with_client(cls, instance_client, project_id, instance_name, zone, debug=False):
        _ = debug

        def _build_request(resource_name: str, granted_permissions: list[str]):
            request = compute_v1.TestIamPermissionsInstanceRequest()
            request.project = project_id
            request.resource = resource_name
            request.zone = zone
            request.test_permissions_request_resource = {"permissions": granted_permissions}
            return request

        return call_test_iam_permissions(
            client=instance_client,
            resource_name=instance_name,
            permissions=cls.TEST_IAM_PERMISSIONS,
            api_name="compute.instances.testIamPermissions",
            service_label="Compute",
            project_id=project_id,
            request_builder=_build_request,
        )

    @staticmethod
    def set_metadata_with_client(instance_client, instance_name, project_id, zone_id, metadata_object, debug=False):
        if debug:
            print(f"[DEBUG] Updating metadata for [{zone_id}] {instance_name} in {project_id} ...")

        instance_metadata = None

        try:
            request = compute_v1.SetMetadataInstanceRequest(
                project=project_id,
                instance=instance_name,
                zone=zone_id,
                metadata_resource=metadata_object,
            )
            instance_metadata = instance_client.set_metadata(request=request)
        except Forbidden as e:
            if "does not have compute.instances.setCommonInstanceMetadata" in str(e):
                UtilityTools.print_403_api_denied("compute.instances.setCommonInstanceMetadata", resource_id=instance_name)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except Exception as e:
            UtilityTools.print_500(instance_name, "compute.instances.setCommonInstanceMetadata", e)

        if debug:
            print("[DEBUG] Successfully completed instances update instance metadata ..")

        return instance_metadata

    @staticmethod
    def stop_with_client(instance_client, project_id: str, zone: str, instance_name: str, debug=False):
        if debug:
            print(f"[DEBUG] Shutting down {instance_name} ...")

        stop_status = None

        try:
            request = compute_v1.StopInstanceRequest(
                instance=instance_name,
                project=project_id,
                zone=zone,
            )
            operation = instance_client.stop(request=request)
            stop_status = wait_for_extended_operation(operation, f"{instance_name} stopping")
            if stop_status is None:
                stop_status = 1
        except Forbidden as e:
            if "does not have compute.instances.stop" in str(e):
                UtilityTools.print_403_api_denied("compute.instances.stop", resource_name=instance_name)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(instance_name)
        except Exception as e:
            UtilityTools.print_500(instance_name, "compute.instances.stop", e)

        return stop_status

    @staticmethod
    def start_with_client(instance_client, project_id: str, zone: str, instance_name: str, debug=False):
        if debug:
            print(f"[DEBUG] Starting {instance_name} ...")

        start_status = None

        try:
            operation = instance_client.start(
                project=project_id,
                zone=zone,
                instance=instance_name,
            )
            start_status = wait_for_extended_operation(operation, "instance start")
            if start_status is None:
                start_status = 1
        except Forbidden as e:
            if "does not have compute.instances.start" in str(e):
                UtilityTools.print_403_api_denied("compute.instances.start", resource_name=instance_name)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(instance_name)
        except Exception as e:
            UtilityTools.print_500(instance_name, "compute.instances.start", e)

        return start_status

    def all_zones(self) -> List[str]:
        if not self._zones_path.exists():
            return []
        return [line.strip() for line in self._zones_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def list(self, *, project_id: str, zone: str | None = None, action_dict=None):
        if zone:
            rows = self.list_zone_with_client(self.client, project_id, zone, debug=getattr(self.session, "debug", False))
            if rows not in ("Not Enabled", None):
                record_permissions(
                    action_dict,
                    permissions=self.LIST_PERMISSION,
                    scope_key="project_permissions",
                    scope_label=project_id,
                )
            return rows
        aggregated = self.list_aggregated_with_client(self.client, project_id, debug=getattr(self.session, "debug", False))
        rows = []
        if isinstance(aggregated, dict):
            for _zone_name, instances in aggregated.items():
                rows.extend(instances or [])
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
        return rows

    def get(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        row = self.get_with_client(self.client, resource_id, project_id, zone, debug=getattr(self.session, "debug", False))
        if row:
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.IAM_RESOURCE_TYPE,
                resource_label=str(getattr(row, "name", "") or resource_id),
            )
        return row

    def get_iam_permissions(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        permissions = self.test_iam_permissions_with_client(
            self.client,
            project_id,
            resource_id,
            zone,
            debug=getattr(self.session, "debug", False),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.IAM_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def download_metadata(self, *, row: Any, project_id: str, zone: str | None = None) -> Path | None:
        payload = resource_to_dict(row)
        resource_id = field_from_row(row, payload, "name")
        if not payload or not resource_id:
            return None
        normalized_zone = extract_path_tail(
            str(zone or payload.get("zone") or ""),
            default=str(zone or payload.get("zone") or "").strip(),
        )
        subdirs = ["instances"]
        if normalized_zone:
            subdirs.append(normalized_zone)
        return _write_compute_download(
            self.session,
            project_id=project_id,
            filename=f"{resource_id}_metadata.json",
            payload=_metadata_only_payload(payload),
            subdirs=subdirs,
        )

    def download_serial(self, *, project_id: str, zone: str, resource_id: str, output: str | None = None, action_dict=None):
        debug = getattr(self.session, "debug", False)
        if debug:
            print(f"[DEBUG] Getting serial output for {resource_id} ...")

        destination = _compute_download_path(
            self.session,
            project_id=project_id,
            filename=f"{resource_id}_{time.time()}.txt",
            subdirs=["serial", zone],
            output=output,
        )
        try:
            request = compute_v1.GetSerialPortOutputInstanceRequest(
                instance=resource_id,
                project=project_id,
                zone=zone,
            )
            instance_serial = self.client.get_serial_port_output(request=request)

            if instance_serial:
                with open(destination, "w", encoding="utf-8") as handle:
                    handle.write(instance_serial.contents)
                record_permissions(
                    action_dict,
                    permissions=self.SERIAL_PERMISSION,
                    project_id=project_id,
                    resource_type=self.IAM_RESOURCE_TYPE,
                    resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
                )
        except Exception as exc:
            if self._handle_expected_artifact_error(exc, resource_id=resource_id, artifact_label="Serial output"):
                return None
            result = handle_service_error(
                exc,
                api_name=self.SERIAL_PERMISSION,
                resource_name=resource_id,
                service_label="Compute",
                project_id=project_id,
                return_not_enabled=True,
            )
            if result == "Not Enabled":
                return "Not Enabled"
            return None

        if debug:
            print("[DEBUG] Successfully completed instances getSerialOutput ..")
        return destination if instance_serial else None

    def download_screenshot(self, *, project_id: str, zone: str, resource_id: str, output: str | None = None, action_dict=None):
        debug = getattr(self.session, "debug", False)
        if debug:
            print(f"[DEBUG] Getting screenshot for {resource_id} ...")

        destination = _compute_download_path(
            self.session,
            project_id=project_id,
            filename=f"{resource_id}_{time.time()}.png",
            subdirs=["screenshots", zone],
            output=output,
        )
        try:
            request = compute_v1.GetScreenshotInstanceRequest(
                project=project_id,
                instance=resource_id,
                zone=zone,
            )
            instance_screenshot_b64 = self.client.get_screenshot(request=request)

            if instance_screenshot_b64:
                with open(destination, "wb") as handle:
                    handle.write(base64.b64decode(instance_screenshot_b64.contents))
                record_permissions(
                    action_dict,
                    permissions=self.SCREENSHOT_PERMISSION,
                    project_id=project_id,
                    resource_type=self.IAM_RESOURCE_TYPE,
                    resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
                )
        except Exception as exc:
            if self._handle_expected_artifact_error(exc, resource_id=resource_id, artifact_label="Screenshot"):
                return None
            result = handle_service_error(
                exc,
                api_name=self.SCREENSHOT_PERMISSION,
                resource_name=resource_id,
                service_label="Compute",
                project_id=project_id,
                return_not_enabled=True,
            )
            if result == "Not Enabled":
                return "Not Enabled"
            return None

        if debug:
            print("[DEBUG] Successfully completed instances getScreenshot ..")
        return destination if instance_screenshot_b64 else None

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                "cloudcompute_instances",
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "metadata_enable_os_login": _oslogin_enabled(raw, metadata_key="metadata"),
                    "zone": extract_path_tail(str(raw.get("zone", "")), default=str(raw.get("zone", "")).strip()) if raw.get("zone") else "",
                },
            )

    @staticmethod
    def normalize_summary_rows(instances):
        for instance in instances or []:
            instance._instance.zone = extract_path_tail(
                str(instance._instance.zone),
                default=str(instance._instance.zone).strip(),
            )
            metadata_items = getattr(instance._instance.metadata, "items", [])
            instance.metadata_output = [f"KEY: {item.key}\nVALUE: {item.value}" for item in metadata_items]
            if ips := get_instance_ip_address(instance):
                instance.network_interfaces_output = "\n".join(ips)
        return instances

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
        }


class CloudComputeDisksResource:
    TABLE_NAME = "cloudcompute_disks"
    COLUMNS = ["name", "zone", "status", "size_gb", "type", "users"]
    LIST_PERMISSION = "compute.disks.list"
    GET_PERMISSION = "compute.disks.get"
    ACTION_RESOURCE_TYPE = "disks"
    TEST_IAM_API_NAME = "compute.disks.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.disks.",
        exclude_permissions=("compute.disks.create","compute.disks.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.DisksClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str | None = None, action_dict=None):
        debug = getattr(self.session, "debug", False)
        try:
            if zone:
                req = compute_v1.ListDisksRequest(project=project_id, zone=zone)
                rows = list(self.client.list(request=req))
                record_permissions(
                    action_dict,
                    permissions=self.LIST_PERMISSION,
                    scope_key="project_permissions",
                    scope_label=project_id,
                )
                return rows

            req = compute_v1.AggregatedListDisksRequest(project=project_id)
            agg = self.client.aggregated_list(request=req)
            out = []
            for _scope, scoped_list in agg:
                disks = getattr(scoped_list, "disks", None) or []
                out.extend(list(disks))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return out
        except Forbidden as e:
            if "does not have compute.disks.list" in str(e):
                UtilityTools.print_403_api_denied("compute.disks.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.disks.list", e)
        if debug:
            print(f"[DEBUG] Failed listing disks for {project_id}")
        return []

    def get(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, zone=zone, disk=resource_id)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.disks.get" in str(e):
                UtilityTools.print_403_api_denied("compute.disks.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.disks.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            zone=zone,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "zone": extract_path_tail(str(raw.get("zone", "")), default=str(raw.get("zone", "")).strip()) if raw.get("zone") else "",
                    "size_gb": raw.get("size_gb") or raw.get("sizeGb") or "",
                    "source_image": raw.get("source_image") or raw.get("sourceImage") or "",
                    "source_snapshot": raw.get("source_snapshot") or raw.get("sourceSnapshot") or "",
                },
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
        }


class CloudComputeBackendBucketsResource:
    TABLE_NAME = "cloudcompute_backend_buckets"
    COLUMNS = ["name", "bucket_name", "enable_cdn"]
    LIST_PERMISSION = "compute.backendBuckets.list"
    GET_PERMISSION = "compute.backendBuckets.get"
    ACTION_RESOURCE_TYPE = "backend_buckets"
    TEST_IAM_API_NAME = "compute.backendBuckets.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.backendBuckets.",
        exclude_permissions=("compute.backendBuckets.create","compute.backendBuckets.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.BackendBucketsClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(request={"project": project_id}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.backendBuckets.list" in str(e):
                UtilityTools.print_403_api_denied("compute.backendBuckets.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.backendBuckets.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "backend_bucket": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.backendBuckets.get" in str(e):
                UtilityTools.print_403_api_denied("compute.backendBuckets.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.backendBuckets.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeBackendServicesResource:
    TABLE_NAME = "cloudcompute_backend_services"
    COLUMNS = ["name", "protocol", "load_balancing_scheme"]
    LIST_PERMISSION = "compute.backendServices.list"
    GET_PERMISSION = "compute.backendServices.get"
    ACTION_RESOURCE_TYPE = "backend_services"
    TEST_IAM_API_NAME = "compute.backendServices.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.backendServices.",
        exclude_permissions=("compute.backendServices.create","compute.backendServices.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.BackendServicesClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = [
                row for row in _aggregated_items(
                    self.client.aggregated_list(
                        request={"project": project_id, "return_partial_success": True}
                    ),
                    "backend_services",
                )
                if not _has_region(row)
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.backendServices.list" in str(e):
                UtilityTools.print_403_api_denied("compute.backendServices.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.backendServices.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "backend_service": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.backendServices.get" in str(e):
                UtilityTools.print_403_api_denied("compute.backendServices.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.backendServices.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeFirewallPoliciesResource:
    TABLE_NAME = "cloudcompute_firewall_policies"
    COLUMNS = ["name", "description"]
    LIST_PERMISSION = "compute.firewallPolicies.list"
    GET_PERMISSION = "compute.firewallPolicies.get"
    ACTION_RESOURCE_TYPE = "firewall_policies"
    TEST_IAM_API_NAME = "compute.firewallPolicies.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.firewallPolicies.",
        exclude_permissions=("compute.firewallPolicies.create","compute.firewallPolicies.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.FirewallPoliciesClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(request=compute_v1.ListFirewallPoliciesRequest()))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.firewallPolicies.list" in str(e):
                UtilityTools.print_403_api_denied("compute.firewallPolicies.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.firewallPolicies.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"firewall_policy": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.firewallPolicies.get" in str(e):
                UtilityTools.print_403_api_denied("compute.firewallPolicies.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.firewallPolicies.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _test_iam_permissions_without_project(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeInterconnectAttachmentGroupsResource:
    TABLE_NAME = "cloudcompute_interconnect_attachment_groups"
    COLUMNS = ["name", "description"]
    LIST_PERMISSION = "compute.interconnectAttachmentGroups.list"
    GET_PERMISSION = "compute.interconnectAttachmentGroups.get"
    ACTION_RESOURCE_TYPE = "interconnect_attachment_groups"
    TEST_IAM_API_NAME = "compute.interconnectAttachmentGroups.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.interconnectAttachmentGroups.",
        exclude_permissions=("compute.interconnectAttachmentGroups.create","compute.interconnectAttachmentGroups.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        client_cls = None
        try:
            client_cls = getattr(
                import_module("google.cloud.compute_v1.services.interconnect_attachment_groups"),
                "InterconnectAttachmentGroupsClient",
                None,
            )
        except Exception:
            client_cls = None
        self.client = client_cls(credentials=session.credentials) if client_cls else None
        self._client_available = self.client is not None
        self._unsupported_warned = False

    def _is_supported(self) -> bool:
        if not self._client_available and not self._unsupported_warned:
            print(
                f"{UtilityTools.YELLOW}[*] Skipping Compute Interconnect Attachment Groups: "
                "installed google-cloud-compute does not expose "
                "`google.cloud.compute_v1.services.interconnect_attachment_groups.InterconnectAttachmentGroupsClient`."
                f"{UtilityTools.RESET}"
            )
            self._unsupported_warned = True
        return self._client_available

    def list(self, *, project_id: str, action_dict=None):
        if not self._is_supported():
            return []
        try:
            rows = list(self.client.list(request={"project": project_id}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.interconnectAttachmentGroups.list" in str(e):
                UtilityTools.print_403_api_denied("compute.interconnectAttachmentGroups.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.interconnectAttachmentGroups.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        if not self._is_supported():
            return None
        try:
            row = self.client.get(request={"project": project_id, "interconnect_attachment_group": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.interconnectAttachmentGroups.get" in str(e):
                UtilityTools.print_403_api_denied(
                    "compute.interconnectAttachmentGroups.get",
                    resource_name=resource_id,
                )
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.interconnectAttachmentGroups.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        if not self._is_supported():
            return []
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeInterconnectGroupsResource:
    TABLE_NAME = "cloudcompute_interconnect_groups"
    COLUMNS = ["name", "description"]
    LIST_PERMISSION = "compute.interconnectGroups.list"
    GET_PERMISSION = "compute.interconnectGroups.get"
    ACTION_RESOURCE_TYPE = "interconnect_groups"
    TEST_IAM_API_NAME = "compute.interconnectGroups.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.interconnectGroups.",
        exclude_permissions=("compute.interconnectGroups.create","compute.interconnectGroups.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        client_cls = None
        try:
            client_cls = getattr(
                import_module("google.cloud.compute_v1.services.interconnect_groups"),
                "InterconnectGroupsClient",
                None,
            )
        except Exception:
            client_cls = None
        self.client = client_cls(credentials=session.credentials) if client_cls else None
        self._client_available = self.client is not None
        self._unsupported_warned = False

    def _is_supported(self) -> bool:
        if not self._client_available and not self._unsupported_warned:
            print(
                f"{UtilityTools.YELLOW}[*] Skipping Compute Interconnect Groups: "
                "installed google-cloud-compute does not expose "
                "`google.cloud.compute_v1.services.interconnect_groups.InterconnectGroupsClient`."
                f"{UtilityTools.RESET}"
            )
            self._unsupported_warned = True
        return self._client_available

    def list(self, *, project_id: str, action_dict=None):
        if not self._is_supported():
            return []
        try:
            rows = list(self.client.list(request={"project": project_id}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.interconnectGroups.list" in str(e):
                UtilityTools.print_403_api_denied("compute.interconnectGroups.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.interconnectGroups.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        if not self._is_supported():
            return None
        try:
            row = self.client.get(request={"project": project_id, "interconnect_group": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.interconnectGroups.get" in str(e):
                UtilityTools.print_403_api_denied("compute.interconnectGroups.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.interconnectGroups.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        if not self._is_supported():
            return []
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeMachineImagesResource:
    TABLE_NAME = "cloudcompute_machine_images"
    COLUMNS = ["name", "creation_timestamp", "source_instance", "status"]
    LIST_PERMISSION = "compute.machineImages.list"
    GET_PERMISSION = "compute.machineImages.get"
    ACTION_RESOURCE_TYPE = "machine_images"
    TEST_IAM_API_NAME = "compute.machineImages.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.machineImages.",
        exclude_permissions=("compute.machineImages.create","compute.machineImages.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.MachineImagesClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = list(self.client.list(request={"project": project_id}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.machineImages.list" in str(e):
                UtilityTools.print_403_api_denied("compute.machineImages.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.machineImages.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "machine_image": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.machineImages.get" in str(e):
                UtilityTools.print_403_api_denied("compute.machineImages.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.machineImages.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeNetworkAttachmentsResource:
    TABLE_NAME = "cloudcompute_network_attachments"
    COLUMNS = ["name", "region", "description"]
    LIST_PERMISSION = "compute.networkAttachments.list"
    GET_PERMISSION = "compute.networkAttachments.get"
    ACTION_RESOURCE_TYPE = "network_attachments"
    TEST_IAM_API_NAME = "compute.networkAttachments.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.networkAttachments.",
        exclude_permissions=("compute.networkAttachments.create","compute.networkAttachments.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.NetworkAttachmentsClient(credentials=session.credentials)

    def list(self, *, project_id: str, region: str | None = None, action_dict=None):
        try:
            if region:
                rows = list(self.client.list(request={"project": project_id, "region": region}))
            else:
                rows = _aggregated_items(
                    self.client.aggregated_list(
                        request={"project": project_id, "return_partial_success": True}
                    ),
                    "network_attachments",
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.networkAttachments.list" in str(e):
                UtilityTools.print_403_api_denied("compute.networkAttachments.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.networkAttachments.list", e)
        return []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "region": region, "network_attachment": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
            return row
        except Forbidden as e:
            if "does not have compute.networkAttachments.get" in str(e):
                UtilityTools.print_403_api_denied("compute.networkAttachments.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.networkAttachments.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_region_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": _normalized_region_from_raw(payload),
        }


class CloudComputeNetworkFirewallPoliciesResource:
    TABLE_NAME = "cloudcompute_network_firewall_policies"
    COLUMNS = ["name", "description"]
    LIST_PERMISSION = "compute.firewallPolicies.list"
    GET_PERMISSION = "compute.firewallPolicies.get"
    ACTION_RESOURCE_TYPE = "network_firewall_policies"
    TEST_IAM_API_NAME = "compute.networkFirewallPolicies.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.firewallPolicies.",
        exclude_permissions=("compute.firewallPolicies.create","compute.firewallPolicies.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.NetworkFirewallPoliciesClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            rows = [
                row for row in _aggregated_items(
                    self.client.aggregated_list(
                        request={"project": project_id, "return_partial_success": True}
                    ),
                    "network_firewall_policies",
                )
                if not _has_region(row)
            ]
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.networkFirewallPolicies.list" in str(e):
                UtilityTools.print_403_api_denied("compute.networkFirewallPolicies.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.networkFirewallPolicies.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "firewall_policy": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.networkFirewallPolicies.get" in str(e):
                UtilityTools.print_403_api_denied("compute.networkFirewallPolicies.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.networkFirewallPolicies.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeNodeGroupsResource:
    TABLE_NAME = "cloudcompute_node_groups"
    COLUMNS = ["name", "zone", "status", "node_template"]
    LIST_PERMISSION = "compute.nodeGroups.list"
    GET_PERMISSION = "compute.nodeGroups.get"
    ACTION_RESOURCE_TYPE = "node_groups"
    TEST_IAM_API_NAME = "compute.nodeGroups.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.nodeGroups.",
        exclude_permissions=("compute.nodeGroups.create","compute.nodeGroups.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.NodeGroupsClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str | None = None, action_dict=None):
        try:
            if zone:
                rows = list(self.client.list(request={"project": project_id, "zone": zone}))
            else:
                rows = _aggregated_items(
                    self.client.aggregated_list(
                        request={"project": project_id, "return_partial_success": True}
                    ),
                    "node_groups",
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.nodeGroups.list" in str(e):
                UtilityTools.print_403_api_denied("compute.nodeGroups.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.nodeGroups.list", e)
        return []

    def get(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "zone": zone, "node_group": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
            return row
        except Forbidden as e:
            if "does not have compute.nodeGroups.get" in str(e):
                UtilityTools.print_403_api_denied("compute.nodeGroups.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.nodeGroups.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            zone=zone,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_zone_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
        }


class CloudComputeNodeTemplatesResource:
    TABLE_NAME = "cloudcompute_node_templates"
    COLUMNS = ["name", "region", "status", "node_type"]
    LIST_PERMISSION = "compute.nodeTemplates.list"
    GET_PERMISSION = "compute.nodeTemplates.get"
    ACTION_RESOURCE_TYPE = "node_templates"
    TEST_IAM_API_NAME = "compute.nodeTemplates.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.nodeTemplates.",
        exclude_permissions=("compute.nodeTemplates.create","compute.nodeTemplates.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.NodeTemplatesClient(credentials=session.credentials)

    def list(self, *, project_id: str, region: str | None = None, action_dict=None):
        try:
            if region:
                rows = list(self.client.list(request={"project": project_id, "region": region}))
            else:
                rows = _aggregated_items(
                    self.client.aggregated_list(
                        request={"project": project_id, "return_partial_success": True}
                    ),
                    "node_templates",
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.nodeTemplates.list" in str(e):
                UtilityTools.print_403_api_denied("compute.nodeTemplates.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.nodeTemplates.list", e)
        return []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "region": region, "node_template": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
            return row
        except Forbidden as e:
            if "does not have compute.nodeTemplates.get" in str(e):
                UtilityTools.print_403_api_denied("compute.nodeTemplates.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.nodeTemplates.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_region_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": _normalized_region_from_raw(payload),
        }


class CloudComputeRegionBackendServicesResource:
    TABLE_NAME = "cloudcompute_region_backend_services"
    COLUMNS = ["name", "region", "protocol", "load_balancing_scheme"]
    LIST_PERMISSION = "compute.regionBackendServices.list"
    GET_PERMISSION = "compute.regionBackendServices.get"
    ACTION_RESOURCE_TYPE = "region_backend_services"
    TEST_IAM_API_NAME = "compute.regionBackendServices.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.regionBackendServices.",
        exclude_permissions=("compute.regionBackendServices.create","compute.regionBackendServices.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.RegionBackendServicesClient(credentials=session.credentials)

    def list(self, *, project_id: str, region: str | None = None, action_dict=None):
        if not region:
            return []
        try:
            rows = list(self.client.list(request={"project": project_id, "region": region}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.regionBackendServices.list" in str(e):
                UtilityTools.print_403_api_denied("compute.regionBackendServices.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.regionBackendServices.list", e)
        return []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "region": region, "backend_service": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
            return row
        except Forbidden as e:
            if "does not have compute.backendServices.get" in str(e):
                UtilityTools.print_403_api_denied("compute.backendServices.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.regionBackendServices.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_region_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": _normalized_region_from_raw(payload),
        }


class CloudComputeRegionDisksResource:
    TABLE_NAME = "cloudcompute_region_disks"
    COLUMNS = ["name", "region", "status", "size_gb", "type"]
    LIST_PERMISSION = "compute.regionDisks.list"
    GET_PERMISSION = "compute.disks.get"
    ACTION_RESOURCE_TYPE = "region_disks"
    TEST_IAM_API_NAME = "compute.regionDisks.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.disks.",
        exclude_permissions=("compute.disks.create","compute.disks.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.RegionDisksClient(credentials=session.credentials)

    def list(self, *, project_id: str, region: str | None = None, action_dict=None):
        if not region:
            return []
        try:
            rows = list(self.client.list(request={"project": project_id, "region": region}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.regionDisks.list" in str(e):
                UtilityTools.print_403_api_denied("compute.regionDisks.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.regionDisks.list", e)
        return []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "region": region, "disk": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
            return row
        except Forbidden as e:
            if "does not have compute.disks.get" in str(e):
                UtilityTools.print_403_api_denied("compute.disks.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.regionDisks.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": _normalized_region_from_raw(raw),
                    "size_gb": raw.get("size_gb") or raw.get("sizeGb") or "",
                    "source_image": raw.get("source_image") or raw.get("sourceImage") or "",
                    "source_snapshot": raw.get("source_snapshot") or raw.get("sourceSnapshot") or "",
                },
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": _normalized_region_from_raw(payload),
        }


class CloudComputeInstantSnapshotsResource:
    TABLE_NAME = "cloudcompute_instant_snapshots"
    COLUMNS = ["name", "zone", "status", "source_disk"]
    LIST_PERMISSION = "compute.instantSnapshots.list"
    GET_PERMISSION = "compute.instantSnapshots.get"
    ACTION_RESOURCE_TYPE = "instant_snapshots"
    TEST_IAM_API_NAME = "compute.instantSnapshots.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.instantSnapshots.",
        exclude_permissions=("compute.instantSnapshots.create","compute.instantSnapshots.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.InstantSnapshotsClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str | None = None, action_dict=None):
        debug = getattr(self.session, "debug", False)
        try:
            if zone:
                rows = list(self.client.list(request={"project": project_id, "zone": zone}))
            else:
                agg = self.client.aggregated_list(
                    request={"project": project_id, "return_partial_success": True}
                )
                rows = []
                for _scope, scoped_list in agg:
                    snapshots = getattr(scoped_list, "instant_snapshots", None) or []
                    rows.extend(list(snapshots))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.instantSnapshots.list" in str(e):
                UtilityTools.print_403_api_denied("compute.instantSnapshots.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(project_id)
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.instantSnapshots.list", e)
        if debug:
            print(f"[DEBUG] Failed listing instant snapshots for {project_id}")
        return []

    def get(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        resource_label = _compute_action_label(resource_id=resource_id, zone=zone)
        try:
            row = self.client.get(
                request={"project": project_id, "zone": zone, "instant_snapshot": resource_id}
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_label,
            )
            return row
        except Forbidden as e:
            if "does not have compute.instantSnapshots.get" in str(e):
                UtilityTools.print_403_api_denied("compute.instantSnapshots.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.instantSnapshots.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            zone=zone,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "zone": _normalized_zone_from_raw(raw),
                    "region": _normalized_region_from_raw(raw),
                    "source_disk": str(raw.get("source_disk") or raw.get("sourceDisk") or "").strip(),
                },
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
        }


class CloudComputeRegionInstantSnapshotsResource:
    TABLE_NAME = "cloudcompute_region_instant_snapshots"
    COLUMNS = ["name", "region", "status", "source_disk"]
    LIST_PERMISSION = "compute.instantSnapshots.list"
    GET_PERMISSION = "compute.instantSnapshots.get"
    ACTION_RESOURCE_TYPE = "region_instant_snapshots"
    TEST_IAM_API_NAME = "compute.regionInstantSnapshots.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.instantSnapshots.",
        exclude_permissions=("compute.instantSnapshots.create","compute.instantSnapshots.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.RegionInstantSnapshotsClient(credentials=session.credentials)

    def list(self, *, project_id: str, region: str | None = None, action_dict=None):
        debug = getattr(self.session, "debug", False)
        if not region:
            return []
        try:
            rows = list(self.client.list(request={"project": project_id, "region": region}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.instantSnapshots.list" in str(e):
                UtilityTools.print_403_api_denied("compute.instantSnapshots.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except NotFound as e:
            if "was not found" in str(e):
                UtilityTools.print_404_resource(project_id)
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.regionInstantSnapshots.list", e)
        if debug:
            print(f"[DEBUG] Failed listing regional instant snapshots for {project_id}")
        return []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        resource_label = _compute_action_label(resource_id=resource_id, region=region)
        try:
            row = self.client.get(
                request={"project": project_id, "region": region, "instant_snapshot": resource_id}
            )
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_label,
            )
            return row
        except Forbidden as e:
            if "does not have compute.instantSnapshots.get" in str(e):
                UtilityTools.print_403_api_denied("compute.instantSnapshots.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.regionInstantSnapshots.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "region": _normalized_region_from_raw(raw),
                    "source_disk": str(raw.get("source_disk") or raw.get("sourceDisk") or "").strip(),
                },
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": _normalized_region_from_raw(payload),
        }


class CloudComputeReservationsResource:
    TABLE_NAME = "cloudcompute_reservations"
    COLUMNS = ["name", "zone", "specific_reservation_required"]
    LIST_PERMISSION = "compute.reservations.list"
    GET_PERMISSION = "compute.reservations.get"
    ACTION_RESOURCE_TYPE = "reservations"
    TEST_IAM_API_NAME = "compute.reservations.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.reservations.",
        exclude_permissions=("compute.reservations.create","compute.reservations.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.ReservationsClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str | None = None, action_dict=None):
        try:
            if zone:
                rows = list(self.client.list(request={"project": project_id, "zone": zone}))
            else:
                rows = _aggregated_items(
                    self.client.aggregated_list(
                        request=compute_v1.AggregatedListReservationsRequest(
                            project=project_id,
                            return_partial_success=True,
                        )
                    ),
                    "reservations",
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.reservations.list" in str(e):
                UtilityTools.print_403_api_denied("compute.reservations.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.reservations.list", e)
        return []

    def get(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "zone": zone, "reservation": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
            return row
        except Forbidden as e:
            if "does not have compute.reservations.get" in str(e):
                UtilityTools.print_403_api_denied("compute.reservations.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.reservations.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            zone=zone,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_zone_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
        }


class CloudComputeResourcePoliciesResource:
    TABLE_NAME = "cloudcompute_resource_policies"
    COLUMNS = ["name", "region", "status"]
    LIST_PERMISSION = "compute.resourcePolicies.list"
    GET_PERMISSION = "compute.resourcePolicies.get"
    ACTION_RESOURCE_TYPE = "resource_policies"
    TEST_IAM_API_NAME = "compute.resourcePolicies.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.resourcePolicies.",
        exclude_permissions=("compute.resourcePolicies.create","compute.resourcePolicies.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.ResourcePoliciesClient(credentials=session.credentials)

    def list(self, *, project_id: str, region: str | None = None, action_dict=None):
        try:
            if region:
                rows = list(self.client.list(request={"project": project_id, "region": region}))
            else:
                rows = _aggregated_items(
                    self.client.aggregated_list(
                        request=compute_v1.AggregatedListResourcePoliciesRequest(
                            project=project_id,
                            return_partial_success=True,
                        )
                    ),
                    "resource_policies",
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.resourcePolicies.list" in str(e):
                UtilityTools.print_403_api_denied("compute.resourcePolicies.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.resourcePolicies.list", e)
        return []

    def get(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "region": region, "resource_policy": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
            return row
        except Forbidden as e:
            if "does not have compute.resourcePolicies.get" in str(e):
                UtilityTools.print_403_api_denied("compute.resourcePolicies.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.resourcePolicies.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, region: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, region=region),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_region_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": _normalized_region_from_raw(payload),
        }


class CloudComputeReservationBlocksResource:
    TABLE_NAME = "cloudcompute_reservation_blocks"
    COLUMNS = ["name", "zone", "reservation", "count", "in_use_count"]
    LIST_PERMISSION = "compute.reservationBlocks.list"
    GET_PERMISSION = "compute.reservationBlocks.get"
    ACTION_RESOURCE_TYPE = "reservation_blocks"
    TEST_IAM_API_NAME = "compute.reservationBlocks.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.reservationBlocks.",
        exclude_permissions=("compute.reservationBlocks.create","compute.reservationBlocks.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.ReservationBlocksClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str, parent_name: str, action_dict=None):
        try:
            rows = list(self.client.list(request={"project": project_id, "zone": zone, "parent_name": parent_name}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.reservationBlocks.list" in str(e):
                UtilityTools.print_403_api_denied("compute.reservationBlocks.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(parent_name or project_id, "compute.reservationBlocks.list", e)
        return []

    def get(self, *, project_id: str, zone: str, parent_name: str, resource_id: str, action_dict=None):
        try:
            response = self.client.get(
                request={
                    "project": project_id,
                    "zone": zone,
                    "parent_name": parent_name,
                    "reservation_block": resource_id,
                }
            )
            row = getattr(response, "resource", response)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone, parent_name=parent_name),
            )
            return row
        except Forbidden as e:
            if "does not have compute.reservationBlocks.get" in str(e):
                UtilityTools.print_403_api_denied("compute.reservationBlocks.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.reservationBlocks.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, parent_name: str, resource_id: str, action_dict=None):
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            request_builder=lambda _resource_name, granted_permissions: list(granted_permissions),
            caller=lambda granted_permissions: self.client.test_iam_permissions(
                project=project_id,
                zone=zone,
                parent_resource=extract_path_tail(parent_name, default=str(parent_name or "").strip()),
                resource=resource_id,
                test_permissions_request_resource={"permissions": list(granted_permissions)},
            ),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone, parent_name=parent_name),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_reservation_block_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
            "parent_name": _reservation_parent_name_from_raw(payload),
        }


class CloudComputeReservationSubBlocksResource:
    TABLE_NAME = "cloudcompute_reservation_sub_blocks"
    COLUMNS = ["name", "zone", "reservation", "reservation_block", "count", "in_use_count"]
    LIST_PERMISSION = "compute.reservationSubBlocks.list"
    GET_PERMISSION = "compute.reservationSubBlocks.get"
    ACTION_RESOURCE_TYPE = "reservation_sub_blocks"
    TEST_IAM_API_NAME = "compute.reservationSubBlocks.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.reservationSubBlocks.",
        exclude_permissions=("compute.reservationSubBlocks.create","compute.reservationSubBlocks.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.ReservationSubBlocksClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str, parent_name: str, action_dict=None):
        try:
            rows = list(self.client.list(request={"project": project_id, "zone": zone, "parent_name": parent_name}))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.reservationSubBlocks.list" in str(e):
                UtilityTools.print_403_api_denied("compute.reservationSubBlocks.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(parent_name or project_id, "compute.reservationSubBlocks.list", e)
        return []

    def get(self, *, project_id: str, zone: str, parent_name: str, resource_id: str, action_dict=None):
        try:
            response = self.client.get(
                request={
                    "project": project_id,
                    "zone": zone,
                    "parent_name": parent_name,
                    "reservation_sub_block": resource_id,
                }
            )
            row = getattr(response, "resource", response)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone, parent_name=parent_name),
            )
            return row
        except Forbidden as e:
            if "does not have compute.reservationSubBlocks.get" in str(e):
                UtilityTools.print_403_api_denied("compute.reservationSubBlocks.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.reservationSubBlocks.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, parent_name: str, resource_id: str, action_dict=None):
        permissions = call_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            request_builder=lambda _resource_name, granted_permissions: list(granted_permissions),
            caller=lambda granted_permissions: self.client.test_iam_permissions(
                project=project_id,
                zone=zone,
                parent_resource=parent_name,
                resource=resource_id,
                test_permissions_request_resource={"permissions": list(granted_permissions)},
            ),
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone, parent_name=parent_name),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_reservation_sub_block_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
            "parent_name": _reservation_block_parent_name_from_raw(payload),
        }


class CloudComputeStoragePoolsResource:
    TABLE_NAME = "cloudcompute_storage_pools"
    COLUMNS = ["name", "zone", "status", "storage_pool_type"]
    LIST_PERMISSION = "compute.storagePools.list"
    GET_PERMISSION = "compute.storagePools.get"
    ACTION_RESOURCE_TYPE = "storage_pools"
    TEST_IAM_API_NAME = "compute.storagePools.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.storagePools.",
        exclude_permissions=("compute.storagePools.create","compute.storagePools.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.StoragePoolsClient(credentials=session.credentials)

    def list(self, *, project_id: str, zone: str | None = None, action_dict=None):
        try:
            if zone:
                rows = list(self.client.list(request={"project": project_id, "zone": zone}))
            else:
                rows = _aggregated_items(
                    self.client.aggregated_list(
                        request=compute_v1.AggregatedListStoragePoolsRequest(
                            project=project_id,
                            return_partial_success=True,
                        )
                    ),
                    "storage_pools",
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.storagePools.list" in str(e):
                UtilityTools.print_403_api_denied("compute.storagePools.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.storagePools.list", e)
        return []

    def get(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(request={"project": project_id, "zone": zone, "storage_pool": resource_id})
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
            return row
        except Forbidden as e:
            if "does not have compute.storagePools.get" in str(e):
                UtilityTools.print_403_api_denied("compute.storagePools.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.storagePools.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, zone: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
            zone=zone,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=_compute_action_label(resource_id=resource_id, zone=zone),
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=_zone_extra_builder,
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "zone": _normalized_zone_from_raw(payload),
        }


class CloudComputeSnapshotsResource:
    TABLE_NAME = "cloudcompute_snapshots"
    COLUMNS = ["name", "status", "storage_bytes"]
    LIST_PERMISSION = "compute.snapshots.list"
    GET_PERMISSION = "compute.snapshots.get"
    ACTION_RESOURCE_TYPE = "snapshots"
    TEST_IAM_API_NAME = "compute.snapshots.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.snapshots.",
        exclude_permissions=("compute.snapshots.create","compute.snapshots.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.SnapshotsClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            req = compute_v1.ListSnapshotsRequest(project=project_id)
            rows = list(self.client.list(request=req))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.snapshots.list" in str(e):
                UtilityTools.print_403_api_denied("compute.snapshots.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.snapshots.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, snapshot=resource_id)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.snapshots.get" in str(e):
                UtilityTools.print_403_api_denied("compute.snapshots.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.snapshots.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeImagesResource:
    TABLE_NAME = "cloudcompute_images"
    COLUMNS = ["name", "family", "status", "creation_timestamp", "source_disk", "source_snapshot"]
    LIST_PERMISSION = "compute.images.list"
    GET_PERMISSION = "compute.images.get"
    ACTION_RESOURCE_TYPE = "images"
    TEST_IAM_API_NAME = "compute.images.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.images.",
        exclude_permissions=("compute.images.create","compute.images.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.ImagesClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            req = compute_v1.ListImagesRequest(project=project_id)
            rows = list(self.client.list(request=req))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.images.list" in str(e):
                UtilityTools.print_403_api_denied("compute.images.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.images.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, action_dict=None):
        try:
            row = self.client.get(project=project_id, image=resource_id)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.images.get" in str(e):
                UtilityTools.print_403_api_denied("compute.images.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.images.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, action_dict=None):
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {"resource_id": field_from_row(row, payload, "name")}


class CloudComputeInstanceTemplatesResource:
    TABLE_NAME = "cloudcompute_instance_templates"
    COLUMNS = ["name", "creation_timestamp"]
    LIST_PERMISSION = "compute.instanceTemplates.list"
    GET_PERMISSION = "compute.instanceTemplates.get"
    ACTION_RESOURCE_TYPE = "instance_templates"
    TEST_IAM_API_NAME = "compute.instanceTemplates.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.instanceTemplates.",
        exclude_permissions=("compute.instanceTemplates.create","compute.instanceTemplates.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.client = compute_v1.InstanceTemplatesClient(credentials=session.credentials)
        self.regional_client = compute_v1.RegionInstanceTemplatesClient(credentials=session.credentials)

    def list(self, *, project_id: str, action_dict=None):
        try:
            req = compute_v1.AggregatedListInstanceTemplatesRequest(
                project=project_id,
                return_partial_success=True,
            )
            aggregated = self.client.aggregated_list(request=req)
            rows = []
            for _scope, scoped_list in aggregated:
                templates = getattr(scoped_list, "instance_templates", None) or []
                rows.extend(list(templates))
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Forbidden as e:
            if "does not have compute.instanceTemplates.list" in str(e):
                UtilityTools.print_403_api_denied("compute.instanceTemplates.list", project_id=project_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
                return "Not Enabled"
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.instanceTemplates.list", e)
        return []

    def get(self, *, project_id: str, resource_id: str, region: str | None = None, action_dict=None):
        try:
            if region:
                row = self.regional_client.get(
                    project=project_id,
                    region=region,
                    instance_template=resource_id,
                )
            else:
                row = self.client.get(project=project_id, instance_template=resource_id)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.instanceTemplates.get" in str(e):
                UtilityTools.print_403_api_denied("compute.instanceTemplates.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.instanceTemplates.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, region: str | None = None, action_dict=None):
        if region:
            return []
        permissions = _compute_test_iam_permissions(
            client=self.client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME,
            service_label="Compute",
            project_id=project_id,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    def download_metadata(self, *, row: Any, project_id: str) -> Path | None:
        payload = resource_to_dict(row)
        resource_id = field_from_row(row, payload, "name")
        if not payload or not resource_id:
            return None
        return _write_compute_download(
            self.session,
            project_id=project_id,
            filename=f"{resource_id}.json",
            payload=_metadata_only_payload(payload, nested_key="properties"),
            subdirs=["instance_templates"],
        )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        return {
            "resource_id": field_from_row(row, payload, "name"),
            "region": extract_path_tail(
                field_from_row(row, payload, "region"),
                default=str(field_from_row(row, payload, "region") or "").strip(),
            ),
        }


def _list_all_compute_regions(session, *, project_id: str) -> list[str]:
    try:
        client = compute_v1.RegionsClient(credentials=session.credentials)
        req = compute_v1.ListRegionsRequest(project=project_id)
        return [region.name for region in client.list(request=req) if getattr(region, "name", None)]
    except Exception:
        preferred = getattr(session, "config_regions_list", None) or []
        return list(preferred) if preferred else []


class CloudComputeInstanceGroupsResource:
    TABLE_NAME = "cloudcompute_instance_groups"
    COLUMNS = ["name", "zone", "region", "size", "network", "subnetwork"]
    LIST_PERMISSION = "compute.instanceGroups.list"
    GET_PERMISSION = "compute.instanceGroups.get"
    ACTION_RESOURCE_TYPE = "instance_groups"
    TEST_IAM_API_NAME_ZONAL = "compute.instanceGroups.testIamPermissions"
    TEST_IAM_API_NAME_REGIONAL = "compute.regionInstanceGroups.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "compute.instanceGroups.",
        exclude_permissions=("compute.instanceGroups.create","compute.instanceGroups.list"),
    )
    SUPPORTS_GET = True
    SUPPORTS_IAM = True

    def __init__(self, session):
        self.session = session
        self.zonal = compute_v1.InstanceGroupsClient(credentials=session.credentials)
        self.regional = compute_v1.RegionInstanceGroupsClient(credentials=session.credentials)

    def list(self, *, project_id: str, zones: list[str] | None = None, regions: list[str] | None = None, threads: int = 3, action_dict=None):
        try:
            zones = zones or []
            regions = regions or []

            if not zones and not regions:
                out = _aggregated_items(
                    self.zonal.aggregated_list(
                        request=compute_v1.AggregatedListInstanceGroupsRequest(
                            project=project_id,
                            return_partial_success=True,
                        )
                    ),
                    "instance_groups",
                )
            else:
                out = []
                zone_batches = parallel_map(
                    zones,
                    lambda zone: list(
                        self.zonal.list(request=compute_v1.ListInstanceGroupsRequest(project=project_id, zone=zone))
                    ),
                    threads=threads,
                )
                for batch in zone_batches:
                    if batch:
                        out.extend(batch)

                region_batches = parallel_map(
                    regions,
                    lambda region: list(
                        self.regional.list(request=compute_v1.ListRegionInstanceGroupsRequest(project=project_id, region=region))
                    ),
                    threads=threads,
                )
                for batch in region_batches:
                    if batch:
                        out.extend(batch)
        except Forbidden as e:
            if _is_insufficient_auth_scopes_error(e):
                UtilityTools.print_403_insufficient_scopes(
                    permission_name="compute.instanceGroups.list",
                    project_id=project_id,
                    current_scopes=getattr(self.session, "scopes", None),
                    suggested_scope="https://www.googleapis.com/auth/cloud-platform",
                )
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
            else:
                UtilityTools.print_403_api_denied("compute.instanceGroups.list", project_id=project_id)
            return []
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.instanceGroups.list", e)
            return []

        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return out

    def get(self, *, project_id: str, resource_id: str, zone: str | None = None, region: str | None = None, action_dict=None):
        try:
            if zone:
                row = self.zonal.get(project=project_id, zone=zone, instance_group=resource_id)
            else:
                row = self.regional.get(project=project_id, region=region, instance_group=resource_id)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.instanceGroups.get" in str(e):
                UtilityTools.print_403_api_denied("compute.instanceGroups.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.instanceGroups.get", e)
        return None

    def get_iam_permissions(self, *, project_id: str, resource_id: str, zone: str | None = None, region: str | None = None, action_dict=None):
        client = self.zonal if zone else self.regional
        permissions = _compute_test_iam_permissions(
            client=client,
            resource_name=resource_id,
            permissions=self.TEST_IAM_PERMISSIONS,
            api_name=self.TEST_IAM_API_NAME_ZONAL if zone else self.TEST_IAM_API_NAME_REGIONAL,
            service_label="Compute",
            project_id=project_id,
            zone=zone,
            region=region,
        )
        if permissions:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
        return permissions

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "zone": extract_path_tail(str(raw.get("zone", "")), default=str(raw.get("zone", "")).strip()) if raw.get("zone") else "",
                    "region": extract_path_tail(str(raw.get("region", "")), default=str(raw.get("region", "")).strip()) if raw.get("region") else "",
                },
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        reference = {
            "resource_id": field_from_row(row, payload, "name"),
        }
        zone = _normalized_zone_from_raw(payload)
        region = _normalized_region_from_raw(payload)
        if zone:
            reference["zone"] = zone
        if region:
            reference["region"] = region
        return reference


class CloudComputeInstanceGroupManagersResource:
    TABLE_NAME = "cloudcompute_instance_group_managers"
    COLUMNS = ["name", "zone", "region", "base_instance_name", "target_size", "instance_template"]
    LIST_PERMISSION = "compute.instanceGroupManagers.list"
    GET_PERMISSION = "compute.instanceGroupManagers.get"
    ACTION_RESOURCE_TYPE = "instance_group_managers"
    SUPPORTS_GET = True
    SUPPORTS_IAM = False

    def __init__(self, session):
        self.session = session
        self.zonal = compute_v1.InstanceGroupManagersClient(credentials=session.credentials)
        self.regional = compute_v1.RegionInstanceGroupManagersClient(credentials=session.credentials)

    def list(self, *, project_id: str, zones: list[str] | None = None, regions: list[str] | None = None, threads: int = 3, action_dict=None):
        try:
            zones = zones or []
            regions = regions or []

            if not zones and not regions:
                out = _aggregated_items(
                    self.zonal.aggregated_list(
                        request=compute_v1.AggregatedListInstanceGroupManagersRequest(
                            project=project_id,
                            return_partial_success=True,
                        )
                    ),
                    "instance_group_managers",
                )
            else:
                out = []
                zone_batches = parallel_map(
                    zones,
                    lambda zone: list(
                        self.zonal.list(request=compute_v1.ListInstanceGroupManagersRequest(project=project_id, zone=zone))
                    ),
                    threads=threads,
                )
                for batch in zone_batches:
                    if batch:
                        out.extend(batch)

                region_batches = parallel_map(
                    regions,
                    lambda region: list(
                        self.regional.list(
                            request=compute_v1.ListRegionInstanceGroupManagersRequest(project=project_id, region=region)
                        )
                    ),
                    threads=threads,
                )
                for batch in region_batches:
                    if batch:
                        out.extend(batch)
        except Forbidden as e:
            if _is_insufficient_auth_scopes_error(e):
                UtilityTools.print_403_insufficient_scopes(
                    permission_name="compute.instanceGroupManagers.list",
                    project_id=project_id,
                    current_scopes=getattr(self.session, "scopes", None),
                    suggested_scope="https://www.googleapis.com/auth/cloud-platform",
                )
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
            else:
                UtilityTools.print_403_api_denied("compute.instanceGroupManagers.list", project_id=project_id)
            return []
        except Exception as e:
            UtilityTools.print_500(project_id, "compute.instanceGroupManagers.list", e)
            return []

        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return out

    def get(self, *, project_id: str, resource_id: str, zone: str | None = None, region: str | None = None, action_dict=None):
        try:
            if zone:
                row = self.zonal.get(project=project_id, zone=zone, instance_group_manager=resource_id)
            else:
                row = self.regional.get(project=project_id, region=region, instance_group_manager=resource_id)
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=resource_id,
            )
            return row
        except Forbidden as e:
            if "does not have compute.instanceGroupManagers.get" in str(e):
                UtilityTools.print_403_api_denied("compute.instanceGroupManagers.get", resource_name=resource_id)
            elif is_api_disabled_error(e):
                UtilityTools.print_403_api_disabled("Compute", project_id)
        except NotFound:
            UtilityTools.print_404_resource(resource_id)
        except Exception as e:
            UtilityTools.print_500(resource_id, "compute.instanceGroupManagers.get", e)
        return None

    def save(self, rows, *, project_id: str):
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id},
                extra_builder=lambda _obj, raw: {
                    "zone": extract_path_tail(str(raw.get("zone", "")), default=str(raw.get("zone", "")).strip()) if raw.get("zone") else "",
                    "region": extract_path_tail(str(raw.get("region", "")), default=str(raw.get("region", "")).strip()) if raw.get("region") else "",
                    "instance_template": raw.get("instance_template") or raw.get("instanceTemplate") or "",
                },
            )

    @staticmethod
    def reference_from_row(row):
        payload = resource_to_dict(row) if not isinstance(row, dict) else dict(row)
        reference = {
            "resource_id": field_from_row(row, payload, "name"),
        }
        zone = _normalized_zone_from_raw(payload)
        region = _normalized_region_from_raw(payload)
        if zone:
            reference["zone"] = zone
        if region:
            reference["region"] = region
        return reference


def update_instance(
        instance_client, 
        instance_name, 
        project_id, 
        instance_zone, 
        action_dict,
        startup_script_data = None, 
        sa_email = None, 
        debug=False
    ):

    print(f"[*] Stopping {instance_name} [{instance_zone}] in {project_id}. Note this might take a minute...")

    # 1. Stop Instance
    result = CloudComputeInstancesResource.stop_with_client(
        instance_client,
        project_id,
        instance_zone,
        instance_name,
        debug=debug,
    )
    if result:
            action_dict.setdefault(project_id, {}).setdefault("compute.instances.stop", {}).setdefault("instances", set()).add(instance_name)            
    else:
        return "Fail Stop"

    # 2. Update Instance (Involves GetInstance for Fingerprint)
    try:

        output = CloudComputeInstancesResource.get_with_client(
            instance_client,
            instance_name,
            project_id,
            instance_zone,
            debug=debug,
        )
        
        if output:

            action_dict.setdefault(project_id, {}).setdefault("compute.instances.get", {}).setdefault("instances", set()).add(instance_name)            
            fingerprint = output.fingerprint

        else:
            return "Fail Fingerprint"

        # TODO See if can mask this in anyway, does not seem to be the case.
        access = compute_v1.AccessConfig()
        access.type_ = compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name
        access.name = "External NAT"

        body = {
            'name': instance_name,
            'fingerprint':f'{fingerprint}',
            'machine_type': f'zones/{instance_zone}/machineTypes/e2-micro',
            'disks': [
                {
                    'auto_delete': True,
                    'boot': True,
                    'initialize_params':{
                        'source_image':'projects/debian-cloud/global/images/family/debian-12'
                    }
                }
            ],
            'network_interfaces': [
                {
                    'access_configs':[access],
                    'network': 'global/networks/default'
                }
            ]
        }

        if startup_script_data:

            body['metadata'] = {
                'items':[
                    {
                        'key': 'startup-script',
                        'value': f'{startup_script_data}'
                    }
                ]
            }

        # Update Service Account to try to get new creds
        if sa_email:

            body['service_accounts'] = []

            added_creds = {
                "email":sa_email,
                "scopes":["https://www.googleapis.com/auth/cloud-platform"]
            }

            body['service_accounts'].append(added_creds)

        # This will FAIL if you don't pass in a fingerprint for some reason
        # https://cloud.google.com/compute/docs/instances/update-instance-properties
        request = compute_v1.UpdateInstanceRequest(
            instance = instance_name,
            instance_resource=body,
            project=project_id,
            zone=instance_zone
        )
    
        # Make the request

        print(f"[*] Updating {instance_name} [{instance_zone}] in {project_id} with fingerprint {fingerprint}. Note this might take a minute...")
        
        operation = instance_client.update_unary(request=request)
        time.sleep(20)

        if operation:
            action_dict.setdefault(project_id, {}).setdefault("compute.instances.update", {}).setdefault("instances", set()).add(instance_name)            

    except Forbidden as e:
        
        if "does not have compute.instances.update" in str(e):
            UtilityTools.print_403_api_denied("compute.instances.update permissions", project_id = project_id)
            return "Fail Update"

        elif is_api_disabled_error(e):
            UtilityTools.print_403_api_disabled("Compute", project_id)
            return "Not Enabled"

    except Exception as e:

        UtilityTools.print_500(instance_name, "compute.instances.update", e)
        return "Fail Update"

    print(f"[*] Starting {instance_name} [{instance_zone}] in {project_id}. Note this might take a minute...")

    # 3. Start Instance Again
    response = CloudComputeInstancesResource.start_with_client(
        instance_client,
        project_id,
        instance_zone,
        instance_name,
        debug=debug,
    )
    
    if response:
        action_dict.setdefault(project_id, {}).setdefault("compute.instances.start", {}).setdefault("instances", set()).add(instance_name)            
    
    else:
        return "Fail Start"

    return 1
