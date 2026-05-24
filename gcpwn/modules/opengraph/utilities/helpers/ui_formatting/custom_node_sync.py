from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
from urllib.parse import quote, urlparse, urlunparse


def _candidate_custom_node_collection_urls(raw_url: str) -> list[str]:
    parsed = urlparse(raw_url)
    candidate_urls: list[str] = []
    if parsed.scheme and parsed.netloc:
        original_path = str(parsed.path or "").strip("/")
        if not original_path:
            candidate_paths = ["/api/v2/custom-nodes"]
        elif original_path.endswith("api/v2"):
            candidate_paths = [f"/{original_path}/custom-nodes"]
        elif original_path.endswith("custom-node-types"):
            candidate_paths = [f"/{original_path}", f"/{original_path[:-len('custom-node-types')]}custom-nodes"]
        elif original_path.endswith("custom-nodes"):
            candidate_paths = [f"/{original_path}"]
        else:
            candidate_paths = [f"/{original_path}", f"/{original_path}/custom-nodes"]

        for path in candidate_paths:
            candidate_urls.append(urlunparse((parsed.scheme, parsed.netloc, path, "", "", "")))
    else:
        candidate_urls.append(raw_url)
    return list(dict.fromkeys(candidate_urls))


def _build_bhe_signature_headers(
    *,
    token_id: str,
    token_key: str,
    method: str,
    candidate_url: str,
    body_bytes: bytes | None,
) -> dict[str, str]:
    parsed = urlparse(candidate_url)
    request_uri = str(parsed.path or "/")
    if parsed.query:
        request_uri = f"{request_uri}?{parsed.query}"

    request_date = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    digester = hmac.new(token_key.encode("utf-8"), None, hashlib.sha256)
    digester.update(f"{method}{request_uri}".encode("utf-8"))

    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    digester.update(request_date[:13].encode("utf-8"))

    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    if body_bytes is not None:
        digester.update(body_bytes)

    signature = base64.b64encode(digester.digest()).decode("utf-8")
    return {
        "Authorization": f"bhesignature {token_id}",
        "RequestDate": request_date,
        "Signature": signature,
        "Content-Type": "application/json",
    }


def _build_auth_headers(
    *,
    mode: str,
    token: str,
    token_id: str,
    token_key: str,
    method: str,
    target_url: str,
    body_bytes: bytes | None,
) -> dict[str, str]:
    if mode == "bearer":
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    return _build_bhe_signature_headers(
        token_id=token_id,
        token_key=token_key,
        method=method,
        candidate_url=target_url,
        body_bytes=body_bytes,
    )


def _extract_existing_custom_types(raw_response_text: str) -> dict[str, dict]:
    text = str(raw_response_text or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except Exception:
        return {}
    data = payload.get("data")
    if not isinstance(data, list):
        return {}

    existing: dict[str, dict] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        kind_name = str(item.get("kindName") or "").strip()
        if not kind_name:
            continue
        config = item.get("config")
        if not isinstance(config, dict):
            config = {}
        existing[kind_name] = config
    return existing


def _json_equivalent(left: dict, right: dict) -> bool:
    left_token = json.dumps(left or {}, sort_keys=True, separators=(",", ":"))
    right_token = json.dumps(right or {}, sort_keys=True, separators=(",", ":"))
    return left_token == right_token


def push_custom_node_attributes(
    *,
    custom_nodes_url: str,
    custom_nodes_token: str = "",
    auth_mode: str = "bearer",
    custom_nodes_token_id: str = "",
    custom_nodes_token_key: str = "",
):
    """
    Push OpenGraph custom node-type metadata to a BloodHound-compatible endpoint.

    Returns a small status dictionary describing success/failure and endpoint details.
    """
    token = (custom_nodes_token or "").strip()
    token_id = (custom_nodes_token_id or "").strip()
    token_key = (custom_nodes_token_key or "").strip()
    mode = str(auth_mode or "bearer").strip().lower()
    if mode not in {"bearer", "signature"}:
        print(f"[*] Skipping custom-nodes push: unsupported auth mode '{mode}'.")
        return {"ok": False, "reason": "unsupported_auth_mode", "auth_mode": mode}

    url = (custom_nodes_url or "").strip()
    if not url:
        url = "http://127.0.0.1:8080"
    if mode == "bearer" and not token:
        print("[*] Skipping custom-nodes push: bearer token not provided.")
        return {"ok": False, "reason": "missing_token"}
    if mode == "signature" and (not token_id or not token_key):
        print("[*] Skipping custom-nodes push: API token id/key not provided for signature auth.")
        return {"ok": False, "reason": "missing_signature_credentials"}

    try:
        import requests
    except Exception:
        print("[*] Skipping custom-nodes push: requests is not installed.")
        return {"ok": False, "reason": "requests_missing"}

    from gcpwn.modules.opengraph.utilities.helpers.ui_formatting.constants import CUSTOM_NODE_TYPES

    custom_types = dict(CUSTOM_NODE_TYPES or {})

    try:
        candidate_urls = _candidate_custom_node_collection_urls(url)
        attempts: list[tuple[str, str, int, str]] = []

        for collection_url in candidate_urls:
            get_headers = _build_auth_headers(
                mode=mode,
                token=token,
                token_id=token_id,
                token_key=token_key,
                method="GET",
                target_url=collection_url,
                body_bytes=None,
            )
            get_resp = requests.request(
                "GET",
                collection_url,
                headers=get_headers,
                verify=False,
                timeout=10,
            )
            get_status = int(get_resp.status_code)
            get_text = str(get_resp.text or "")
            attempts.append(("GET", collection_url, get_status, get_text))

            if get_status in {401, 403}:
                print(f"[*] custom-nodes auth failed during existing-node fetch: {get_status} (GET {collection_url})")
                return {
                    "ok": False,
                    "reason": "auth_error",
                    "status_code": get_status,
                    "method": "GET",
                    "url": collection_url,
                    "body": get_text[:300],
                    "auth_mode": mode,
                }
            if not (200 <= get_status < 300):
                continue

            existing_custom_types = _extract_existing_custom_types(get_text)
            created_kinds = 0
            updated_kinds = 0
            unchanged_kinds = 0

            for kind_name, kind_config in custom_types.items():
                kind_key = str(kind_name or "").strip()
                kind_path = quote(kind_key, safe="")
                if not kind_path:
                    continue
                desired_config = dict(kind_config or {})
                existing_config = existing_custom_types.get(kind_key)

                if existing_config is None:
                    create_payload = {"custom_types": {kind_key: desired_config}}
                    create_body = json.dumps(
                        create_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    create_headers = _build_auth_headers(
                        mode=mode,
                        token=token,
                        token_id=token_id,
                        token_key=token_key,
                        method="POST",
                        target_url=collection_url,
                        body_bytes=create_body,
                    )
                    create_resp = requests.request(
                        "POST",
                        collection_url,
                        headers=create_headers,
                        data=create_body,
                        verify=False,
                        timeout=10,
                    )
                    create_status = int(create_resp.status_code)
                    create_text = str(create_resp.text or "")
                    attempts.append(("POST", collection_url, create_status, create_text))
                    if 200 <= create_status < 300:
                        created_kinds += 1
                        continue
                    if create_status == 409:
                        print(f"[*] custom-nodes create conflict: {create_status} (POST {collection_url})")
                        return {
                            "ok": False,
                            "reason": "conflict_error",
                            "status_code": create_status,
                            "method": "POST",
                            "url": collection_url,
                            "body": create_text[:300],
                            "auth_mode": mode,
                        }
                    if create_status in {401, 403}:
                        print(f"[*] custom-nodes auth failed during create: {create_status} (POST {collection_url})")
                        return {
                            "ok": False,
                            "reason": "auth_error",
                            "status_code": create_status,
                            "method": "POST",
                            "url": collection_url,
                            "body": create_text[:300],
                            "auth_mode": mode,
                        }
                    continue

                if _json_equivalent(existing_config, desired_config):
                    unchanged_kinds += 1
                    continue

                kind_url = f"{collection_url.rstrip('/')}/{kind_path}"
                update_payload = {"config": desired_config}
                update_body = json.dumps(update_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                update_headers = _build_auth_headers(
                    mode=mode,
                    token=token,
                    token_id=token_id,
                    token_key=token_key,
                    method="PUT",
                    target_url=kind_url,
                    body_bytes=update_body,
                )
                update_resp = requests.request(
                    "PUT",
                    kind_url,
                    headers=update_headers,
                    data=update_body,
                    verify=False,
                    timeout=10,
                )
                update_status = int(update_resp.status_code)
                update_text = str(update_resp.text or "")
                attempts.append(("PUT", kind_url, update_status, update_text))
                if 200 <= update_status < 300:
                    updated_kinds += 1
                    continue
                if update_status == 409:
                    print(f"[*] custom-nodes update conflict: {update_status} (PUT {kind_url})")
                    return {
                        "ok": False,
                        "reason": "conflict_error",
                        "status_code": update_status,
                        "method": "PUT",
                        "url": kind_url,
                        "body": update_text[:300],
                        "auth_mode": mode,
                    }
                if update_status in {401, 403}:
                    print(f"[*] custom-nodes auth failed during update: {update_status} (PUT {kind_url})")
                    return {
                        "ok": False,
                        "reason": "auth_error",
                        "status_code": update_status,
                        "method": "PUT",
                        "url": kind_url,
                        "body": update_text[:300],
                        "auth_mode": mode,
                    }

            print(
                "[*] custom-nodes sync complete: "
                f"unchanged={unchanged_kinds}, updated={updated_kinds}, created={created_kinds}"
            )
            return {
                "ok": True,
                "unchanged_kinds": unchanged_kinds,
                "updated_kinds": updated_kinds,
                "created_kinds": created_kinds,
                "url": collection_url,
                "auth_mode": mode,
            }

        last_method, last_url, last_status, last_body = attempts[-1]
        attempted_signatures = ", ".join(f"{method} {target_url}" for method, target_url, _status, _body in attempts)
        print(f"[*] custom-nodes push failed: {last_status} ({last_method} {last_url}) {str(last_body or '')[:300]}")
        return {
            "ok": False,
            "reason": "http_error",
            "status_code": last_status,
            "method": last_method,
            "url": last_url,
            "body": str(last_body or "")[:300],
            "attempted": attempted_signatures,
            "auth_mode": mode,
        }
    except Exception as exc:
        print("custom-nodes request failed", f"{type(exc).__name__}: {exc}")
        return {"ok": False, "reason": "request_failed", "error": f"{type(exc).__name__}: {exc}"}
