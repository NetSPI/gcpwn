from __future__ import annotations

# Adapted from https://github.com/ozguralp/gmapsapiscanner
# Copyright (c) 2020 Ozgur Alp
# This module is a repo-local port / code copy of that MIT-licensed scanner.
# See LICENSE.gmapsapiscanner in this directory for the original MIT license text.

import argparse
import json
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

import requests
from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.modules.gcp.apikeys.unauthenticated._shared import prompt_yes_no
from gcpwn.modules.gcp.apikeys.unauthenticated._shared import set_tls_verification
from gcpwn.modules.gcp.apikeys.unauthenticated._shared import tls_verify
from gcpwn.modules.gcp.apikeys.utilities.helpers import _key_fingerprint
from gcpwn.modules.gcp.apikeys.utilities.helpers import _key_preview
from gcpwn.modules.gcp.apikeys.utilities.helpers import _safe_json


REQUEST_TIMEOUT = 15
ERROR_KEYS_DEFAULT = ("error_message", "errorMessage", "error")


@dataclass(frozen=True)
class ApiProbe:
    name: str
    cost_reference: str
    method: str
    url: str
    proof: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str | None = None
    allow_redirects: bool = True
    expected_status: int = 200
    inspect_json: bool = False
    error_keys: tuple[str, ...] = ERROR_KEYS_DEFAULT
    required_text: str | None = None
    failure_reason: Callable[[Any], str] | None = None


@dataclass(frozen=True)
class ProbeResult:
    probe: ApiProbe
    vulnerable: bool
    reason: str = ""
    proof: str = ""
    project_number: str = ""


UNAUTH_APIKEY_PERMISSIONS_TABLE = "unauth_apikey_permissions"
GEMINI_REFERENCE_NAMES = {"Gemini Files API", "Gemini Cached Contents API"}
VERTEX_REFERENCE_NAMES = {"Vertex AI CountTokens API"}

def _extract_error_value(payload: Any, keys: tuple[str, ...]) -> str | None:
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        payload = payload[0]

    if not isinstance(payload, dict):
        return None

    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict) and "message" in value:
            return str(value["message"])
        if isinstance(value, str):
            return value

    error_value = payload.get("error")
    if isinstance(error_value, dict):
        message = error_value.get("message")
        if isinstance(message, str):
            return message

    return None


def _extract_project_number_from_payload(payload: Any) -> str:
    if isinstance(payload, dict):
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            consumer = str(metadata.get("consumer") or "").strip()
            if consumer.startswith("projects/"):
                return extract_path_tail(consumer, default=consumer)
        for value in payload.values():
            project_number = _extract_project_number_from_payload(value)
            if project_number:
                return project_number
    elif isinstance(payload, list):
        for item in payload:
            project_number = _extract_project_number_from_payload(item)
            if project_number:
                return project_number
    return ""


def _extract_project_number(response: Any) -> str:
    return _extract_project_number_from_payload(_safe_json(response))


def _error_message(response: Any, keys: tuple[str, ...] = ERROR_KEYS_DEFAULT) -> str:
    message = _extract_error_value(_safe_json(response), keys)
    if message:
        return message

    content = getattr(response, "content", b"") or b""
    if content:
        try:
            return bytes(content[:500]).decode("utf-8", errors="replace").strip()
        except Exception:
            return str(content[:200])

    status_code = getattr(response, "status_code", "?")
    return f"Unknown error (status {status_code})"


def _pretty_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _normalize_detail(detail: Any, *, project_number: str = "") -> str:
    message = " ".join(str(detail or "").strip().split()) or "-"
    project_number = str(project_number or "").strip()
    match = re.search(r"has not been used in project\s+([0-9]+)", message, flags=re.IGNORECASE)
    if match:
        return f"Not been used in project {match.group(1)}"
    if "has not been used in project" in message.lower():
        if project_number:
            return f"Not been used in project {project_number}"
        return "Not been used in project"
    return message


def _detail_from_result(result: ProbeResult) -> str:
    if result.vulnerable:
        return result.proof or "-"
    return _normalize_detail(result.reason or "-", project_number=result.project_number)


def _inject_api_key_into_detail(detail: str, api_key: str) -> str:
    text = str(detail or "")
    token = str(api_key or "").strip()
    if not text or not token:
        return text
    if "YOUR_KEY" not in text.upper():
        return text
    return re.sub(r"YOUR_KEY", token, text, flags=re.IGNORECASE)


def _summary_rows_from_cached_rows(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "api": str(row.get("api") or ""),
            "status": str(row.get("status") or ""),
            "method": str(row.get("method") or ""),
            "cost_reference": str(row.get("cost_reference") or ""),
            "detail": _normalize_detail(row.get("detail"), project_number=str(row.get("project_number") or "")),
            "project_number": str(row.get("project_number") or ""),
            "last_tested": str(row.get("last_tested") or ""),
        }
        for row in rows
    ]


def _cache_rows_from_results(api_key: str, results: list[ProbeResult]) -> list[dict[str, str]]:
    fingerprint = _key_fingerprint(api_key)
    preview = _key_preview(api_key)
    timestamp = datetime.now().isoformat(timespec="seconds")
    return [
        {
            "key_fingerprint": fingerprint,
            "key_preview": preview,
            "api": result.probe.name,
            "method": result.probe.method,
            "status": "VULNERABLE" if result.vulnerable else "NOT VULNERABLE",
            "cost_reference": result.probe.cost_reference,
            "detail": (
                _inject_api_key_into_detail(_detail_from_result(result), api_key)
                if result.vulnerable
                else _detail_from_result(result)
            ),
            "project_number": result.project_number,
            "last_tested": timestamp,
        }
        for result in results
    ]


def _load_cached_key_rows(session: Any, api_key: str) -> list[dict[str, Any]]:
    if session is None or not hasattr(session, "get_data"):
        return []
    return session.get_data(
        UNAUTH_APIKEY_PERMISSIONS_TABLE,
        where={"key_fingerprint": _key_fingerprint(api_key)},
    ) or []


def _save_results(session: Any, api_key: str, results: list[ProbeResult]) -> None:
    if session is None or not hasattr(session, "insert_data"):
        return
    for row in _cache_rows_from_results(api_key, results):
        session.insert_data(UNAUTH_APIKEY_PERMISSIONS_TABLE, row)


def _accessible_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows if str(row.get("status") or "").strip().upper() == "VULNERABLE"]


def _style_vulnerable_rows(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    _ = fields
    return [
        index
        for index, row in enumerate(rows)
        if str(row.get("status") or "").strip().upper() == "VULNERABLE"
    ]


def _scan_project_number(rows: list[dict[str, Any]]) -> str:
    for row in rows:
        project_number = str(row.get("project_number") or "").strip()
        if project_number:
            return project_number
    return ""


def _rows_with_scan_project_number(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    project_number = _scan_project_number(rows)
    output = []
    for row in rows:
        rendered = dict(row)
        if project_number and not str(rendered.get("project_number") or "").strip():
            rendered["project_number"] = project_number
        output.append(rendered)
    return output, project_number


def _display_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    rows, project_number = _rows_with_scan_project_number(rows)
    display_rows: list[dict[str, Any]] = []
    for row in rows:
        rendered = dict(row)
        rendered["status"] = str(rendered.get("status") or "").strip().upper()
        rendered["detail"] = _normalize_detail(
            rendered.get("detail"),
            project_number=str(rendered.get("project_number") or ""),
        )
        display_rows.append(rendered)
    return display_rows, project_number


def _reference_entries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    vulnerable_names = {
        str(row.get("api") or "").strip()
        for row in rows
        if str(row.get("status") or "").strip().upper() == "VULNERABLE"
    }

    entries: list[dict[str, Any]] = []
    if vulnerable_names & GEMINI_REFERENCE_NAMES:
        entries.append(
            {
                "title": "Gemini API",
                "body": [
                    (
                        "This key is valid for the Gemini API and is often created through Google AI Studio. "
                        "It may allow access to uploaded files, cached content, and related Gemini resources."
                    ),
                    "See unauth_apikey_gemini_exploit.py for follow-on validation, file/cache collection, and SDK-backed prompting.",
                ],
                "bold_title": True,
                "bold_body_indices": {1},
                "links": [
                    (
                        "API key usage",
                        "https://ai.google.dev/gemini-api/docs/api-key#provide-api-key-explicitly",
                    ),
                    (
                        "Text generation docs",
                        "https://ai.google.dev/gemini-api/docs/text-generation",
                    ),
                    (
                        "Files docs",
                        "https://ai.google.dev/gemini-api/docs/files#list-uploaded-files",
                    ),
                    (
                        "Module to Exploit",
                        "unauth_apikey_gemini_exploit",
                    ),
                ],
            }
        )
    if vulnerable_names & VERTEX_REFERENCE_NAMES:
        entries.append(
            {
                "title": "Vertex AI",
                "body": [
                    (
                        "This key appears able to reach the Vertex AI express-mode publisher model surface on "
                        "aiplatform.googleapis.com. That typically means prompt submission against Google "
                        "publisher models, even when Gemini file or cache resources are not exposed."
                    ),
                    "See unauth_apikey_vertex_exploit.py to discover working models and open an interactive query shell.",
                ],
                "bold_title": True,
                "bold_body_indices": {1},
                "links": [
                    (
                        "Express mode REST resource",
                        "https://cloud.google.com/vertex-ai/generative-ai/docs/reference/express-mode/rest/v1/publishers.models",
                    ),
                    (
                        "streamGenerateContent docs",
                        "https://cloud.google.com/vertex-ai/generative-ai/docs/reference/express-mode/rest/v1/publishers.models/streamGenerateContent",
                    ),
                    (
                        "Module to Exploit",
                        "unauth_apikey_vertex_exploit",
                    ),
                ],
            }
        )
    return entries


def _print_reference_entries(entries: list[dict[str, Any]]) -> None:
    if not entries:
        return

    print("\n[*] References")
    for entry in entries:
        title = str(entry.get("title") or "").strip()
        body = entry.get("body") or []
        links = entry.get("links") or []
        bold_title = bool(entry.get("bold_title"))
        bold_body_indices = set(entry.get("bold_body_indices") or set())

        rendered_title = f"{UtilityTools.BOLD}{title}{UtilityTools.RESET}" if bold_title else title
        print(f"  {rendered_title}")
        if isinstance(body, str):
            body = [body]
        for index, paragraph in enumerate(body):
            text = str(paragraph or "").strip()
            if not text:
                continue
            wrapped = textwrap.fill(
                text,
                width=98,
                initial_indent="    ",
                subsequent_indent="    ",
                break_long_words=False,
                break_on_hyphens=False,
            )
            if index in bold_body_indices:
                wrapped = f"{UtilityTools.BOLD}{wrapped}{UtilityTools.RESET}"
            print(wrapped)
        for label, url in links:
            print(f"    {label}:")
            print(f"      {url}")


def _curl_command(url: str, *, body: str, headers: list[str] | None = None) -> str:
    header_args = " ".join(f'-H "{header}"' for header in (headers or []))
    prefix = " ".join(part for part in ("curl -X POST", header_args) if part)
    return f'{prefix} -d \'{body}\' "{url}"'


def _manual_check_failure_reason(url: str, *, error_keys: tuple[str, ...] = ("error_message", "errorMessage")):
    def _reason(response: Any) -> str:
        if b"PNG" in (getattr(response, "content", b"") or b""):
            return f"Manually check {url} to view the reason."
        return _error_message(response, error_keys)

    return _reason


def _places_photo_failure_reason(_response: Any) -> str:
    return "Verbose responses are not enabled for this API, cannot determine the reason."


def _probe(
    *,
    name: str,
    cost_reference: str,
    method: str,
    url: str,
    proof: str | None = None,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
    allow_redirects: bool = True,
    expected_status: int = 200,
    inspect_json: bool = False,
    error_keys: tuple[str, ...] = ERROR_KEYS_DEFAULT,
    required_text: str | None = None,
    failure_reason: Callable[[Any], str] | None = None,
) -> ApiProbe:
    return ApiProbe(
        name=name,
        cost_reference=cost_reference,
        method=method,
        url=url,
        proof=proof or url,
        headers=headers or {},
        body=body,
        allow_redirects=allow_redirects,
        expected_status=expected_status,
        inspect_json=inspect_json,
        error_keys=error_keys,
        required_text=required_text,
        failure_reason=failure_reason,
    )


def build_probes(api_key: str) -> list[ApiProbe]:
    geolocation_body = _pretty_json({"considerIp": "true"})
    address_validation_body = _pretty_json(
        {"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA"]}}
    )
    places_text_search_body = _pretty_json(
        {
            "textQuery": "restaurants near 1600 Amphitheatre Parkway, Mountain View, CA",
            "pageSize": 1,
        }
    )
    places_nearby_search_body = _pretty_json(
        {
            "includedTypes": ["restaurant"],
            "maxResultCount": 1,
            "locationRestriction": {
                "circle": {
                    "center": {"latitude": 37.4220, "longitude": -122.0841},
                    "radius": 500.0,
                }
            },
        }
    )
    places_autocomplete_body = _pretty_json(
        {
            "input": "1600 Amph",
            "locationBias": {
                "circle": {
                    "center": {"latitude": 37.4220, "longitude": -122.0841},
                    "radius": 500.0,
                }
            },
        }
    )
    air_quality_body = _pretty_json({"location": {"latitude": 37.4220, "longitude": -122.0841}})
    compute_routes_body = _pretty_json(
        {
            "destination": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}},
            "origin": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
            "travelMode": "DRIVE",
        }
    )
    compute_route_matrix_body = _pretty_json(
        {
            "destinations": [
                {"waypoint": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}}},
            ],
            "origins": [
                {"waypoint": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}}}
            ],
            "travelMode": "DRIVE",
        }
    )
    vertex_count_tokens_body = _pretty_json(
        {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": "whoami"}],
                }
            ]
        }
    )
    status_get_specs = [
        (
            "Staticmap API",
            "$2 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/staticmap?center=37.4220,-122.0841&zoom=17&size=400x400&key={api_key}",
            200,
            _manual_check_failure_reason(
                f"https://maps.googleapis.com/maps/api/staticmap?center=37.4220,-122.0841&zoom=17&size=400x400&key={api_key}"
            ),
            True,
            ("error_message", "errorMessage", "error"),
        ),
        (
            "Streetview API",
            "$7 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=37.4220,-122.0841&fov=90&heading=90&pitch=0&key={api_key}",
            200,
            _manual_check_failure_reason(
                f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=37.4220,-122.0841&fov=90&heading=90&pitch=0&key={api_key}"
            ),
            True,
            ("error_message", "errorMessage", "error"),
        ),
        (
            "Places Photo API",
            "$7 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key={api_key}",
            302,
            _places_photo_failure_reason,
            False,
            ("error_message", "errorMessage", "error"),
        ),
        (
            "Gemini Files API",
            "Data leak risk",
            f"https://generativelanguage.googleapis.com/v1beta/files?key={api_key}",
            200,
            None,
            True,
            ("error",),
        ),
        (
            "Gemini Cached Contents API",
            "Data leak risk",
            f"https://generativelanguage.googleapis.com/v1beta/cachedContents?key={api_key}",
            200,
            None,
            True,
            ("error",),
        ),
    ]
    json_get_specs = [
        (
            "Directions API",
            "$5 per 1000 requests / $10 advanced",
            f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Geocode API",
            "$5 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/geocode/json?latlng=37.4220,-122.0841&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Distance Matrix API",
            "$5 per 1000 elements / $10 advanced",
            f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=1600+Amphitheatre+Parkway,+Mountain+View,+CA&destinations=1+Market+Street,+San+Francisco,+CA&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Find Place From Text API",
            "$17 per 1000 elements",
            f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Autocomplete API",
            "$2.83 per 1000 requests / $17 per 1000 sessions",
            f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Elevation API",
            "$5 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/elevation/json?locations=37.4220,-122.0841&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Timezone API",
            "$5 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/timezone/json?location=37.4220,-122.0841&timestamp=1331161200&key={api_key}",
            ("errorMessage",),
            None,
        ),
        (
            "Nearest Roads API",
            "$10 per 1000 requests",
            f"https://roads.googleapis.com/v1/nearestRoads?points=37.4220,-122.0841|37.4250,-122.0860&key={api_key}",
            ("error",),
            None,
        ),
        (
            "Route to Traveled API",
            "$10 per 1000 requests",
            f"https://roads.googleapis.com/v1/snapToRoads?path=37.4220,-122.0841|37.4250,-122.0860&interpolate=true&key={api_key}",
            ("error",),
            None,
        ),
        (
            "Speed Limit-Roads API",
            "$20 per 1000 requests",
            f"https://roads.googleapis.com/v1/speedLimits?path=37.4220,-122.0841|37.4250,-122.0860&key={api_key}",
            ("error",),
            None,
        ),
        (
            "Place Details API",
            "$17 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Nearby Search-Places API",
            "$32 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=37.4220,-122.0841&radius=100&types=food&name=google&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Text Search-Places API",
            "$32 per 1000 requests",
            f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={api_key}",
            ("error_message",),
            None,
        ),
        (
            "Aerial View API",
            "Paid per request",
            f"https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?key={api_key}&address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111",
            ("error",),
            None,
        ),
    ]

    probes = [
        *[
            _probe(
                name=name,
                cost_reference=cost,
                method="GET",
                url=url,
                allow_redirects=allow_redirects,
                expected_status=status,
                error_keys=error_keys,
                failure_reason=failure_reason,
            )
            for name, cost, url, status, failure_reason, allow_redirects, error_keys in status_get_specs
        ],
        *[
            _probe(
                name=name,
                cost_reference=cost,
                method="GET",
                url=url,
                inspect_json=True,
                error_keys=error_keys,
                required_text=required_text,
            )
            for name, cost, url, error_keys, required_text in json_get_specs
        ],
        _probe(
            name="Places API (New) Text Search",
            cost_reference="Paid per request",
            method="POST",
            url=f"https://places.googleapis.com/v1/places:searchText?key={api_key}",
            body=places_text_search_body,
            headers={
                "Content-Type": "application/json",
                "X-Goog-FieldMask": "places.id,places.displayName",
            },
            inspect_json=True,
            error_keys=("error",),
            required_text="places",
            proof=_curl_command(
                "https://places.googleapis.com/v1/places:searchText?key=YOUR_KEY",
                body=places_text_search_body,
                headers=[
                    "Content-Type: application/json",
                    "X-Goog-FieldMask: places.id,places.displayName",
                ],
            ),
        ),
        _probe(
            name="Places API (New) Nearby Search",
            cost_reference="Paid per request",
            method="POST",
            url=f"https://places.googleapis.com/v1/places:searchNearby?key={api_key}",
            body=places_nearby_search_body,
            headers={
                "Content-Type": "application/json",
                "X-Goog-FieldMask": "places.id,places.displayName",
            },
            inspect_json=True,
            error_keys=("error",),
            required_text="places",
            proof=_curl_command(
                "https://places.googleapis.com/v1/places:searchNearby?key=YOUR_KEY",
                body=places_nearby_search_body,
                headers=[
                    "Content-Type: application/json",
                    "X-Goog-FieldMask: places.id,places.displayName",
                ],
            ),
        ),
        _probe(
            name="Places API (New) Place Details",
            cost_reference="Paid per request",
            method="GET",
            url=f"https://places.googleapis.com/v1/places/ChIJj61dQgK6j4AR4GeTYWZsKWw?key={api_key}",
            headers={
                "Content-Type": "application/json",
                "X-Goog-FieldMask": "id,displayName",
            },
            inspect_json=True,
            error_keys=("error",),
            required_text="displayName",
            proof=(
                "curl -X GET -H \"Content-Type: application/json\" "
                "-H \"X-Goog-FieldMask: id,displayName\" "
                "\"https://places.googleapis.com/v1/places/ChIJj61dQgK6j4AR4GeTYWZsKWw?key=YOUR_KEY\""
            ),
        ),
        _probe(
            name="Places API (New) Autocomplete",
            cost_reference="Paid per request/session",
            method="POST",
            url=f"https://places.googleapis.com/v1/places:autocomplete?key={api_key}",
            body=places_autocomplete_body,
            headers={
                "Content-Type": "application/json",
                "X-Goog-FieldMask": "suggestions.placePrediction.place,suggestions.placePrediction.text",
            },
            inspect_json=True,
            error_keys=("error",),
            required_text="suggestions",
            proof=_curl_command(
                "https://places.googleapis.com/v1/places:autocomplete?key=YOUR_KEY",
                body=places_autocomplete_body,
                headers=[
                    "Content-Type: application/json",
                    "X-Goog-FieldMask: suggestions.placePrediction.place,suggestions.placePrediction.text",
                ],
            ),
        ),
        _probe(
            name="Geolocation API",
            cost_reference="$5 per 1000 requests",
            method="POST",
            url=f"https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}",
            body=geolocation_body,
            headers={"Content-Type": "application/json"},
            inspect_json=True,
            error_keys=("error",),
            proof=_curl_command(
                f"https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}",
                body=geolocation_body,
                headers=["Content-Type: application/json"],
            ),
        ),
        _probe(
            name="Address Validation API",
            cost_reference="$5 per 1000 requests",
            method="POST",
            url=f"https://addressvalidation.googleapis.com/v1:validateAddress?key={api_key}",
            body=address_validation_body,
            headers={"Content-Type": "application/json"},
            inspect_json=True,
            error_keys=("error",),
            proof=_curl_command(
                "https://addressvalidation.googleapis.com/v1:validateAddress?key=YOUR_KEY",
                body=_pretty_json({"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy"]}}),
                headers=["Content-Type: application/json"],
            ),
        ),
        _probe(
            name="Air Quality API",
            cost_reference="Paid per request",
            method="POST",
            url=f"https://airquality.googleapis.com/v1/currentConditions:lookup?key={api_key}",
            body=air_quality_body,
            headers={"Content-Type": "application/json"},
            inspect_json=True,
            error_keys=("error",),
            proof=_curl_command(
                "https://airquality.googleapis.com/v1/currentConditions:lookup?key=YOUR_KEY",
                body=_pretty_json({"location": {"latitude": 37.4220, "longitude": -122.0841}}),
                headers=["Content-Type: application/json"],
            ),
        ),
        _probe(
            name="Routes API (computeRoutes)",
            cost_reference="Paid per request",
            method="POST",
            url=f"https://routes.googleapis.com/directions/v2:computeRoutes?key={api_key}",
            body=compute_routes_body,
            headers={
                "Content-Type": "application/json",
                "X-Goog-FieldMask": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline",
            },
            inspect_json=True,
            error_keys=("error",),
            required_text="routes",
            proof=_curl_command(
                "https://routes.googleapis.com/directions/v2:computeRoutes?key=YOUR_KEY",
                body=_pretty_json(
                    {
                        "destination": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}},
                        "origin": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
                        "travelMode": "DRIVE",
                    }
                ),
                headers=[
                    "Content-Type: application/json",
                    "X-Goog-FieldMask: routes.duration,routes.distanceMeters",
                ],
            ),
        ),
        _probe(
            name="Routes API (computeRouteMatrix)",
            cost_reference="Paid per element",
            method="POST",
            url=f"https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={api_key}",
            body=compute_route_matrix_body,
            headers={
                "Content-Type": "application/json",
                "X-Goog-FieldMask": "originIndex,destinationIndex,status,distanceMeters,duration",
            },
            inspect_json=True,
            error_keys=("error",),
            proof=_curl_command(
                "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key=YOUR_KEY",
                body=_pretty_json(
                    {
                        "destinations": [
                            {"waypoint": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}}}
                        ],
                        "origins": [
                            {"waypoint": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}}}
                        ],
                        "travelMode": "DRIVE",
                    }
                ),
                headers=[
                    "Content-Type: application/json",
                    "X-Goog-FieldMask: originIndex,destinationIndex,status,distanceMeters,duration",
                ],
            ),
        ),
        _probe(
            name="Vertex AI CountTokens API",
            cost_reference=(
                "Model access risk (low-impact token counting); See API docs here - "
                "https://cloud.google.com/vertex-ai/generative-ai/docs/reference/express-mode/rest/v1/publishers.models/countTokens"
            ),
            method="POST",
            url=f"https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-2.5-flash:countTokens?key={api_key}",
            body=vertex_count_tokens_body,
            headers={"Content-Type": "application/json"},
            error_keys=("error",),
            proof=_curl_command(
                "https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-2.5-flash:countTokens?key=YOUR_KEY",
                body=vertex_count_tokens_body,
                headers=["Content-Type: application/json"],
            ),
        ),
    ]
    return probes


def _probe_succeeded(response: Any, probe: ApiProbe) -> bool:
    if getattr(response, "status_code", None) != probe.expected_status:
        return False
    if probe.inspect_json and _extract_error_value(_safe_json(response), probe.error_keys):
        return False
    if probe.required_text and probe.required_text not in str(getattr(response, "text", "") or ""):
        return False
    return True


def _normalize_proxy_address(proxy_address: str | None) -> str | None:
    value = str(proxy_address or "").strip()
    if not value:
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        value = f"http://{value}"
    return value


def execute_probe(http_client: Any, probe: ApiProbe, *, proxy: str | None = None, debug: bool = False) -> ProbeResult:
    normalized_proxy = _normalize_proxy_address(proxy)
    request_kwargs: dict[str, Any] = {
        "allow_redirects": probe.allow_redirects,
        "timeout": REQUEST_TIMEOUT,
        "verify": tls_verify(),
    }
    if probe.headers:
        request_kwargs["headers"] = dict(probe.headers)
    if probe.body is not None:
        request_kwargs["data"] = probe.body
    if normalized_proxy:
        request_kwargs["proxies"] = {"http": normalized_proxy, "https": normalized_proxy}

    UtilityTools.dlog(debug, "Testing API scope", method=probe.method, url=probe.url, api=probe.name)

    try:
        response = http_client.request(probe.method, probe.url, **request_kwargs)
    except Exception as exc:
        return ProbeResult(probe=probe, vulnerable=False, reason=str(exc))

    if _probe_succeeded(response, probe):
        return ProbeResult(probe=probe, vulnerable=True, proof=probe.proof)

    reason = probe.failure_reason(response) if probe.failure_reason else _error_message(response, probe.error_keys)
    return ProbeResult(
        probe=probe,
        vulnerable=False,
        reason=reason,
        project_number=_extract_project_number(response),
    )


def scan_api_key(
    api_key: str,
    *,
    http_client: Any | None = None,
    proxy: str | None = None,
    debug: bool = False,
) -> list[ProbeResult]:
    client = http_client or requests
    normalized_proxy = _normalize_proxy_address(proxy)
    probes = build_probes(api_key)
    results: list[ProbeResult] = []
    total = len(probes)
    for index, probe in enumerate(probes, start=1):
        result = execute_probe(client, probe, proxy=normalized_proxy, debug=debug)
        results.append(result)
        status = "accessible" if result.vulnerable else "not accessible"
        print(f"[*] [{index}/{total}] {probe.name} [{probe.method}] -> {status}")
    return results


def _result_rows(results: list[ProbeResult]) -> list[dict[str, str]]:
    return [
        {
            "api": result.probe.name,
            "status": "VULNERABLE" if result.vulnerable else "NOT VULNERABLE",
            "method": result.probe.method,
            "cost_reference": result.probe.cost_reference,
            "detail": _detail_from_result(result),
            "project_number": result.project_number,
        }
        for result in results
    ]


def summarize_results(rows: list[dict[str, Any]], *, cached: bool = False) -> None:
    rows, project_number = _display_rows(rows)
    accessible_rows = _accessible_rows(rows)
    reference_entries = _reference_entries(rows)
    total = len(rows)
    if cached:
        print(
            f"[*] Cached API key scope results: {len(accessible_rows)} accessible API(s), "
            f"{max(total - len(accessible_rows), 0)} blocked/disabled API(s) from {total} total probes"
        )
    else:
        print(
            f"[*] API key scope scan complete: {len(accessible_rows)} accessible API(s), "
            f"{max(total - len(accessible_rows), 0)} blocked/disabled API(s) from {total} total probes"
        )
    if not accessible_rows:
        print("[*] No accessible unauthenticated API scopes found.")
    display_fields = ["api", "status", "method", "cost_reference", "detail"]
    vulnerable_row_indices = set(_style_vulnerable_rows(rows, display_fields))
    UtilityTools.print_limited_table(
        rows,
        display_fields,
        title="Cached API Scope Results" if cached else "API Scope Results",
        resource_type="API Scopes",
        sort_key="api",
        max_rows=len(rows),
        max_col_width=72,
        column_max_widths={"cost_reference": 36},
        highlight_row_indices=vulnerable_row_indices,
        highlight_prefix=UtilityTools.RED + UtilityTools.BOLD,
        highlight_suffix=UtilityTools.RESET,
    )
    if project_number:
        print(
            f"{UtilityTools.BOLD}The Project ID identified through error codes is {project_number}"
            f"{UtilityTools.RESET}"
        )
    _print_reference_entries(reference_entries)


def _prompt_before_rescan(session: Any, api_key: str) -> bool:
    cached_rows = _load_cached_key_rows(session, api_key)
    if not cached_rows:
        return True
    preview = _key_preview(api_key)
    print(f"[*] API key {preview} has already been tested in this workspace.")
    summarize_results(_summary_rows_from_cached_rows(cached_rows), cached=True)
    return prompt_yes_no(session, "Do you want to continue and re-test this key? [y/n] ")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate unauthenticated Google Maps and related API scope for a Google API key. "
            "Ported from ozguralp/gmapsapiscanner (MIT)."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--api-key", "-a", required=False, help="API key value to test.")
    parser.add_argument("--proxy", "-p", required=False, help="HTTP/HTTPS/SOCKS proxy URL.")
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        required=False,
        help="Disable TLS verification (for intercepting proxies like Burp); verification is ON by default",
    )
    parser.add_argument("-v", "--debug", action="store_true", required=False, help="Verbose output.")
    return parser


def run_module(user_args, session):
    parser = _build_parser()
    args = parser.parse_args(user_args)

    set_tls_verification(insecure=bool(args.insecure))

    api_key = str(args.api_key or "").strip()
    if not api_key:
        api_key = str(input("Please enter the Google API key you want to test: ") or "").strip()
    if not api_key:
        UtilityTools.print_error("No API key supplied.")
        return -1

    if not _prompt_before_rescan(session, api_key):
        return 1

    results = scan_api_key(api_key, proxy=getattr(args, "proxy", None), debug=args.debug)

    _save_results(session, api_key, results)
    summarize_results(_result_rows(results))
    return 1
