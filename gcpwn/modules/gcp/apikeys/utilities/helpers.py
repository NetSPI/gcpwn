from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from collections.abc import Iterable
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.module_helpers import (
    extract_location_from_resource_name,
    extract_path_tail,
    extract_project_id_from_resource,
    resource_name_from_value,
)
from gcpwn.core.utils.persistence import save_to_table
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import handle_service_error


MODEL_LIST_PATH = Path(__file__).resolve().parent / "data" / "model_list.txt"


# ---------------------------------------------------------------------------
# Shared model inventory
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_model_sections() -> dict[str, tuple[str, ...]]:
    """Parse the bundled model_list.txt into {section_name: (model, ...)}.

    The file uses an INI-like format: ``[section]`` headers group bare model
    names; ``#`` lines and blanks are ignored. Cached for the process lifetime
    (the list is static data shipped alongside the module).
    """
    sections: dict[str, list[str]] = {}
    current_section = ""

    for raw_line in MODEL_LIST_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            sections.setdefault(current_section, [])
            continue
        if current_section:
            sections.setdefault(current_section, []).append(line)

    return {section: tuple(values) for section, values in sections.items()}


def _section_models(section: str) -> tuple[str, ...]:
    return _load_model_sections().get(str(section or "").strip(), ())


def _default_section_model(section: str) -> str:
    models = _section_models(section)
    return models[0] if models else ""


def _prefix_model_name(model_name: str, *, prefix: str) -> str:
    """Re-prefix a bare model name with the API-specific path prefix.

    Strips any existing ``publishers/google/models/`` or ``models/`` prefix
    first, then prepends ``prefix`` so the same model_list.txt entry can be
    rendered for both the Gemini (``models/``) and Vertex
    (``publishers/google/models/``) surfaces. Returns "" for blank input.
    """
    value = str(model_name or "").strip()
    if not value:
        return ""
    for known_prefix in ("publishers/google/models/", "models/"):
        if value.startswith(known_prefix):
            value = value.removeprefix(known_prefix)
            break
    return f"{prefix}{value}"


def _prefixed_models(section: str, *, prefix: str) -> tuple[str, ...]:
    return tuple(
        prefixed
        for prefixed in (_prefix_model_name(model_name, prefix=prefix) for model_name in _section_models(section))
        if prefixed
    )


def get_shared_generative_model_names() -> tuple[str, ...]:
    return _section_models("shared_generative_models")


def get_gemini_model_list() -> tuple[str, ...]:
    return _prefixed_models("shared_generative_models", prefix="models/")


def get_default_gemini_model() -> str:
    return _prefix_model_name(
        _default_section_model("shared_generative_models"),
        prefix="models/",
    )


def get_vertex_model_list() -> tuple[str, ...]:
    return _prefixed_models("shared_generative_models", prefix="publishers/google/models/")


def get_default_vertex_model() -> str:
    return _prefix_model_name(
        _default_section_model("shared_generative_models"),
        prefix="publishers/google/models/",
    )


def get_gemini_embedding_model_list() -> tuple[str, ...]:
    return _prefixed_models("gemini_embedding_models", prefix="models/")


def get_default_gemini_embedding_model() -> str:
    return _prefix_model_name(
        _default_section_model("gemini_embedding_models"),
        prefix="models/",
    )


# ---------------------------------------------------------------------------
# Shared model cycle + prompt helpers
# ---------------------------------------------------------------------------


def build_model_cycle(
    primary_model: str,
    fallback_models: Iterable[str],
    *,
    normalize_model: Callable[[str], str],
) -> list[str]:
    """Build an ordered, de-duplicated model fallback list to try in sequence.

    Puts ``primary_model`` first, then ``fallback_models``, normalizing each via
    ``normalize_model`` and dropping blanks and duplicates (preserving first-seen
    order). Used by callers to attempt a generation/embedding call against each
    candidate model until one succeeds.
    """
    cycle: list[str] = []
    for raw_model in [primary_model, *list(fallback_models)]:
        normalized_model = normalize_model(raw_model)
        if not normalized_model or normalized_model in cycle:
            continue
        cycle.append(normalized_model)
    return cycle


def select_model_candidate(
    session: Any,
    candidates: list[dict[str, Any]],
    *,
    message: str,
    single_message_template: str = "",
    no_prompt_message_template: str = "",
    prompt_numbered_choice: Callable[..., dict[str, Any] | None] | None = None,
    prefer_numbered_choice: bool = False,
) -> str:
    """Pick one model from candidate dicts, prompting interactively if needed.

    Resolution order: zero candidates -> ""; exactly one -> that model (optionally
    announced via single_message_template); else, if a chooser is available, prompt
    the user (preferring an explicit numbered-choice callback when
    prefer_numbered_choice is set, then the session's choice_selector, then any
    provided prompt_numbered_choice). With no chooser, falls back to the first
    candidate (optionally announced via no_prompt_message_template).

    Each candidate is a dict with at least a "model" key (and "printout" for the
    selector display). Returns the chosen model string, or "" if the user declined.
    """
    if not candidates:
        return ""

    first_model = str(candidates[0].get("model") or "").strip()
    if len(candidates) == 1:
        if single_message_template and first_model:
            print(single_message_template.format(model=first_model))
        return first_model

    if prefer_numbered_choice and prompt_numbered_choice is not None:
        selected = prompt_numbered_choice(session, candidates, message=message)
        if isinstance(selected, dict):
            return str(selected.get("model") or "").strip()
        return ""

    if session is not None and hasattr(session, "choice_selector"):
        selected = session.choice_selector(
            candidates,
            message,
            fields=["printout"],
        )
        if isinstance(selected, dict):
            return str(selected.get("model") or "").strip()
        return ""

    if prompt_numbered_choice is not None:
        selected = prompt_numbered_choice(session, candidates, message=message)
        if isinstance(selected, dict):
            return str(selected.get("model") or "").strip()
        return ""

    if no_prompt_message_template and first_model:
        print(no_prompt_message_template.format(model=first_model))
    return first_model


# ---------------------------------------------------------------------------
# Shared unauthenticated API-key plumbing
# ---------------------------------------------------------------------------


def _prompt_text(session: Any, prompt: str) -> str:
    if session is not None and hasattr(session, "choice_prompt"):
        answer = session.choice_prompt(prompt)
    else:
        answer = input(prompt)
    return str(answer or "").strip()


def _key_fingerprint(api_key: str) -> str:
    """Return a SHA-256 hex digest of the API key for stable, non-reversible IDs.

    Used as a primary key when recording discovered models so the same key maps
    to one row without ever persisting the raw secret.
    """
    return hashlib.sha256(str(api_key or "").encode("utf-8")).hexdigest()


def _key_preview(api_key: str) -> str:
    """Return a redacted, human-readable preview of an API key (head...tail).

    Shows ``first6...last4`` for normal keys and a truncated ``first4...`` for
    short tokens, so logs/tables can reference a key without leaking it in full.
    """
    token = str(api_key or "").strip()
    if len(token) <= 12:
        return token[:4] + "..." if len(token) > 4 else token
    return f"{token[:6]}...{token[-4:]}"


def _safe_json(response: Any) -> Any:
    """Parse response.json() defensively, returning None on any failure.

    Tolerates non-JSON / empty / malformed HTTP error bodies from the REST
    surfaces probed by the unauthenticated key modules.
    """
    try:
        return response.json()
    except Exception:
        return None


def _error_message(response: Any) -> str:
    """Extract the best human-readable error string from an HTTP error response.

    Prefers the structured ``error.message`` / top-level ``message`` JSON fields,
    falls back to the raw text body (capped at 500 chars), and finally to
    ``HTTP <status>``. Note: the raw error text may itself leak an embedded API
    key, which is why callers pair this with _extract_api_key_from_detail.
    """
    payload = _safe_json(response)
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = str(error.get("message") or "").strip()
            if message:
                return message
        message = str(payload.get("message") or "").strip()
        if message:
            return message

    text = str(getattr(response, "text", "") or "").strip()
    if text:
        return text[:500]

    return f"HTTP {getattr(response, 'status_code', '?')}"


def _is_full_api_key(candidate: str) -> bool:
    """Heuristically decide whether a string looks like a real, usable API key.

    Rejects blanks and the ``YOUR_KEY`` placeholder; requires >=12 chars of the
    URL-safe key alphabet (``A-Za-z0-9._-``). Used to filter candidates scraped
    out of error messages before treating them as a leaked key.
    """
    value = str(candidate or "").strip()
    if not value:
        return False
    if value.upper() == "YOUR_KEY":
        return False
    return len(value) >= 12 and bool(re.match(r"^[A-Za-z0-9._-]+$", value))


def _extract_api_key_from_detail(detail: Any) -> str:
    """Scrape a leaked API key out of an error/detail string, or return "".

    Matches several patterns where APIs echo the supplied key back (``key=...``,
    ``Authorization: key=...``, JSON ``"key": "..."``) and returns the first match
    that passes _is_full_api_key. Supports the offensive flow of recovering a
    valid key from a verbose error response.
    """
    text = str(detail or "").strip()
    if not text:
        return ""
    patterns = (
        r"(?i)\bkey=([^\s'\"&]+)",
        r"(?i)Authorization:\s*key=([^\s'\"&]+)",
        r'(?i)"key"\s*:\s*"([A-Za-z0-9._-]+)"',
        r"(?i)'key'\s*:\s*'([A-Za-z0-9._-]+)'",
    )
    for pattern in patterns:
        for match in re.findall(pattern, text):
            candidate = str(match or "").strip()
            if _is_full_api_key(candidate):
                return candidate
    return ""


def _record_discovered_models(
    session: Any,
    *,
    table_name: str,
    api_key: str,
    models: list[str] | tuple[str, ...],
    source: str,
    normalize_model: Any,
    detail: str = "",
) -> None:
    """Persist models discovered via an (unauthenticated) API key into a table.

    Records one workspace-scoped row per normalized model, keyed by the key's
    SHA-256 fingerprint plus a redacted preview (never the raw key), with the
    discovery source/detail and a UTC ``last_seen`` timestamp. No-op if the
    session lacks insert_data. Must be called on the main thread -- insert_data
    writes through the single-threaded DataController.
    """
    if session is None or not hasattr(session, "insert_data"):
        return

    fingerprint = _key_fingerprint(api_key)
    preview = _key_preview(api_key)
    last_seen = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    for model in models:
        normalized_model = str(normalize_model(model) or "").strip()
        if not normalized_model:
            continue
        session.insert_data(
            table_name,
            {
                "key_fingerprint": fingerprint,
                "key_preview": preview,
                "model": normalized_model,
                "source": str(source or "").strip() or "unknown",
                "detail": str(detail or "").strip(),
                "last_seen": last_seen,
            },
        )


# ---------------------------------------------------------------------------
# API Keys resource helpers
# ---------------------------------------------------------------------------


def _key_name(*, project_id: str, key_id: str, location: str = "global") -> str:
    """Build the fully-qualified API-key resource name from a bare key id.

    Returns key_id unchanged if it's already a full ``projects/...`` path (or
    blank); otherwise expands it to
    ``projects/<project_id>/locations/<location>/keys/<key_id>``.
    """
    text = str(key_id or "").strip()
    if not text or text.startswith("projects/"):
        return text
    return f"projects/{project_id}/locations/{location}/keys/{text}"


def get_key_rows(resource, names: list[str], action_dict=None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in names:
        row = resource.get(name=name, action_dict=action_dict)
        if isinstance(row, dict) and row:
            rows.append(row)
    return rows


def key_row_names(resource, rows: list[dict[str, Any]]) -> list[str]:
    return [name for row in rows if (name := resource.resource_name(row))]


def attach_key_strings(
    resource,
    names: list[str],
    rows: list[dict[str, Any]],
    action_dict=None,
    *,
    require_key_string: bool,
) -> list[dict[str, Any]]:
    """Enrich key metadata rows with their secret key_string via getKeyString.

    For each requested name, merges the matching metadata row (synthesizing a
    minimal row if absent) and calls the privileged getKeyString API. When
    require_key_string is True, names whose secret can't be fetched are dropped;
    otherwise the bare metadata row is kept without a key_string. Each
    getKeyString call records its permission into action_dict as evidence.
    """
    base_rows_by_name = {
        resource.resource_name(row): dict(row)
        for row in rows
        if resource.resource_name(row)
    }
    enriched_rows: list[dict[str, Any]] = []
    for name in names:
        merged = dict(base_rows_by_name.get(name) or {})
        if not merged:
            merged["name"] = name
            merged["key_id"] = extract_path_tail(name, default=name)
        key_string = resource.get_key_string(name=name, action_dict=action_dict)
        if require_key_string and not key_string:
            continue
        if key_string:
            merged["key_string"] = key_string
        enriched_rows.append(merged)
    return enriched_rows


class ApiKeysKeysResource:
    """List/get GCP API Keys and their secret key strings, recording permission evidence.

    Wraps the google-cloud-api-keys v2 client. list/get/get_key_string each record
    the API permission they exercised into the passed action_dict (provenance =
    direct_api) and route failures through handle_service_error so a disabled API,
    403, or 404 is reported consistently. save() persists rows workspace-scoped.
    """

    TABLE_NAME = "apikeys_keys"
    COLUMNS = [
        "display_name",
        "key_id",
        "uid",
        "state",
        "location",
        "name",
        "create_time",
        "update_time",
        "key_string",
    ]
    SERVICE_LABEL = "API Keys"
    ACTION_RESOURCE_TYPE = "keys"
    LIST_API_NAME = "apikeys.keys.list"
    GET_API_NAME = "apikeys.keys.get"
    GET_KEY_STRING_API_NAME = "apikeys.keys.getKeyString"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import api_keys_v2  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "API Keys enumeration requires the `google-cloud-api-keys` package."
            ) from exc
        self._api_keys_v2 = api_keys_v2
        self.client = api_keys_v2.ApiKeysClient(credentials=session.credentials)

    def _request(self, callback):
        return callback()

    resource_name = staticmethod(resource_name_from_value)
    key_name = staticmethod(_key_name)

    def list(self, *, project_id: str, location: str = "global", action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}/locations/{location}"
        try:
            request = self._api_keys_v2.ListKeysRequest(parent=parent)
            rows = [resource_to_dict(key) for key in self._request(lambda: self.client.list_keys(request=request))]
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

    def get(self, *, name: str = "", resource_id: str = "", action_dict=None) -> dict[str, Any] | None:
        name = name or resource_id
        if not name:
            return None
        try:
            request = self._api_keys_v2.GetKeyRequest(name=name)
            row = resource_to_dict(self._request(lambda: self.client.get_key(request=request)))
            if row:
                record_permissions(
                    action_dict,
                    permissions=self.GET_API_NAME,
                    project_id=extract_project_id_from_resource(
                        row,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=resource_name_from_value(row, "name"),
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

    def get_key_string(self, *, name: str, action_dict=None) -> str:
        """Fetch the secret key string for a key resource; "" on missing/error.

        Records apikeys.keys.getKeyString as evidence when a secret is returned.
        Unlike list/get, swallows errors after reporting them and returns "" so
        callers can keep the metadata row even when the secret is inaccessible.
        """
        if not name:
            return ""
        try:
            request = self._api_keys_v2.GetKeyStringRequest(name=name)
            response = self._request(lambda: self.client.get_key_string(request=request))
            key_string = str(getattr(response, "key_string", "") or "")
            if key_string:
                record_permissions(
                    action_dict,
                    permissions=self.GET_KEY_STRING_API_NAME,
                    project_id=extract_project_id_from_resource(
                        name,
                        fallback_project=getattr(self.session, "project_id", ""),
                    ),
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=str(name or "").strip(),
                )
            return key_string
        except Exception as exc:
            handle_service_error(
                exc,
                api_name=self.GET_KEY_STRING_API_NAME,
                resource_name=name,
                service_label=self.SERVICE_LABEL,
                project_id=getattr(self.session, "project_id", None),
            )
            return ""

    def download_key_string(self, *, row: dict[str, Any], project_id: str) -> Path | None:
        """Write a captured key_string to a per-key loot file; None if absent.

        Side effect: creates ``apikeys/.../keys/api_key_<key_id>.txt`` under the
        session download path. Returns the destination Path, or None when the row
        carries no key_string to dump.
        """
        key_string = str((row or {}).get("key_string") or "").strip()
        if not key_string:
            return None

        key_id = str((row or {}).get("key_id") or extract_path_tail(resource_name_from_value(row, "name"))).strip() or "api_key"
        destination = Path(
            self.session.get_download_save_path(
                service_name="apikeys",
                project_id=project_id,
                subdirs=["keys"],
                filename=compact_filename_component(f"api_key_{key_id}.txt"),
            )
        )
        destination.write_text(key_string, encoding="utf-8")
        return destination

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str = "global") -> None:
        for row in rows or []:
            save_to_table(
                self.session,
                self.TABLE_NAME,
                row,
                defaults={
                    "project_id": project_id,
                    "location": extract_location_from_resource_name(resource_name_from_value(row, "name")) or location,
                },
                extra_builder=lambda _obj, raw: {
                    "key_id": extract_path_tail(resource_name_from_value(raw, "name")),
                },
            )
