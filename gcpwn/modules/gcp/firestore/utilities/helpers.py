from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from gcpwn.core.console import UtilityTools
from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.service_runtime import (
    build_discovery_service,
    handle_discovery_error,
    paged_list,
)
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.persistence import save_to_table, to_snake_key
from gcpwn.core.utils.serialization import resource_to_dict
from gcpwn.core.utils.service_runtime import get_cached_rows
from gcpwn.core.utils.service_runtime import handle_service_error
from gcpwn.core.utils.service_runtime import DownloadBudget


class FirestoreDatabasesResource(GcpListResource):
    """List/get Firestore databases via the firestore_admin_v1 GAPIC client.

    The LIST/GET permission is datastore.databases.getMetadata (Firestore shares
    the Datastore permission namespace). list() returns the "Not Enabled" sentinel
    via handle_service_error when the API is disabled. get() builds the full
    database resource name from a bare id, so it overrides the base body.
    """

    SERVICE_LABEL = "Firestore"
    TABLE_NAME = "firestore_databases"
    COLUMNS = ["database_id", "name", "location_id", "type", "concurrency_mode", "delete_protection_state"]
    ACTION_RESOURCE_TYPE = "databases"
    LIST_PERMISSION = "datastore.databases.getMetadata"
    GET_PERMISSION = "datastore.databases.getMetadata"
    LIST_API_NAME = "firestore.projects.databases.list"
    ID_FIELD = "database_id"
    PARENT_FROM_PROJECT_LOCATION = False
    PARENT_FROM_PROJECT = True

    def _build_client(self, session):
        try:
            from google.cloud import firestore_admin_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Firestore enumeration requires the `google-cloud-firestore` package."
            ) from exc
        return firestore_admin_v1.FirestoreAdminClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        response = self.client.list_databases(parent=parent)
        return getattr(response, "databases", response) or []

    def get(self, *, project_id: str | None = None, resource_id: str, action_dict=None) -> dict[str, Any] | None:
        project_id = project_id or getattr(self.session, "project_id", None)
        if not resource_id:
            return None
        normalized_name = _database_name(project_id, resource_id)
        try:
            row = resource_to_dict(self.client.get_database(name=normalized_name))
            record_permissions(
                action_dict,
                permissions=self.GET_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_name,
            )
            return row
        except Exception as exc:
            return handle_service_error(
                exc,
                api_name="firestore.projects.databases.get",
                resource_name=normalized_name,
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )

    def resolve_cached_targets(self, *, project_id: str) -> list[str]:
        rows = get_cached_rows(self.session, self.TABLE_NAME, project_id=project_id, columns=["database_id", "name"]) or []
        targets: list[str] = []
        seen: set[str] = set()
        for row in rows:
            candidate = _normalize_database_id(row.get("database_id") or row.get("name"))
            if candidate and candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)
        return targets


def _normalize_keys(value: Any) -> Any:
    """Recursively snake_case all dict keys in a (camelCase) discovery payload."""
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            out_key = to_snake_key(str(key))
            if not out_key:
                continue
            normalized[out_key] = _normalize_keys(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


class FirestoreRulesResource:
    """Enumerate Firebase Security Rules releases/rulesets attached to Firestore DBs.

    Correlates firebaserules releases with their rulesets, filters to the
    Firestore service, and (with include_get) fetches full rule source. Security-
    relevant: exposes the rule logic guarding a database. Uses the firebaserules
    v1 discovery API; recorded permissions are evidence (direct_api).
    """

    TABLE_NAME = "firestore_rules"
    COLUMNS = ["database_id", "release_name", "ruleset_name", "attachment_point", "services", "create_time"]
    LIST_RELEASES_PERMISSION = "firebaserules.releases.list"
    LIST_RULESETS_PERMISSION = "firebaserules.rulesets.list"
    GET_RULESET_PERMISSION = "firebaserules.rulesets.get"
    ACTION_RESOURCE_TYPE = "databases"
    SERVICE_LABEL = "Firebase Rules"

    def __init__(self, session) -> None:
        self.session = session
        self.service = build_discovery_service(session.credentials, "firebaserules", "v1")

    def list_releases(self, *, project_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}"
        try:
            rows = paged_list(
                lambda page_token: self.service.projects().releases().list(
                    name=parent,
                    pageToken=page_token,
                    pageSize=100,
                ),
                items_key="releases",
            )
            rows = [_normalize_keys(row) for row in rows or [] if isinstance(row, dict)]
            record_permissions(
                action_dict,
                permissions=self.LIST_RELEASES_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_discovery_error(
                self.session,
                "firebaserules.releases.list",
                parent,
                exc,
                service_label=self.SERVICE_LABEL,
            )

    def list_rulesets(self, *, project_id: str, action_dict=None) -> list[dict[str, Any]] | str | None:
        parent = f"projects/{project_id}"
        try:
            rows = paged_list(
                lambda page_token: self.service.projects().rulesets().list(
                    name=parent,
                    pageToken=page_token,
                    pageSize=100,
                ),
                items_key="rulesets",
            )
            rows = [_normalize_keys(row) for row in rows or [] if isinstance(row, dict)]
            record_permissions(
                action_dict,
                permissions=self.LIST_RULESETS_PERMISSION,
                scope_key="project_permissions",
                scope_label=project_id,
            )
            return rows
        except Exception as exc:
            return handle_discovery_error(
                self.session,
                "firebaserules.rulesets.list",
                parent,
                exc,
                service_label=self.SERVICE_LABEL,
            )

    def get_ruleset(self, *, project_id: str, ruleset_name: str, action_dict=None) -> dict[str, Any] | None:
        if not ruleset_name:
            return None
        try:
            row = self.service.projects().rulesets().get(name=ruleset_name).execute()
            return _normalize_keys(row) if isinstance(row, dict) else None
        except Exception as exc:
            result = handle_discovery_error(
                self.session,
                "firebaserules.rulesets.get",
                ruleset_name,
                exc,
                service_label=self.SERVICE_LABEL,
            )
            return result if isinstance(result, dict) else None

    def enumerate(
        self,
        *,
        project_id: str,
        include_get: bool = False,
        database_ids: list[str] | None = None,
        scope_actions=None,
        api_actions=None,
    ) -> list[dict[str, Any]]:
        """Join releases to rulesets, keep only Firestore rules, and build report rows.

        Lists releases and rulesets once, then for each release resolves its
        ruleset (fetching full source via get_ruleset only when include_get is
        set, cached per ruleset name), derives the bound database_id from the
        attachment point / release name, and filters by _is_firestore_rules_release
        and any database_ids allow-list. Returns one row per matching Firestore
        rules release. Returns [] if either list call is disabled/None.
        """
        releases = self.list_releases(project_id=project_id, action_dict=scope_actions)
        if releases in ("Not Enabled", None):
            return []

        rulesets = self.list_rulesets(project_id=project_id, action_dict=scope_actions)
        if rulesets in ("Not Enabled", None):
            return []

        ruleset_lookup = {
            str(row.get("name") or "").strip(): dict(row)
            for row in rulesets or []
            if isinstance(row, dict) and str(row.get("name") or "").strip()
        }
        allowed_databases = {_normalize_database_id(value) for value in (database_ids or []) if _normalize_database_id(value)}
        detailed_cache: dict[str, dict[str, Any]] = {}
        output: list[dict[str, Any]] = []

        for release in releases or []:
            if not isinstance(release, dict):
                continue
            release_name = str(release.get("name") or "").strip()
            ruleset_name = str(release.get("ruleset_name") or "").strip()
            ruleset = dict(ruleset_lookup.get(ruleset_name, {}))
            if include_get and ruleset_name:
                if ruleset_name not in detailed_cache:
                    detailed_cache[ruleset_name] = self.get_ruleset(
                        project_id=project_id,
                        ruleset_name=ruleset_name,
                    ) or {}
                if detailed_cache[ruleset_name]:
                    ruleset = detailed_cache[ruleset_name]

            if not _is_firestore_rules_release(release, ruleset):
                continue

            database_id = _database_id_from_rules_payload(release, ruleset)
            if include_get and ruleset_name and ruleset:
                record_permissions(
                    api_actions,
                    permissions=self.GET_RULESET_PERMISSION,
                    project_id=project_id,
                    resource_type=self.ACTION_RESOURCE_TYPE,
                    resource_label=database_id or ruleset_name,
                )
            if allowed_databases and database_id not in allowed_databases:
                continue

            services = _rules_services(ruleset)
            output.append(
                {
                    "database_id": database_id,
                    "release_name": release_name,
                    "ruleset_name": ruleset_name,
                    "attachment_point": _rules_attachment_point(ruleset),
                    "services": services,
                    "create_time": str(ruleset.get("create_time") or "").strip(),
                    "source_files": _rules_source_files(ruleset) if include_get else [],
                }
            )
        return output

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})


class FirestoreCollectionsResource:
    """Enumerate and exfiltrate Firestore collection documents via the data-plane client.

    Uses the firestore_v1 data client (not admin) to list top-level collections
    and recursively dump documents (and subcollections) to JSONL loot files.
    Datastore Mode databases don't support this API, so calls detect that error
    and skip gracefully (return None/[]). Document listing is recorded under the
    datastore.entities.list permission.
    """

    TABLE_NAME = "firestore_collections"
    COLUMNS = ["database_id", "collection_id", "collection_path"]
    LIST_PERMISSION = "datastore.entities.list"
    DOWNLOAD_PERMISSION = "datastore.entities.list"
    ACTION_RESOURCE_TYPE = "databases"

    def __init__(self, session) -> None:
        self.session = session
        try:
            from google.cloud import firestore_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Firestore collection enumeration requires the `google-cloud-firestore` package."
            ) from exc
        self.firestore_client_cls = firestore_v1.Client

    def _client(self, *, project_id: str, database_id: str):
        return self.firestore_client_cls(
            project=project_id,
            credentials=self.session.credentials,
            database=_normalize_database_id(database_id),
        )

    def list(self, *, project_id: str, database_id: str = "", parent: str = "", location: str | None = None, action_dict=None) -> list[dict[str, Any]] | str | None:
        if not database_id and parent:
            database_id = parent.rsplit("/databases/", 1)[-1] if "/databases/" in parent else parent
        normalized_database_id = _normalize_database_id(database_id)
        try:
            client = self._client(project_id=project_id, database_id=normalized_database_id)
            rows = []
            for collection_ref in client.collections():
                collection_path = str(getattr(collection_ref, "path", "") or "").strip() or str(
                    getattr(collection_ref, "id", "") or ""
                ).strip()
                collection_id = str(getattr(collection_ref, "id", "") or "").strip() or extract_path_tail(collection_path)
                rows.append(
                    {
                        "database_id": normalized_database_id,
                        "collection_id": collection_id,
                        "collection_path": collection_path,
                    }
                )
            record_permissions(
                action_dict,
                permissions=self.LIST_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_database_id,
            )
            return rows
        except Exception as exc:
            if _is_datastore_mode_collection_unsupported(exc):
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping collection enumeration for "
                    f"{_database_name(project_id, normalized_database_id)} because it is a "
                    f"Firestore in Datastore Mode database.{UtilityTools.RESET}"
                )
                return None
            return handle_service_error(
                exc,
                api_name="firestore.collections.list",
                resource_name=_database_name(project_id, normalized_database_id),
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )

    def save(self, rows: Iterable[dict[str, Any]], *, project_id: str, location: str | None = None, **_) -> None:
        for row in rows or []:
            save_to_table(self.session, self.TABLE_NAME, row, defaults={"project_id": project_id})

    def download_collection_documents(
        self,
        *,
        project_id: str,
        database_id: str,
        collection_path: str,
        limit: int = 0,
        action_dict=None,
    ) -> Path | None:
        """Recursively dump one collection's documents (and subcollections) to a JSONL file.

        Returns the loot file path, or None if the collection path is empty or the
        DB is Datastore Mode. Honors a per-collection ``limit`` and records the
        datastore.entities.list permission as evidence.
        """
        normalized_database_id = _normalize_database_id(database_id)
        normalized_collection_path = str(collection_path or "").strip()
        if not normalized_collection_path:
            return None

        try:
            client = self._client(project_id=project_id, database_id=normalized_database_id)
            destination = resolve_download_path(
                self.session,
                service_name="firestore",
                project_id=project_id,
                filename=f"{_safe_filename_token(normalized_database_id)}_{_safe_filename_token(normalized_collection_path)}_contents.txt",
                subdirs=["collections"],
            )
            visited: set[str] = set()
            with destination.open("w", encoding="utf-8", newline="\n") as handle:
                self._write_collection_recursive(
                    handle=handle,
                    collection_ref=client.collection(normalized_collection_path),
                    limit=limit,
                    visited=visited,
                )
            record_permissions(
                action_dict,
                permissions=self.DOWNLOAD_PERMISSION,
                project_id=project_id,
                resource_type=self.ACTION_RESOURCE_TYPE,
                resource_label=normalized_database_id,
            )
            return destination
        except Exception as exc:
            if _is_datastore_mode_collection_unsupported(exc):
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping collection download for "
                    f"{_database_name(project_id, normalized_database_id)} because it is a "
                    f"Firestore in Datastore Mode database.{UtilityTools.RESET}"
                )
                return None
            handle_service_error(
                exc,
                api_name="firestore.documents.list",
                resource_name=f"{_database_name(project_id, normalized_database_id)}:{normalized_collection_path}",
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )
            return None

    def download_database_documents(
        self,
        *,
        project_id: str,
        database_id: str,
        limit: int = 0,
        action_dict=None,
    ) -> list[Path]:
        """Dump every top-level collection in a database to its own JSONL loot file.

        Returns the list of files written (one per collection). Skips Datastore
        Mode databases. Subcollections are followed recursively per collection.
        """
        normalized_database_id = _normalize_database_id(database_id)
        try:
            client = self._client(project_id=project_id, database_id=normalized_database_id)
            destinations: list[Path] = []
            budget = DownloadBudget(self.session, label="firestore data")
            for collection_ref in client.collections():
                if budget.exceeded():  # per-type --download-timeout cap: stop and move on
                    break
                collection_path = str(getattr(collection_ref, "path", "") or "").strip() or str(
                    getattr(collection_ref, "id", "") or ""
                ).strip()
                if not collection_path:
                    continue
                destination = self.download_collection_documents(
                    project_id=project_id,
                    database_id=normalized_database_id,
                    collection_path=collection_path,
                    limit=limit,
                    action_dict=action_dict,
                )
                if destination is not None:
                    destinations.append(destination)
            return destinations
        except Exception as exc:
            if _is_datastore_mode_collection_unsupported(exc):
                print(
                    f"{UtilityTools.YELLOW}[*] Skipping collection download for "
                    f"{_database_name(project_id, normalized_database_id)} because it is a "
                    f"Firestore in Datastore Mode database.{UtilityTools.RESET}"
                )
                return []
            handle_service_error(
                exc,
                api_name="firestore.documents.list",
                resource_name=_database_name(project_id, normalized_database_id),
                service_label="Firestore",
                project_id=getattr(self.session, "project_id", None),
            )
            return []

    def _write_collection_recursive(self, *, handle, collection_ref, limit: int, visited: set[str]) -> None:
        """Stream a collection's docs to ``handle`` as JSONL, recursing into subcollections.

        Writes one JSON object per document; uses ``visited`` (collection paths)
        to avoid re-processing and possible cycles. ``limit`` caps docs per
        collection (0 = no limit).
        """
        collection_path = str(getattr(collection_ref, "path", "") or "").strip() or str(
            getattr(collection_ref, "id", "") or ""
        ).strip()
        if not collection_path or collection_path in visited:
            return
        visited.add(collection_path)

        query = collection_ref.limit(limit) if limit > 0 else collection_ref
        for snapshot in query.stream():
            payload = {
                "collection_path": collection_path,
                "document_id": str(getattr(snapshot, "id", "") or "").strip(),
                "document_path": str(getattr(getattr(snapshot, "reference", None), "path", "") or "").strip(),
                "data": snapshot.to_dict() if getattr(snapshot, "exists", True) else None,
            }
            handle.write(json.dumps(payload, ensure_ascii=False, default=str))
            handle.write("\n")
            for child_collection in getattr(snapshot.reference, "collections")():
                self._write_collection_recursive(
                    handle=handle,
                    collection_ref=child_collection,
                    limit=limit,
                    visited=visited,
                )

def _normalize_database_id(value: Any) -> str:
    """Reduce any database name/path to a bare database id (e.g. "(default)").

    Accepts a full ``projects/.../databases/<id>`` path or a bare id and returns
    just the trailing id, stripped of slashes.
    """
    token = str(value or "").strip()
    if not token:
        return ""
    if "/databases/" in token:
        token = token.partition("/databases/")[2]
    return token.strip("/")


def _database_name(project_id: str, database_id: Any) -> str:
    normalized_database_id = _normalize_database_id(database_id)
    return f"projects/{project_id}/databases/{normalized_database_id}" if normalized_database_id else ""


def _rules_services(ruleset: dict[str, Any]) -> list[str]:
    metadata = ruleset.get("metadata") or {}
    if not isinstance(metadata, dict):
        return []
    values = metadata.get("services") or []
    return [str(value).strip() for value in values if str(value).strip()]


def _rules_attachment_point(ruleset: dict[str, Any]) -> str:
    return str(ruleset.get("attachment_point") or "").strip()


def _rules_source_files(ruleset: dict[str, Any]) -> list[dict[str, Any]]:
    source = ruleset.get("source") or {}
    if not isinstance(source, dict):
        return []
    files = source.get("files") or []
    return [dict(entry) for entry in files if isinstance(entry, dict)]


def _is_firestore_rules_release(release: dict[str, Any], ruleset: dict[str, Any]) -> bool:
    """Return True if a rules release governs Firestore (vs Storage/RTDB rules).

    firebaserules releases cover multiple products; this filters to Firestore by
    checking the ruleset services, attachment point host, or the release name.
    """
    release_name = str(release.get("name") or "").strip()
    attachment_point = _rules_attachment_point(ruleset)
    services = _rules_services(ruleset)
    return (
        "cloud.firestore" in services
        or "firestore.googleapis.com" in attachment_point
        or "/releases/cloud.firestore" in release_name
    )


def _database_id_from_rules_payload(release: dict[str, Any], ruleset: dict[str, Any]) -> str:
    """Derive which database a rules release binds to from its attachment point/name.

    Prefers a ``/databases/<id>`` suffix on the attachment point, else parses the
    ``/releases/cloud.firestore[/<db>]`` release name (defaulting to "(default)").
    Returns "" if neither yields a database id.
    """
    attachment_point = _rules_attachment_point(ruleset)
    match = re.search(r"/databases/([^/]+)$", attachment_point)
    if match:
        return _normalize_database_id(match.group(1))

    release_name = str(release.get("name") or "").strip()
    release_prefix = "/releases/cloud.firestore"
    if release_prefix in release_name:
        suffix = release_name.split(release_prefix, 1)[1].strip("/")
        return _normalize_database_id(suffix or "(default)")
    return ""


def _safe_filename_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    token = token.strip("._")
    return token or "unknown"


def _is_datastore_mode_collection_unsupported(exc: Exception) -> bool:
    """Detect the error raised when collection ops hit a Datastore Mode database.

    The data-plane collection API is unavailable for Firestore-in-Datastore-Mode
    DBs; callers use this to skip such databases gracefully instead of erroring.
    """
    message = str(exc or "")
    return (
        "Cloud Firestore API is not available for Firestore in Datastore Mode database" in message
        or "Firestore in Datastore Mode database" in message
    )
