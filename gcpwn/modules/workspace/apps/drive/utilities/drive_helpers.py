"""Google Drive helpers (Drive API v3, read-only).

Drive is a *user-data-plane* API: you read a specific user's Drive by impersonating
them. Google APIs have NO username/password auth, so the access paths are a
service-account **domain-wide delegation** impersonating the target user
(``--caller-email``) or a stolen/consented OAuth token loaded as the credential.

Scope: ``https://www.googleapis.com/auth/drive.readonly`` (list + download). The
Drive API must also be enabled in the service account's GCP project.
"""

from __future__ import annotations

import io
import re
from typing import Any, Iterable

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import build_workspace_service, handle_directory_error


DRIVE_SCOPES = ("https://www.googleapis.com/auth/drive.readonly",)

# Google-native docs can't be downloaded raw -- they're exported to a real format.
_EXPORT_MAP = {
    "application/vnd.google-apps.document": ("text/plain", ".txt"),
    "application/vnd.google-apps.spreadsheet": ("text/csv", ".csv"),
    "application/vnd.google-apps.presentation": ("text/plain", ".txt"),
    "application/vnd.google-apps.script": ("application/vnd.google-apps.script+json", ".json"),
}

_FILE_FIELDS = (
    "id,name,mimeType,size,modifiedTime,owners(emailAddress),shared,ownedByMe,"
    "webViewLink,permissions(id,type,role,emailAddress,domain,allowFileDiscovery)"
)

# Extensions / MIME substrings worth grabbing first in --focused mode: documents,
# spreadsheets, archives, source, and the usual credential-bearing file types.
_INTERESTING_EXTENSIONS = {
    ".txt", ".csv", ".tsv", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".rtf", ".odt", ".ods", ".md", ".json", ".yaml", ".yml", ".xml",
    ".ini", ".conf", ".cfg", ".env", ".properties", ".sql", ".db", ".sqlite",
    ".pem", ".key", ".pfx", ".p12", ".ppk", ".kdbx", ".kdb", ".ovpn",
    ".sh", ".bash", ".ps1", ".py", ".js", ".ts", ".tf", ".tfvars",
    ".zip", ".tar", ".gz", ".7z", ".bak", ".log",
}
_INTERESTING_MIME_HINTS = (
    "application/vnd.google-apps.document",
    "application/vnd.google-apps.spreadsheet",
    "application/vnd.google-apps.presentation",
    "application/vnd.google-apps.script",
    "text/", "application/pdf", "application/json", "application/xml",
    "application/zip", "application/x-", "application/octet-stream",
)


def is_interesting_file(file_row: dict[str, Any]) -> bool:
    """True when a file looks worth grabbing first in --focused mode.

    Matches on filename extension or MIME type; folders are always skipped.
    """
    mime = str(file_row.get("mimeType") or "")
    if mime == "application/vnd.google-apps.folder":
        return False
    name = str(file_row.get("name") or "").lower()
    dot = name.rfind(".")
    if dot != -1 and name[dot:] in _INTERESTING_EXTENSIONS:
        return True
    return any(mime.startswith(hint) for hint in _INTERESTING_MIME_HINTS)


def classify_exposure(file_row: dict[str, Any], *, org_domains: set[str] | None = None) -> tuple[str, str]:
    """Return (exposure, shared_with) for a file from its permissions.

    exposure (most-open first): public > anyone_with_link > external > domain > private.
    shared_with is a short human summary of the notable (non-owner) grants.
    """
    org_domains = {d.lower() for d in (org_domains or set())}
    labels: set[str] = set()
    shared_with: list[str] = []
    for perm in file_row.get("permissions") or []:
        if not isinstance(perm, dict):
            continue
        perm_type = str(perm.get("type") or "")
        role = str(perm.get("role") or "")
        if perm_type == "anyone":
            label = "public" if perm.get("allowFileDiscovery") else "anyone_with_link"
            labels.add(label)
            shared_with.append(f"anyone({role})")
        elif perm_type == "domain":
            labels.add("domain")
            shared_with.append(f"domain:{perm.get('domain') or '*'}({role})")
        elif perm_type in ("user", "group"):
            email = str(perm.get("emailAddress") or "").lower()
            domain = email.split("@")[-1] if "@" in email else ""
            if domain and org_domains and domain not in org_domains:
                labels.add("external")
                shared_with.append(f"{perm_type}:{email}({role})")
    for level in ("public", "anyone_with_link", "external", "domain"):
        if level in labels:
            return level, "; ".join(shared_with[:8])
    return "private", ""


def compile_secret_patterns(extra: Iterable[str] | None = None) -> list[re.Pattern]:
    """Built-in credential/secret regexes (+ any caller-supplied patterns)."""
    builtin = [
        r"AKIA[0-9A-Z]{16}",                                   # AWS access key id
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----",  # private keys
        r"AIza[0-9A-Za-z_\-]{35}",                             # Google API key
        r"ya29\.[0-9A-Za-z_\-]+",                              # Google OAuth token
        r"\"private_key_id\"\s*:",                             # GCP SA key json
        r"xox[baprs]-[0-9A-Za-z-]{10,}",                       # Slack token
        r"gh[pousr]_[0-9A-Za-z]{36}",                          # GitHub token
        r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}",  # generic assignment
    ]
    patterns = list(builtin) + [str(p) for p in (extra or []) if str(p or "").strip()]
    compiled: list[re.Pattern] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            continue
    return compiled


class DriveResource:
    """List/download Drive files for the impersonated user (or the token's owner)."""

    def __init__(self, session, subject: str | None = None, *, credentials=None) -> None:
        self.session = session
        self.subject = subject
        # Optional credential override -- lets enum_drive download as a *different*
        # Google identity (a stored credential via --downloader-cred / --downloader-creds-all)
        # instead of the session credential. None => use the session credential (with `subject` for SA DWD).
        self._credentials = credentials
        self._service = None
        self.last_call_ok: bool | None = None
        self.last_error_status: int | None = None

    @property
    def service(self):
        if self._service is None:
            if self._credentials is not None:
                from googleapiclient.discovery import build  # type: ignore

                from gcpwn.modules.workspace.common import apply_workspace_delegation, ensure_scoped_credentials

                scoped = ensure_scoped_credentials(self._credentials, DRIVE_SCOPES)
                scoped = apply_workspace_delegation(scoped, self.subject)
                self._service = build("drive", "v3", credentials=scoped, cache_discovery=False)
            else:
                self._service = build_workspace_service(self.session, "drive", "v3", DRIVE_SCOPES, subject=self.subject)
        return self._service

    def list_files(self, *, query: str | None = None, page_size: int = 1000, max_files: int = 0) -> list[dict[str, Any]]:
        """Drive ``files.list`` (paged, incl. shared drives). Returns raw file dicts, [] on error."""
        try:
            files: list[dict[str, Any]] = []
            page_token = None
            while True:
                response = self.service.files().list(
                    q=query,
                    fields=f"nextPageToken, files({_FILE_FIELDS})",
                    pageSize=min(int(page_size), 1000),
                    pageToken=page_token,
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                    corpora="allDrives",
                ).execute() or {}
                files.extend([row for row in response.get("files", []) if isinstance(row, dict)])
                page_token = response.get("nextPageToken")
                if not page_token or (max_files and len(files) >= max_files):
                    break
            self.last_call_ok = True
            return files[:max_files] if max_files else files
        except Exception as exc:
            self.last_call_ok = False
            self.last_error_status = handle_directory_error(exc, skipping="Drive file enumeration")
            return []

    def download(self, *, file_id: str, mime_type: str) -> tuple[bytes | None, str]:
        """Download a file's bytes. Google-native docs are exported; binaries via get_media.

        Returns (content_bytes, filename_suffix) or (None, "") for folders / unsupported
        native types / errors.
        """
        from googleapiclient.http import MediaIoBaseDownload  # type: ignore

        try:
            if str(mime_type or "").startswith("application/vnd.google-apps."):
                export = _EXPORT_MAP.get(mime_type)
                if not export:
                    return None, ""  # folders / forms / drawings etc. -- nothing to pull
                export_mime, suffix = export
                data = self.service.files().export(fileId=file_id, mimeType=export_mime).execute()
                return (data if isinstance(data, bytes) else str(data).encode("utf-8", "replace")), suffix
            request = self.service.files().get_media(fileId=file_id, supportsAllDrives=True)
            buffer = io.BytesIO()
            downloader = MediaIoBaseDownload(buffer, request)
            done = False
            while not done:
                _status, done = downloader.next_chunk()
            return buffer.getvalue(), ""
        except Exception as exc:
            self.last_error_status = handle_directory_error(exc, skipping=f"Drive download of {file_id}")
            return None, ""

    def save(self, files: list[dict[str, Any]], *, caller_email: str, org_domains: set[str] | None = None) -> None:
        """Persist file metadata + exposure to ``workspace_drive_files`` and each ACL
        entry to ``workspace_drive_permissions`` (so the download step can filter on, e.g.,
        ``--download-public`` without re-listing)."""
        file_rows: list[dict[str, Any]] = []
        perm_rows: list[dict[str, Any]] = []
        for file_row in files or []:
            if not isinstance(file_row, dict):
                continue
            file_id = str(file_row.get("id") or "")
            exposure, shared_with = classify_exposure(file_row, org_domains=org_domains)
            owners = file_row.get("owners") or []
            owner_email = str((owners[0] or {}).get("emailAddress") or "") if owners else ""
            file_rows.append(
                {
                    "file_id": file_id,
                    "name": str(file_row.get("name") or ""),
                    "mime_type": str(file_row.get("mimeType") or ""),
                    "owner_email": owner_email,
                    "size": str(file_row.get("size") or ""),
                    "modified_time": str(file_row.get("modifiedTime") or ""),
                    "exposure": exposure,
                    "shared_with": shared_with,
                    "web_view_link": str(file_row.get("webViewLink") or ""),
                    "raw_json": file_row,
                }
            )
            for perm in file_row.get("permissions") or []:
                if not isinstance(perm, dict):
                    continue
                perm_rows.append(
                    {
                        "file_id": file_id,
                        "permission_id": str(perm.get("id") or ""),
                        "type": str(perm.get("type") or ""),
                        "role": str(perm.get("role") or ""),
                        "email_address": str(perm.get("emailAddress") or ""),
                        "domain": str(perm.get("domain") or ""),
                        "allow_file_discovery": str(perm.get("allowFileDiscovery")),
                        "raw_json": perm,
                    }
                )
        if file_rows:
            save_to_table(self.session, "workspace_drive_files", file_rows, defaults={"caller_email": caller_email})
        if perm_rows:
            save_to_table(self.session, "workspace_drive_permissions", perm_rows, defaults={"caller_email": caller_email})
