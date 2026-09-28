from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any


OUTPUT_ROOT_DIR_NAME = "gcpwn_output"
OUTPUT_DIR_NAMES = {
    "downloads": "downloads",
    "exports": "exports",
    "logs": "tool_logs",
}

NAMED_SAVE_PATHS: dict[str, dict[str, Any]] = {
    "Storage": {"bucket": "downloads", "service": "storage", "scope": "global"},
    "Secrets": {"bucket": "downloads", "service": "secretmanager", "scope": "global"},
    "Compute Base": {"bucket": "downloads", "service": "compute", "scope": "global"},
    "Compute Serial": {
        "bucket": "downloads",
        "service": "compute",
        "scope": "global",
        "subdirs": ["serial"],
    },
    "Compute Screenshots": {
        "bucket": "downloads",
        "service": "compute",
        "scope": "global",
        "subdirs": ["screenshots"],
    },
    "Functions": {"bucket": "downloads", "service": "functions", "scope": "global"},
    "Reports": {"bucket": "exports", "service": "reports", "scope": "global"},
    "Reports Snapshot": {
        "bucket": "exports",
        "service": "reports",
        "scope": "global",
        "subdirs": ["snapshots"],
    },
    "Reports Graphs": {
        "bucket": "exports",
        "service": "reports",
        "scope": "global",
        "subdirs": ["graphs"],
    },
    "System Log": {"bucket": "logs"},
}


def safe_path_component(value: str) -> str:
    """Sanitize one untrusted value into a single safe filesystem path segment.

    Strips path separators and ``:`` (Windows drive/ADS), collapses whitespace to
    ``_``, drops anything outside ``[A-Za-z0-9_.-]``, and trims leading/trailing
    ``._-``. Guards against path traversal when building output paths from
    attacker-influenced names (bucket/resource/project ids). May return "" if the
    input has no safe characters -- callers supply a fallback (e.g. ``or "file"``).
    """
    text = str(value or "")
    text = text.replace("/", "_").replace("\\", "_").replace(":", "_")
    text = re.sub(r"\s+", "_", text)
    return re.sub(r"[^A-Za-z0-9_.\-]", "", text).strip("._-")


# A ".." path segment is the one thing that cannot be written verbatim without
# escaping the download directory. Percent-encoding it keeps the name faithful and
# reversible instead of dropping information the operator may care about.
PARENT_SEGMENT_ESCAPE = "%2E%2E"


def safe_relative_path(name: str, *, fallback: str = "file") -> str:
    """Turn a remote object name into a relative path that cannot escape its root.

    PRESERVES the name -- ``.env``, ``...`` and ``report..v2`` are valid, distinct
    objects and the operator wants the real filename on disk -- and neutralizes only
    what traverses: a literal ``..`` segment becomes ``%2E%2E``, absolute anchors and
    ``\\`` separators are dropped, ``:`` is handled on Windows. Escaping rather than
    collapsing ``..`` keeps ``a/../b`` distinct from ``a/b``, which are different
    objects in Cloud Storage's flat namespace.

    Join the result with :func:`resolve_within`, which is the actual guarantee.
    """
    segments = []
    for raw in str(name or "").replace("\\", "/").split("/"):
        if raw in ("", "."):
            continue
        if raw == "..":
            segments.append(PARENT_SEGMENT_ESCAPE)
            continue
        segments.append(raw.replace(":", "_") if os.name == "nt" else raw)
    return "/".join(segments) or fallback


def resolve_within(root: str | Path, relative_name: str, *, fallback: str = "file") -> Path:
    """Join ``relative_name`` under ``root``, guaranteed to stay inside it.

    Resolves symlinks before comparing, and collapses the name to one safe segment
    if it would still land outside. Makes containment a property of the code rather
    than of :func:`safe_relative_path` being correct.
    """
    root_path = Path(root).expanduser()
    root_path.mkdir(parents=True, exist_ok=True)
    resolved_root = root_path.resolve()

    candidate = (resolved_root / safe_relative_path(relative_name, fallback=fallback)).resolve()
    if candidate == resolved_root or resolved_root in candidate.parents:
        return candidate
    return resolved_root / (compact_filename_component(relative_name) or fallback)


def compact_filename_component(filename: str, *, max_len: int = 128) -> str:
    safe_name = safe_path_component(filename) or "file"
    if len(safe_name) <= max_len:
        return safe_name

    stem, dot, ext = safe_name.rpartition(".")
    if not stem:
        stem, ext = safe_name, ""

    digest = hashlib.sha1(safe_name.encode("utf-8")).hexdigest()[:12]
    ext_len = (len(ext) + 1) if ext else 0
    keep = max(24, max_len - ext_len - len(digest) - 2)
    compact_stem = stem[:keep]
    compact = f"{compact_stem}__{digest}"
    return f"{compact}.{ext}" if ext else compact


def make_workspace_slug(workspace_id: int | str, workspace_name: str) -> str:
    safe_name = re.sub(r"\s+", "_", str(workspace_name or "workspace").strip().lower())
    safe_name = re.sub(r"[^a-z0-9_\-]+", "", safe_name) or "workspace"
    return f"{workspace_id}_{safe_name}"


def build_output_path(
    workspace_slug: str,
    *,
    bucket: str,
    filename: str = "",
    service_name: str | None = None,
    scope: str | None = None,
    subdirs: list[str] | None = None,
    mkdir: bool = True,
) -> Path:
    safe_slug = safe_path_component(workspace_slug) or "workspace"
    output_root = (Path.cwd() / OUTPUT_ROOT_DIR_NAME) / safe_slug
    if mkdir:
        output_root.mkdir(parents=True, exist_ok=True)
    parts: list[str | Path] = [output_root, OUTPUT_DIR_NAMES[bucket]]

    if service_name:
        parts.append(safe_path_component(service_name) or "service")
    if scope:
        parts.append(safe_path_component(scope) or "global")

    for raw_part in subdirs or []:
        cleaned = safe_path_component(raw_part)
        if cleaned:
            parts.append(cleaned)

    if filename:
        output_path = Path(*parts) / compact_filename_component(filename)
        if mkdir:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        return output_path

    output_dir = Path(*parts)
    if mkdir:
        output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def resolve_named_save_path(
    workspace_slug: str,
    *,
    filename: str = "",
    key: str,
    mkdir: bool = True,
) -> Path:
    path_config = NAMED_SAVE_PATHS[key]
    return build_output_path(
        workspace_slug,
        bucket=path_config["bucket"],
        filename=filename,
        service_name=path_config.get("service"),
        scope=path_config.get("scope"),
        subdirs=path_config.get("subdirs"),
        mkdir=mkdir,
    )


def resolve_download_path(
    session,
    *,
    service_name: str,
    project_id: str,
    filename: str = "",
    output: str | None = None,
    subdirs: list[str] | None = None,
    sanitize_fallback: bool = False,
) -> Path:
    """Resolve where a per-service downloaded loot file should be written.

    Shared replacement for the per-service ``_download_path`` helpers. Precedence:

    1. explicit ``output`` dir (``--output``) -> ``<output>/<filename>``;
    2. else ``session.get_download_save_path`` -- the canonical, workspace-slugged
       and sanitized path (authenticated runs);
    3. else a hand-built ``./gcpwn_output/downloads/<service>/<project>[/<subdirs>]/<filename>``
       fallback, reached only when the session lacks that method (unauth runs).

    The session branch forwards the *raw* ``filename`` (``get_download_save_path``
    sanitizes internally, and ``compact_filename_component`` is idempotent); the
    hand-built ``output``/fallback branches run it through
    ``compact_filename_component`` only when ``sanitize_fallback=True``. The parent
    directory is created for the ``output`` and fallback branches (the session
    branch already creates it).
    """
    fallback_name = compact_filename_component(filename) if sanitize_fallback else filename
    if output:
        destination = Path(output).expanduser() / fallback_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        return destination
    if hasattr(session, "get_download_save_path"):
        return Path(
            session.get_download_save_path(
                service_name=service_name,
                filename=filename,
                project_id=project_id,
                subdirs=subdirs,
            )
        )
    fallback_dir = Path.cwd() / OUTPUT_ROOT_DIR_NAME / OUTPUT_DIR_NAMES["downloads"] / service_name / project_id
    for part in subdirs or []:
        fallback_dir = fallback_dir / str(part)
    fallback_dir.mkdir(parents=True, exist_ok=True)
    return fallback_dir / fallback_name
