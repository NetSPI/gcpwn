from __future__ import annotations

from typing import Any, Iterable

from google.api_core.exceptions import Forbidden
from google.cloud import resourcemanager_v3

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.persistence import save_to_table

"""
Shared Google Workspace infrastructure used by BOTH the Cloud Identity API
(``cloudidentity.googleapis.com``) and the Admin SDK Directory API
(``admin.googleapis.com``) module trees.

This module holds pure infra: OAuth scopes, the Directory/Cloud-Identity client
builders (including service-account domain-wide delegation), HTTP error helpers,
and customer-id / organization resolution via GCP Resource Manager.
"""


CLOUD_IDENTITY_SCOPES = ("https://www.googleapis.com/auth/cloud-identity.groups.readonly",)
DIRECTORY_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
)


def ensure_scoped_credentials(credentials, scopes: Iterable[str]):
    """Best-effort: attach OAuth scopes to credentials when required/supported."""
    try:
        import google.auth.credentials

        return google.auth.credentials.with_scopes_if_required(credentials, scopes)
    except Exception:
        try:
            return credentials.with_scopes(list(scopes))  # type: ignore[attr-defined]
        except Exception:
            return credentials


def apply_workspace_delegation(credentials, subject: str | None):
    """Impersonate a Workspace admin via domain-wide delegation (SA path).

    GCP credentials do NOT grant Workspace access on their own. A user that is a
    Workspace admin works directly; a service account must have domain-wide
    delegation configured in the Workspace Admin console (its OAuth client ID
    authorized for the scopes) AND impersonate an admin user -- that impersonation
    is ``credentials.with_subject(subject)``. No-op for user/ADC creds (no
    ``with_subject``) or when ``subject`` is empty, so the admin-user path is
    unaffected.
    """
    subject = str(subject or "").strip()
    if not subject:
        return credentials
    with_subject = getattr(credentials, "with_subject", None)
    if callable(with_subject):
        try:
            return with_subject(subject)
        except Exception:
            return credentials
    return credentials


def resolve_workspace_admin_subject(session, subject: str | None = None) -> str | None:
    """Resolve the Workspace admin email to impersonate for SA domain-wide delegation.

    Order: explicit ``--impersonate``/``subject`` arg, then
    ``session.workspace_config.workspace_admin_subject`` (set via
    ``configs set workspace_admin_subject admin@domain``). None means "no
    impersonation" (fine for an admin-user credential).
    """
    if subject:
        return str(subject).strip()
    configured = getattr(getattr(session, "workspace_config", None), "workspace_admin_subject", None)
    return str(configured).strip() if configured else None


def record_workspace_delegation(session, *, customer_id: str | None, subject: str | None) -> None:
    """Record that the active SERVICE-ACCOUNT credential has domain-wide delegation to
    this Workspace tenant -- *proven* by a successful impersonated enumeration.

    Only fires for a service-account credential impersonating an admin (``subject``);
    a no-op for user/admin creds or when there's nothing to prove. This is the data
    source for the OpenGraph ``DOMAIN_WIDE_DELEG`` edge (SA -> every user it can
    impersonate), a GCP->Workspace-takeover path invisible to normal IAM enumeration.
    """
    sa_email = str(getattr(session.credentials, "service_account_email", "") or "").strip()
    customer = str(customer_id or "").strip()
    admin = str(subject or "").strip()
    if not (sa_email and customer and admin):
        return
    try:
        save_to_table(
            session,
            "workspace_delegations",
            [{"sa_email": sa_email, "customer_id": customer, "admin_subject": admin}],
        )
    except Exception:
        pass


def build_cloud_identity_service(credentials, *, subject: str | None = None):
    """
    Build a Cloud Identity discovery client (optionally impersonating ``subject``
    for service-account domain-wide delegation).

    Uses the discovery doc at:
      `https://cloudidentity.googleapis.com/$discovery/rest?version=v1`
    """
    from googleapiclient.discovery import build  # type: ignore

    scoped = ensure_scoped_credentials(credentials, CLOUD_IDENTITY_SCOPES)
    scoped = apply_workspace_delegation(scoped, subject)
    # Cloud Identity API discovery doc:
    # - https://cloudidentity.googleapis.com/$discovery/rest?version=v1
    return build("cloudidentity", "v1", credentials=scoped, cache_discovery=False)


def build_directory_service(credentials, *, subject: str | None = None):
    """
    Build an Admin SDK Directory API discovery client (optionally impersonating
    ``subject`` for service-account domain-wide delegation).

    Discovery doc:
      `https://admin.googleapis.com/$discovery/rest?version=directory_v1`
    """
    from googleapiclient.discovery import build  # type: ignore

    scoped = ensure_scoped_credentials(credentials, DIRECTORY_SCOPES)
    scoped = apply_workspace_delegation(scoped, subject)
    return build("admin", "directory_v1", credentials=scoped, cache_discovery=False)


def build_scoped_directory_service(session, scopes, *, subject: str | None = None):
    """Build an Admin SDK Directory client with ``scopes`` explicitly requested.

    Directory sub-APIs (domains/orgunits/devices/roles/tokens) each need their own
    ``admin.directory.*.readonly`` scope. Requesting it here means a service-account
    domain-wide-delegation token is minted WITH that scope (``build_directory_service``
    alone only requests the narrow user/group scopes). Impersonates ``subject`` for SA
    DWD. Consolidates the per-helper ``ensure_scoped_credentials`` + build boilerplate.
    """
    credentials = ensure_scoped_credentials(session.credentials, scopes)
    return build_directory_service(credentials, subject=subject)


def build_workspace_service(session, api: str, version: str, scopes, *, subject: str | None = None):
    """Build any Google Workspace discovery client with ``scopes`` explicitly requested.

    For Admin SDK sub-APIs beyond the Directory API -- e.g. ``groupssettings``/v1,
    ``admin``/``datatransfer_v1`` -- that don't share ``admin``/``directory_v1``.
    Impersonates ``subject`` for service-account domain-wide delegation.
    """
    from googleapiclient.discovery import build  # type: ignore

    scoped = ensure_scoped_credentials(session.credentials, scopes)
    scoped = apply_workspace_delegation(scoped, subject)
    return build(api, version, credentials=scoped, cache_discovery=False)


def handle_directory_error(exc: Exception, *, skipping: str) -> int | None:
    """Print a consistent Admin SDK Directory skip notice and return the HTTP status.

    ``skipping`` names what was skipped (e.g. ``"domain enumeration"``). 403 -> access
    denied; 404 -> API not enabled / no Workspace org; anything else -> generic failure.
    Shared across the directory helpers so error wording stays uniform.
    """
    status = _http_error_status(exc)
    text = str(exc).lower()
    # A 403 whose body says the API "has not been used / is disabled" is GCP API
    # enablement, NOT a scope/DWD problem -- say the accurate thing to fix.
    if "has not been used in project" in text or "it is disabled" in text or "accessnotconfigured" in text:
        print(f"[*] The Google API backing {skipping} is not enabled in this GCP project -- enable it in the Cloud Console, then retry.")
        return 403
    # A SA domain-wide-delegation token whose grant lacks the requested scope fails at
    # token-mint with `unauthorized_client` (a RefreshError, not an HTTP 403); treat it
    # as a denial so per-item loops break early instead of repeating it for every item.
    if status == 403 or "unauthorized_client" in text or "insufficient authentication scopes" in text:
        print(f"[*] Admin SDK access denied (check the credential's scopes / DWD authorization); skipping {skipping}.")
        return 403
    if status == 404:
        print(f"[*] Admin SDK Directory API not enabled or no Google Workspace org; skipping {skipping}.")
        return 404
    print(f"[*] Admin SDK Directory {skipping} failed: {type(exc).__name__}: {exc}")
    return status


def _http_error_status(exc: Exception) -> int | None:
    try:
        from googleapiclient.errors import HttpError  # type: ignore

        if isinstance(exc, HttpError) and getattr(exc, "resp", None) is not None:
            return int(getattr(exc.resp, "status", None))
    except Exception:
        return None
    return None


def _http_error_details(exc: Exception) -> tuple[int | None, str]:
    status = _http_error_status(exc)
    detail = str(exc)
    try:
        from googleapiclient.errors import HttpError  # type: ignore

        if isinstance(exc, HttpError):
            content = getattr(exc, "content", b"")
            if isinstance(content, (bytes, bytearray)) and content:
                decoded = content.decode("utf-8", errors="replace").strip()
                if decoded:
                    detail = decoded
    except Exception:
        pass
    return status, detail


def _handle_cloudidentity_error(session, api_name: str, resource_name: str, exc: Exception) -> None:
    status = _http_error_status(exc)
    if status == 403:
        UtilityTools.print_403_api_denied(api_name, resource_name=resource_name)
        return
    if status == 404:
        UtilityTools.print_404_resource(resource_name)
        return
    UtilityTools.print_500(resource_name, api_name, exc)


def _select_project_hierarchy_row(session, *, project_id: str) -> dict[str, Any] | None:
    rows = session.get_data("abstract_tree_hierarchy", where={"type": "project", "project_id": project_id}) or []
    if not rows:
        return None
    # Prefer the row whose name looks like projects/<number>.
    for row in rows:
        name = str(row.get("name", ""))
        if name.startswith("projects/"):
            return row
    return dict(rows[0])


def resolve_org_id(session, *, explicit_org_id: str | None = None) -> str | None:
    """
    Best-effort organization ID resolution.

    Prefer cached hierarchy rows (abstract_tree_hierarchy). Fallback is Resource Manager `projects.get` plus
    walking folder parents to an `organizations/<id>` parent.
    """
    if explicit_org_id:
        return str(explicit_org_id).strip()

    cached = _select_project_hierarchy_row(session, project_id=session.project_id)
    if cached:
        parent = str(cached.get("parent") or "")
        # Walk cached hierarchy via parent pointers.
        visited = set()
        while parent and parent not in {"N/A", "None"} and parent not in visited:
            visited.add(parent)
            if parent.startswith("organizations/"):
                return extract_path_tail(parent, default=parent)
            next_rows = session.get_data("abstract_tree_hierarchy", where={"name": parent}) or []
            parent = str(next_rows[0].get("parent") or "") if next_rows else ""

    # Best-effort fallback via Resource Manager.
    try:
        projects_client = resourcemanager_v3.ProjectsClient(credentials=session.credentials)
        folders_client = resourcemanager_v3.FoldersClient(credentials=session.credentials)
        project = projects_client.get_project(name=f"projects/{session.project_id}")
        parent = str(getattr(project, "parent", "") or "")
        while parent:
            if parent.startswith("organizations/"):
                return extract_path_tail(parent, default=parent)
            if parent.startswith("folders/"):
                folder = folders_client.get_folder(name=parent)
                parent = str(getattr(folder, "parent", "") or "")
                continue
            break
    except Exception:
        return None

    return None


def resolve_directory_customer_id(session, *, customer_id: str | None = None, organization_id: str | None = None) -> str | None:
    """
    Resolve Directory Customer ID (aka `directoryCustomerId`, looks like `C0xxxxxxx`).

    Resolution order:
      1) explicit `--customer-id`
      2) `session.workspace_config.workspace_customer_id`
      3) Resource Manager `organizations.get` → `directoryCustomerId`
    """
    if customer_id:
        return str(customer_id).strip()
    if getattr(session.workspace_config, "workspace_customer_id", None):
        return str(session.workspace_config.workspace_customer_id).strip()

    org_id = str(organization_id).strip() if organization_id else None
    if not org_id:
        org_id = resolve_org_id(session)
    if not org_id:
        return None

    try:
        org_client = resourcemanager_v3.OrganizationsClient(credentials=session.credentials)
        # Resource Manager API: organizations.get
        # We use this strictly to derive directoryCustomerId for Workspace scoping.
        org = org_client.get_organization(name=f"organizations/{org_id}")
        directory_customer_id = getattr(org, "directory_customer_id", None) or getattr(org, "directoryCustomerId", None)
        if directory_customer_id:
            resolved = str(directory_customer_id)
            # Cache it so subsequent runs skip the organizations.get round-trip.
            try:
                session.workspace_config.workspace_customer_id = resolved
                session.set_configs()
            except Exception:
                pass
            return resolved
    except Forbidden:
        UtilityTools.print_403_api_denied("resourcemanager.organizations.get", resource_name=f"organizations/{org_id}")
    except Exception as exc:
        UtilityTools.print_500(f"organizations/{org_id}", "resourcemanager.organizations.get", exc)

    return None


def track_workspace_permission(
    workspace_actions: dict[str, dict[str, set[str]]],
    *,
    customer_id: str | None,
    permission: str,
) -> None:
    """Record a discovered Workspace permission under its tenant (customer) scope.

    No-op if permission or customer_id is empty. Shared by the tenant-scoped
    enumerators so they don't each re-declare it.
    """
    if not permission:
        return
    scope_id = str(customer_id or "").strip()
    if not scope_id:
        return
    workspace_actions["workspace_permissions"].setdefault(scope_id, set()).add(permission)
