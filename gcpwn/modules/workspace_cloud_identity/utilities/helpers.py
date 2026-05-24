from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable

from google.api_core.exceptions import Forbidden
from google.cloud import resourcemanager_v3

from gcpwn.core.console import UtilityTools
from gcpwn.core.utils.module_helpers import extract_path_tail
from gcpwn.core.utils.persistence import save_to_table

"""
Google Workspace / Cloud Identity helpers.

These helpers use two families of APIs:

1) Google Workspace / Cloud Identity (Directory-style data)
   - API host: `cloudidentity.googleapis.com`
   - Client: `googleapiclient.discovery.build("cloudidentity", "v1")`
   - Calls:
     - `groups.list(parent="customers/<directoryCustomerId>", view=FULL|BASIC, filter=...)`
       - REST: `GET /v1/groups?parent=customers/<C...>&view=FULL&pageSize=...&filter=...`
     - `groups.search(query="...")`
       - REST: `GET /v1/groups:search?query=...&pageSize=...`
       - Mirrors `gcloud identity groups search ...`
     - `groups.memberships.list(parent="groups/<groupId>", view=FULL|BASIC)`
       - REST: `GET /v1/groups/<groupId>/memberships?view=FULL&pageSize=...`
     - `groups.memberships.searchTransitiveMemberships(parent="groups/<groupId>", ...)`
       - REST: `GET /v1/groups/<groupId>/memberships:searchTransitiveMemberships?...`

   Note: this is *not* Cloud IAM. Group membership lives in Workspace/Cloud Identity, not in GCP IAM policies.
   Your ADC / token must have Workspace/Cloud Identity permission and include the scope:
   `https://www.googleapis.com/auth/cloud-identity.groups.readonly`.

2) GCP Resource Manager (to derive tenant scope)
   - API host: `cloudresourcemanager.googleapis.com`
   - Client: `google.cloud.resourcemanager_v3.OrganizationsClient`
   - Call:
     - `organizations.get` → read `directoryCustomerId` (aka Directory Customer ID, looks like `C03mo2fhw`)

We store Workspace data in `workspace_*` tables (e.g., `workspace_groups`, `workspace_users`, `workspace_group_memberships`).
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


def build_cloud_identity_service(credentials):
    """
    Build a Cloud Identity discovery client.

    Uses the discovery doc at:
      `https://cloudidentity.googleapis.com/$discovery/rest?version=v1`
    """
    from googleapiclient.discovery import build  # type: ignore

    scoped = ensure_scoped_credentials(credentials, CLOUD_IDENTITY_SCOPES)
    # Cloud Identity API discovery doc:
    # - https://cloudidentity.googleapis.com/$discovery/rest?version=v1
    return build("cloudidentity", "v1", credentials=scoped, cache_discovery=False)


def build_directory_service(credentials):
    """
    Build an Admin SDK Directory API discovery client.

    Discovery doc:
      `https://admin.googleapis.com/$discovery/rest?version=directory_v1`
    """
    from googleapiclient.discovery import build  # type: ignore

    scoped = ensure_scoped_credentials(credentials, DIRECTORY_SCOPES)
    return build("admin", "directory_v1", credentials=scoped, cache_discovery=False)


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


class CloudIdentityGroupsResource:
    TABLE_NAME = "workspace_groups"
    COLUMNS = ["email", "display_name", "name", "description", "create_time", "update_time"]

    def __init__(self, session) -> None:
        self.session = session
        self.service = build_cloud_identity_service(session.credentials)
        self.last_call_ok: bool | None = None
        self.last_method: str | None = None
        self.last_request: dict[str, Any] = {}
        self.last_error_status: int | None = None
        self.last_error_message: str | None = None

    def list(
        self,
        *,
        parent: str,
        view: str = "FULL",
        page_size: int = 1000,
        filter_value: str | None = None,
    ) -> list[dict[str, Any]]:
        self.last_method = "groups.list"
        self.last_request = {
            "parent": parent,
            "view": view,
            "page_size": page_size,
            "filter": filter_value,
        }
        self.last_error_status = None
        self.last_error_message = None
        try:
            self.last_call_ok = True
            return list_groups(self.service, parent=parent, view=view, page_size=page_size, filter_value=filter_value)
        except Exception as exc:
            self.last_call_ok = False
            status, detail = _http_error_details(exc)
            self.last_error_status = status
            self.last_error_message = detail
            _handle_cloudidentity_error(self.session, "cloudidentity.groups.list", parent, exc)
        return []

    def search(self, *, query: str, page_size: int = 1000) -> list[dict[str, Any]]:
        self.last_method = "groups.search"
        self.last_request = {
            "query": query,
            "page_size": page_size,
        }
        self.last_error_status = None
        self.last_error_message = None
        try:
            self.last_call_ok = True
            return search_groups(self.service, query=query, page_size=page_size)
        except Exception as exc:
            self.last_call_ok = False
            status, detail = _http_error_details(exc)
            self.last_error_status = status
            self.last_error_message = detail
            _handle_cloudidentity_error(self.session, "cloudidentity.groups.search", query, exc)
        return []

    def get(self, *, group_name: str, view: str = "FULL") -> dict[str, Any] | None:
        try:
            self.last_call_ok = True
            # Cloud Identity API: groups.get
            try:
                request = self.service.groups().get(name=group_name, view=view)
            except TypeError:
                request = self.service.groups().get(name=group_name)
                if view:
                    request.uri += f"&view={urllib.parse.quote(view)}"
            return dict(request.execute() or {})
        except Exception as exc:
            self.last_call_ok = False
            _handle_cloudidentity_error(self.session, "cloudidentity.groups.get", group_name, exc)
        return None

    def save(self, groups: Iterable[WorkspaceGroup]) -> None:
        save_to_table(self.session, "workspace_groups", [workspace_group_to_row(group) for group in groups or []])

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudIdentityGroupMembershipsResource:
    TABLE_NAME = "workspace_group_memberships"
    COLUMNS = ["group_email", "group_member", "member_email", "member", "member_type", "roles", "transitive", "source"]

    def __init__(self, session) -> None:
        self.session = session
        self.service = build_cloud_identity_service(session.credentials)
        self.last_call_ok: bool | None = None

    def list(
        self,
        *,
        group_name: str,
        view: str = "FULL",
        page_size: int = 1000,
        transitive: bool = False,
    ) -> list[dict[str, Any]]:
        try:
            self.last_call_ok = True
            if transitive:
                return search_transitive_group_memberships(self.service, group_name=group_name, view=view, page_size=page_size)
            return list_group_memberships(self.service, group_name=group_name, view=view, page_size=page_size)
        except Exception as exc:
            self.last_call_ok = False
            api_name = (
                "cloudidentity.groups.memberships.searchTransitiveMemberships"
                if transitive
                else "cloudidentity.groups.memberships.list"
            )
            _handle_cloudidentity_error(self.session, api_name, group_name, exc)
        return []

    def save(
        self,
        *,
        customer_id: str,
        group: WorkspaceGroup,
        memberships: Iterable[dict[str, Any]],
        transitive: bool,
        source: str,
    ) -> list[str]:
        rows, member_emails = build_workspace_group_membership_rows(
            customer_id=customer_id,
            group=group,
            memberships=memberships,
            transitive=transitive,
            source=source,
        )
        if rows:
            save_to_table(self.session, "workspace_group_memberships", rows)
        return member_emails

    def get(self, *, resource_id: str) -> dict[str, Any] | None:
        _ = resource_id
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class WorkspaceUsersResource:
    TABLE_NAME = "workspace_users"
    COLUMNS = ["email", "display_name", "user_id"]

    def __init__(self, session) -> None:
        self.session = session
        self.last_call_ok: bool | None = None

    def list(self, *args, **kwargs):
        """
        List users via the Admin SDK Directory API.

        Requires Workspace admin privileges and Directory scopes. If the caller does not have
        Admin SDK access, this returns an empty list (and sets `last_call_ok=False`).
        """
        try:
            self.last_call_ok = True
            service = build_directory_service(self.session.credentials)
            return list_directory_users(service, *args, **kwargs)
        except Exception as exc:
            self.last_call_ok = False
            status = _http_error_status(exc)
            if status == 403:
                print("[*] Admin SDK Directory API access denied; skipping user enumeration.")
                return []
            if status == 404:
                print("[*] Admin SDK Directory API not enabled or no Google Workspace org; skipping user enumeration.")
                return []
            print(f"[*] Admin SDK Directory API user enumeration failed: {type(exc).__name__}: {exc}")
            return []

    def get(self, *args, **kwargs):
        _ = (args, kwargs)
        return None

    def save_emails(self, *, customer_id: str, member_emails: Iterable[str]) -> None:
        save_to_table(
            self.session,
            "workspace_users",
            [
                workspace_user_to_row(customer_id=customer_id, email=str(email).strip())
                for email in member_emails or []
                if str(email).strip()
            ],
        )

    def save_users(self, *, customer_id: str, users: Iterable[dict[str, Any]]) -> None:
        rows: list[dict[str, Any]] = []
        for user in users or []:
            if not isinstance(user, dict):
                continue
            email = str(user.get("primaryEmail") or user.get("email") or "").strip()
            if not email:
                continue
            rows.append(
                workspace_user_to_row(
                    customer_id=customer_id,
                    email=email,
                    user_id=str(user.get("id") or email),
                    display_name=str((user.get("name") or {}).get("fullName") or user.get("displayName") or ""),
                    raw=user,
                )
            )
        if rows:
            save_to_table(self.session, "workspace_users", rows)

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


def _select_project_hierarchy_row(session, *, project_id: str) -> dict[str, Any] | None:
    rows = session.get_data("abstract_tree_hierarchy", conditions=f'type="project" AND project_id="{project_id}"') or []
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
            next_rows = session.get_data("abstract_tree_hierarchy", conditions=f'name="{parent}"') or []
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
    Resolve Directory Customer ID (aka `directoryCustomerId`, looks like `C03mo2fhw`).

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
            return str(directory_customer_id)
    except Forbidden:
        UtilityTools.print_403_api_denied("resourcemanager.organizations.get", resource_name=f"organizations/{org_id}")
    except Exception as exc:
        UtilityTools.print_500(f"organizations/{org_id}", "resourcemanager.organizations.get", exc)

    return None


@dataclass(frozen=True)
class WorkspaceGroup:
    customer_id: str
    name: str
    email: str
    display_name: str = ""
    description: str = ""
    labels: dict[str, Any] | None = None
    create_time: str = ""
    update_time: str = ""
    raw: dict[str, Any] | None = None


def _extract_group_email(group: dict[str, Any]) -> str:
    for key in ("preferredGroupKey", "groupKey", "preferred_group_key", "group_key"):
        value = group.get(key)
        if isinstance(value, dict) and value.get("id"):
            return str(value["id"])
    return ""


def _paged_execute(request, collection_key: str):
    items: list[dict[str, Any]] = []
    while request is not None:
        response = request.execute() or {}
        items.extend([dict(row) for row in response.get(collection_key, []) if isinstance(row, dict)])
        try:
            request = request.list_next(request, response)  # type: ignore[attr-defined]
        except Exception:
            request = None
    return items


def list_groups(
    service,
    *,
    parent: str,
    view: str = "FULL",
    page_size: int = 1000,
    filter_value: str | None = None,
) -> list[dict[str, Any]]:
    """
    Cloud Identity API: `groups.list`.

    `parent` should look like `customers/<directoryCustomerId>`.
    `view=FULL` typically returns additional metadata (labels/timestamps/keys) compared to BASIC.
    """
    try:
        request = service.groups().list(parent=parent, view=view, pageSize=page_size, filter=filter_value)
    except TypeError:
        request = service.groups().list(parent=parent, pageSize=page_size)
        if view:
            request.uri += f"&view={urllib.parse.quote(view)}"
        if filter_value:
            request.uri += f"&filter={urllib.parse.quote(str(filter_value))}"
    return _paged_execute(request, "groups")


def search_groups(
    service,
    *,
    query: str,
    page_size: int = 1000,
) -> list[dict[str, Any]]:
    """
    Cloud Identity API: `groups.search`.

    Useful for workflows that mirror `gcloud identity groups search ...`.
    The query syntax is controlled by the caller; we pass it through as-is.
    """
    try:
        request = service.groups().search(query=query, pageSize=page_size)
    except TypeError:
        request = service.groups().search(query=query)
        request.uri += f"&pageSize={int(page_size)}"
    return _paged_execute(request, "groups")


def workspace_group_to_row(group: WorkspaceGroup) -> dict[str, Any]:
    """Normalize a `WorkspaceGroup` into the `workspace_groups` table schema."""
    return {
        "customer_id": group.customer_id,
        "name": group.name,
        "email": group.email,
        "display_name": group.display_name,
        "description": group.description,
        "labels": group.labels or {},
        "create_time": group.create_time,
        "update_time": group.update_time,
        "raw_json": group.raw or {},
    }


def _extract_member_email(membership: dict[str, Any]) -> str:
    for key in ("preferredMemberKey", "memberKey", "preferred_member_key", "member_key"):
        value = membership.get(key)
        if isinstance(value, dict) and value.get("id"):
            return str(value["id"])
    return ""


def _member_type_from_email(email: str) -> str:
    token = str(email or "").lower()
    if not token:
        return "unknown"
    if token.endswith(".gserviceaccount.com"):
        return "service_account"
    if "@" in token:
        return "user"
    return "unknown"


def _canonical_workspace_member_token(email: str, member_type: str) -> str:
    token = str(email or "").strip().lower()
    if not token:
        return ""
    normalized_type = str(member_type or "").strip().lower()
    if normalized_type == "service_account" or token.endswith(".gserviceaccount.com"):
        return f"serviceAccount:{token}"
    if "@" in token:
        return f"user:{token}"
    return token


def list_group_memberships(service, *, group_name: str, view: str = "FULL", page_size: int = 1000) -> list[dict[str, Any]]:
    """
    Cloud Identity API: `groups.memberships.list`.

    `group_name` should look like `groups/<groupId>`.
    With `view=FULL`, membership records typically include `preferredMemberKey`/`memberKey` which we use to extract
    the member's email.
    """
    try:
        request = service.groups().memberships().list(parent=group_name, view=view, pageSize=page_size)
    except TypeError:
        request = service.groups().memberships().list(parent=group_name, pageSize=page_size)
        if view:
            request.uri += f"&view={urllib.parse.quote(view)}"
    return _paged_execute(request, "memberships")


def search_transitive_group_memberships(service, *, group_name: str, view: str = "FULL", page_size: int = 1000) -> list[dict[str, Any]]:
    """
    Cloud Identity API: `groups.memberships.searchTransitiveMemberships`.

    Returns nested memberships (members inherited via group-in-group relationships).
    """
    try:
        request = service.groups().memberships().searchTransitiveMemberships(parent=group_name, pageSize=page_size)
    except TypeError:
        request = service.groups().memberships().searchTransitiveMemberships(parent=group_name)
        request.uri += f"&pageSize={int(page_size)}"
    if view:
        request.uri += f"&view={urllib.parse.quote(view)}"
    return _paged_execute(request, "memberships")


def list_directory_users(service, *, customer: str = "my_customer", max_results: int = 500, order_by: str = "email") -> list[dict[str, Any]]:
    """
    Admin SDK Directory API: `users.list`.

    Returns raw user dicts as returned by the API.
    """
    users: list[dict[str, Any]] = []
    request = service.users().list(customer=customer, maxResults=int(max_results), orderBy=order_by)
    while request is not None:
        response = request.execute()
        batch = response.get("users", []) if isinstance(response, dict) else []
        if isinstance(batch, list):
            for user in batch:
                if isinstance(user, dict):
                    users.append(user)
        request = service.users().list_next(previous_request=request, previous_response=response)
    return users


def workspace_user_to_row(*, customer_id: str, email: str, user_id: str | None = None, display_name: str | None = None, raw: Any | None = None) -> dict[str, Any]:
    """Normalize a user into the `workspace_users` schema (email-centric)."""
    return {
        "customer_id": customer_id,
        "email": email,
        "user_id": str(user_id or email),
        "display_name": str(display_name or ""),
        "raw_json": raw if isinstance(raw, dict) else {},
    }


def build_workspace_group_membership_rows(
    *,
    customer_id: str,
    group: WorkspaceGroup,
    memberships: Iterable[dict[str, Any]],
    transitive: bool,
    source: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    member_emails: list[str] = []

    for membership in memberships or []:
        member_email = _extract_member_email(membership)
        if not member_email:
            continue
        member_emails.append(member_email)
        normalized_member_type = _member_type_from_email(member_email)

        roles = membership.get("roles") or []
        rows.append(
            {
                "customer_id": customer_id,
                "group_name": group.name,
                "group_email": group.email,
                "group_member": f"group:{str(group.email or '').strip().lower()}",
                "member_email": member_email,
                "member": _canonical_workspace_member_token(member_email, normalized_member_type),
                "member_type": normalized_member_type,
                "roles": roles,
                "transitive": "true" if transitive else "false",
                "source": source,
                "raw_json": membership,
            }
        )

    return rows, sorted(set(member_emails))
