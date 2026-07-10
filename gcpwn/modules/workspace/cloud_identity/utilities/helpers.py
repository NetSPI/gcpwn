from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable

from gcpwn.core.utils.persistence import save_to_table
from gcpwn.modules.workspace.common import (
    _handle_cloudidentity_error,
    _http_error_details,
    _http_error_status,
    build_cloud_identity_service,
    build_directory_service,
)

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
     - `organizations.get` → read `directoryCustomerId` (aka Directory Customer ID, looks like `C0xxxxxxx`)

We store Workspace data in `workspace_*` tables (e.g., `workspace_groups`, `workspace_users`, `workspace_group_memberships`).
"""


class CloudIdentityGroupsResource:
    TABLE_NAME = "workspace_groups"
    COLUMNS = ["email", "display_name", "name", "description", "create_time", "update_time"]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.service = build_cloud_identity_service(session.credentials, subject=subject)
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

    def save(self, groups: Iterable[WorkspaceGroup]) -> None:
        save_to_table(self.session, "workspace_groups", [workspace_group_to_row(group) for group in groups or []])


class CloudIdentityGroupMembershipsResource:
    TABLE_NAME = "workspace_group_memberships"
    COLUMNS = ["group_email", "group_member", "member_email", "member", "member_type", "roles", "transitive", "source"]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.service = build_cloud_identity_service(session.credentials, subject=subject)
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


class WorkspaceUsersResource:
    TABLE_NAME = "workspace_users"
    COLUMNS = ["email", "display_name", "user_id"]

    def __init__(self, session, subject: str | None = None) -> None:
        self.session = session
        self.subject = subject
        self.last_call_ok: bool | None = None

    def list(self, *args, **kwargs):
        """
        List users via the Admin SDK Directory API.

        Requires Workspace admin privileges and Directory scopes. If the caller does not have
        Admin SDK access, this returns an empty list (and sets `last_call_ok=False`).
        """
        try:
            self.last_call_ok = True
            service = build_directory_service(self.session.credentials, subject=self.subject)
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


def _paged_execute(collection, request, collection_key: str, *, rebuild=None):
    """Page through a Cloud Identity request and collect ``collection_key`` items.

    Standard list methods paginate via ``collection.list_next(...)`` (the method
    lives on the COLLECTION, e.g. ``service.groups()``, not on the HttpRequest).
    The custom ``groups.search`` / ``searchTransitiveMemberships`` methods have no
    ``list_next``, so the caller passes ``rebuild(page_token) -> request`` and we
    page on ``nextPageToken``.
    """
    items: list[dict[str, Any]] = []
    while request is not None:
        response = request.execute() or {}
        items.extend(dict(row) for row in response.get(collection_key, []) if isinstance(row, dict))
        if rebuild is not None:
            token = response.get("nextPageToken")
            request = rebuild(token) if token else None
        else:
            request = collection.list_next(previous_request=request, previous_response=response)
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
    collection = service.groups()
    try:
        request = collection.list(parent=parent, view=view, pageSize=page_size, filter=filter_value)
    except TypeError:
        request = collection.list(parent=parent, pageSize=page_size)
        if view:
            request.uri += f"&view={urllib.parse.quote(view)}"
        if filter_value:
            request.uri += f"&filter={urllib.parse.quote(str(filter_value))}"
    return _paged_execute(collection, request, "groups")


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
    collection = service.groups()

    def _build(page_token: str | None = None):
        kwargs: dict[str, Any] = {"query": query, "pageSize": page_size}
        if page_token:
            kwargs["pageToken"] = page_token
        return collection.search(**kwargs)

    return _paged_execute(collection, _build(), "groups", rebuild=_build)


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
        # searchTransitiveMemberships returns preferredMemberKey as a LIST of EntityKey.
        if isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict) and entry.get("id"):
                    return str(entry["id"])
    # Transitive results also carry the member resource, sometimes a bare email.
    member = membership.get("member")
    if isinstance(member, str) and "@" in member:
        return member.strip()
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
    collection = service.groups().memberships()
    try:
        request = collection.list(parent=group_name, view=view, pageSize=page_size)
    except TypeError:
        request = collection.list(parent=group_name, pageSize=page_size)
        if view:
            request.uri += f"&view={urllib.parse.quote(view)}"
    return _paged_execute(collection, request, "memberships")


def search_transitive_group_memberships(service, *, group_name: str, view: str = "FULL", page_size: int = 1000) -> list[dict[str, Any]]:
    """
    Cloud Identity API: `groups.memberships.searchTransitiveMemberships`.

    Returns nested memberships (members inherited via group-in-group relationships).
    """
    _ = view  # searchTransitiveMemberships does not support a `view` param
    collection = service.groups().memberships()

    def _build(page_token: str | None = None):
        kwargs: dict[str, Any] = {"parent": group_name, "pageSize": page_size}
        if page_token:
            kwargs["pageToken"] = page_token
        return collection.searchTransitiveMemberships(**kwargs)

    return _paged_execute(collection, _build(), "memberships", rebuild=_build)


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
