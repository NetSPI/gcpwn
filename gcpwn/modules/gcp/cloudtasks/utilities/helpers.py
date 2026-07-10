from __future__ import annotations

import base64
from typing import Any, Iterable

from google.cloud import tasks_v2

from gcpwn.core.output_paths import resolve_download_path
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)
from gcpwn.core.utils.service_runtime import DownloadBudget


def _http_auth_details(http_request: dict[str, Any]) -> tuple[bool, str]:
    """Inspect a Cloud Tasks HTTP target's auth config; return (is_authed, detail).

    Detects OIDC tokens, OAuth tokens, or an explicit Authorization header and
    summarizes the impersonated service account / audience / scope. Relevant
    offensively: an unauthenticated HTTP target (returns False) is a
    request-forgery primitive callable by anyone who can enqueue tasks.
    """
    if not isinstance(http_request, dict):
        return False, "no"
    oidc_token = http_request.get("oidc_token")
    if isinstance(oidc_token, dict) and oidc_token:
        email = str(oidc_token.get("service_account_email") or "").strip()
        audience = str(oidc_token.get("audience") or "").strip()
        detail = "yes (OIDC token)"
        if email:
            detail += f", service_account_email={email}"
        if audience:
            detail += f", audience={audience}"
        return True, detail
    oauth_token = http_request.get("oauth_token")
    if isinstance(oauth_token, dict) and oauth_token:
        email = str(oauth_token.get("service_account_email") or "").strip()
        scope = str(oauth_token.get("scope") or "").strip()
        detail = "yes (OAuth token)"
        if email:
            detail += f", service_account_email={email}"
        if scope:
            detail += f", scope={scope}"
        return True, detail
    headers = http_request.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "authorization" and str(value or "").strip():
                return True, "yes (explicit Authorization header)"
    return False, "no"


def _decode_http_body(body_value: Any) -> tuple[str, str]:
    """Best-effort decode a task HTTP body; return (text, format_label).

    Tries strict base64 then UTF-8 (the wire format Cloud Tasks uses), falling
    back to the raw text. format_label is one of empty/plain/utf-8/base64 to tell
    the reader how the returned text was obtained.
    """
    text = str(body_value or "").strip()
    if not text:
        return "", "empty"
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception:
        return text, "plain"
    try:
        return decoded.decode("utf-8"), "utf-8"
    except Exception:
        return text, "base64"


def _http_request_sample_text(task_row: dict[str, Any]) -> str:
    """Render a task's HTTP target as a human-readable request dump for loot files.

    Reconstructs the parent queue name from the task path and lays out method,
    URL, auth status, sorted headers, and the decoded body so an operator can
    see (and replay) exactly what the task would fire. "" if no http_request.
    """
    http_request = (task_row or {}).get("http_request")
    if not isinstance(http_request, dict):
        return ""

    task_name = str(task_row.get("name") or "").strip()
    queue_name = ""
    queue_project = extract_path_segment(task_name, "projects")
    queue_location = extract_path_segment(task_name, "locations")
    queue_id = extract_path_segment(task_name, "queues")
    if queue_project and queue_location and queue_id:
        queue_name = f"projects/{queue_project}/locations/{queue_location}/queues/{queue_id}"

    method = str(http_request.get("http_method") or "POST").strip()
    url = str(http_request.get("url") or "").strip()
    headers = http_request.get("headers") if isinstance(http_request.get("headers"), dict) else {}
    auth_required, auth_detail = _http_auth_details(http_request)
    body_text, body_format = _decode_http_body(http_request.get("body"))

    lines = [
        f"task_name: {task_name}",
        f"queue_name: {queue_name}",
        f"http_method: {method}",
        f"url: {url}",
        f"auth_required: {'yes' if auth_required else 'no'}",
        f"auth_detail: {auth_detail}",
        "",
        "headers:",
    ]
    if headers:
        for key in sorted(headers):
            lines.append(f"{key}: {headers[key]}")
    else:
        lines.append("(none)")
    lines.extend(
        [
            "",
            f"body_encoding: {body_format}",
            "body:",
            body_text if body_text else "(empty)",
        ]
    )
    return "\n".join(lines) + "\n"


resolve_locations = region_resolver_for("cloudtasks", ("cloudtasks", "v2"))


class CloudTasksQueuesResource(GcpListResource):
    """List/get Cloud Tasks queues via the tasks_v2 GAPIC client (GcpListResource)."""

    SERVICE_LABEL = "Cloud Tasks"
    TABLE_NAME = "cloudtasks_queues"
    COLUMNS = ["location", "queue_id", "name", "state"]
    ACTION_RESOURCE_TYPE = "queues"
    LIST_PERMISSION = "cloudtasks.queues.list"
    GET_PERMISSION = "cloudtasks.queues.get"
    TEST_IAM_API_NAME = "cloudtasks.queues.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "cloudtasks.queues.",
        exclude_permissions=("cloudtasks.queues.create", "cloudtasks.queues.list"),
    )
    ID_FIELD = "queue_id"

    def _build_client(self, session):
        return tasks_v2.CloudTasksClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_queues(request=tasks_v2.ListQueuesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_queue(request=tasks_v2.GetQueueRequest(name=resource_id))


class CloudTasksTasksResource(GcpListResource):
    """List/get individual tasks under a queue, capturing their HTTP targets.

    Tasks are listed per parent queue (PARENT_FROM_PROJECT_LOCATION = False), and
    listing requires a permission on the queue, not the task (LIST_RESOURCE_TYPE =
    queues). Uses the FULL response view to capture bodies/headers for the
    request-dump loot in download_http_request_samples.
    """

    SERVICE_LABEL = "Cloud Tasks"
    TABLE_NAME = "cloudtasks_tasks"
    COLUMNS = [
        "location",
        "queue_id",
        "task_id",
        "name",
        "dispatch_type",
        "schedule_time",
        "create_time",
        "dispatch_deadline",
        "http_method",
        "url",
        "auth_required",
    ]
    ACTION_RESOURCE_TYPE = "tasks"
    LIST_PERMISSION = "cloudtasks.tasks.list"
    LIST_RESOURCE_TYPE = "queues"  # listing tasks is a permission on the parent queue
    GET_PERMISSION = "cloudtasks.tasks.get"
    ID_FIELD = "task_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent queue

    def _build_client(self, session):
        return tasks_v2.CloudTasksClient(credentials=session.credentials)

    def _list_items(self, parent, *, full_view=False):
        request = tasks_v2.ListTasksRequest(
            parent=parent,
            response_view=tasks_v2.Task.View.FULL if full_view else tasks_v2.Task.View.BASIC,
        )
        return self.client.list_tasks(request=request)

    def _get_item(self, resource_id, *, full_view=True):
        request = tasks_v2.GetTaskRequest(
            name=resource_id,
            response_view=tasks_v2.Task.View.FULL if full_view else tasks_v2.Task.View.BASIC,
        )
        return self.client.get_task(request=request)

    def _extra_save_fields(self, raw):
        http_request = raw.get("http_request") if isinstance(raw.get("http_request"), dict) else {}
        return {
            "queue_id": extract_path_segment(str(raw.get("name", "") or ""), "queues"),
            "dispatch_type": (
                "http"
                if isinstance(raw.get("http_request"), dict) and raw.get("http_request")
                else "app_engine"
                if isinstance(raw.get("app_engine_http_request"), dict) and raw.get("app_engine_http_request")
                else ""
            ),
            "http_method": http_request.get("http_method") or "",
            "url": http_request.get("url") or "",
            "auth_required": "yes" if _http_auth_details(raw.get("http_request") or {})[0] else "no",
        }

    def download_http_request_samples(
        self,
        *,
        task_rows: Iterable[dict[str, Any]],
        project_id: str,
        output: str | None = None,
    ) -> list[str]:
        """Dump each HTTP task's request to a loot file; return the paths written.

        Side effect: writes one ``<loc>_<queue>_<task>_http_request.txt`` per task
        that has an http_request, creating parent dirs. Skips non-dict rows and
        tasks without an HTTP target (e.g. App Engine tasks).
        """
        written_paths: list[str] = []
        budget = DownloadBudget(self.session, label="cloud tasks requests")
        for row in task_rows or []:
            if budget.exceeded():  # per-type --download-timeout cap: stop and move on
                break
            if not isinstance(row, dict):
                continue
            http_request = row.get("http_request")
            if not isinstance(http_request, dict) or not http_request:
                continue
            name = str(row.get("name") or "").strip()
            task_id = extract_path_segment(name, "tasks") or "task"
            queue_id = extract_path_segment(name, "queues") or "queue"
            location = extract_path_segment(name, "locations") or "location"
            filename = f"{location}_{queue_id}_{task_id}_http_request.txt"
            destination = resolve_download_path(
                self.session,
                service_name="cloudtasks",
                project_id=project_id,
                filename=filename,
                output=output,
            )
            destination.write_text(_http_request_sample_text(row), encoding="utf-8")
            written_paths.append(str(destination))
        return written_paths
