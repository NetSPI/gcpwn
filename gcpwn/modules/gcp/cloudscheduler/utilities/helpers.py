from __future__ import annotations

from typing import Any

from google.cloud import scheduler_v1

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)


resolve_locations = region_resolver_for("cloudscheduler", ("cloudscheduler", "v1"))


def _target_details(raw: dict[str, Any]) -> tuple[str, str, str]:
    """Return (target_type, target_uri, target_sa_email) for a scheduler job.

    The service-account email is the offensively interesting field: an HTTP target
    carrying an OIDC/OAuth token fires *as that SA*, so a principal who can create
    or update scheduler jobs (``cloudscheduler.jobs.create``) gains an oracle to
    act as it -- the same primitive OpenGraph models as
    ``CREATE_CLOUDSCHEDULER_JOB_AS_SA``. Enumerating existing jobs surfaces which
    SAs are already wired up as targets.
    """
    http_target = raw.get("http_target") if isinstance(raw.get("http_target"), dict) else None
    if http_target:
        sa_email = ""
        for token_key in ("oidc_token", "oauth_token"):
            token = http_target.get(token_key)
            if isinstance(token, dict) and token.get("service_account_email"):
                sa_email = str(token.get("service_account_email") or "").strip()
                break
        return "http", str(http_target.get("uri") or "").strip(), sa_email
    pubsub_target = raw.get("pubsub_target") if isinstance(raw.get("pubsub_target"), dict) else None
    if pubsub_target:
        return "pubsub", str(pubsub_target.get("topic_name") or "").strip(), ""
    appengine_target = raw.get("app_engine_http_target") if isinstance(raw.get("app_engine_http_target"), dict) else None
    if appengine_target:
        return "app_engine", str(appengine_target.get("relative_uri") or "").strip(), ""
    return "", "", ""


class CloudSchedulerJobsResource(GcpListResource):
    """List/get Cloud Scheduler jobs via the scheduler_v1 GAPIC client.

    Cloud Scheduler exposes IAM only at the location level (no per-job
    testIamPermissions on the GAPIC client), so the component runs with
    ``supports_iam=False``.
    """

    SERVICE_LABEL = "Cloud Scheduler"
    TABLE_NAME = "cloudscheduler_jobs"
    COLUMNS = ["location", "job_id", "name", "state", "schedule", "time_zone", "target_type", "target_uri", "target_sa_email"]
    ACTION_RESOURCE_TYPE = "jobs"
    LIST_PERMISSION = "cloudscheduler.jobs.list"
    GET_PERMISSION = "cloudscheduler.jobs.get"
    ID_FIELD = "job_id"

    def _build_client(self, session):
        return scheduler_v1.CloudSchedulerClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_jobs(request=scheduler_v1.ListJobsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_job(request=scheduler_v1.GetJobRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        target_type, target_uri, target_sa_email = _target_details(raw)
        return {
            "job_id": extract_path_segment(str(raw.get("name", "") or ""), "jobs"),
            "target_type": target_type,
            "target_uri": target_uri,
            "target_sa_email": target_sa_email,
        }
