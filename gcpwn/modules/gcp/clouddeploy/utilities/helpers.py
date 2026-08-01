from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any

from google.cloud import deploy_v1

from gcpwn.core.console import UtilityTools
from gcpwn.core.output_paths import compact_filename_component
from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    region_resolver_for,
)
from gcpwn.core.utils.service_runtime import DownloadBudget


resolve_locations = region_resolver_for("clouddeploy", ("clouddeploy", "v1"))


# The five oneof members of Target.deployment_target, in declaration order. Whichever
# one is set names the runtime the pipeline deploys into.
_DEPLOY_TARGET_TYPES = ("gke", "run", "anthos_cluster", "multi_target", "custom_target")


def _deploy_target_type(raw: dict[str, Any]) -> str:
    """Return the destination oneof that is set on a Target ("gke"/"run"/...)."""
    for target_type in _DEPLOY_TARGET_TYPES:
        if raw.get(target_type) not in (None, "", [], {}):
            return target_type
    return ""


def _execution_service_account(raw: dict[str, Any]) -> str:
    """Return the first execution config's service_account -- the deploy-as identity.

    A Cloud Deploy Target runs each rollout *as* the service account in its
    ExecutionConfig, so a principal who can create or modify targets/pipelines
    (clouddeploy.targets.update, etc.) gains an oracle to act as that SA. The
    enumerated value surfaces which SAs are already wired up as deploy identities.
    """
    configs = raw.get("execution_configs")
    if isinstance(configs, list):
        for config in configs:
            if isinstance(config, dict):
                sa = str(config.get("service_account") or "").strip()
                if sa:
                    return sa
    return ""


class CloudDeployDeliveryPipelinesResource(GcpListResource):
    """List/get Cloud Deploy delivery pipelines via the deploy_v1 GAPIC client."""

    SERVICE_LABEL = "Cloud Deploy"
    TABLE_NAME = "clouddeploy_delivery_pipelines"
    COLUMNS = ["location", "pipeline_id", "name", "uid", "suspended"]
    ACTION_RESOURCE_TYPE = "deliveryPipelines"
    LIST_PERMISSION = "clouddeploy.deliveryPipelines.list"
    GET_PERMISSION = "clouddeploy.deliveryPipelines.get"
    TEST_IAM_API_NAME = "clouddeploy.deliveryPipelines.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "clouddeploy.deliveryPipelines.",
        exclude_permissions=("clouddeploy.deliveryPipelines.create", "clouddeploy.deliveryPipelines.list"),
    )
    ID_FIELD = "pipeline_id"

    def _build_client(self, session):
        return deploy_v1.CloudDeployClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_delivery_pipelines(request=deploy_v1.ListDeliveryPipelinesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_delivery_pipeline(request=deploy_v1.GetDeliveryPipelineRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {"pipeline_id": extract_path_tail(str(raw.get("name", "") or ""))}

    def delete(self, pipeline_name: str, *, force: bool = True, allow_missing: bool = True) -> bool:
        """Delete a delivery pipeline, cascading to all child releases/rollouts when force=True."""
        try:
            op = self.client.delete_delivery_pipeline(
                request=deploy_v1.DeleteDeliveryPipelineRequest(
                    name=pipeline_name, force=force, allow_missing=allow_missing
                )
            )
            op.result(timeout=120)
            print(f"    [cleanup] pipeline deleted: {pipeline_name.split('/')[-1]}")
            return True
        except Exception as exc:
            print(f"{UtilityTools.YELLOW}    [cleanup] pipeline: {exc}{UtilityTools.RESET}")
            return False


class CloudDeployTargetsResource(GcpListResource):
    """List/get Cloud Deploy targets via the deploy_v1 GAPIC client.

    The execution config's service_account is the offensively interesting field --
    rollouts to this target run as that SA (see _execution_service_account).
    """

    SERVICE_LABEL = "Cloud Deploy"
    TABLE_NAME = "clouddeploy_targets"
    COLUMNS = ["location", "target_id", "name", "deploy_target_type", "service_account", "require_approval"]
    ACTION_RESOURCE_TYPE = "targets"
    LIST_PERMISSION = "clouddeploy.targets.list"
    GET_PERMISSION = "clouddeploy.targets.get"
    TEST_IAM_API_NAME = "clouddeploy.targets.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "clouddeploy.targets.",
        exclude_permissions=("clouddeploy.targets.create", "clouddeploy.targets.list"),
    )
    ID_FIELD = "target_id"

    def _build_client(self, session):
        return deploy_v1.CloudDeployClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_targets(request=deploy_v1.ListTargetsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_target(request=deploy_v1.GetTargetRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "target_id": extract_path_tail(str(raw.get("name", "") or "")),
            "deploy_target_type": _deploy_target_type(raw),
            "service_account": _execution_service_account(raw),
        }

    def delete(self, target_name: str, *, allow_missing: bool = True) -> bool:
        """Delete a Cloud Deploy target."""
        try:
            op = self.client.delete_target(
                request=deploy_v1.DeleteTargetRequest(name=target_name, allow_missing=allow_missing)
            )
            op.result(timeout=60)
            print(f"    [cleanup] target deleted: {target_name.split('/')[-1]}")
            return True
        except Exception as exc:
            print(f"{UtilityTools.YELLOW}    [cleanup] target: {exc}{UtilityTools.RESET}")
            return False


class CloudDeployRolloutsResource(GcpListResource):
    """Get/cancel Cloud Deploy rollouts nested under releases."""

    SERVICE_LABEL = "Cloud Deploy"
    TABLE_NAME = "clouddeploy_rollouts"
    COLUMNS = ["location", "rollout_id", "name", "state", "target_id", "deploy_failure_cause"]
    ACTION_RESOURCE_TYPE = "rollouts"
    LIST_PERMISSION = "clouddeploy.rollouts.list"
    GET_PERMISSION = "clouddeploy.rollouts.get"
    PARENT_FROM_PROJECT_LOCATION = False  # nested under releases
    ID_FIELD = "rollout_id"

    def _build_client(self, session):
        return deploy_v1.CloudDeployClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_rollouts(request=deploy_v1.ListRolloutsRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_rollout(request=deploy_v1.GetRolloutRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "rollout_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state") or ""),
            "target_id": str(raw.get("target_id") or ""),
            "deploy_failure_cause": str(raw.get("deploy_failure_cause") or ""),
        }

    def get_rollout(self, rollout_name: str) -> deploy_v1.Rollout | None:
        """Fetch a rollout by full resource name; returns None on error."""
        try:
            return self.client.get_rollout(request=deploy_v1.GetRolloutRequest(name=rollout_name))
        except Exception as exc:
            print(f"  [rollout] get error: {exc}")
            return None

    def cancel(self, rollout_name: str) -> bool:
        """Request cancellation of a rollout; returns True if the request was accepted."""
        try:
            self.client.cancel_rollout(request=deploy_v1.CancelRolloutRequest(name=rollout_name))
            print(f"    [cleanup] rollout cancel requested: {rollout_name.split('/')[-1]}")
            return True
        except Exception as exc:
            print(f"{UtilityTools.YELLOW}    [cleanup] rollout: {exc}{UtilityTools.RESET}")
            return False


class CloudDeployReleasesResource(GcpListResource):
    """List Cloud Deploy releases nested under delivery pipelines.

    Releases reference user-uploaded Skaffold config archives (skaffold_config_uri → gs://).
    --download extracts those archives and saves the contained YAML files.
    """

    SERVICE_LABEL = "Cloud Deploy"
    TABLE_NAME = "clouddeploy_releases"
    COLUMNS = ["location", "release_id", "name", "skaffold_config_uri", "skaffold_config_path"]
    ACTION_RESOURCE_TYPE = "releases"
    LIST_PERMISSION = "clouddeploy.releases.list"
    GET_PERMISSION = "clouddeploy.releases.get"
    PARENT_FROM_PROJECT_LOCATION = False  # nested under pipelines, not project/location directly
    ID_FIELD = "release_id"

    def _build_client(self, session):
        return deploy_v1.CloudDeployClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_releases(request=deploy_v1.ListReleasesRequest(parent=parent))

    def _get_item(self, resource_id, **_):
        return self.client.get_release(request=deploy_v1.GetReleaseRequest(name=resource_id))

    def _extra_save_fields(self, raw):
        return {
            "release_id": extract_path_tail(str(raw.get("name", "") or "")),
            "skaffold_config_uri": raw.get("skaffold_config_uri") or "",
            "skaffold_config_path": raw.get("skaffold_config_path") or "",
        }

    def _skaffold_download_budget(self) -> DownloadBudget:
        budget = getattr(self, "_dl_budget", None)
        if budget is None:
            budget = DownloadBudget(self.session, label="cloud deploy skaffold configs")
            self._dl_budget = budget
        return budget

    def download_skaffold_configs(self, *, pipeline_name: str, project_id: str) -> list[Path]:
        """List releases for pipeline_name, download + extract their Skaffold archives from GCS.

        Returns paths of files written. Each gs:// archive is extracted; individual YAML/text
        files inside are saved under clouddeploy/skaffold/<release_id>/.
        """
        from gcpwn.modules.gcp.cloudstorage.utilities.helpers import CloudStorageBlobsResource  # avoid circular

        paths: list[Path] = []
        try:
            releases = list(self.client.list_releases(
                request=deploy_v1.ListReleasesRequest(parent=pipeline_name)
            ))
        except Exception as exc:
            print(f"  [!] Cannot list releases for {pipeline_name}: {exc}")
            return paths

        if not releases:
            return paths

        blobs = CloudStorageBlobsResource(self.session)
        storage_client = blobs.build_client(project_id)
        pipeline_id = extract_path_tail(pipeline_name)

        for release in releases:
            if self._skaffold_download_budget().exceeded():
                break
            uri = str(getattr(release, "skaffold_config_uri", "") or "").strip()
            if not uri.startswith("gs://"):
                continue
            # Parse gs://bucket/path
            without_scheme = uri[len("gs://"):]
            bucket_name, _, gcs_object_path = without_scheme.partition("/")
            if not bucket_name or not gcs_object_path:
                continue

            release_id = extract_path_tail(str(getattr(release, "name", "") or ""))
            raw_bytes = CloudStorageBlobsResource.download_bytes_with_client(
                storage_client, bucket_name, gcs_object_path
            )
            if raw_bytes is None:
                print(f"  [!] Could not download {uri} (storage.objects.get required)")
                continue

            # Attempt to extract as tar.gz; fallback to saving the raw bytes
            extracted = _extract_archive(raw_bytes)
            for filename, content_bytes in extracted.items():
                save_filename = compact_filename_component(f"{pipeline_id}_{release_id}_{filename}")
                dest = self.session.get_download_save_path(
                    service_name="clouddeploy",
                    project_id=project_id,
                    subdirs=["skaffold"],
                    filename=save_filename,
                )
                dest.write_bytes(content_bytes)
                paths.append(dest)

        return paths


def _extract_archive(data: bytes) -> dict[str, bytes]:
    """Extract a .tar.gz archive into {filename: bytes}. Returns raw bytes under 'archive' on failure."""
    try:
        buf = io.BytesIO(data)
        result: dict[str, bytes] = {}
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        result[member.name.lstrip("./")] = f.read()
        return result
    except Exception:
        return {"archive.bin": data}
