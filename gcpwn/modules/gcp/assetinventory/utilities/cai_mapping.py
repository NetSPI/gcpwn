"""Map Cloud Asset Inventory (CAI) records to the gcpwn tables OpenGraph consumes.

Shared by BOTH the live `enum_asset_inventory` module (records from the CAI
search/export API) and the `process_og --cai-file` plugin (records parsed from a
`gcloud asset export` file). The OpenGraph pipeline reads ALL input through
`session.get_data(<table>)`, so once CAI assets are turned into the same row
shapes, the unchanged (golden-guarded) pipeline builds a graph from them.

Input: an iterable of CAI records. Each is a dict from a CAI **export** `Asset`
(keys: name, assetType, resource.data, iamPolicy, ancestors) -- proto JSON uses
camelCase, gcloud sometimes snake_case, so every accessor tries both spellings.

Output: ``{table_name: [row, ...]}`` for the tables in ``CAI_TABLES``.

GOTCHA handled here: CAI resource names carry the project NUMBER
(`//.../projects/123456`) but every gcpwn table uses the project STRING ID
(`projects/proj-a`). A first pass builds a number->projectId map from
`cloudresourcemanager.googleapis.com/Project` assets; a second pass rewrites all
names/ancestors through it.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from gcpwn.core.utils.module_helpers import extract_path_segment, extract_path_tail

# Tables this mapper can populate (everything the OpenGraph stages read from CAI).
CAI_TABLES = (
    "abstract_tree_hierarchy",
    "iam_allow_policies",
    "iam_service_accounts",
    "iam_sa_keys",
    "iam_roles",
    "cloudcompute_instances",
    "workload_identity_pools",
    "workload_identity_providers",
)

# asset_type -> the resource_type token gcpwn records on iam_allow_policies rows.
_IAM_RESOURCE_TYPE = {
    "cloudresourcemanager.googleapis.com/Organization": "organization",
    "cloudresourcemanager.googleapis.com/Folder": "folder",
    "cloudresourcemanager.googleapis.com/Project": "project",
    "iam.googleapis.com/ServiceAccount": "service-account",
    "compute.googleapis.com/Instance": "compute-instance",
    "storage.googleapis.com/Bucket": "bucket",
}


def _first(record: dict, *keys: str, default: Any = None) -> Any:
    """Return the first present key (handles camelCase vs snake_case CAI exports)."""
    for key in keys:
        if isinstance(record, dict) and key in record and record[key] not in (None, ""):
            return record[key]
    return default


def _strip_host(name: str) -> str:
    """`//compute.googleapis.com/projects/1/zones/z/instances/i` -> `projects/1/zones/z/instances/i`."""
    text = str(name or "").strip()
    if text.startswith("//"):
        # drop leading '//<host>/'
        rest = text[2:]
        slash = rest.find("/")
        return rest[slash + 1:] if slash >= 0 else rest
    return text


def _rewrite_project_number(path: str, num_to_id: dict[str, str]) -> str:
    """Rewrite a `projects/<number>/...` segment to `projects/<projectId>/...`."""
    text = str(path or "").strip()
    if not text:
        return text
    parts = text.split("/")
    for i in range(len(parts) - 1):
        if parts[i] == "projects" and parts[i + 1] in num_to_id:
            parts[i + 1] = num_to_id[parts[i + 1]]
    return "/".join(parts)


def _resource_data(record: dict) -> dict:
    resource = _first(record, "resource", default={}) or {}
    data = _first(resource, "data", default={}) if isinstance(resource, dict) else {}
    return data if isinstance(data, dict) else {}


def _ancestor_parent(record: dict, self_name: str, num_to_id: dict[str, str]) -> str:
    """Return the immediate parent scope name (`folders/..`/`organizations/..`/`projects/..`).

    Prefers resource.data.parent, else the second entry of `ancestors` (the first
    is the resource itself). Rewrites project numbers to ids.
    """
    data = _resource_data(record)
    parent = str(data.get("parent") or "").strip()
    if parent:
        # resource.data.parent may be "folders/456" or "organizations/789" or "123" (legacy)
        if parent.isdigit():
            parent = f"projects/{parent}"  # unusual, but normalize
        return _rewrite_project_number(parent, num_to_id)
    ancestors = _first(record, "ancestors", default=[]) or []
    if isinstance(ancestors, list) and len(ancestors) >= 2:
        return _rewrite_project_number(str(ancestors[1]).strip(), num_to_id)
    return ""


def _build_number_to_id(records: list[dict]) -> dict[str, str]:
    num_to_id: dict[str, str] = {}
    for record in records:
        if _first(record, "assetType", "asset_type") != "cloudresourcemanager.googleapis.com/Project":
            continue
        data = _resource_data(record)
        project_id = str(data.get("projectId") or data.get("project_id") or "").strip()
        path = _strip_host(_first(record, "name", default=""))  # projects/<number>
        number = extract_path_segment(path, "projects")
        if project_id and number:
            num_to_id[number] = project_id
    return num_to_id


def _policy_json(record: dict) -> str | None:
    iam_policy = _first(record, "iamPolicy", "iam_policy")
    if not isinstance(iam_policy, dict):
        return None
    bindings = iam_policy.get("bindings") or []
    norm = [
        {"role": str(b.get("role") or ""), "members": list(b.get("members") or [])}
        for b in bindings
        if isinstance(b, dict) and b.get("role")
    ]
    if not norm:
        return None
    return json.dumps({"bindings": norm})


def cai_records_to_tables(records: Iterable[dict]) -> dict[str, list[dict]]:
    """Map CAI Asset records to ``{table: [rows]}`` for the OpenGraph pipeline."""
    records = [r for r in records if isinstance(r, dict)]
    num_to_id = _build_number_to_id(records)
    out: dict[str, list[dict]] = {t: [] for t in CAI_TABLES}

    for record in records:
        asset_type = str(_first(record, "assetType", "asset_type", default="")).strip()
        raw_name = _first(record, "name", default="")
        name = _rewrite_project_number(_strip_host(raw_name), num_to_id)
        data = _resource_data(record)
        # the project this asset lives in (for project_id columns)
        project_id = ""
        if name.startswith("projects/") and len(name.split("/")) >= 2:
            project_id = name.split("/")[1]

        # --- hierarchy nodes ---
        if asset_type == "cloudresourcemanager.googleapis.com/Organization":
            out["abstract_tree_hierarchy"].append({
                "name": name, "type": "organization",
                "display_name": str(data.get("displayName") or data.get("display_name") or ""),
                "project_id": "", "parent": "",
            })
        elif asset_type == "cloudresourcemanager.googleapis.com/Folder":
            out["abstract_tree_hierarchy"].append({
                "name": name, "type": "folder",
                "display_name": str(data.get("displayName") or data.get("display_name") or ""),
                "project_id": "", "parent": _ancestor_parent(record, name, num_to_id),
            })
        elif asset_type == "cloudresourcemanager.googleapis.com/Project":
            out["abstract_tree_hierarchy"].append({
                "name": name, "type": "project",
                "display_name": str(data.get("name") or project_id),
                "project_id": project_id, "parent": _ancestor_parent(record, name, num_to_id),
            })

        # --- IAM policy on this asset ---
        policy = _policy_json(record)
        if policy is not None:
            resource_type = _IAM_RESOURCE_TYPE.get(asset_type, (extract_path_tail(asset_type)).lower())
            # SA / resource policies are project-scoped; org/folder carry project_id=""
            row_project = "" if resource_type in ("organization", "folder") else project_id
            resource_name = name
            if resource_type == "service-account":
                # gcpwn keys SA policies by the SA email path tail
                resource_name = str(data.get("email") or name)
            out["iam_allow_policies"].append({
                "project_id": row_project, "resource_type": resource_type,
                "resource_name": resource_name, "policy": policy,
            })

        # --- typed resources OpenGraph expands ---
        if asset_type == "iam.googleapis.com/ServiceAccount":
            out["iam_service_accounts"].append({
                "name": name, "email": str(data.get("email") or ""), "project_id": project_id,
            })
        elif asset_type == "iam.googleapis.com/ServiceAccountKey":
            out["iam_sa_keys"].append({"name": name})
        elif asset_type == "iam.googleapis.com/Role":
            perms = data.get("includedPermissions") or data.get("included_permissions") or []
            out["iam_roles"].append({
                "name": name, "included_permissions": json.dumps(list(perms)),
            })
        elif asset_type == "compute.googleapis.com/Instance":
            sa_emails = [
                str(sa.get("email") or "").strip()
                for sa in (data.get("serviceAccounts") or data.get("service_accounts") or [])
                if isinstance(sa, dict) and sa.get("email")
            ]
            out["cloudcompute_instances"].append({
                "name": name, "project_id": project_id,
                "service_account_emails": json.dumps(sa_emails),
            })
        elif asset_type == "iam.googleapis.com/WorkloadIdentityPool":
            pool_id = extract_path_tail(name)
            out["workload_identity_pools"].append({
                "name": name, "pool_id": pool_id, "project_id": project_id,
            })
        elif asset_type == "iam.googleapis.com/WorkloadIdentityPoolProvider":
            provider_id = extract_path_tail(name)
            pool_name = name.rsplit("/providers/", 1)[0] if "/providers/" in name else ""
            out["workload_identity_providers"].append({
                "name": name, "pool_name": pool_name, "provider_id": provider_id, "project_id": project_id,
            })

    return out
