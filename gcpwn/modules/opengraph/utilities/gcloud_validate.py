#!/usr/bin/env python3
"""
Validate OG graph edges against live GCP IAM policies via gcloud.

Edge source-node prefix taxonomy (from graph inspection):
  iambinding:       PE single-perm edges + ROLE_OWNER/EDITOR
  CAP:              combo final-hop edges (CREATE_*_AS_SA etc.)
  combo_iambinding: combo intermediate-hop edges (SWAP/IAP/RESET/START) + combo→CAP structural edges
  service_account_key: ServiceAccountKeyFor
  implied-iambinding:  INFERRED_* edges (skip — needs complex implied-role reasoning)
  principalSet/user/group/serviceAccount: HAS_IAM_BINDING (src = principal, dst = iambinding:)
  resource:         ExistsInProject, RunsAs, SWAP_COMPUTE_INSTANCE_SA
"""

import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SAMPLE_PER_KIND = 4

_policy_cache: dict = {}
_role_perm_cache: dict = {}
_sa_keys_cache: dict = {}

REQUIRED_PERMS = {
    "CAN_IMPERSONATE_SA":               ["iam.serviceAccounts.implicitDelegation"],
    "CAN_CREATE_SA_ACCESS_TOKEN":       ["iam.serviceAccounts.getAccessToken"],
    "CAN_CREATE_SA_OIDC_TOKEN":         ["iam.serviceAccounts.generateOpenIdToken"],
    "CAN_SIGN_JWT_AS_SA":               ["iam.serviceAccounts.signJwt"],
    "CAN_SIGN_BLOB_AS_SA":              ["iam.serviceAccounts.signBlob"],
    "CAN_CREATE_SA_KEY":                ["iam.serviceAccounts.createKey", "iam.serviceAccountKeys.create"],
    "CAN_DELETE_SA_KEY":                ["iam.serviceAccounts.deleteKey"],
    "CAN_MODIFY_PROJECT_IAM":           ["resourcemanager.projects.setIamPolicy"],
    "CAN_MODIFY_FOLDER_IAM":            ["resourcemanager.folders.setIamPolicy"],
    "CAN_MODIFY_ORG_IAM":               ["resourcemanager.organizations.setIamPolicy"],
    "CAN_MODIFY_SA_IAM":                ["iam.serviceAccounts.setIamPolicy"],
    "CAN_MODIFY_COMPUTE_INSTANCE_IAM":  ["compute.instances.setIamPolicy"],
    "UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS": ["iam.roles.update"],
    "CAN_CREATE_CLOUDBUILD_DEFAULT_IDENTITY": ["cloudbuild.builds.create"],
    "CAN_READ_SECRET_DATA":             ["secretmanager.versions.access"],
    "CREATE_DATAPROC_CLUSTER_AS_SA":    ["dataproc.clusters.create"],
}

# Scope types that cannot be validated via simple gcloud IAM policy calls
_UNSUPPORTED_SCOPE_TYPES = {"secrets", "kmscryptokey", "kmskeyring", "storage", "bqtable", "bqdataset"}


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"


def get_policy(scope_type: str, scope_name: str) -> dict:
    key = f"{scope_type}:{scope_name}"
    if key in _policy_cache:
        return _policy_cache[key]
    if scope_type in _UNSUPPORTED_SCOPE_TYPES:
        _policy_cache[key] = {}
        return {}
    if scope_type == "project":
        rc, out, _ = run(["gcloud", "projects", "get-iam-policy", scope_name, "--format=json"])
    elif scope_type == "folder":
        rc, out, _ = run(["gcloud", "resource-manager", "folders", "get-iam-policy",
                           scope_name.lstrip("folders/"), "--format=json"])
    elif scope_type in ("org", "organization"):
        rc, out, _ = run(["gcloud", "organizations", "get-iam-policy",
                           scope_name.lstrip("organizations/"), "--format=json"])
    elif scope_type == "service-account":
        rc, out, _ = run(["gcloud", "iam", "service-accounts", "get-iam-policy",
                           scope_name, "--format=json"])
    elif scope_type == "secrets":
        rc, out, _ = run(["gcloud", "secrets", "get-iam-policy", scope_name, "--format=json"])
    else:
        _policy_cache[key] = {}
        return {}
    if rc != 0:
        _policy_cache[key] = {}
        return {}
    try:
        pol = json.loads(out)
        _policy_cache[key] = pol
        return pol
    except Exception:
        _policy_cache[key] = {}
        return {}


def get_role_permissions(role: str) -> list:
    if role in _role_perm_cache:
        return _role_perm_cache[role]
    parts = role.split("/")
    if len(parts) == 4 and parts[0] == "projects":
        rc, out, _ = run(["gcloud", "iam", "roles", "describe", parts[3],
                           "--project", parts[1], "--format=json"])
    elif len(parts) == 4 and parts[0] == "organizations":
        rc, out, _ = run(["gcloud", "iam", "roles", "describe", parts[3],
                           "--organization", parts[1], "--format=json"])
    else:
        rc, out, _ = run(["gcloud", "iam", "roles", "describe", role, "--format=json"])
    if rc != 0:
        _role_perm_cache[role] = []
        return []
    try:
        perms = json.loads(out).get("includedPermissions") or []
        _role_perm_cache[role] = perms
        return perms
    except Exception:
        _role_perm_cache[role] = []
        return []


def get_sa_keys(sa_email: str) -> list:
    if sa_email in _sa_keys_cache:
        return _sa_keys_cache[sa_email]
    rc, out, _ = run(["gcloud", "iam", "service-accounts", "keys", "list",
                       "--iam-account", sa_email, "--format=json"])
    if rc != 0:
        _sa_keys_cache[sa_email] = []
        return []
    try:
        keys = [k.get("name", "").split("/")[-1] for k in json.loads(out)]
        _sa_keys_cache[sa_email] = keys
        return keys
    except Exception:
        _sa_keys_cache[sa_email] = []
        return []


# iambinding:ROLE@SCOPE_TYPE:SCOPE_NAME[#cond:hash][#src:SRC_TYPE:SRC_NAME]
_BCID_RE = re.compile(r"^iambinding:([^@]+)@([^:]+):(.+?)(?:#(?:cond|src):.+)?$")
_SRC_RE = re.compile(r"#src:([^:]+):(.+)$")


def parse_binding_node(node_id: str):
    """→ (role, scope_type, scope_name, src_type, src_name) or None.
    src_type/src_name are the ORIGIN scope for inherited bindings (may be None)."""
    m = _BCID_RE.match(node_id or "")
    if not m:
        return None
    role, scope_type, scope_name_raw = m.group(1), m.group(2), m.group(3)
    # Strip any trailing #cond/#src from scope_name
    clean = re.sub(r"#(?:cond|src):.+$", "", scope_name_raw)
    # Check for src suffix on original string
    src_m = _SRC_RE.search(node_id)
    src_type = src_m.group(1) if src_m else None
    src_name = src_m.group(2) if src_m else None
    return role, scope_type, clean, src_type, src_name


def principal_in_policy(policy: dict, principal: str, role: str) -> bool:
    for b in (policy.get("bindings") or []):
        if b.get("role") == role and principal in (b.get("members") or []):
            return True
    return False


def principal_in_any_role(policy: dict, principal: str) -> str:
    """Return the first role the principal has, or ''."""
    for b in (policy.get("bindings") or []):
        if principal in (b.get("members") or []):
            return b.get("role", "")
    return ""


def role_has_any_perm(role: str, perms: list) -> bool:
    rp = get_role_permissions(role)
    return any(p in rp for p in perms)


def scope_id_to_type_name(scope_id: str):
    """'projects/P' → ('project','P'), 'projects/P/serviceAccounts/E' → ('service-account','E')"""
    if not scope_id:
        return None
    s = scope_id.strip()
    if s.startswith("organizations/"):
        return "org", s.split("/")[-1]
    if s.startswith("folders/"):
        return "folder", s.split("/")[-1]
    if "/serviceAccounts/" in s:
        return "service-account", s.split("/serviceAccounts/")[-1]
    if s.startswith("projects/"):
        return "project", s.split("/")[1]
    if "@" in s and "." in s and "/" not in s:
        return "service-account", s
    return None


# ── Validators ─────────────────────────────────────────────────────────────

def _get_policy_for_binding(parsed):
    """Get policy for a parsed binding, using source scope for inherited (#src:) bindings."""
    role, scope_type, scope_name, src_type, src_name = parsed
    if src_type and src_name:
        # Inherited binding: the actual policy entry is at the SOURCE scope
        return get_policy(src_type, src_name), src_type, src_name
    return get_policy(scope_type, scope_name), scope_type, scope_name


def check_has_iam_binding(edge: dict):
    principal = edge["start"]["value"]
    binding_node = edge["end"]["value"]
    parsed = parse_binding_node(binding_node)
    if not parsed:
        return False, f"unparseable binding node: {binding_node[-60:]}"
    role, scope_type, scope_name, _, _ = parsed
    policy, chk_type, chk_name = _get_policy_for_binding(parsed)
    if not policy:
        return False, f"no policy for {chk_type}:{chk_name[-50:]}"
    if principal_in_policy(policy, principal, role):
        return True, f"{role[-50:]} @ {chk_type}:{chk_name[-40:]}"
    # WIF / conditional principal — check substring
    for b in (policy.get("bindings") or []):
        if b.get("role") == role:
            for m in (b.get("members") or []):
                if principal in m or m in principal:
                    return True, f"wif/cond: {role[-50:]}"
    return False, f"NOT in {role[-50:]} @ {chk_type}:{chk_name[-40:]}"


def check_pe_single(edge: dict, required_perms: list):
    binding_node = edge["start"]["value"]
    props = edge.get("properties") or {}
    principal = props.get("principal_member") or ""
    parsed = parse_binding_node(binding_node)
    if not parsed:
        return False, f"unparseable: {binding_node[-60:]}"
    role, scope_type, scope_name, _, _ = parsed
    if not principal:
        return False, "no principal_member"
    policy, chk_type, chk_name = _get_policy_for_binding(parsed)
    if not policy:
        return False, f"no policy for {chk_type}:{chk_name[-50:]}"
    if not principal_in_policy(policy, principal, role):
        found = any(
            b.get("role") == role and principal in " ".join(b.get("members") or [])
            for b in (policy.get("bindings") or [])
        )
        if not found:
            return False, f"NOT in {role} @ {chk_type}:{chk_name[-40:]}"
    if not role_has_any_perm(role, required_perms):
        return False, f"{role} lacks {required_perms[0]}"
    return True, f"{role[-50:]} has {required_perms[0]}"


def check_service_account_key_for(edge: dict):
    src = edge["start"]["value"]
    dst = edge["end"]["value"]
    sa_email = dst.replace("serviceAccount:", "")
    if "/keys/" in src:
        key_id = src.split("/keys/")[-1]
    else:
        return False, f"cannot parse key id: {src[-80:]}"
    keys = get_sa_keys(sa_email)
    if key_id in keys:
        return True, f"key {key_id[:16]}... on {sa_email}"
    return False, f"key {key_id[:16]}... NOT in {len(keys)} live keys on {sa_email}"


def check_combo_binding(edge: dict):
    """HAS_COMBO_BINDING — verify principal appears in at least one scope's policy."""
    principal = edge["start"]["value"]
    props = edge.get("properties") or {}
    # Accept both singular and plural forms
    scope_ids = props.get("effective_scope_ids") or []
    if isinstance(scope_ids, str):
        scope_ids = [scope_ids]
    if not scope_ids:
        single = props.get("effective_scope_id") or ""
        if single:
            scope_ids = [single]
    if not scope_ids:
        return False, "no effective_scope_id(s) in props"
    for scope_id in scope_ids:
        parsed = scope_id_to_type_name(scope_id)
        if not parsed:
            continue
        stype, sname = parsed
        policy = get_policy(stype, sname)
        if not policy:
            continue
        r = principal_in_any_role(policy, principal)
        if r:
            return True, f"has {r} in {stype}:{sname[-40:]}"
    return False, f"principal NOT found in {[s[-40:] for s in scope_ids[:2]]}"


def check_combo_pe_hop(edge: dict):
    """CAP: or combo_iambinding: → resource/SA. Verify principal_member in project."""
    props = edge.get("properties") or {}
    principal = props.get("principal_member") or ""
    project_id = props.get("project_id") or ""
    if not principal:
        return False, "no principal_member"
    if not project_id:
        for sid in (props.get("effective_scope_ids") or []):
            parsed = scope_id_to_type_name(sid)
            if parsed and parsed[0] == "project":
                project_id = parsed[1]
                break
    if not project_id:
        return False, "no project_id"
    policy = get_policy("project", project_id)
    if not policy:
        return False, f"no policy for project:{project_id}"
    r = principal_in_any_role(policy, principal)
    if r:
        return True, f"has {r} in project:{project_id}"
    return False, f"NOT found in project:{project_id}"


def check_exists_in_project(edge: dict):
    props = edge.get("properties") or {}
    project_id = props.get("project_id") or ""
    return (True, f"project_id={project_id}") if project_id else (False, "no project_id")


# ── Dispatch ───────────────────────────────────────────────────────────────

SKIP_KINDS = {
    "CanFederateWith", "FederatedPrincipalInPool", "IdentityProviderInPool",
    "HasImpliedPermissions", "RunsAs", "SWAP_COMPUTE_INSTANCE_SA",
}


def _is_combo_internal(edge):
    """combo_iambinding→CAP or iambinding→CAP are structural wiring edges with no principal_member."""
    dst = edge["end"]["value"]
    if not dst.startswith("CAP:"):
        return False
    src = edge["start"]["value"]
    if src.startswith("combo_iambinding:"):
        return True
    # iambinding:→CAP: structural edge (happens for some project-scoped combo rules)
    if src.startswith("iambinding:"):
        pm = (edge.get("properties") or {}).get("principal_member")
        return not pm  # only skip if no principal_member (true structural)
    return False


def validate_edge(edge: dict):
    kind = edge.get("kind", "")
    src = edge["start"]["value"]

    if kind in SKIP_KINDS or _is_combo_internal(edge):
        return "skip", "structural connector"

    if kind == "ServiceAccountKeyFor":
        ok, note = check_service_account_key_for(edge)
        return ("pass" if ok else "fail"), note

    if kind == "ExistsInProject":
        ok, note = check_exists_in_project(edge)
        return ("pass" if ok else "fail"), note

    if kind == "HAS_IAM_BINDING":
        # Check for unsupported scope in binding node
        parsed = parse_binding_node(edge["end"]["value"])
        if parsed:
            _, scope_type, _, _, _ = parsed
            if scope_type in _UNSUPPORTED_SCOPE_TYPES:
                return "skip", f"unsupported scope type: {scope_type}"
        ok, note = check_has_iam_binding(edge)
        return ("pass" if ok else "fail"), note

    if kind == "HAS_COMBO_BINDING":
        ok, note = check_combo_binding(edge)
        return ("pass" if ok else "fail"), note

    if src.startswith("implied-iambinding:") or kind.startswith("INFERRED_"):
        return "skip", "INFERRED — implied-role reasoning not validated"

    if src.startswith("iambinding:"):
        parsed = parse_binding_node(src)
        if parsed:
            _, scope_type, _, _, _ = parsed
            if scope_type in _UNSUPPORTED_SCOPE_TYPES:
                return "skip", f"unsupported scope type: {scope_type}"
        perms = REQUIRED_PERMS.get(kind) or ["iam.serviceAccounts.actAs"]
        ok, note = check_pe_single(edge, perms)
        return ("pass" if ok else "fail"), note

    if src.startswith("CAP:") or src.startswith("combo_iambinding:"):
        ok, note = check_combo_pe_hop(edge)
        return ("pass" if ok else "fail"), note

    return "skip", f"unhandled: src={src[:30]}"


# ── Main ───────────────────────────────────────────────────────────────────

def main(graph_file: str, label: str = "") -> int:
    print(f"\n{'='*72}")
    print(f"Validating: {label or Path(graph_file).name}")
    print(f"{'='*72}")

    with open(graph_file) as f:
        raw = json.load(f)
    g = raw.get("graph", raw)
    edges = g["edges"]

    by_kind = defaultdict(list)
    for e in edges:
        by_kind[e.get("kind", "")].append(e)

    priority_first = [
        "HAS_IAM_BINDING", "HAS_COMBO_BINDING",
        "CAN_CREATE_SA_KEY", "CAN_CREATE_SA_ACCESS_TOKEN", "CAN_IMPERSONATE_SA",
        "CAN_SIGN_JWT_AS_SA", "CAN_SIGN_BLOB_AS_SA",
        "CAN_MODIFY_PROJECT_IAM", "CAN_MODIFY_FOLDER_IAM", "CAN_MODIFY_ORG_IAM",
        "CAN_MODIFY_SA_IAM", "CAN_MODIFY_COMPUTE_INSTANCE_IAM", "CAN_READ_SECRET_DATA",
        "UPDATE_CUSTOM_ROLE_ADD_PERMISSIONS", "CAN_CREATE_CLOUDBUILD_DEFAULT_IDENTITY",
        "ServiceAccountKeyFor", "ExistsInProject",
        "CREATE_COMPUTE_INSTANCE_AS_SA", "SWAP_VM_SA_VIA_setServiceAccount",
        "RESET_COMPUTE_STARTUP_SA", "START_COMPUTE_STARTUP_SA", "IAP_TUNNEL_TO_VM_SA",
        "CREATE_CLOUDBUILD_AS_SA", "CREATE_CLOUDRUN_JOB_AS_SA", "CREATE_APPENGINE_VERSION_AS_SA",
        "CREATE_DATAPROC_CLUSTER_AS_SA", "ROLE_OWNER", "ROLE_EDITOR",
    ]
    all_kinds = priority_first + sorted(k for k in by_kind if k not in priority_first)

    total_pass = total_fail = total_skip = 0
    all_fails = []

    for kind in all_kinds:
        kind_edges = by_kind.get(kind, [])
        if not kind_edges:
            continue

        seen_principals = set()
        sample = []
        for e in kind_edges:
            p = (e.get("properties") or {}).get("principal_member") or e["start"]["value"]
            if p not in seen_principals or len(sample) < 2:
                seen_principals.add(p)
                sample.append(e)
            if len(sample) >= SAMPLE_PER_KIND:
                break

        kp = kf = ks = 0
        for e in sample:
            status, note = validate_edge(e)
            src_s = e["start"]["value"][-55:]
            dst_s = e["end"]["value"][-55:]
            marker = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[status]
            if status == "pass":
                total_pass += 1; kp += 1
            elif status == "fail":
                total_fail += 1; kf += 1
                all_fails.append({"kind": kind, "src": src_s, "dst": dst_s, "note": note})
            else:
                total_skip += 1; ks += 1
            print(f"  [{marker}] {kind}")
            print(f"         src: {src_s}")
            print(f"         dst: {dst_s}")
            print(f"         {note}")

        if kp + kf > 0:
            pct = f"{kp}/{kp+kf} pass"
        else:
            pct = f"{ks} skip"
        print(f"  ── {kind}: {pct}  ({len(kind_edges)} total)\n")

    print(f"\n{'='*72}")
    print(f"RESULT  {label}: {total_pass} PASS  {total_fail} FAIL  {total_skip} SKIP")
    if all_fails:
        print("\nFAILED EDGES:")
        for r in all_fails:
            print(f"  [{r['kind']}] {r['note']}")
            print(f"    src: {r['src']}")
            print(f"    dst: {r['dst']}")
    print(f"{'='*72}")
    return total_fail


if __name__ == "__main__":
    BASE = "/tmp/claude-1000/-home-kali-Desktop-TheBench/289ce989-7b4d-4ba2-b5b4-359d75915ce7/scratchpad"
    sa_key = os.path.expanduser("~/Downloads/my_key.json")
    if os.path.exists(sa_key):
        subprocess.run(["gcloud", "auth", "activate-service-account", "--key-file", sa_key],
                       capture_output=True)

    SECTION_SUFFIXES = [
        "_iam_bindings.json", "_resource_expansion.json", "_inferred_permissions.json",
        "_policy_bindings.json", "_allow_policies.json", "_deny_policies.json",
    ]

    fails = 0
    for label, subdir in [
        ("DEFAULT", f"{BASE}/val_default"),
        ("INHERIT", f"{BASE}/val_inherit"),
        ("DENY",    f"{BASE}/val_deny"),
    ]:
        files = glob.glob(f"{subdir}/*.json")
        if not files:
            print(f"\nSKIPPING {label}: no files in {subdir}")
            continue
        candidates = [f for f in files if not any(f.endswith(s) for s in SECTION_SUFFIXES)]
        gf = candidates[0] if candidates else files[0]
        fails += main(gf, label)

    sys.exit(0 if fails == 0 else 1)
