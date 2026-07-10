"""Shared helpers for the ``everything`` IAM-bindings pipeline.

Turns cached allow-policies (iam_allow_policies) into the per-member roles/assets
view used by the report module, the `data` command, and OpenGraph: normalizing
members, splitting convenience principals (projectViewer/Editor/Owner), resolving
inherited roles up the org/folder/project hierarchy, and rendering summaries.

canonical_iam_member is imported from core and RE-EXPORTED here so the
process-bindings path, this module, OpenGraph, and iam_policy_bindings all share
one member normalizer (iam_policy_bindings imports it from this module).
"""

from __future__ import annotations

import datetime
from typing import Any, Callable, Iterable

import pandas as pd

from gcpwn.core.console import UtilityTools
# canonical_iam_member is imported (and re-exported) from core so the process-bindings
# path and OpenGraph share one normalizer; iam_policy_bindings imports it from here.
from gcpwn.core.utils.iam_principals import canonical_iam_member
from gcpwn.core.utils.iam_simplifier import create_simplified_hierarchy_permissions
from gcpwn.core.utils.module_helpers import normalize_str_set, parse_json_value, parse_string_list


def generate_summary_of_roles_or_vulns(
    session,
    member,
    roles_and_assets,
    snapshot = False,
    first_run=False,
    output_file=None,
    csv=False,
    txt=False,
    stdout=False
):
    """Render one member's roles/assets tree to stdout / a .txt / a .csv report.

    Walks roles_and_assets (the dict from build_roles_and_assets_for_member),
    grouping by asset type and listing Direct then Inherited roles per asset;
    inherited roles already covered by a direct grant are filtered out, and
    convenience ancestors (projectOwner/Editor/Viewer) get a distinct label.

    Output is controlled by the stdout/txt/csv flags (any combination). first_run
    selects write-vs-append (and CSV header) so a caller looping over members can
    accumulate one report. snapshot/output_file pick the filename. Returns nothing;
    its purpose is the side-effect output. Note: this only emits a "Summary".
    """

    def formatted_asset_name(asset_official_name, parent_id=None, asset_common_name=None, asset_project_id=None):
        formatted_string = f"  - \"{asset_official_name}\""
        if asset_type not in ["org", "folder", "project"]:
            formatted_string += f" (in {parent_id})"
        elif asset_common_name != "N/A":
            formatted_string += f" - {asset_common_name}"
        if asset_type == "project" and asset_project_id != "N/A":
            formatted_string += f" ({asset_project_id})"
        return formatted_string + "\n"

    def formatted_member_header():
        summary_type = "Summary"
        return f"{UtilityTools.BOLD}\n[******] {summary_type} for {member} [******]\n{UtilityTools.RESET}"


    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    output = output_file if output_file else f"Snapshots/Roles_Summary_{member}_{timestamp}" if snapshot else "Roles_Summary"
    txt_output = UtilityTools.get_save_filepath(session.workspace_directory_name, f"{output}.txt", "Reports") if txt else None
    csv_output = UtilityTools.get_save_filepath(session.workspace_directory_name, f"{output}.csv", "Reports") if csv else None
    csv_rows = []

    if stdout or txt:
        formatted_string = formatted_member_header()

    asset_headers = {
        "org": "Organization Summary\n",
        "project": "Project Summary\n",
        "folder": "Folder Summary\n",
        "bucket": "Cloud Storage Summary\n",
        "cloudfunction": "Cloud Function Summary\n",
        "computeinstance": "Cloud Compute Summary\n",
        "saaccounts": "Service Accounts Summary\n",
        "secrets": "Secret Manager Summary\n",
    }

    for asset_type, all_assets in roles_and_assets.items():

        roles_exist = False
        asset_type_header = asset_headers.get(asset_type, "")

        for asset_official_name, asset_details in all_assets.items():

            parent_id = asset_details["parent_id"]
            asset_project_id = parent_id if asset_type == "project" else "N/A"
            asset_common_name = asset_details["common_name"] if asset_type in ["org", "project", "folder"] else "N/A"
            all_direct_roles, all_inherited_roles = asset_details["Direct Permissions"], asset_details["Inherited Permissions"]

            if stdout or txt:
                if not roles_exist:
                    formatted_string += asset_type_header
                    roles_exist = True

                formatted_string += formatted_asset_name(asset_official_name, parent_id, asset_common_name, asset_project_id)

                for role in sorted(all_direct_roles):
                    formatted_string += f"    - {role}\n"

                    
                filtered_inherited_roles = [
                    {'ancestor': item['ancestor'], 'roles': item['roles'] - all_direct_roles}
                    for item in all_inherited_roles
                    if item['roles'] - all_direct_roles
                ]
            
                for item in filtered_inherited_roles:
                    ancestor, inherited_roles = item["ancestor"], item["roles"]
                    if inherited_roles:
                        for role in sorted(inherited_roles):
                            if any(x in ancestor for x in ["projectEditor", "projectViewer", "projectOwner"]):
                                ending = ancestor
                            else:
                                ending = f" (Inherited From {ancestor})"
                            formatted_string = formatted_string +  f"    - {role} " + ending + "\n"
                       
            if csv:
                row = {
                    "member": member,
                    "asset_type": asset_type,
                    "asset_name": asset_official_name,
                    "asset_common_name": asset_common_name,
                    "asset_project_id": asset_project_id,
                    "resource_owner": parent_id,
                    "asset_direct_permissions": str(all_direct_roles),
                    "asset_inherited_permissions": str(all_inherited_roles),
                }
                csv_rows.append(row)

    if stdout:
        print(formatted_string)

    if txt:
        mode = "w" if first_run else "a"
        with open(txt_output, mode) as txt_file:
            txt_file.write(formatted_string)

    if csv:
        df = pd.DataFrame(csv_rows)
        mode = "w" if first_run else "a"
        header = first_run
        df.to_csv(csv_output, mode=mode, header=header, index=False)


def policy_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    parsed = parse_json_value(raw, default=None)
    return parsed if isinstance(parsed, dict) else {}


def iter_member_roles_from_policy(policy: dict[str, Any]) -> Iterable[tuple[str, list[str]]]:
    """Yield (canonical_member, sorted_roles) pairs from a cached allow-policy dict.

    Prefers the precomputed ``by_member`` inverse map (written by
    _reorganize_allow_policy); falls back to collapsing the raw ``bindings`` list
    when it's absent. Members are normalized via canonical_iam_member and dropped
    if they normalize to empty; members with no roles are skipped.
    """
    by_member = policy.get("by_member")
    if isinstance(by_member, dict):
        for member, details in by_member.items():
            member_token = canonical_iam_member(str(member))
            if not member_token:
                continue
            roles = details.get("roles") if isinstance(details, dict) else []
            if not isinstance(roles, list):
                roles = [roles]
            normalized_roles = sorted(normalize_str_set(roles))
            if normalized_roles:
                yield member_token, normalized_roles
        return

    collapsed: dict[str, set[str]] = {}
    for binding in policy.get("bindings") or []:
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role") or "").strip()
        if not role:
            continue
        members = binding.get("members") or []
        if not isinstance(members, list):
            members = [members]
        for member in members:
            member_token = canonical_iam_member(member)
            if member_token:
                collapsed.setdefault(member_token, set()).add(role)

    for member, roles in collapsed.items():
        normalized_roles = sorted(normalize_str_set(roles))
        if normalized_roles:
            yield member, normalized_roles


def flatten_iam_allow_policies(
    allow_rows: Iterable[dict[str, Any]] | None,
    *,
    asset_name: str | None = None,
    type_of_asset: str | None = None,
    display_name_lookup: Callable[[str], str] | None = None,
) -> list[dict[str, str]]:
    """Flatten iam_allow_policies rows into one row per (member, resource) grant.

    Runs the shared simplifier (no inheritance) to produce flattened member rows,
    then optionally filters to a single asset_name / type_of_asset and, for
    hierarchy nodes, swaps in a friendly display name via display_name_lookup.
    Each output dict has member/project_id/name/display_name/type/roles (roles is a
    JSON string). Convenience members are detected but not dropped here.
    """
    target_asset = str(asset_name or "").strip()
    target_type = str(type_of_asset or "").strip()
    simplified = create_simplified_hierarchy_permissions(
        allow_rows or [],
        include_inheritance=False,
        normalize_member=canonical_iam_member,
        is_convenience_member=lambda member: str(member or "").strip().startswith(
            ("projectViewer:", "projectEditor:", "projectOwner:")
        ),
    )

    out: list[dict[str, str]] = []
    for row in simplified.get("flattened_member_rows") or []:
        resource_name = str(row.get("name") or "").strip()
        resource_type = str(row.get("type") or "").strip()
        project_id = str(row.get("project_id") or "").strip()
        if not resource_name or not resource_type:
            continue
        if target_asset and resource_name != target_asset:
            continue
        if target_type and resource_type != target_type:
            continue

        display_name = str(row.get("display_name") or "").strip()
        if display_name_lookup and resource_type in {"org", "folder", "project"}:
            display_name = str(display_name_lookup(resource_name) or "").strip()

        out.append(
            {
                "member": str(row.get("member") or "").strip(),
                "project_id": project_id,
                "name": resource_name,
                "display_name": display_name,
                "type": resource_type,
                "roles": str(row.get("roles") or "[]"),
            }
        )
    return out


def split_members_by_kind(members: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition members into (convenience, normal), each sorted and deduped.

    Convenience members are the project-scoped pseudo-principals
    projectViewer:/projectEditor:/projectOwner: (used to fold a project's basic
    roles onto its child resources); everything else is a normal principal.
    """
    members_set = normalize_str_set(members)
    convenience = sorted(m for m in members_set if m.startswith(("projectViewer:", "projectEditor:", "projectOwner:")))
    normal = sorted(members_set - set(convenience))
    return convenience, normal


def add_convenience_roles(data_dict: dict[str, Any], convenience_summary: dict[str, Any]) -> None:
    """Fold project convenience-role grants onto buckets as Inherited Permissions.

    For each bucket in convenience_summary whose project carries a matching
    basic role (viewer/editor/owner) as a Direct Permission, append an inherited
    entry tagged "project<Role> Points to <project>". Mutates data_dict in place;
    used by build_roles_and_assets_for_member to surface that a member with, e.g.,
    project Editor also effectively has the bucket roles bound to projectEditor.
    """
    for bucket, perms_by_project in (convenience_summary or {}).items():
        if bucket not in data_dict.get("bucket", {}):
            continue
        for project_name, roles in (perms_by_project or {}).items():
            proj_data = data_dict.get("project", {}).get(project_name)
            if not proj_data or "Direct Permissions" not in proj_data:
                continue
            direct_roles = proj_data["Direct Permissions"]
            for role in ("viewer", "editor", "owner"):
                if roles.get(role) and f"roles/{role}" in direct_roles:
                    data_dict["bucket"][bucket]["Inherited Permissions"].append(
                        {
                            "ancestor": f"project{role.capitalize()} Points to {project_name}",
                            "roles": roles[role],
                        }
                    )


def consolidate_convenience_roles(
    session,
    convenience_members: list[str],
    bindings: list[dict[str, Any]],
    project_name_cache: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Group convenience-member bindings into {resource: {project: {viewer/editor/owner: roles}}}.

    For each projectViewer/Editor/Owner member, collects the roles it holds on
    each resource and buckets them by the resource and resolved project name, so
    add_convenience_roles can later attribute them to direct members of that
    project. project_name_cache is shared by the caller so each project_id is
    resolved with a single get_project_name (avoids re-querying under the DB lock).
    """
    # project_name_cache is shared across members by the caller so the same
    # project_id is not re-queried (one get_project_name per distinct project).
    if project_name_cache is None:
        project_name_cache = {}
    all_convenience_summary: dict[str, Any] = {}
    member_data_dict: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings or []:
        member = binding.get("member")
        if not member:
            continue
        member_data_dict.setdefault(str(member), []).append(binding)

    for member in convenience_members or []:
        for data in member_data_dict.get(member, []):
            full_resource_name = data["name"]
            project_id = member.split(":", 1)[1]
            if project_id in project_name_cache:
                project_name = project_name_cache[project_id]
            else:
                _resp = session.get_project_name(project_id)
                project_name = _resp[0]["name"] if _resp else "Unknown"
                project_name_cache[project_id] = project_name
            roles = set(
                parse_string_list(
                    data["roles"],
                    allow_json=True,
                    allow_python_literal=True,
                    fallback_to_single=True,
                )
            )
            role_type = (
                "owner"
                if member.startswith("projectOwner:")
                else "editor" if member.startswith("projectEditor:") else "viewer"
            )

            all_convenience_summary.setdefault(full_resource_name, {}).setdefault(
                project_name,
                {"viewer": set(), "editor": set(), "owner": set()},
            )[role_type].update(roles)

    return all_convenience_summary


def build_roles_and_assets_for_member(
    session,
    *,
    member: str,
    member_bindings: list[dict[str, Any]],
    convenience_summary: dict[str, Any] | None = None,
    project_name_cache: dict[str, str] | None = None,
    ancestor_cache: dict[str, list] | None = None,
) -> dict[str, Any]:
    """Build one member's roles/assets tree, resolving inherited roles up the hierarchy.

    Returns a dict keyed by asset type (org/folder/project + resource types); each
    asset entry has Direct Permissions (roles bound directly to ``member`` here),
    Inherited Permissions (roles the member holds on this asset's ancestors), plus
    common_name/parent_id/parent_name. Inheritance flows project<-folder<-org via
    find_ancestors; non-hierarchy resources inherit from their parent project (and
    its ancestors). convenience_summary, when given, folds project basic roles onto
    child resources via add_convenience_roles.

    project_name_cache and ancestor_cache are shared across members by the caller
    (materialize_member_permissions) so the recursive-CTE find_ancestors and
    project-name lookups run once per distinct asset/project instead of
    O(members x assets) under the DB RLock.
    """
    # Caches are shared across members by the caller (materialize_member_permissions)
    # so project-name lookups and the recursive-CTE find_ancestors are computed once
    # per distinct project/asset instead of O(members x assets) under the DB RLock.
    if project_name_cache is None:
        project_name_cache = {}
    if ancestor_cache is None:
        ancestor_cache = {}

    def _project_name(project_id: str) -> str:
        token = str(project_id or "").strip()
        if token in project_name_cache:
            return project_name_cache[token]
        response = session.get_project_name(token)
        resolved = response[0]["name"] if response else "Unknown"
        project_name_cache[token] = resolved
        return resolved

    def _ancestors(asset: str) -> list:
        if asset not in ancestor_cache:
            ancestor_cache[asset] = list(session.find_ancestors(asset))
        return ancestor_cache[asset]

    # member_bindings is already filtered to this member by the caller (grouped once,
    # O(bindings) total) -- do NOT rescan the full binding set here (that was O(members x
    # bindings): ~6e9 comparisons on a 30k-member / 200k-binding org, every materialize).
    # Every row shares the same member, so the old per-member sort was a no-op copy.
    member_rows = list(member_bindings or [])

    data_dict: dict[str, Any] = {}
    for rtype in ("org", "folder", "project"):
        data_dict.setdefault(rtype, {})

    for row in member_rows:
        rtype, rname, pid = row["type"], row["name"], row["project_id"]
        data_dict.setdefault(rtype, {})
        roles = set(
            parse_string_list(
                row["roles"],
                allow_json=True,
                allow_python_literal=True,
                fallback_to_single=True,
            )
        )
        display = row.get("display_name", rname)
        pname = _project_name(pid)

        entry = data_dict[rtype].setdefault(
            rname,
            {
                "Direct Permissions": set(),
                "Inherited Permissions": [],
                "common_name": display if rtype in ["org", "project", "folder"] else rname,
                "parent_id": pid,
                "parent_name": pname,
            },
        )
        entry["Direct Permissions"].update(roles)

    for level in ("project", "folder", "org"):
        for asset, info in (data_dict.get(level) or {}).items():
            for anc_type, anc_name in _ancestors(asset):
                anc_roles = data_dict.get(anc_type, {}).get(anc_name, {}).get("Direct Permissions")
                if anc_roles:
                    info["Inherited Permissions"].append({"ancestor": anc_name, "roles": anc_roles})

    for rtype, entries in data_dict.items():
        if rtype in ("project", "folder", "org"):
            continue
        for _name, info in entries.items():
            parent = info.get("parent_name")
            proj_data = data_dict.get("project", {}).get(parent)
            if proj_data:
                info["Inherited Permissions"] = list(proj_data["Inherited Permissions"] or [])
                info["Inherited Permissions"].append({"ancestor": parent, "roles": proj_data["Direct Permissions"]})
                continue
            for anc_type, anc_name in _ancestors(parent):
                roles = data_dict.get(anc_type, {}).get(anc_name, {}).get("Direct Permissions")
                if roles:
                    info["Inherited Permissions"].append({"ancestor": anc_name, "roles": roles})

    if convenience_summary:
        add_convenience_roles(data_dict, convenience_summary)
    return data_dict
