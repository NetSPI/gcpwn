from __future__ import annotations

# Canonical IAM-principal prefix normalization shared by the process-bindings path
# (member_permissions_summary) and OpenGraph. These historically diverged: OpenGraph's
# principal_node_id mapped users:/groups:/domains:/hyphenated forms while the process
# path's canonical_iam_member did not, so the same policy member could key differently
# depending on which path normalized it. This is PURE prefix canonicalization; graph-
# specific filtering (dropping deleted:, principalSet:// node typing) stays in OpenGraph.

_MEMBER_PREFIX_ALIASES = {
    "service_account": "serviceAccount",
    "serviceaccount": "serviceAccount",
    "service-account": "serviceAccount",
    "user": "user",
    "users": "user",
    "group": "group",
    "groups": "group",
    "domain": "domain",
    "domains": "domain",
    "project_owner": "projectOwner",
    "projectowner": "projectOwner",
    "project-owner": "projectOwner",
    "project_editor": "projectEditor",
    "projecteditor": "projectEditor",
    "project-editor": "projectEditor",
    "project_viewer": "projectViewer",
    "projectviewer": "projectViewer",
    "project-viewer": "projectViewer",
}


def canonical_iam_member(member: str) -> str:
    """Normalize an IAM member token to its canonical GCP prefix form.

    e.g. ``users:alice@x`` -> ``user:alice@x``, ``service_account:s`` ->
    ``serviceAccount:s``, ``all_users`` -> ``allUsers``. Unknown prefixes (incl.
    ``deleted:`` and ``principalSet://``) and prefix-less tokens are returned as-is.
    """
    token = str(member or "").strip()
    if not token:
        return ""
    lowered = token.lower()
    if lowered in {"all_users", "allusers"}:
        return "allUsers"
    if lowered in {"all_authenticated_users", "allauthenticatedusers"}:
        return "allAuthenticatedUsers"
    if ":" not in token:
        return token
    prefix, rest = token.split(":", 1)
    mapped = _MEMBER_PREFIX_ALIASES.get(prefix.strip().lower())
    return f"{mapped}:{rest.strip()}" if mapped else token
