from __future__ import annotations

from gcpwn.core.utils.enum_framework import (
    Component,
    NESTED,
    PROJECT,
    parse_enum_args,
    run_components,
)
from gcpwn.modules.gcp.gkehub.utilities.helpers import (
    GkehubMembershipsResource,
    GkehubRbacBindingsResource,
    GkehubScopesResource,
)


COMPONENTS = [
    Component(
        "memberships",
        GkehubMembershipsResource,
        "GKE Hub Fleet Memberships",
        "Memberships",
        help_text=(
            "Enumerate fleet-enrolled clusters (GKE Hub memberships). "
            "Uses locations/- to return all regions in one call. "
            "REQUIRES: gkehub.memberships.list"
        ),
        scope=PROJECT,
        supports_get=False,
        supports_iam=False,
    ),
    Component(
        "scopes",
        GkehubScopesResource,
        "GKE Hub Fleet Scopes",
        "Scopes",
        help_text=(
            "Enumerate fleet scopes (named membership groupings). "
            "REQUIRES: gkehub.scopes.list"
        ),
        scope=PROJECT,
        supports_get=False,
        supports_iam=False,
        primary_sort_key="name",
    ),
    Component(
        "rbac_bindings",
        GkehubRbacBindingsResource,
        "GKE Hub Fleet RBAC Role Bindings",
        "RBAC Bindings",
        help_text=(
            "Enumerate fleet RBAC role bindings per scope. "
            "REQUIRES: gkehub.rbacrolebindings.list + gkehub.scopes.list"
        ),
        scope=NESTED,
        parent_key="scopes",
        dependency_label="Scopes",
        save_parent_kwarg="scope_name",
        supports_get=False,
        supports_iam=False,
        primary_sort_key="name",
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate GKE Hub (Fleet) resources: memberships, scopes, and RBAC role bindings",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="gkehub_actions_allowed",
        module_name="enum_gkehub",
    )
    return 1
