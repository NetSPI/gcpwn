from __future__ import annotations

from gcpwn.core.utils.enum_framework import Component, NESTED, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.developerconnect.utilities.helpers import (
    DevConnectConnectionsResource,
    DevConnectRepoLinksResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "connections",
        DevConnectConnectionsResource,
        "Developer Connect Connections",
        "Connections",
        help_text="Enumerate Developer Connect OAuth connections to GitHub, GitLab, Bitbucket, and SSM",
        scope=REGION,
        supports_iam=False,
        manual_id_arg="connection_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "connections", 1),
        manual_error="Invalid connection ID. Use LOCATION/CONNECTION_ID or the full resource name.",
        manual_help="Connection IDs as LOCATION/CONNECTION_ID or full resource names.",
    ),
    Component(
        "repo_links",
        DevConnectRepoLinksResource,
        "Developer Connect Repo Links",
        "Repo Links",
        help_text="Enumerate Git repository links under each Developer Connect connection",
        scope=NESTED,
        parent_key="connections",
        dependency_label="connections",
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Developer Connect connections and linked Git repositories",
        region_label="Developer Connect locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="developerconnect_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_developerconnect",
    )
    return 1
