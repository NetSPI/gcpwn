from __future__ import annotations

from gcpwn.core.utils.enum_framework import Component, NESTED, REGION, parse_enum_args, run_components
from gcpwn.modules.gcp.privateca.utilities.helpers import (
    PrivateCACertificateAuthoritiesResource,
    PrivateCAPoolsResource,
    resolve_locations,
)


COMPONENTS = [
    Component(
        "ca_pools",
        PrivateCAPoolsResource,
        "Private CA Pools",
        "CA Pools",
        help_text="Enumerate Certificate Authority Service CA pools (grouped by issuance policy and tier)",
        scope=REGION,
        manual_id_arg="pool_ids",
        manual_template=("projects", "{project_id}", "locations", 0, "caPools", 1),
        manual_error="Invalid pool ID. Use LOCATION/POOL_ID or the full resource name.",
        manual_help="Pool IDs as LOCATION/POOL_ID or full resource names.",
    ),
    Component(
        "certificate_authorities",
        PrivateCACertificateAuthoritiesResource,
        "Certificate Authorities",
        "Certificate Authorities",
        help_text="Enumerate Certificate Authorities under each CA pool",
        scope=NESTED,
        parent_key="ca_pools",
        dependency_label="ca_pools",
        supports_iam=False,
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Certificate Authority Service CA pools and certificate authorities",
        region_label="Certificate Authority Service locations",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="privateca_actions_allowed",
        region_resolver=resolve_locations, module_name="enum_privateca",
    )
    return 1
