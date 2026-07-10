from __future__ import annotations

import argparse
from collections import defaultdict

from gcpwn.core.action_schema import ACTION_EVIDENCE_TEST_IAM_PERMISSIONS
from gcpwn.core.utils.action_recording import has_recorded_actions
from gcpwn.core.utils.service_runtime import (
    map_regions_with_disabled_short_circuit,
    parse_component_args,
    resolve_selected_components,
)
from gcpwn.modules.gcp.cloudcompute.enumeration.enum_cloudcompute_resources import (
    _process_existing_resource,
    _resolve_regions,
)
from gcpwn.modules.gcp.cloudcompute.utilities.helpers import cloudcompute_gapic_resource
from gcpwn.modules.gcp.cloudcompute.utilities.lb_helpers import (
    LbForwardingRulesResource,
    LbTargetProxiesResource,
    LbUrlMapsResource,
)


COMPONENTS = [
    ("backend_buckets", "Enumerate backend buckets"),
    ("backend_services", "Enumerate global backend services"),
    ("region_backend_services", "Enumerate regional backend services"),
    ("forwarding_rules", "Enumerate forwarding rules (global + regional)"),
    ("url_maps", "Enumerate URL maps"),
    ("target_proxies", "Enumerate target proxies (HTTP/HTTPS/TCP/SSL/GRPC)"),
]


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        regions_group = parser.add_mutually_exclusive_group()
        regions_group.add_argument("--all-regions", action="store_true", required=False, help="Try every known region")
        regions_group.add_argument("--regions-list", required=False, help="Regions in comma-separated format")
        regions_group.add_argument("--regions-file", required=False, help="File containing regions, one per line")
        parser.add_argument("--threads", type=int, default=3, help="Worker threads for region fan-out (default: 3)")

    return parse_component_args(
        user_args,
        description="Enumerate Compute Engine load balancing resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        standard_args=("iam", "get", "debug"),
        standard_arg_overrides={
            "iam": {"help": "Run TestIamPermissions on supported load balancing resources"},
        },
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    selected = resolve_selected_components(args, [component_key for component_key, _help_text in COMPONENTS])
    project_id = session.project_id

    backend_buckets_resource = (
        cloudcompute_gapic_resource(session, "backend_buckets") if selected.get("backend_buckets", False) else None
    )
    backend_services_resource = (
        cloudcompute_gapic_resource(session, "backend_services") if selected.get("backend_services", False) else None
    )
    region_backend_services_resource = (
        cloudcompute_gapic_resource(session, "region_backend_services")
        if selected.get("region_backend_services", False)
        else None
    )
    forwarding_rules_resource = LbForwardingRulesResource(session)
    url_maps_resource = LbUrlMapsResource(session)
    target_proxies_resource = LbTargetProxiesResource(session)

    scope_actions = {
        "project_permissions": defaultdict(set),
        "folder_permissions": {},
        "organization_permissions": {},
    }
    api_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    iam_actions = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    regions = _resolve_regions(
        args,
        session,
        project_id=project_id,
        require_all=selected.get("region_backend_services", False),
    )

    _process_existing_resource(
        selected_key="backend_buckets",
        title="Load Balancer Backend Buckets",
        primary_resource="Backend Buckets",
        resource=backend_buckets_resource,
        list_callback=lambda action_dict: backend_buckets_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="backend_services",
        title="Load Balancer Backend Services",
        primary_resource="Backend Services",
        resource=backend_services_resource,
        list_callback=lambda action_dict: backend_services_resource.list(project_id=project_id, action_dict=action_dict),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="region_backend_services",
        title="Load Balancer Region Backend Services",
        primary_resource="Region Backend Services",
        resource=region_backend_services_resource,
        list_callback=lambda action_dict: sum(
            (
                batch or []
                for _region, batch in map_regions_with_disabled_short_circuit(
                    regions,
                    lambda region: region_backend_services_resource.list(
                        project_id=project_id,
                        region=region,
                        action_dict=action_dict,
                    ),
                    threads=getattr(args, "threads", 3),
                    progress_label="Load Balancer Region Backend Services",
                )
                if batch not in ("Not Enabled", None)
            ),
            [],
        ),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="region",
    )
    _process_existing_resource(
        selected_key="forwarding_rules",
        title="Load Balancer Forwarding Rules",
        primary_resource="Forwarding Rules",
        resource=forwarding_rules_resource,
        list_callback=lambda _action_dict: forwarding_rules_resource.list(project_id=project_id),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="scope",
    )
    _process_existing_resource(
        selected_key="url_maps",
        title="Load Balancer URL Maps",
        primary_resource="URL Maps",
        resource=url_maps_resource,
        list_callback=lambda _action_dict: url_maps_resource.list(project_id=project_id),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
    )
    _process_existing_resource(
        selected_key="target_proxies",
        title="Load Balancer Target Proxies",
        primary_resource="Target Proxies",
        resource=target_proxies_resource,
        list_callback=lambda _action_dict: target_proxies_resource.list(project_id=project_id),
        args=args,
        selected=selected,
        session=session,
        project_id=project_id,
        scope_actions=scope_actions,
        api_actions=api_actions,
        iam_actions=iam_actions,
        sort_key="proxy_type",
    )

    if has_recorded_actions(scope_actions):
        session.insert_actions(scope_actions, project_id, column_name="compute_actions_allowed")
    if has_recorded_actions(api_actions):
        session.insert_actions(api_actions, project_id, column_name="compute_actions_allowed")
    if has_recorded_actions(iam_actions):
        session.insert_actions(
            iam_actions,
            project_id,
            column_name="compute_actions_allowed",
            evidence_type=ACTION_EVIDENCE_TEST_IAM_PERMISSIONS,
        )

    return 1
