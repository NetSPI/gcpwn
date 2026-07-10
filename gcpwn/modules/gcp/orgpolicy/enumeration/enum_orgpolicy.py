from __future__ import annotations

from gcpwn.core.utils.enum_framework import PROJECT, Component, build_extra_args, component_args, run_components
from gcpwn.core.utils.service_runtime import parse_component_args
from gcpwn.modules.gcp.orgpolicy.utilities.helpers import OrgPolicyPoliciesResource


COMPONENTS = [
    Component("policies", OrgPolicyPoliciesResource, "Organization Policies", "Policies",
              help_text="Enumerate Organization Policy constraints set on the project",
              scope=PROJECT, primary_sort_key="constraint", supports_iam=False,
              manual_id_arg="policy_ids",
              manual_template=("projects", "{project_id}", "policies", 0),
              manual_error="Invalid policy ID format. Use CONSTRAINT or full projects/PROJECT_ID/policies/CONSTRAINT.",
              manual_help="Constraint names as CONSTRAINT or full projects/.../policies/CONSTRAINT."),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate Organization Policy constraints",
        components=component_args(COMPONENTS),
        add_extra_args=build_extra_args(COMPONENTS),
        standard_args=("get", "debug"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session, args, components=COMPONENTS, column_name="orgpolicy_actions_allowed",
        module_name="enum_orgpolicy",
    )
    return 1
