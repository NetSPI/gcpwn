from __future__ import annotations

from gcpwn.core.utils.enum_framework import (
    Component,
    NESTED,
    PROJECT,
    parse_enum_args,
    run_components,
)
from gcpwn.modules.gcp.parametermanager.utilities.helpers import (
    ParameterManagerParametersResource,
    ParameterManagerVersionsResource,
)


COMPONENTS = [
    Component(
        "parameters",
        ParameterManagerParametersResource,
        "Parameter Manager Parameters",
        "Parameters",
        help_text=(
            "Enumerate Parameter Manager parameters "
            "(GCP global config/secrets store). "
            "REQUIRES: parametermanager.parameters.list"
        ),
        scope=PROJECT,
        supports_iam=False,
    ),
    Component(
        "versions",
        ParameterManagerVersionsResource,
        "Parameter Manager Parameter Versions",
        "Parameter Versions",
        help_text=(
            "Enumerate versions per parameter. "
            "REQUIRES: parametermanager.parameterVersions.list + --parameters"
        ),
        scope=NESTED,
        parent_key="parameters",
        dependency_label="Parameters",
        save_parent_kwarg="parameter",
        supports_get=False,
        supports_iam=False,
        primary_sort_key="name",
    ),
]


def _parse_args(user_args):
    return parse_enum_args(
        user_args,
        COMPONENTS,
        description="Enumerate Parameter Manager resources (parameters and versions)",
    )


def run_module(user_args, session):
    args = _parse_args(user_args)
    run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="parametermanager_actions_allowed",
        module_name="enum_parametermanager",
    )
    return 1
