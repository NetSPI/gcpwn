from __future__ import annotations

from gcpwn.core.utils.enum_framework import PROJECT, Component, component_args, run_components
from gcpwn.core.utils.service_runtime import DownloadBudget, parse_component_args
from gcpwn.modules.gcp.clouddomains.utilities.helpers import DomainsRegistrationsResource


COMPONENTS = [
    Component(
        "registrations",
        DomainsRegistrationsResource,
        "Cloud Domains Registrations",
        "Registrations",
        help_text="Enumerate Cloud Domains registrations",
        scope=PROJECT,
        supports_iam=True,
    ),
]


def _parse_args(user_args):
    return parse_component_args(
        user_args,
        description="Enumerate Cloud Domains domain registrations.",
        components=component_args(COMPONENTS),
        standard_args=("iam", "download", "get"),
    )


def run_module(user_args, session):
    args = _parse_args(user_args)

    if getattr(args, "download", False):
        args.get = True
        args.registrations = True

    discovered = run_components(
        session,
        args,
        components=COMPONENTS,
        column_name="clouddomains_actions_allowed",
        module_name="enum_clouddomains",
    )

    if getattr(args, "download", False):
        project_id = session.project_id
        resource = DomainsRegistrationsResource(session)
        downloaded_paths = []
        budget = DownloadBudget(session, label="domain registration contacts")
        for row in discovered.get("registrations", []):
            if budget.exceeded():
                break
            path = resource.download_contacts(row=row, project_id=project_id)
            if path is not None:
                downloaded_paths.append(str(path))
        for p in downloaded_paths:
            print(f"[*] Wrote domain contact settings to {p}")
        if downloaded_paths:
            print(f"[*] Downloaded {len(downloaded_paths)} domain contact file(s) for project {project_id}.")
        elif discovered.get("registrations"):
            print(f"[*] No contact data was available to download for project {project_id}.")

    return 1
