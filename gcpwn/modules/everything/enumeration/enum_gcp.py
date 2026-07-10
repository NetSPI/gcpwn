"""enum_gcp: the GCP-only enumeration orchestrator.

Part of the three-way split: ``enum_all`` = GCP + Google Workspace, ``enum_gcp``
= GCP only, ``enum_google_workspace`` = Workspace only. This re-exports ``enum_all``'s
``run_module`` unchanged (the per-project path never ran Workspace anyway) and wraps
``run_parallel`` to suppress the trailing Workspace phase (``include_workspace=False``).
The cli treats ``enum_gcp`` like ``enum_all`` for the --parallel-services
orchestrator + return-code-2 project discovery.
"""

from __future__ import annotations

from gcpwn.modules.everything.enumeration.enum_all import run_module  # noqa: F401  (re-exported)
from gcpwn.modules.everything.enumeration.enum_all import run_parallel as _run_parallel_all


def run_parallel(session, user_args, explicit_project_ids=None) -> int:
    """GCP-only parallel orchestrator: same as enum_all's but without the Workspace phase."""
    return _run_parallel_all(session, user_args, explicit_project_ids, include_workspace=False)
