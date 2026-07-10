"""Per-task project-scoped view over a shared session.

Cross-project parallel enumeration needs each worker task to act on its own
project while sharing one session (credentials + the thread-safe DataController).
A single mutable ``session.project_id`` cannot express "project A and project B
at the same time", so each task wraps the base session in a
``ProjectScopedSession`` whose ``project_id`` is isolated; every other attribute
and method delegates to the shared base.

Methods that derive output paths from ``self.project_id`` are overridden so a
task's downloads land under its own project rather than the base session's.
"""

from __future__ import annotations

from typing import Any


class ProjectScopedSession:
    _OWN_ATTRS = {"_base", "_overrides"}

    def __init__(self, base: Any, project_id: str | None) -> None:
        object.__setattr__(self, "_base", base)
        object.__setattr__(self, "_overrides", {"project_id": project_id})

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_base"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._OWN_ATTRS:
            object.__setattr__(self, name, value)
            return
        # Keep writes local to this view so concurrent tasks never corrupt the
        # shared base session (project_id especially).
        object.__getattribute__(self, "_overrides")[name] = value

    # Output-path helpers read project_id off the *base* when bound there, so
    # override them to inject this task's project unless the caller is explicit.
    def get_download_save_path(self, *, project_id: str | None = None, **kwargs: Any) -> Any:
        base = object.__getattribute__(self, "_base")
        return base.get_download_save_path(project_id=project_id or self.project_id, **kwargs)

    def resolve_output_path(self, *, project_id: str | None = None, **kwargs: Any) -> Any:
        base = object.__getattribute__(self, "_base")
        return base.resolve_output_path(project_id=project_id or self.project_id, **kwargs)
