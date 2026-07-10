"""Thread-aware stdout multiplexing for parallel service enumeration.

When services fan out across worker threads, naive printing interleaves every
module's output into noise. ``ParallelOutputManager`` buffers each worker
thread's writes and flushes them as one atomic block when that thread's task
finishes, so a service's output stays contiguous. On a TTY it also renders a
single compact live status line (done/total, in-flight tasks, failures); when
stdout is not a TTY it falls back to plain per-task progress lines.

The manager is installed as ``sys.stdout`` for the duration of the parallel
section, so existing ``print(...)`` calls inside modules need no changes.
"""

from __future__ import annotations

import shutil
import sys
import threading


class ParallelOutputManager:
    def __init__(self, *, total: int, real_stdout=None, force_status: bool | None = None) -> None:
        self._real = real_stdout if real_stdout is not None else sys.__stdout__
        self._buffers: dict[int, list[str]] = {}
        self._labels: dict[int, str] = {}
        self._lock = threading.RLock()
        self._total = max(0, int(total))
        self._done = 0
        self._failed = 0
        self._installed_stdout = None
        if force_status is None:
            self._status_enabled = bool(getattr(self._real, "isatty", lambda: False)())
        else:
            self._status_enabled = bool(force_status)

    # --- stdout interface (per-thread buffering) ---
    def write(self, text: str) -> int:
        thread_id = threading.get_ident()
        with self._lock:
            self._buffers.setdefault(thread_id, []).append(text)
        return len(text)

    def flush(self) -> None:  # pragma: no cover - stdout protocol
        pass

    def isatty(self) -> bool:
        return False

    # --- task lifecycle ---
    def begin_task(self, label: str) -> None:
        thread_id = threading.get_ident()
        with self._lock:
            self._labels[thread_id] = str(label or "")
            self._buffers.setdefault(thread_id, [])
        self._render_status()

    def end_task(self, *, failed: bool = False) -> None:
        thread_id = threading.get_ident()
        with self._lock:
            buffered = "".join(self._buffers.pop(thread_id, []))
            self._labels.pop(thread_id, None)
            self._done += 1
            if failed:
                self._failed += 1
        self._clear_status_line()
        if buffered:
            self._real.write(buffered)
            if not buffered.endswith("\n"):
                self._real.write("\n")
        self._real.flush()
        self._render_status()

    # --- status rendering ---
    def _clear_status_line(self) -> None:
        if self._status_enabled:
            self._real.write("\r\033[K")
            self._real.flush()

    def _render_status(self) -> None:
        with self._lock:
            in_flight = [label for label in self._labels.values() if label]
            done, total, failed = self._done, self._total, self._failed
        preview = ", ".join(in_flight[:4])
        if len(in_flight) > 4:
            preview += f", +{len(in_flight) - 4} more"
        line = f"[*] services {done}/{total}"
        if failed:
            line += f" ({failed} failed)"
        if preview:
            line += f" | running: {preview}"
        if self._status_enabled:
            width = max(20, shutil.get_terminal_size((120, 24)).columns - 1)
            self._real.write("\r\033[K" + line[:width])
            self._real.flush()

    # --- install / restore ---
    def install(self) -> "ParallelOutputManager":
        self._installed_stdout = sys.stdout
        sys.stdout = self
        return self

    def uninstall(self) -> None:
        with self._lock:
            leftovers = ["".join(chunks) for chunks in self._buffers.values()]
            self._buffers.clear()
            self._labels.clear()
        self._clear_status_line()
        for buffered in leftovers:
            if buffered:
                self._real.write(buffered)
        if self._status_enabled:
            self._real.write("\n")
        self._real.flush()
        if self._installed_stdout is not None:
            sys.stdout = self._installed_stdout
            self._installed_stdout = None

    def __enter__(self) -> "ParallelOutputManager":
        return self.install()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.uninstall()
