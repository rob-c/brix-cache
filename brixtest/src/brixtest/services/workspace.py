"""Lane-confined, uniquely named per-test workspaces.

``sweep()`` removes only workspaces created by the current allocator.
"""

from __future__ import annotations

import re
import shutil
import threading
from pathlib import Path
from typing import Dict, List

from brixtest.config.lanes import Lane

__all__ = ["WorkspaceAllocator"]

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_STEM = 80


def _safe_stem(test_id: str) -> str:
    """A filesystem-safe, human-recognizable stem from a pytest nodeid."""
    stem = _UNSAFE.sub("_", test_id).strip("_")
    return stem[-_MAX_STEM:] if len(stem) > _MAX_STEM else stem or "test"


def _remove_tree(path: Path) -> bool:
    try:
        shutil.rmtree(path)
    except OSError:
        return False
    return True


class WorkspaceAllocator:
    def __init__(self, lane: Lane) -> None:
        self.lane = lane
        self.root = lane.root / "workspaces"
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {}
        self._created: List[Path] = []

    def for_test(self, test_id: str) -> Path:
        """A fresh directory for this test invocation.  Same test run
        twice (retries, parametrization reruns) gets ``-2``, ``-3``, … —
        an old workspace is never emptied and handed back."""
        stem = _safe_stem(test_id)
        with self._lock:
            count = self._counters.get(stem, 0)
            while True:
                count += 1
                name = stem if count == 1 else "%s-%d" % (stem, count)
                path = self.root / name
                try:
                    path.mkdir(parents=True, exist_ok=False)
                except FileExistsError:
                    continue  # a previous session's workspace in a kept lane
                break
            self._counters[stem] = count
            self._created.append(path)
        return path

    def fresh(self, prefix: str = "scratch") -> Path:
        """An anonymous workspace for non-test callers (CLI, prep)."""
        return self.for_test(prefix)

    def created(self) -> List[Path]:
        return list(self._created)

    def sweep(self, *, keep: int = 0) -> int:
        """Delete workspaces THIS allocator created (never anyone
        else's), oldest first, keeping the ``keep`` most recent.
        Returns how many were removed."""
        with self._lock:
            victims = self._created[: len(self._created) - keep if keep else None]
            removed = sum(_remove_tree(path) for path in victims)
            self._created = [p for p in self._created if p.exists()]
        return removed
