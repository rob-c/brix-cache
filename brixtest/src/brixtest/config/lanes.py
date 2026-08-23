"""Filesystem and port isolation for concurrent test sessions.

A lane is ``(root, port_base)``.  Two distinct lanes on one host never
interact: not through ports, not through paths, not through reapers.
Every destructive operation checks lane identity first; the on-disk
ownership record makes refusal messages precise: which session owns
the lane, since when, and whether it is still alive.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from brixtest.errors import LaneOwnershipError

__all__ = ["Lane", "OwnershipRecord", "refuse_foreign_lane"]

_RECORD_NAME = "lane-owner.json"


def refuse_foreign_lane(test_root: str, host: str, port: int) -> str:
    """Return the shared diagnostic for a foreign lane owner."""
    return (
        f"refusing to start TEST_ROOT={test_root}: {host}:{port} "
        "is owned by another or incomplete test fleet. Choose a "
        "non-overlapping TEST_PORT_START; each lane reserves the complete "
        "central port ladder. The foreign listener was not modified."
    )


@dataclasses.dataclass(frozen=True)
class OwnershipRecord:
    lane_root: str
    port_base: int
    pid: int
    session: str
    hostname: str
    started_at: str

    def alive(self) -> bool:
        if self.hostname != socket.gethostname():
            return True  # cannot verify a foreign host's pid; assume alive
        try:
            os.kill(self.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True


@dataclasses.dataclass(frozen=True)
class Lane:
    root: Path
    port_base: int
    port_span: int = 1000

    @property
    def log_dir(self) -> Path:
        return self.root / "logs"

    @property
    def instances_dir(self) -> Path:
        return self.root / "instances"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def tmp_dir(self) -> Path:
        # The TMPDIR pin: workers and helpers confine temp files to the
        # lane so concurrent lanes and system tmp-reapers never interact.
        return self.root / "tmp"

    def port_range(self) -> range:
        return range(self.port_base, self.port_base + self.port_span)

    def contains_path(self, path: Path) -> bool:
        try:
            Path(path).resolve().relative_to(self.root.resolve())
            return True
        except ValueError:
            return False

    @property
    def _record_path(self) -> Path:
        return self.root / _RECORD_NAME

    def owner(self) -> Optional[OwnershipRecord]:
        try:
            raw = json.loads(self._record_path.read_text())
            return OwnershipRecord(**raw)
        except (OSError, ValueError, TypeError):
            return None

    def acquire(self, session: Optional[str] = None) -> OwnershipRecord:
        """Write this process's ownership record; refuse a live foreign owner."""
        existing = self.owner()
        if existing is not None and existing.pid != os.getpid() and existing.alive():
            raise LaneOwnershipError(str(self.root), dataclasses.asdict(existing))
        record = OwnershipRecord(
            lane_root=str(self.root),
            port_base=self.port_base,
            pid=os.getpid(),
            session=session or uuid.uuid4().hex[:8],
            hostname=socket.gethostname(),
            started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self.root.mkdir(parents=True, exist_ok=True)
        self._record_path.write_text(
            json.dumps(dataclasses.asdict(record), sort_keys=True) + "\n"
        )
        return record

    def release(self) -> None:
        """Remove the record if this process owns it (never a foreign one)."""
        existing = self.owner()
        if existing is not None and existing.pid != os.getpid():
            return
        with contextlib.suppress(OSError):
            self._record_path.unlink()

    def owns_root(self, path: Path) -> bool:
        """Require exact root identity rather than a string prefix match."""
        return Path(path).resolve() == self.root.resolve()

    def owns_port(self, port: int) -> bool:
        return port in self.port_range()
