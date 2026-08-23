"""Ownership-checked orphan process reaping.

The reaper exists because crashed sessions leave listeners behind, and
a process is reaped only when every ownership test passes.

Ownership tests, all required:

1. the pid's cwd (or an argv path) resolves **inside** this lane's
   root, checked by ``Lane.contains_path``;
2. the port it holds is inside this lane's port range;
3. the lane's ownership record, if present, names a dead session.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import signal
import time
from pathlib import Path
from typing import List, Optional, Tuple

from brixtest.config.lanes import Lane
from brixtest.events import emit
from brixtest.util.net import listening_ports, pids_on_port

__all__ = ["Orphan", "find_orphans", "owns", "reap"]


@dataclasses.dataclass(frozen=True)
class Orphan:
    pid: int
    port: int
    cwd: str
    owned: bool
    refusal: str = ""     # why this pid will NOT be touched, when not owned


def _pid_cwd(pid: int) -> Optional[str]:
    try:
        return str(Path("/proc/%d/cwd" % pid).readlink())
    except OSError:
        return None


def owns(lane: Lane, pid: int, port: int) -> Tuple[bool, str]:
    """(owned, refusal reason).  Every test must pass; the first failure
    is the refusal that gets reported."""
    if port not in lane.port_range():
        return False, "port %d is outside this lane's range %d-%d" % (
            port, lane.port_base, lane.port_base + lane.port_span - 1,
        )
    cwd = _pid_cwd(pid)
    if cwd is None:
        return False, "pid %d cwd is unreadable — cannot prove lane identity" % pid
    if not lane.contains_path(Path(cwd)):
        return False, "pid %d runs outside the lane root (%s)" % (pid, cwd)
    owner = lane.owner()
    if owner is not None and owner.pid != os.getpid() and owner.alive():
        return False, (
            "lane is owned by live session %s (pid %d, since %s) — "
            "not reaping under a living owner" % (owner.session, owner.pid, owner.started_at)
        )
    return True, ""


def find_orphans(lane: Lane) -> List[Orphan]:
    """Survey the lane's port range for listeners and classify each."""
    orphans: List[Orphan] = []
    for port in sorted(listening_ports(lane.port_range())):
        for pid in sorted(pids_on_port(port)):
            if pid == os.getpid():
                continue
            owned, refusal = owns(lane, pid, port)
            orphans.append(Orphan(pid, port, _pid_cwd(pid) or "?", owned, refusal))
    return orphans


def _signal(pids, selected: signal.Signals) -> None:
    for pid in pids:
        with contextlib.suppress(OSError):
            os.kill(pid, selected)


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_exit(pids, grace: float) -> set[int]:
    deadline = time.monotonic() + grace
    pending = set(pids)
    while pending and time.monotonic() < deadline:
        pending = {pid for pid in pending if _process_exists(pid)}
        if pending:
            time.sleep(0.1)
    return pending


def reap(lane: Lane, *, grace: float = 3.0) -> Tuple[List[Orphan], List[Orphan]]:
    """SIGTERM (then SIGKILL after ``grace``) every *owned* orphan.

    Returns (reaped, refused).  Refused pids are reported, never
    signalled — the foreign listener is not modified.
    """
    survey = find_orphans(lane)
    owned, refused = _partition_orphans(survey)
    _terminate_owned(owned, grace)
    emit("orphans.reaped", reaped=len(owned), refused=len(refused))
    return owned, refused


def _partition_orphans(survey: List[Orphan]) -> tuple[List[Orphan], List[Orphan]]:
    owned, refused = [], []
    for orphan in survey:
        destination = owned if orphan.owned else refused
        destination.append(orphan)
    return owned, refused


def _terminate_owned(owned: List[Orphan], grace: float) -> None:
    _signal((orphan.pid for orphan in owned), signal.SIGTERM)
    if owned:
        _signal(_wait_for_exit((orphan.pid for orphan in owned), grace), signal.SIGKILL)
