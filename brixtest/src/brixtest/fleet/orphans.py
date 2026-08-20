"""Ownership-checked orphan reaping (feature F9).

The reaper exists because crashed sessions leave listeners behind, and
the *wrong* reaper once existed: a substring match on lane roots let
one lane SIGTERM every lane whose root merely started with its own
(recorded in the suite's incident history).  This module is that
lesson as code — a process is reaped only when **every** ownership
test passes, and refusal is loud and specific, never silent.

Ownership tests, all required:

1. the pid's cwd (or an argv path) resolves **inside** this lane's
   root — exact-prefix via ``Lane.contains_path``, never substring;
2. the port it holds is inside this lane's port range;
3. the lane's ownership record, if present, names a dead session —
   a live foreign owner turns reaping into refusal.
"""

from __future__ import annotations

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
        return os.readlink("/proc/%d/cwd" % pid)
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


def reap(lane: Lane, *, grace: float = 3.0) -> Tuple[List[Orphan], List[Orphan]]:
    """SIGTERM (then SIGKILL after ``grace``) every *owned* orphan.

    Returns (reaped, refused).  Refused pids are reported, never
    signalled — the foreign listener is not modified.
    """
    survey = find_orphans(lane)
    owned = [o for o in survey if o.owned]
    refused = [o for o in survey if not o.owned]
    for orphan in owned:
        try:
            os.kill(orphan.pid, signal.SIGTERM)
        except OSError:
            continue
    if owned:
        deadline = time.monotonic() + grace
        pending = {o.pid for o in owned}
        while pending and time.monotonic() < deadline:
            for pid in list(pending):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pending.discard(pid)
            if pending:
                time.sleep(0.1)
        for pid in pending:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    emit("orphans.reaped", reaped=len(owned), refused=len(refused))
    return owned, refused
