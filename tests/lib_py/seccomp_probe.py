"""Observe actual nginx workers after init_process has installed their filter."""

from pathlib import Path
import time

from lib_py.util import children_of, process_cmdline
from lib_py.process_host import nginx_worker_title


def _seccomp_mode(pid):
    """Return the kernel's filter mode, never infer it from a log message."""
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    return next((line.split()[1] for line in lines if line.startswith("Seccomp:")), None)


def _worker_modes(master):
    """Exclude helpers and managers rather than selecting the first child."""
    return [_seccomp_mode(pid) for pid in children_of(master)
            if nginx_worker_title(process_cmdline(pid))]


def _observed_modes(modes):
    """Make missing or mixed filter states visible to the caller's assertion."""
    if not modes:
        return None
    return ",".join(sorted({mode or "unknown" for mode in modes}))


def worker_seccomp(prefix, timeout=10):
    """Return '2' only when every observed worker is filtered, or the last modes.

    A bound listening socket is not worker-init readiness: it may already accept
    connections while init_process is still setting up its seccomp filter. Do
    not mistake a cache manager or the transient startup mode for a worker.
    """
    master = int((Path(prefix) / "logs/nginx.pid").read_text(encoding="utf-8"))
    deadline = time.monotonic() + timeout
    while True:
        modes = _worker_modes(master)
        observed = _observed_modes(modes)
        if observed == "2":
            return "2"
        if time.monotonic() >= deadline:
            return observed
        time.sleep(0.05)
