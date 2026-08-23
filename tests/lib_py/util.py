"""Utility helpers replacing tests/lib/util.sh."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import socket
import subprocess
import time


def run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **(env or {})},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def render_cfg(template: Path, dest: Path, **values: str) -> None:
    text = template.read_text()
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text)


def have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def find_xrd_library(*names: str) -> Path | None:
    """Find an XRootD library across RPM, Debian multiarch, and ldconfig layouts."""
    for name in names:
        found = _direct_xrd_library(name)
        if found:
            return found
    return _ldconfig_xrd_library(names)


def _direct_xrd_library(name):
    requested = Path(name)
    if requested.is_absolute() and requested.is_file():
        return requested.resolve()
    roots = (Path("/usr/lib64"), Path("/usr/lib"), Path("/lib64"), Path("/lib"))
    for root in roots:
        found = _library_below(root, name)
        if found:
            return found
    return None


def _library_below(root, name):
    candidate = root / name
    if candidate.is_file():
        return candidate.resolve()
    for multiarch in root.glob(f"*/{name}"):
        if multiarch.is_file():
            return multiarch.resolve()
    return None


def _ldconfig_xrd_library(names):
    if not shutil.which("ldconfig"):
        return None
    wanted = set(names)
    for line in run(["ldconfig", "-p"]).stdout.splitlines():
        found = _ldconfig_line_library(line, wanted)
        if found:
            return found
    return None


def _ldconfig_line_library(line, wanted):
    fields = line.strip().split()
    if not fields or fields[0] not in wanted or "=>" not in fields:
        return None
    candidate = Path(fields[-1])
    return candidate.resolve() if candidate.is_file() else None


def find_xrd_sec_lib() -> Path | None:
    return find_xrd_library("libXrdSec-5.so", "libXrdSec.so")


def pids_on_port(port: int | str) -> list[int]:
    if have_cmd("ss"):
        output = run(["ss", "-ltnp", f"( sport = :{port} )"]).stdout
        return sorted(_pids_in_text(output))
    if have_cmd("lsof"):
        output = run(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"]).stdout
        return sorted({int(value) for value in output.split() if value.isdigit()})
    return []


def _pids_in_text(text):
    pids = set()
    for part in text.replace(",", " ").split():
        pid = _pid_field(part)
        if pid is not None:
            pids.add(pid)
    return pids


def _pid_field(part):
    if not part.startswith("pid="):
        return None
    try:
        return int(part.split("=", 1)[1])
    except ValueError:
        return None


def listening_port_pids() -> dict[int, set[int]] | None:
    """One `ss -ltnp` survey of every TCP listener: port -> owning PIDs.

    A single fleet-wide survey costs about the same as one per-port query, so
    callers that would otherwise probe many ports (the ~127-port fleet teardown
    sweep) take this snapshot once instead of spawning one subprocess per port.
    A port whose PIDs are unreadable (another user's process) still appears as
    a key with an empty set — presence means "someone is listening", so callers
    must key quiescence off membership, not off the PID set being non-empty.
    Returns None when `ss` is unavailable; callers fall back to per-port scans.
    """
    if not have_cmd("ss"):
        return None
    proc = run(["ss", "-ltnp"])
    listeners: dict[int, set[int]] = {}
    for line in proc.stdout.splitlines():
        port = _listener_port(line)
        if port is not None:
            listeners.setdefault(port, set()).update(_pids_in_text(line))
    return listeners


def _listener_port(line):
    fields = line.split()
    if len(fields) < 4:
        return None
    endpoint = fields[3].rsplit(":", 1)[-1]
    return int(endpoint) if endpoint.isdigit() else None


def pids_in_port_range(start: int, end: int) -> list[int]:
    """Return listener PIDs in the half-open port range using one survey."""
    listeners = listening_port_pids()
    if listeners is not None:
        pids: set[int] = set()
        for port, port_pids in listeners.items():
            if start <= port < end:
                pids.update(port_pids)
        return sorted(pids)
    pids = set()
    for port in range(start, end):
        pids.update(pids_on_port(port))
    return sorted(pids)


_CLK_TCK = os.sysconf("SC_CLK_TCK")


def process_age(pid: int) -> float | None:
    """Seconds the process ``pid`` has been alive, or ``None`` if it is gone.

    Read from ``/proc/<pid>/stat`` field 22 (``starttime``, in clock ticks
    since boot) against ``/proc/uptime`` — no ``ps`` fork, and immune to PID
    reuse within the read because a vanished/replaced pid surfaces as an
    ``OSError``/parse miss rather than a stale age.  The ``comm`` field can
    contain spaces and parentheses, so split *after* its final ``)``.
    """
    try:
        with open(f"/proc/{pid}/stat", "r") as fh:
            data = fh.read()
        with open("/proc/uptime", "r") as fh:
            uptime = float(fh.read().split()[0])
    except (OSError, ValueError):
        return None
    try:
        after_comm = data[data.rindex(")") + 2:].split()
        starttime = int(after_comm[19])  # field 22, 0-based past state
    except (ValueError, IndexError):
        return None
    return uptime - starttime / _CLK_TCK


def kill_pid_list(pids: list[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    time.sleep(0.3)
    for pid in pids:
        try:
            os.kill(pid, 0)
        except OSError:
            continue
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def wait_tcp(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def wait_ready_xrdfs(url: str, tries: int = 30, sleep_s: float = 0.5) -> bool:
    hostport = url.removeprefix("root://").split("/", 1)[0]
    host, _, port_text = hostport.partition(":")
    if port_text and not wait_tcp(host, int(port_text), tries * sleep_s):
        return False
    if not have_cmd("xrdfs"):
        return True
    for _ in range(10):
        proc = run(["xrdfs", url, "ls", "/"])
        if proc.returncode == 0:
            return True
        time.sleep(0.1)
    return False
