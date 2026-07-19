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
    for name in names:
        for root in (Path("/usr/lib64"), Path("/usr/lib")):
            candidate = root / name
            if candidate.exists():
                return candidate
    return None


def find_xrd_sec_lib() -> Path | None:
    return find_xrd_library("libXrdSec-5.so", "libXrdSec.so")


def pids_on_port(port: int | str) -> list[int]:
    if have_cmd("ss"):
        proc = run(["ss", "-ltnp", f"( sport = :{port} )"])
        pids = set()
        for part in proc.stdout.replace(",", " ").split():
            if part.startswith("pid="):
                try:
                    pids.add(int(part.split("=", 1)[1]))
                except ValueError:
                    pass
        return sorted(pids)
    if have_cmd("lsof"):
        proc = run(["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"])
        return sorted({int(p) for p in proc.stdout.split() if p.isdigit()})
    return []


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

