"""Utility helpers replacing tests/lib/util.sh."""

from __future__ import annotations

from pathlib import Path
import os
import functools
import re
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


def true_command() -> str:
    """Absolute path of true(1): a program that exits 0 and does nothing.

    The suite uses it as the do-nothing default for configured hooks (the
    stage command an export runs). "/bin/true" is where Linux keeps it; macOS
    keeps true(1) in /usr/bin and has no /bin/true at all, so a hardcoded path
    makes the SERVER fail to exec its own default hook. Resolve it on PATH and
    fall back to the merged-/usr location both platforms have.
    """
    return shutil.which("true") or "/usr/bin/true"


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
    return _homebrew_xrd_library(name)


def _homebrew_xrd_library(name):
    """Homebrew (macOS) keeps XRootD's plugins under its prefix and ships the
    next soversion (libXrdSec-6.so); accept any soversion of the same stem."""
    pattern = re.sub(r"-\d+\.so$", "-*.so", name)
    for root in (Path("/usr/local/lib"), Path("/opt/homebrew/lib")):
        found = _library_below(root, name)
        if found:
            return found
        for candidate in sorted(root.glob(pattern)):
            if candidate.is_file():
                return candidate.resolve()
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


def children_of(master: int) -> set[int]:
    """Pids whose parent is ``master`` (procfs on Linux, pgrep -P elsewhere).

    Used to find an nginx master's workers by pid file rather than by name,
    since the suite runs many masters at once."""
    if not os.path.isdir("/proc"):
        out = run(["pgrep", "-P", str(master)]).stdout
        return {int(tok) for tok in out.split() if tok.isdigit()}
    return {pid for pid in (int(e) for e in os.listdir("/proc") if e.isdigit())
            if _procfs_ppid(pid) == master}


def _procfs_ppid(pid: int) -> int:
    """Parent pid from /proc/<pid>/stat, 0 if the process is already gone.
    comm can contain spaces and parens; the fields start after the last ')'."""
    try:
        with open(f"/proc/{pid}/stat") as handle:
            stat = handle.read()
    except OSError:
        return 0                          # exited between listdir and open
    return int(stat[stat.rindex(")") + 2:].split()[1])


def process_cmdline(pid: int) -> bytes:
    """The argv of ``pid`` as one space-joined byte string, or b"" if gone.

    Linux reads /proc/<pid>/cmdline; hosts without procfs (Darwin/BSD) ask
    ps(1).  Callers match a fleet prefix against it before signalling a pid
    read back from a pidfile, so an unreadable process must come back empty
    (never raise) — empty means "do not touch".
    """
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            return handle.read().replace(b"\0", b" ")
    except OSError:
        if os.path.isdir("/proc"):
            return b""
    try:
        out = subprocess.run(
            ["ps", "-o", "command=", "-p", str(pid)],
            capture_output=True, check=False, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return b""
    return out.strip()


def _ss_row_peer_port(line: str) -> str | None:
    """The PEER port of one ``ss -tn`` row (``State Recv-Q Send-Q local peer``).

    None when the row has no peer column, which is what the header line and any
    short/oddly-formatted row look like.
    """
    fields = line.split()
    if len(fields) < 5:
        return None
    return fields[4].rsplit(":", 1)[-1]


def _ss_established_to_port(port: int | str) -> int:
    """Rows whose PEER port is ``port`` — the column, not a substring search.

    A LOOPBACK connection appears in ``ss -tn`` TWICE, once from each end, and
    both rows carry the port: matching ``f":{port}" in line`` therefore returned
    2 for a single connection, and every count in this suite is of a connection
    to 127.0.0.1.  That is what failed `test_manager_mode`'s per-worker CMS
    assertion — the node's ONE gated upstream link read as the two-worker
    self-collision the gate exists to prevent.  The netstat and lsof arms below
    always compared the peer end; this one now does too.
    """
    return sum(1 for line in run(["ss", "-tn"]).stdout.splitlines()
               if "ESTAB" in line and _ss_row_peer_port(line) == str(port))


def _lsof_established_to_port(port: int | str) -> int:
    out = run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:ESTABLISHED", "-F", "n"]).stdout
    return sum(1 for line in out.splitlines()
               if line.startswith("n") and line.rsplit("->", 1)[-1].endswith(f":{port}"))


def established_to_port(port: int | str) -> int:
    """TCP connections whose REMOTE end is ``port`` (ss -tn, or netstat/lsof elsewhere)."""
    if have_cmd("ss"):
        return _ss_established_to_port(port)
    if have_cmd("netstat"):
        return sum(1 for _l, foreign, _p in _darwin_netstat_rows("ESTABLISHED")
                   if _darwin_addr_port(foreign) == str(port))
    return _lsof_established_to_port(port) if have_cmd("lsof") else 0


def _darwin_netstat_rows(state: str) -> list[tuple[str, str, int]]:
    """``[(local, foreign, pid)]`` TCP sockets in ``state`` from ``netstat -anv``.

    The kernel table, read in one call — unlike lsof(8), which walks every
    process's descriptors and stalls for tens of seconds on a loaded host
    (817 processes, 8 xdist workers).  Column 11 is the owning pid on Darwin.
    """
    try:
        out = run(["netstat", "-anv", "-p", "tcp"]).stdout
    except OSError:
        return []
    rows = []
    for line in out.splitlines():
        f = line.split()
        if len(f) > 10 and f[0].startswith("tcp") and f[5] == state and f[10].isdigit():
            rows.append((f[3], f[4], int(f[10])))
    return rows


def close_wait_on_ports(ports) -> int:
    """TCP connections in CLOSE_WAIT whose LOCAL port is one of ``ports``.

    CLOSE_WAIT is the descriptor-leak signal: the peer closed and our process
    still holds the fd. Linux reads it from /proc/net/tcp (state 08); a host
    with no procfs reads the same thing out of the kernel's own table via
    netstat, so the check keeps working instead of silently counting zero and
    passing (which is what a bare FileNotFoundError guard does on Darwin).
    """
    wanted = {int(p) for p in ports}
    if os.path.exists("/proc/net/tcp"):
        return _procfs_close_wait(wanted)
    return sum(1 for local, _foreign, _pid in _darwin_netstat_rows("CLOSE_WAIT")
               if _darwin_addr_port(local).isdigit()
               and int(_darwin_addr_port(local)) in wanted)


def _procfs_close_wait(wanted: set) -> int:
    """CLOSE_WAIT (state 08) rows of /proc/net/tcp on one of ``wanted``."""
    count = 0
    try:
        with open("/proc/net/tcp", "r") as stream:
            for line in stream:
                fields = line.split()
                if len(fields) < 4 or ":" not in fields[1]:
                    continue                  # header or malformed row
                if fields[3] != "08":
                    continue
                if int(fields[1].split(":")[1], 16) in wanted:
                    count += 1
    except (OSError, ValueError):
        pass
    return count


def _darwin_addr_port(addr: str) -> str:
    return addr.rsplit(".", 1)[-1]        # "127.0.0.1.10005" / "*.10005" / "::1.10005"


def _netstat_listener_lines() -> list[str]:
    return [f'LISTEN 0 128 {local.rsplit(".", 1)[0]}:{_darwin_addr_port(local)} 0.0.0.0:* '  # net-literal-allow: the peer column of an `ss -tlnp` line — the OUTPUT SHAPE synthesized here, not a target
            f'users:(("?",pid={pid},fd=0))'
            for local, _foreign, pid in _darwin_netstat_rows("LISTEN")]


def _lsof_listener_lines() -> list[str]:
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"]).stdout
    lines, pid, comm = [], None, ""
    for field in out.splitlines():
        tag, value = field[:1], field[1:]
        if tag == "p":
            pid, comm = value, ""
        elif tag == "c":
            comm = value
        elif tag == "n" and pid is not None:
            lines.append(f'LISTEN 0 128 {value} 0.0.0.0:* users:(("{comm}",pid={pid},fd=0))')  # net-literal-allow: the `ss -tlnp` peer column again
    return lines


def listener_table_lines() -> list[str]:
    """Every TCP listener as ``ss -tlnp``-shaped lines.

    ``ss`` output where it exists; elsewhere (Darwin/BSD) the same shape is
    synthesized from ``netstat`` or ``lsof`` so the mesh/fleet sweeps that grep
    for ``:<port> `` and ``pid=<n>,`` keep working unchanged:
    ``LISTEN 0 128 127.0.0.1:11799 0.0.0.0:* users:(("nginx",pid=23509,fd=6))``
    """
    if have_cmd("ss"):
        return run(["ss", "-tlnp"]).stdout.splitlines()
    if have_cmd("netstat"):
        return _netstat_listener_lines()
    return _lsof_listener_lines() if have_cmd("lsof") else []


def budget_scale() -> float:
    """``TEST_BUDGET_SCALE``: a wall-clock multiplier for a slower or shared
    host (1.0 on the CI reference).  Unparseable or non-positive ⇒ 1.0, so a
    typo can never shrink a budget to nothing."""
    try:
        value = float(os.environ.get("TEST_BUDGET_SCALE", "1"))
    except ValueError:
        return 1.0
    return value if value > 0 else 1.0


@functools.lru_cache(maxsize=None)
def loopback_alias_usable(addr: str) -> bool:
    """Whether a socket can bind ``addr``, a loopback address other than
    127.0.0.1.

    Linux routes the whole 127.0.0.0/8 to lo; macOS assigns only 127.0.0.1, so
    binding 127.0.0.2 fails with EADDRNOTAVAIL until an alias is added
    (``sudo ifconfig lo0 alias 127.0.0.2 up``, which does not survive a
    reboot).  Cached: the answer cannot change inside one test session without
    an administrator's intervention.

    The port comes from the session's mock lease rather than the kernel: a
    ``bind((addr, 0))`` here is indistinguishable to
    ``test_fleet_port_uniqueness`` from a test opening an unledgered listener,
    and the lane's TEST_PORT_START range can overlap the host's ephemeral one.
    A leased port cannot be in use by anything else in the lane, so it cannot
    turn a usable alias into a false negative."""
    from ephemeral_port import free_port  # noqa: PLC0415 — tests-root helper

    probe = socket.socket()
    try:
        probe.bind((addr, free_port()))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def pid_alive(pid) -> bool:
    """Whether ``pid`` still exists.

    ``/proc/<pid>`` where procfs is mounted (Linux); ``kill(pid, 0)`` elsewhere
    (macOS has no procfs at all).  EPERM means the process exists but belongs
    to another user, which is still alive."""
    if os.path.isdir("/proc"):
        return os.path.exists(f"/proc/{int(pid)}")
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def linked_libraries(binary: str) -> str:
    """The dynamic libraries ``binary`` links, one per line: ``ldd`` where it
    exists, ``otool -L`` on Darwin (which has no ldd).  Empty on failure."""
    tool = ["ldd", binary] if have_cmd("ldd") else ["otool", "-L", binary]
    try:
        return run(tool).stdout
    except OSError:
        return ""


def _lsof_listener_pids(port: int | str) -> list[int]:
    """Every pid listening on ``port``, from lsof (authoritative)."""
    output = run(["lsof", "-t", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"]).stdout
    return sorted({int(value) for value in output.split() if value.isdigit()})


def _netstat_listener_pids(port: int | str) -> list[int]:
    """Last resort: netstat credits a socket to ONE pid, so this can miss the
    other holders (a pre-forking master).  Used only where lsof is absent."""
    return sorted({pid for local, _f, pid in _darwin_netstat_rows("LISTEN")
                   if _darwin_addr_port(local) == str(port)})


def _netstat_has_listener(port: int | str) -> bool:
    """Whether ANYTHING listens on ``port``, from one cheap kernel table read.

    lsof walks every process's network descriptors, which costs real time on a
    busy host (1000+ processes under a full fleet); netstat cannot say WHICH
    processes hold the socket, but it can say whether the port is occupied at
    all — and the common case, a fresh port nobody holds, then needs no lsof.
    """
    return any(_darwin_addr_port(local) == str(port)
               for local, _foreign, _pid in _darwin_netstat_rows("LISTEN"))


def pids_on_port(port: int | str) -> list[int]:
    """EVERY pid holding a listener on ``port``.

    "Every" is the whole point: callers reap a leaked server by killing what
    this returns, and a pre-forking master respawns its worker, so a list that
    names only the worker frees nothing.  ``ss -ltnp`` lists them all; Darwin's
    netstat credits the socket to ONE pid (the worker), so lsof — authoritative
    and, restricted to network descriptors, ~0.2 s even on a loaded host — is
    used there instead.
    """
    if have_cmd("ss"):
        return sorted(_pids_in_text(
            run(["ss", "-ltnp", f"( sport = :{port} )"]).stdout))
    if have_cmd("netstat") and not _netstat_has_listener(port):
        return []               # cheap and decisive: nothing holds the port
    if have_cmd("lsof"):
        return _lsof_listener_pids(port)
    return _netstat_listener_pids(port)


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
    if not have_cmd("ss") and not have_cmd("lsof"):
        return None
    listeners: dict[int, set[int]] = {}
    for line in listener_table_lines():        # ss(8), or lsof-derived
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
    """Wait for something to accept on ``host:port``; True once it does.

    ``timeout`` is a CI-reference budget and is stretched by
    ``TEST_BUDGET_SCALE`` like every other wall-clock budget in the suite. Its
    callers are waiting for a process to finish starting, and on a busy host
    that takes longer for reasons that have nothing to do with the code under
    test: a 10 s wait for a mock Stratum-1 to bind expired at load average
    200+ and failed the lane (2026-09-17). Nothing here waits for a port to
    STAY closed, so a longer budget can only avoid a false negative.
    """
    deadline = time.time() + timeout * budget_scale()
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
