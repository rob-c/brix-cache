"""Python ports for top-level operator/runtime shell entrypoints."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cmdscripts.compile_run import REPO_ROOT, result, run
from settings import BIND_HOST, HOST, TEST_PORT_START
from port_ladder import PORT_COUNT


TESTS = REPO_ROOT / "tests"


def _tail(proc: subprocess.CompletedProcess, limit: int = 3000) -> str:
    return (proc.stderr or proc.stdout or "")[-limit:]


def _popen(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout=None,
    stderr=None,
    stdin=None,
    start_new_session: bool = False,
) -> subprocess.Popen:
    return subprocess.Popen(
        argv,
        cwd=str(cwd or REPO_ROOT),
        env={**os.environ, **(env or {})},
        text=True,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        start_new_session=start_new_session,
    )


def _run_stream(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> int:
    proc = _popen(argv, cwd=cwd, env=env)
    return int(proc.wait())


def _wait_tcp(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _safe_kill(pid: int, sig: int = signal.SIGTERM) -> None:
    try:
        os.kill(pid, sig)
    except OSError:
        pass


def _process_cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore")
    except OSError:
        return ""


def _pgrep_name(name: str) -> list[int]:
    proc = run(["pgrep", "-x", name], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return []
    pids = []
    for text in proc.stdout.split():
        try:
            pids.append(int(text))
        except ValueError:
            pass
    return pids


def clean_test_fleet(test_root: Path = Path("/tmp/xrd-test")) -> None:
    # Cross-lane shared state: the default credential store on tmpfs is owned
    # by whichever lane's worker identity touched it last (root lane -> nobody,
    # unprivileged lane -> the test user).  A store left by the OTHER lane is
    # 0700 foreign-owned, so this lane's workers EACCES every delegation PUT
    # and the config-time ensure shouts ownership warnings that trip the
    # credential tests.  It holds only throwaway test delegations — wipe it
    # (best-effort: unprivileged we may not own it, but then the pre-existing
    # skip guards apply).
    shutil.rmtree("/dev/shm/brix-creds", ignore_errors=True)
    owned: set[int] = set()
    root_marker = str(test_root.resolve())
    for name in ("nginx", "xrootd", "cmsd", "krb5kdc", "kadmind", "haproxy"):
        for pid in _pgrep_name(name):
            if root_marker in _process_cmdline(pid):
                owned.add(pid)
                _safe_kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 3
    while owned and time.monotonic() < deadline:
        owned = {pid for pid in owned if Path(f"/proc/{pid}").exists()}
        if owned:
            time.sleep(0.05)
    for pid in owned:
        if root_marker in _process_cmdline(pid):
            _safe_kill(pid, signal.SIGKILL)

    # A killed nginx master can leave workers whose rewritten process title no
    # longer contains TEST_ROOT. Likewise, an interrupted earlier invocation may
    # have used another root with this same explicitly-selected port ladder.
    # Those listeners make the new suite fail hundreds of tests with EADDRINUSE.
    # The configured ladder is exclusive to this invocation, so reap only known
    # test-server executables that are actually listening inside that exact band.
    from lib_py.util import kill_pid_list, pids_in_port_range  # noqa: PLC0415

    listeners = pids_in_port_range(TEST_PORT_START, TEST_PORT_START + PORT_COUNT)
    stale = []
    for pid in listeners:
        cmdline = _process_cmdline(pid).strip()
        executable = Path(f"/proc/{pid}/exe")
        try:
            exe_name = executable.resolve().name
        except OSError:
            continue
        if exe_name in {"nginx", "xrootd", "cmsd", "haproxy"} or \
                cmdline.startswith("nginx: worker process"):
            stale.append(pid)
    if stale:
        kill_pid_list(stale)


def teardown_test_fleet(test_root: Path) -> None:
    """Stop through the registry helper, then reap exact-root stragglers."""
    subprocess.run(
        [sys.executable, "-m", "cmdscripts.manage_test_servers", "stop-all"],
        cwd=str(TESTS),
        env={**os.environ, "TEST_ROOT": str(test_root), "PYTHONPATH": str(TESTS)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    clean_test_fleet(test_root)


def _prepare_test_root(test_root: Path) -> bool:
    """Create the suite ownership root, reporting unusable paths cleanly."""
    try:
        test_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: cannot create TEST_ROOT={test_root}: {exc}", file=sys.stderr)
        return False
    return True


def _resolve_suite_binary(value: str, option: str) -> str | None:
    """Resolve a suite server binary from either a path or a PATH command."""
    expanded = os.path.expanduser(value)
    if os.sep in expanded:
        resolved = os.path.abspath(expanded)
        if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
            return resolved
    else:
        found = shutil.which(expanded)
        if found:
            return os.path.abspath(found)
    print(f"ERROR: {option} is not an executable file or command: {value}", file=sys.stderr)
    return None


def _configure_suite_binaries(nginx: str, xrootd: str) -> bool:
    """Publish canonical server choices to registry and legacy helpers."""
    nginx_bin = _resolve_suite_binary(nginx, "--nginx-bin")
    xrootd_bin = _resolve_suite_binary(xrootd, "--xrootd-bin")
    if nginx_bin is None or xrootd_bin is None:
        return False
    os.environ.update({
        "TEST_NGINX_BIN": nginx_bin,
        "NGINX_BIN": nginx_bin,
        "TEST_BRIX_BIN": xrootd_bin,
        "BRIX_BIN": xrootd_bin,
        "XROOTD_BIN": xrootd_bin,
        "REF_BIN": xrootd_bin,
    })
    return True


def _nginx_modules_path(nginx_bin: str) -> Path | None:
    """Read the packaged module directory from the selected nginx build."""
    try:
        probe = run([nginx_bin, "-V"])
    except OSError:
        return None
    output = f"{probe.stdout}\n{probe.stderr}"
    if probe.returncode != 0 or "--with-stream=dynamic" not in output:
        return None
    match = re.search(r"--modules-path=(?:'([^']+)'|\"([^\"]+)\"|(\S+))", output)
    if not match:
        return None
    return Path(next(group for group in match.groups() if group))


def _configure_nginx_modules(nginx_bin: str, requested: list[str]) -> bool:
    """Validate modules and discover the distro's dynamic stream dependency."""
    candidates = list(requested)
    if candidates and not any(Path(value).name == "ngx_stream_module.so"
                              for value in candidates):
        module_dir = _nginx_modules_path(nginx_bin)
        stream_module = module_dir / "ngx_stream_module.so" if module_dir else None
        if stream_module is not None and stream_module.is_file():
            candidates.insert(0, str(stream_module))
    if not candidates:
        module_dir = _nginx_modules_path(nginx_bin)
        if module_dir is not None:
            candidates = [
                str(module_dir / "ngx_stream_module.so"),
                str(module_dir / "ngx_stream_brix_module.so"),
                str(module_dir / "ngx_http_brix_xrdhttp_filter_module.so"),
            ]
            if not all(Path(path).is_file() for path in candidates):
                candidates = []
    resolved: list[str] = []
    for value in candidates:
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            print(f"ERROR: --nginx-load-module is not a file: {value}", file=sys.stderr)
            return False
        resolved.append(str(path))
    if resolved:
        os.environ["TEST_NGINX_LOAD_MODULES"] = os.pathsep.join(resolved)
    else:
        os.environ.pop("TEST_NGINX_LOAD_MODULES", None)
    return True


def _existing(paths: Iterable[str]) -> list[str]:
    kept = []
    for rel in paths:
        if (REPO_ROOT / rel).exists():
            kept.append(rel)
        else:
            print(f"WARNING: path missing, skipping: {rel}", file=sys.stderr)
    return kept


DESTRUCTIVE = [
    "tests/test_chaos_mesh.py",
    "tests/test_chaos_mixed_auth.py",
    "tests/test_cms_resilience.py",
    "tests/test_compression_fuse_resilience.py",
    "tests/test_evil_actor.py",
    "tests/test_evil_actor_v2.py",
    "tests/test_evil_actor_v3.py",
    "tests/test_evil_actor_v3_b.py",
    "tests/test_evil_paths.py",
    "tests/test_netfault_stream.py",
    "tests/test_net_resilience.py",
    "tests/test_official_xrootd_resilience.py",
    "tests/test_phase51_resilience.py",
    "tests/test_xrootdfs_resilience.py",
    "tests/resilience",
]

CLIENTCONF = [
    "tests/test_clientconf_cksum.py",
    "tests/test_clientconf_narrative.py",
    "tests/test_clientconf_surface.py",
    "tests/test_clientconf_xrdcp.py",
    "tests/test_clientconf_xrdfs.py",
    "tests/test_clientconf_xrdgsiproxy.py",
    "tests/test_clientconf_xrdmapc.py",
]


def _pytest_lane(selection: list[str], main: list[str], common: list[str]) -> bool:
    # Single pass, no retry ladder: a first-run failure is the signal to fix,
    # not something to launder through --lf reruns.
    return _run_stream([sys.executable, "-m", "pytest", *selection, *main, *common]) == 0


def _serial_lane(selection: list[str], common: list[str]) -> bool:
    """Run serially while keeping xdist loaded and disabling ini xdist args."""
    return _pytest_lane(selection, ["-n", "0", "-o", "addopts="], common)


class FleetSentinelAbort(Exception):
    """A lane's fleet sentinel detected a shared server being killed/crashed.

    Raised after a lane so the suite driver halts the remaining lanes instead of
    running them against a damaged fleet (which would spray ConnectionRefused).
    """


def _sentinel_marker(test_root: Path) -> Path:
    root = os.environ.get("TEST_REGISTRY_ROOT") or str(test_root / "registry")
    return Path(root) / ".fleet-sentinel-abort"


def clear_sentinel_marker(test_root: Path) -> None:
    try:
        _sentinel_marker(test_root).unlink()
    except OSError:
        pass


def _raise_if_sentinel_tripped(test_root: Path) -> None:
    marker = _sentinel_marker(test_root)
    try:
        body = marker.read_text(encoding="utf-8") if marker.exists() else ""
    except OSError:
        body = ""
    if body:
        raise FleetSentinelAbort(body)


def _suite_lane(
    test_root: Path,
    selection: list[str],
    main: list[str],
    common: list[str],
) -> bool:
    """Run one lane and guarantee teardown even on Ctrl-C or pytest failure.

    After teardown, re-raise as ``FleetSentinelAbort`` if the lane's sentinel
    tripped, so the suite stops before wasting the remaining lanes on a fleet a
    test already damaged."""
    try:
        return _pytest_lane(selection, main, common)
    finally:
        teardown_test_fleet(test_root)
        _raise_if_sentinel_tripped(test_root)


def _suite_serial_lane(test_root: Path, selection: list[str], common: list[str]) -> bool:
    try:
        return _serial_lane(selection, common)
    finally:
        teardown_test_fleet(test_root)
        _raise_if_sentinel_tripped(test_root)

# These are physical continuations, not independent modules: their functions
# intentionally use the launch/cleanup helpers defined above.  Execute them in
# this module's namespace so ``python -m cmdscripts.operator_runtime`` retains
# the pre-split semantics (ordinary imports give each part isolated globals).
for _part_name in ("operator_runtime_part2.py", "operator_runtime_part3.py",
                   "operator_runtime_part4.py"):
    _part_path = Path(__file__).with_name(_part_name)
    exec(compile(_part_path.read_text(encoding="utf-8"), str(_part_path), "exec"),
         globals())
del _part_name, _part_path
