"""
Chaos Mesh integration tests from docs/comprehensive-testing-roadmap.md.

These are the first no-mock slices of the roadmap topology:

  * delayed CMS discovery with a real data server that starts before its
    CMS/redirector, then reconnects and registers through the real CMS path;
  * Tier1 proxy -> Tier2 read-through cache -> Tier3 storage, with Tier2
    reloaded while the client reads a cache-filled file.
"""

import hashlib
import os
import platform
import signal
import socket
import struct
import time
import uuid
from pathlib import Path

import pytest

from settings import (
    CHAOS_DISCOVERY_DS_PORT,
    CHAOS_DISCOVERY_REDIR_PORT,
    CHAOS_TIER1_PORT,
    CHAOS_TIER2_CACHE_ROOT,
    CHAOS_TIER2_PORT,
    CHAOS_TIER3_DATA_ROOT,
    CHAOS_TIER3_PORT,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_BIN,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    REGISTRY_ROOT,
    S3_BUCKET,
    SERVER_HOST,
    TEST_ROOT,
)


def _require(condition, message):
    if not condition:
        raise AssertionError(message)
from test_manager_mode import _wait_for_redirect, _wait_port
from test_proxy_mode import (
    _close,
    _connect,
    _fh,
    _read,
    _read_resp_all,
    _read_resp,
    kXR_ok,
    kXR_open,
    kXR_open_read,
    kXR_open_updt,
    kXR_new,
    kXR_read,
)


pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.serial,
]

CHAOS_FILE_SIZE = 32 * 1024 * 1024
READ_CHUNK = 512 * 1024
RELOAD_AFTER_BYTES = 4 * 1024 * 1024


@pytest.fixture(scope="module")
def chaos_mesh():
    """Wait for the dedicated Chaos Mesh fleet started by manage_test_servers.sh."""
    ports = (
        CHAOS_TIER1_PORT,
        CHAOS_TIER2_PORT,
        CHAOS_TIER3_PORT,
        CHAOS_DISCOVERY_REDIR_PORT,
        CHAOS_DISCOVERY_DS_PORT,
    )
    for port in ports:
        _wait_port(port, f"chaos mesh port {port}", timeout=30.0)
    return {
        "tier1": CHAOS_TIER1_PORT,
        "tier2": CHAOS_TIER2_PORT,
        "tier3": CHAOS_TIER3_PORT,
        "discovery_redir": CHAOS_DISCOVERY_REDIR_PORT,
        "discovery_ds": CHAOS_DISCOVERY_DS_PORT,
    }


def _send_open_only(sock: socket.socket, path: str, flags=None):
    if flags is None:
        flags = kXR_open_read
    payload = path.encode("utf-8")
    req = struct.pack(
        ">2sHHH12sI",
        b"\x00\x20",
        kXR_open,
        0o644,
        flags,
        b"\x00" * 12,
        len(payload),
    )
    sock.sendall(req + payload)


def _send_read_only(sock: socket.socket, fhandle: bytes, offset: int, rlen: int):
    req = struct.pack(
        ">2sH4sQiI",
        b"\x00\x30",
        kXR_read,
        fhandle,
        offset,
        rlen,
        0,
    )
    sock.sendall(req)


def _cache_artifacts(cache_path: Path):
    return (
        cache_path,
        Path(str(cache_path) + ".ngx-xrootd-part"),
        Path(str(cache_path) + ".ngx-xrootd-lock"),
    )


def _unlink_cache_artifacts(cache_path: Path):
    for path in _cache_artifacts(cache_path):
        path.unlink(missing_ok=True)


def _wait_for_cache_activity(cache_path: Path, timeout: float = 30.0) -> str:
    cache_file, part_file, lock_file = _cache_artifacts(cache_path)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if part_file.exists() or lock_file.exists():
            return "in-progress"
        if cache_file.exists():
            return "complete"
        time.sleep(0.05)
    return "not-started"


def _instance_prefix(name: str) -> Path:
    """Filesystem prefix (``-p`` root) of a registry-launched fleet instance.

    The fixed-port RegistryLauncher lays each instance out under
    ``REGISTRY_ROOT/<name>`` (see ``server_registry.endpoint_for``), so its
    ``conf/``, ``logs/nginx.pid`` and ``logs/error.log`` live there. The old
    bash ``start_all_dedicated`` layout used ``TEST_ROOT/dedicated/<name>``;
    that path no longer exists, which silently emptied the log-assertion below.
    """
    return Path(REGISTRY_ROOT) / name


def _host_is_wsl() -> bool:
    """True on a WSL/WSL2 kernel (SIGHUP graceful-reload teardown is unreliable).

    Reload-resilience of the *real* client path is verified on this host by
    ``TestChaosMeshStep5SIGHUPDuringTPC`` — a live ``xrdcp`` TPC driven through
    a mid-transfer Tier2 SIGHUP completes byte-exact. What this WSL2-RT kernel
    does *not* survive is the stricter raw-socket variant that pins one
    persistent connection to the draining old worker and never retries: once
    that worker finishes its single in-flight read and exits, the background
    upstream cache-fill it was driving halts, so a later sequential read past
    the fill watermark gets kXR_error. Whether a mainline-Linux draining worker
    continues that background fill (making the pinned read pass) is not
    adjudicable here, so the pinned-connection variant skips on WSL and runs
    for real on CI. See docs/refactor/testsuite-state-2026-07-28.md,
    Tier2 reload-fill finding.
    """
    release = platform.uname().release.lower()
    return "wsl" in release or "microsoft" in release


def _reload_nginx_instance(name: str, port: int) -> None:
    """SIGHUP-reload a dedicated instance, recovering a WSL2-dead master first.

    On a real graceful reload the master keeps the old worker(s) alive to
    finish in-flight requests while new workers take over new connections. On
    WSL2 the SIGHUP handling is unreliable (the master can die outright,
    orphaning a worker with ``ngx_exiting=1``); if a previous reload left the
    master dead we clear the orphans and cold-start before reloading again.
    """
    import subprocess as _sp
    nginx_prefix = _instance_prefix(name)
    pidfile = nginx_prefix / "logs" / "nginx.pid"
    assert pidfile.exists(), f"nginx pidfile not found: {pidfile}"
    pid = int(pidfile.read_text(encoding="utf-8").strip())

    try:
        os.kill(pid, 0)  # check if master is alive
    except ProcessLookupError:
        # Master died after a previous SIGHUP (WSL2 signal-handling quirk);
        # kill any orphaned workers still listening on the port, then restart.
        for conn in _get_pids_on_port(port):
            try:
                os.kill(conn, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.2)
        _sp.run(
            [NGINX_BIN, "-p", str(nginx_prefix), "-c", "conf/nginx.conf"],
            check=True, capture_output=True,
        )
        time.sleep(0.3)
        pid = int(pidfile.read_text(encoding="utf-8").strip())

    os.kill(pid, signal.SIGHUP)
    _wait_port(port, f"{name} after reload", timeout=10.0)


def _get_pids_on_port(port: int):
    """Return PIDs of processes listening on the given TCP port."""
    import subprocess as _sp
    result = _sp.run(
        ["ss", "-tlnp", f"sport = :{port}"],
        capture_output=True, text=True,
    )
    pids = []
    for line in result.stdout.splitlines():
        if f":{port}" in line and "pid=" in line:
            import re
            for m in re.finditer(r"pid=(\d+)", line):
                pids.append(int(m.group(1)))
    return pids


def _restart_nginx_instance(name: str, port: int):
    """Stop and restart a dedicated nginx instance with a clean slate.

    Used as teardown after SIGHUP tests that may leave the master process dead
    (WSL2 kills the nginx master after SIGHUP).  Without this cleanup the next
    test finds an orphaned worker with ngx_exiting=1 that refuses new
    connections, causing unrelated failures.
    """
    import subprocess as _sp
    nginx_prefix = _instance_prefix(name)
    pidfile = nginx_prefix / "logs" / "nginx.pid"

    # Kill the master process if it is still running.
    if pidfile.exists():
        try:
            pid = int(pidfile.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
        except (ProcessLookupError, ValueError, OSError):
            pass

    # Kill any orphaned workers still holding the port.
    for worker_pid in _get_pids_on_port(port):
        try:
            os.kill(worker_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(0.2)

    _sp.run(
        [NGINX_BIN, "-p", str(nginx_prefix), "-c", "conf/nginx.conf"],
        check=True, capture_output=True,
    )
    _wait_port(port, f"{name} after restart", timeout=10.0)


def _seed_large_fixture_prefix(dst: Path) -> tuple[int, str]:
    src = Path(DATA_ROOT) / "large200.bin"
    if not src.exists():
        pytest.skip("large200.bin not present in DATA_ROOT")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.unlink(missing_ok=True)
    digest = hashlib.md5()
    remaining = CHAOS_FILE_SIZE

    with src.open("rb") as source, dst.open("wb") as target:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                pytest.fail(
                    f"large200.bin ended before {CHAOS_FILE_SIZE} bytes were read"
                )
            target.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)

    return CHAOS_FILE_SIZE, digest.hexdigest()


def _wait_for_log(path: Path, predicate, timeout: float = 10.0) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        if path.exists():
            last = path.read_text(encoding="utf-8", errors="replace")
            if predicate(last):
                return last
        time.sleep(0.2)
    pytest.fail(f"log condition not met in {path}; tail={last[-2000:]!r}")
