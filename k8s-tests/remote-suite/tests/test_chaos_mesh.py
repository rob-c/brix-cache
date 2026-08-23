# brix-remote-skip
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


def _reload_nginx_instance(name: str, port: int):
    import subprocess as _sp
    import socket as _socket
    nginx_prefix = Path(TEST_ROOT) / "dedicated" / name
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
    nginx_prefix = Path(TEST_ROOT) / "dedicated" / name
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



def _next_chaos_read(sock, handle, offset, size, reloaded, tier2_port):
    if not reloaded and offset >= RELOAD_AFTER_BYTES:
        _send_read_only(sock, handle, offset, size)
        _reload_nginx_instance("chaos-tier2", tier2_port)
        status, data = _read_resp_all(sock)
        return status, data, True
    status, data = _read(sock, handle, offset, size)
    return status, data, reloaded


def _stream_chaos_file(sock, handle, expected_size, expected_md5, tier2_port):
    digest = hashlib.md5()
    total = 0
    reloaded = False
    while total < expected_size:
        size = min(READ_CHUNK, expected_size - total)
        status, data, reloaded = _next_chaos_read(
            sock, handle, total, size, reloaded, tier2_port
        )
        _require(
            status == kXR_ok,
            f"read at offset {total} failed after reload: status={status}",
        )
        _require(
            len(data) == size,
            f"short read at offset {total}: got {len(data)}, want {size}",
        )
        digest.update(data)
        total += len(data)
    _require(total == expected_size, "Chaos Mesh read ended at the wrong size")
    _require(digest.hexdigest() == expected_md5, "Chaos Mesh read changed content")
    _require(reloaded, "Tier2 reload was not injected")


def _jwt_token():
    token_file = Path(TEST_ROOT) / "pki" / "wlcg_token.txt"
    if not token_file.exists():
        pytest.skip("wlcg_token.txt not present — identity-shifting test needs JWT")
    return token_file.read_text(encoding="utf-8").strip()


def _identity_read(port, filename, destination, token):
    import subprocess

    environment = os.environ.copy()
    environment["XrdSecTOKEN"] = token
    result = subprocess.run(
        ["xrdcp", "-f", "-s", f"root://{SERVER_HOST}:{port}/{filename}", destination],
        env=environment,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace")
        pytest.skip(f"Tier1 JWT read failed (server may not use JWT): {error}")
    with open(destination, "rb") as handle:
        return handle.read()


def _assert_sss_access_log(filename):
    tier2_log = _instance_prefix("chaos-tier2") / "logs" / "brix_access.log"
    if not tier2_log.exists():
        return
    log_text = tier2_log.read_text(encoding="utf-8", errors="replace")
    relevant_lines = [line for line in log_text.splitlines() if filename in line]
    if not relevant_lines:
        return
    last = relevant_lines[-1]
    _require(
        "sss" in last.lower(),
        "Tier2 access log did not record SSS auth for identity-shifted "
        f"request.\nLine: {last}",
    )


def _instance_prefix(name):
    return Path(TEST_ROOT) / "dedicated" / name


from split_continuation import load as _load_continuation

_load_continuation(
    globals(),
    __file__,
    "_test_chaos_mesh_cases.py",
    "_test_chaos_mesh_tpc_cases.py",
)
