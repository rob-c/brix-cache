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
    SERVER_HOST,
    TEST_ROOT,
)
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


def _send_open_only(sock: socket.socket, path: str):
    payload = path.encode("utf-8")
    req = struct.pack(
        ">2sHHH12sI",
        b"\x00\x20",
        kXR_open,
        0o644,
        kXR_open_read,
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
    pidfile = Path(TEST_ROOT) / "dedicated" / name / "logs" / "nginx.pid"
    assert pidfile.exists(), f"nginx pidfile not found: {pidfile}"
    pid = int(pidfile.read_text(encoding="utf-8").strip())
    os.kill(pid, signal.SIGHUP)
    _wait_port(port, f"{name} after reload", timeout=10.0)


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


class TestChaosMeshDiscovery:
    def test_delayed_cms_start_registers_data_server(self, chaos_mesh):
        path = "/chaos-discovery/file.dat"

        _wait_for_redirect(
            chaos_mesh["discovery_redir"],
            path,
            chaos_mesh["discovery_ds"],
            timeout=25.0,
        )

        log_path = (
            Path(TEST_ROOT)
            / "dedicated"
            / "chaos-discovery-ds"
            / "logs"
            / "error.log"
        )

        def saw_failed_then_successful_cms_login(text: str) -> bool:
            saw_failure = (
                ("CMS connect to" in text and "failed" in text)
                or "CMS connect/write timed out" in text
                or "Connection refused" in text
                or "recv() failed" in text
            )
            return saw_failure and "CMS login sent" in text

        _wait_for_log(log_path, saw_failed_then_successful_cms_login)


class TestChaosMeshReload:
    @pytest.mark.timeout(240)
    def test_tier2_reload_during_stream_read_preserves_md5(self, chaos_mesh):
        remote_name = f"chaos_reload_{os.getpid()}_{uuid.uuid4().hex}.bin"
        remote_path = f"/{remote_name}"
        tier3_path = Path(CHAOS_TIER3_DATA_ROOT) / remote_name
        cache_path = Path(CHAOS_TIER2_CACHE_ROOT) / remote_name
        sock = None

        expected_size, expected_md5 = _seed_large_fixture_prefix(tier3_path)
        _unlink_cache_artifacts(cache_path)

        try:
            sock = _connect(SERVER_HOST, chaos_mesh["tier1"])
            sock.settimeout(60)

            _send_open_only(sock, remote_path)
            activity = _wait_for_cache_activity(cache_path)
            assert activity != "not-started", (
                "Tier2 cache fill did not start for Chaos Mesh transfer"
            )

            status, body = _read_resp(sock)
            assert status == kXR_ok, f"open failed after Tier2 cache fill: {status}"
            fhandle = _fh(body)

            digest = hashlib.md5()
            total = 0
            reloaded_during_read = False

            while total < expected_size:
                want = min(READ_CHUNK, expected_size - total)
                if (
                    not reloaded_during_read
                    and total >= RELOAD_AFTER_BYTES
                ):
                    _send_read_only(sock, fhandle, total, want)
                    _reload_nginx_instance("chaos-tier2", chaos_mesh["tier2"])
                    status, data = _read_resp_all(sock)
                    reloaded_during_read = True
                else:
                    status, data = _read(sock, fhandle, total, want)

                assert status == kXR_ok, (
                    f"read at offset {total} failed after reload: status={status}"
                )
                assert len(data) == want, (
                    f"short read at offset {total}: got {len(data)}, want {want}"
                )

                digest.update(data)
                total += len(data)

            assert total == expected_size
            assert digest.hexdigest() == expected_md5
            assert reloaded_during_read, "Tier2 reload was not injected"

            status, _ = _close(sock, fhandle)
            assert status == kXR_ok, f"close failed after Chaos Mesh read: {status}"

        finally:
            if sock is not None:
                sock.close()
            tier3_path.unlink(missing_ok=True)
            _unlink_cache_artifacts(cache_path)
