# brix-remote-skip
"""
Cache and Write-Through server integration tests.

Three dedicated pre-started servers (launched by manage_test_servers.sh):
  cache-only   (CACHE_ONLY_PORT=11200): read-through cache, no WT
  wt-sync      (WT_SYNC_PORT=11201):   write-through, sync flush to origin
  wt-async     (WT_ASYNC_PORT=11202):  write-through, async flush to origin

The origin for all three servers is the shared anonymous nginx (NGINX_ANON_PORT=11094).
Each server's data dir is TEST_ROOT/data-<role> (created by start_dedicated_nginx).
"""

import hashlib
import os
import socket
import struct
import subprocess
import time

import pytest

from settings import (
    CACHE_ONLY_PORT,
    TEST_ROOT,
    WT_ASYNC_PORT,
    WT_SYNC_PORT,
)

CACHE_ONLY_DATA = os.path.join(TEST_ROOT, "data-cache-only")
WT_SYNC_DATA    = os.path.join(TEST_ROOT, "data-wt-sync")
WT_ASYNC_DATA   = os.path.join(TEST_ROOT, "data-wt-async")


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

kXR_ok    = 0
kXR_error = 4003


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    if hdr is None:
        return None, b""
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">I", hdr[4:8])[0]
    body   = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _establish_session(host, port):
    """Minimal XRootD session: handshake + protocol + anonymous login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.settimeout(10)

    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)

    proto_hdr = struct.pack(">BBHIBB10xI", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0)
    sock.sendall(proto_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_protocol failed: status={status}"

    login_payload = b"anon\x00\x00\x00\x00"
    login_hdr = (struct.pack(">2sH", b"\x00\x01", 3007)
                 + struct.pack(">I", 0)
                 + login_payload
                 + struct.pack(">BBB", 0, 0, 5)
                 + struct.pack(">B", 0)
                 + struct.pack(">I", 0))
    sock.sendall(login_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_login failed: status={status}"

    return sock, b"\x00\x01"


def _wait_port(host, port, timeout=10.0):
    """Block until host:port accepts a TCP connection or raise pytest.fail."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.2)
    pytest.fail(f"server at {host}:{port} not reachable after {timeout}s")


# ---------------------------------------------------------------------------
# Fixtures — wait for each pre-started server, then yield connection info
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def cache_only_server(test_env):
    """Pre-started cache-only server (nginx_cache_only.conf, CACHE_ONLY_PORT)."""
    host = test_env["server_host"]
    _wait_port(host, CACHE_ONLY_PORT)
    yield {"host": host, "port": CACHE_ONLY_PORT, "data_dir": CACHE_ONLY_DATA}


@pytest.fixture(scope="session")
def write_through_sync_server(test_env):
    """Pre-started WT-sync server (nginx_wt_sync.conf, WT_SYNC_PORT)."""
    host = test_env["server_host"]
    _wait_port(host, WT_SYNC_PORT)
    yield {"host": host, "port": WT_SYNC_PORT, "data_dir": WT_SYNC_DATA}


@pytest.fixture(scope="session")
def write_through_async_server(test_env):
    """Pre-started WT-async server (nginx_wt_async.conf, WT_ASYNC_PORT)."""
    host = test_env["server_host"]
    _wait_port(host, WT_ASYNC_PORT)
    yield {"host": host, "port": WT_ASYNC_PORT, "data_dir": WT_ASYNC_DATA}


# ---------------------------------------------------------------------------
# Cache read-through tests
# ---------------------------------------------------------------------------

class TestCacheReadThrough:
    """Cache-only server: connectivity and basic file access."""

    def test_server_accepts_brix_session(self, cache_only_server):
        """Cache-only server must accept a complete XRootD login."""
        sock, _ = _establish_session(cache_only_server["host"], cache_only_server["port"])
        sock.close()

    def test_read_seeded_file(self, cache_only_server, tmp_path):
        """test.txt seeded by start_dedicated_nginx must be readable."""
        url = (f"root://{cache_only_server['host']}"
               f":{cache_only_server['port']}//test.txt")
        r = subprocess.run(["xrdcp", "-s", url, str(tmp_path / "test.txt")],
                           capture_output=True, timeout=30)
        assert r.returncode == 0, (
            f"xrdcp from cache-only server failed:\n"
            f"  {r.stderr.decode('utf-8', errors='replace')}"
        )

    @pytest.mark.requires_local_server
    def test_stat_seeded_file(self, cache_only_server):
        """kXR_stat on test.txt must return kXR_ok from the cache server."""
        sock, sid = _establish_session(cache_only_server["host"], cache_only_server["port"])
        path = b"/test.txt\x00"
        hdr = struct.pack(">2sHBI11sI", sid, 3017, 0, 0, b"\x00" * 11, len(path))
        sock.sendall(hdr + path)
        status, _ = _read_response(sock)
        sock.close()
        assert status == kXR_ok, f"kXR_stat on cache-only server: status={status}"


# ---------------------------------------------------------------------------
# Write-through sync server tests
# ---------------------------------------------------------------------------

class TestWriteThroughSync:
    """WT-sync server: connectivity and round-trip write+read with checksum."""

    def test_server_accepts_brix_session(self, write_through_sync_server):
        """WT-sync server must accept a complete XRootD login."""
        sock, _ = _establish_session(
            write_through_sync_server["host"], write_through_sync_server["port"]
        )
        sock.close()

    def test_read_seeded_file(self, write_through_sync_server, tmp_path):
        """test.txt seeded by start_dedicated_nginx must be readable."""
        url = (f"root://{write_through_sync_server['host']}"
               f":{write_through_sync_server['port']}//test.txt")
        r = subprocess.run(["xrdcp", "-s", url, str(tmp_path / "test.txt")],
                           capture_output=True, timeout=30)
        assert r.returncode == 0, (
            f"xrdcp from wt-sync server failed:\n"
            f"  {r.stderr.decode('utf-8', errors='replace')}"
        )

    @pytest.mark.requires_local_server
    def test_write_and_read_back(self, write_through_sync_server, tmp_path):
        """File written to WT-sync server must be readable back with identical content."""
        payload = os.urandom(4096)
        fname = f"wt_sync_rw_{int(time.time())}.bin"
        src = str(tmp_path / fname)
        with open(src, "wb") as f:
            f.write(payload)

        base_url = (f"root://{write_through_sync_server['host']}"
                    f":{write_through_sync_server['port']}")
        r = subprocess.run(["xrdcp", "-s", src, f"{base_url}//{fname}"],
                           capture_output=True, timeout=30)
        assert r.returncode == 0, (
            f"WT-sync write failed:\n{r.stderr.decode('utf-8', errors='replace')}"
        )

        out = str(tmp_path / f"back_{fname}")
        r2 = subprocess.run(["xrdcp", "-s", f"{base_url}//{fname}", out],
                            capture_output=True, timeout=30)
        assert r2.returncode == 0, (
            f"WT-sync read-back failed:\n{r2.stderr.decode('utf-8', errors='replace')}"
        )

        with open(out, "rb") as f:
            got = f.read()
        assert got == payload, "Read-back content differs from written payload"


# ---------------------------------------------------------------------------
# Write-through async server tests
# ---------------------------------------------------------------------------

class TestWriteThroughAsync:
    """WT-async server: connectivity and round-trip write+read with checksum."""

    def test_server_accepts_brix_session(self, write_through_async_server):
        """WT-async server must accept a complete XRootD login."""
        sock, _ = _establish_session(
            write_through_async_server["host"], write_through_async_server["port"]
        )
        sock.close()

    def test_read_seeded_file(self, write_through_async_server, tmp_path):
        """test.txt seeded by start_dedicated_nginx must be readable."""
        url = (f"root://{write_through_async_server['host']}"
               f":{write_through_async_server['port']}//test.txt")
        r = subprocess.run(["xrdcp", "-s", url, str(tmp_path / "test.txt")],
                           capture_output=True, timeout=30)
        assert r.returncode == 0, (
            f"xrdcp from wt-async server failed:\n"
            f"  {r.stderr.decode('utf-8', errors='replace')}"
        )

    @pytest.mark.requires_local_server
    def test_write_and_read_back(self, write_through_async_server, tmp_path):
        """File written to WT-async server must be readable back with identical content."""
        payload = os.urandom(4096)
        fname = f"wt_async_rw_{int(time.time())}.bin"
        src = str(tmp_path / fname)
        with open(src, "wb") as f:
            f.write(payload)

        base_url = (f"root://{write_through_async_server['host']}"
                    f":{write_through_async_server['port']}")
        r = subprocess.run(["xrdcp", "-s", src, f"{base_url}//{fname}"],
                           capture_output=True, timeout=30)
        assert r.returncode == 0, (
            f"WT-async write failed:\n{r.stderr.decode('utf-8', errors='replace')}"
        )

        # Async mode: flush is posted to a thread pool; brief wait for completion.
        time.sleep(0.5)

        out = str(tmp_path / f"back_{fname}")
        r2 = subprocess.run(["xrdcp", "-s", f"{base_url}//{fname}", out],
                            capture_output=True, timeout=30)
        assert r2.returncode == 0, (
            f"WT-async read-back failed:\n{r2.stderr.decode('utf-8', errors='replace')}"
        )

        with open(out, "rb") as f:
            got = f.read()
        assert got == payload, "Read-back content differs from written payload"


# ---------------------------------------------------------------------------
# Checksum consistency tests (Section 6C)
# ---------------------------------------------------------------------------

class TestWTChecksumConsistency:
    """Write-through data integrity: SHA-256 of written payload matches read-back."""

    @pytest.mark.requires_local_server
    def test_sync_checksum_matches(self, write_through_sync_server, tmp_path):
        """64 KiB write through WT-sync server: read-back SHA-256 must match original."""
        payload = os.urandom(64 * 1024)
        fname = f"wt_cksum_sync_{int(time.time())}.bin"
        src = str(tmp_path / fname)
        with open(src, "wb") as fh:
            fh.write(payload)
        expected = hashlib.sha256(payload).hexdigest()

        base_url = (f"root://{write_through_sync_server['host']}"
                    f":{write_through_sync_server['port']}")
        r = subprocess.run(["xrdcp", "-f", "-s", src, f"{base_url}//{fname}"],
                           capture_output=True, timeout=60)
        assert r.returncode == 0, (
            f"WT-sync write failed:\n{r.stderr.decode('utf-8', errors='replace')}"
        )

        dst = str(tmp_path / f"back_{fname}")
        r2 = subprocess.run(["xrdcp", "-f", "-s", f"{base_url}//{fname}", dst],
                            capture_output=True, timeout=60)
        assert r2.returncode == 0, (
            f"WT-sync read-back failed:\n{r2.stderr.decode('utf-8', errors='replace')}"
        )

        with open(dst, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        assert got == expected, (
            f"Checksum mismatch after WT-sync flush!\n"
            f"  Expected: {expected}\n  Got:      {got}"
        )

    @pytest.mark.requires_local_server
    def test_async_checksum_matches(self, write_through_async_server, tmp_path):
        """64 KiB write through WT-async server: read-back SHA-256 must match original."""
        payload = os.urandom(64 * 1024)
        fname = f"wt_cksum_async_{int(time.time())}.bin"
        src = str(tmp_path / fname)
        with open(src, "wb") as fh:
            fh.write(payload)
        expected = hashlib.sha256(payload).hexdigest()

        base_url = (f"root://{write_through_async_server['host']}"
                    f":{write_through_async_server['port']}")
        r = subprocess.run(["xrdcp", "-f", "-s", src, f"{base_url}//{fname}"],
                           capture_output=True, timeout=60)
        assert r.returncode == 0, (
            f"WT-async write failed:\n{r.stderr.decode('utf-8', errors='replace')}"
        )

        time.sleep(1)  # Allow async flush thread to complete before reading back.

        dst = str(tmp_path / f"back_{fname}")
        r2 = subprocess.run(["xrdcp", "-f", "-s", f"{base_url}//{fname}", dst],
                            capture_output=True, timeout=60)
        assert r2.returncode == 0, (
            f"WT-async read-back failed:\n{r2.stderr.decode('utf-8', errors='replace')}"
        )

        with open(dst, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        assert got == expected, (
            f"Checksum mismatch after WT-async flush!\n"
            f"  Expected: {expected}\n  Got:      {got}"
        )
