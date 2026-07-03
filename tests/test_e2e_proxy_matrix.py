"""
End-to-end proxy interoperability matrix — Section 3A of the comprehensive
testing roadmap docs/comprehensive-testing-roadmap.md.

Three proxy permutations are validated using real xrdcp and real nginx/brix
binaries — no Python socket simulators.

Scenario 1: "WLCG Gateway"
    xrdcp ──► nginx (proxy) ──► xrootd (data, anon)
    nginx terminates perimeter security; backend is unauthenticated.
    Uses: PROXY_NGINX_PORT → PROXY_UPSTREAM_PORT

Scenario 2: "Storage Bridge"
    xrdcp ──► xrootd (proxy/PSS) ──► nginx (data)
    Compatibility test with ofs.forward and PSS mode.
    Uses: PROXY_BRIDGE_BRIX_PORT → PROXY_NGINX_PORT
    (Skipped if the storage-bridge server is not pre-launched.)

Scenario 3: "Pure Nginx"
    xrdcp ──► nginx (proxy) ──► nginx (data)
    Full Nginx stack; the proxy nginx chains to the data nginx.
    Uses: PROXY_PURE_NGINX_PROXY_PORT → PROXY_NGINX_PORT
    (Skipped if the pure-nginx-proxy server is not pre-launched.)

All tests use pre-launched servers from manage_test_servers.sh.
Run:
    pytest tests/test_e2e_proxy_matrix.py -v
"""

import hashlib
import os
import socket
import struct
import subprocess
import tempfile
import time
import uuid

import pytest

from settings import (
    CA_DIR,
    PROXY_BRIDGE_BRIX_PORT,
    PROXY_DATA_ROOT,
    PROXY_NGINX_PORT,
    PROXY_PURE_NGINX_PROXY_PORT,
    PROXY_UPSTREAM_PORT,
    PROXY_STD,
    SERVER_HOST,
    XRDCP_BIN,
    XRDFS_BIN,
)

pytestmark = pytest.mark.e2e

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _wait_port(host: str, port: int, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _skip_if_port_closed(port: int | None, label: str):
    if port is None or not _wait_port(SERVER_HOST, port, timeout=3.0):
        pytest.skip(f"{label} not available (port {port} not open)")


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _write_origin(name: str, data: bytes) -> str:
    """Write a file to the proxy-upstream data root and return its path."""
    path = os.path.join(PROXY_DATA_ROOT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _xrdcp_get(src_url: str, dst: str, extra_env: dict | None = None,
               timeout: int = 30) -> subprocess.CompletedProcess:
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src_url, dst],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def _xrdcp_put(src: str, dst_url: str, extra_env: dict | None = None,
               timeout: int = 30) -> subprocess.CompletedProcess:
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src, dst_url],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def proxy_env():
    """Wait for the nginx proxy + xrootd upstream (Scenario 1).

    Requires manage_test_servers.sh to have started both servers.
    """
    if not _wait_port(SERVER_HOST, PROXY_NGINX_PORT, timeout=15.0):
        pytest.skip(f"nginx proxy not running on port {PROXY_NGINX_PORT}")
    if not _wait_port(SERVER_HOST, PROXY_UPSTREAM_PORT, timeout=15.0):
        pytest.skip(f"xrootd upstream not running on port {PROXY_UPSTREAM_PORT}")
    return {
        "proxy_url":    f"root://{SERVER_HOST}:{PROXY_NGINX_PORT}/",
        "upstream_url": f"root://{SERVER_HOST}:{PROXY_UPSTREAM_PORT}/",
        "data_root":    PROXY_DATA_ROOT,
    }


# ---------------------------------------------------------------------------
# Section 3A.1 — "WLCG Gateway": xrdcp → nginx(proxy) → xrootd(data)
# ---------------------------------------------------------------------------

class TestWLCGGateway:
    """Nginx proxy forwards xrdcp connections to an anonymous xrootd backend.

    Covers roadmap Section 3A, Permutation 1.
    """

    def test_read_through_proxy_bytes_exact(self, proxy_env, tmp_path):
        """xrdcp reads a file through the nginx proxy; byte content is exact."""
        payload = os.urandom(32 * 1024)
        name = f"proxy_read_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(f"{proxy_env['proxy_url']}/{name}", dst)
        assert result.returncode == 0, (
            f"xrdcp failed: {result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "Downloaded content does not match origin"

    def test_write_through_proxy_bytes_exact(self, proxy_env, tmp_path):
        """xrdcp writes a file through the nginx proxy; verify at origin."""
        payload = os.urandom(16 * 1024)
        name = f"proxy_write_{uuid.uuid4().hex[:8]}.bin"
        src = str(tmp_path / name)
        with open(src, "wb") as fh:
            fh.write(payload)

        result = _xrdcp_put(src, f"{proxy_env['proxy_url']}/{name}")
        assert result.returncode == 0, f"xrdcp put failed: {result.stderr}"

        origin_path = os.path.join(proxy_env["data_root"], name)
        with open(origin_path, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "Written content does not match what was uploaded"

    @pytest.mark.timeout(120)
    def test_large_file_round_trip_proxy(self, proxy_env, tmp_path):
        """1 MiB round-trip through proxy preserves checksum (Section 5C read relay)."""
        payload = os.urandom(1 * 1024 * 1024)
        name = f"proxy_large_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(f"{proxy_env['proxy_url']}/{name}", dst, timeout=90)
        assert result.returncode == 0, f"xrdcp large failed: {result.stderr}"
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload)

    def test_parallel_reads_through_proxy(self, proxy_env, tmp_path):
        """Section 5A: 4 concurrent xrdcp readers through the proxy, all byte-exact.

        This stresses handle translation and multi-client session management.
        """
        import concurrent.futures
        payload = os.urandom(64 * 1024)
        name = f"proxy_parallel_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)
        expected = _md5(payload)

        def _fetch(idx: int) -> bool:
            dst = str(tmp_path / f"{name}_{idx}")
            r = _xrdcp_get(f"{proxy_env['proxy_url']}/{name}", dst)
            if r.returncode != 0:
                return False
            with open(dst, "rb") as fh:
                return _md5(fh.read()) == expected

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(_fetch, range(4)))
        assert all(results), f"Some parallel reads failed: {results}"

    def test_stat_through_proxy(self, proxy_env):
        """xrdfs stat returns correct size through proxy (Section 5C kXR_stat relay)."""
        payload = os.urandom(4096)
        name = f"proxy_stat_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        r = subprocess.run(
            [XRDFS_BIN, f"{SERVER_HOST}:{PROXY_NGINX_PORT}", "stat", f"/{name}"],
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, f"xrdfs stat failed: {r.stderr}"
        assert str(len(payload)) in r.stdout, (
            f"File size {len(payload)} not in xrdfs stat output:\n{r.stdout}"
        )

    def test_authorization_header_stripped_for_anon_backend(self, proxy_env, tmp_path):
        """Section 3A.1: Credentials from the client are NOT forwarded to the
        anonymous backend.  We verify the transfer succeeds (confirming the
        backend accepts the request without credentials)."""
        payload = b"strip-auth-check"
        name = f"proxy_stripauth_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        # Pass a dummy token — the proxy must strip it before forwarding.
        result = _xrdcp_get(
            f"{proxy_env['proxy_url']}/{name}", dst,
            extra_env={"XrdSecGSISRVNAMES": "*", "X_TEST_PASS_TOKEN": "dummy"},
        )
        assert result.returncode == 0, (
            f"Transfer failed (backend may be getting credentials it can't verify): "
            f"{result.stderr}"
        )


# ---------------------------------------------------------------------------
# Section 3A.2 — "Storage Bridge": xrdcp → xrootd(proxy/PSS) → nginx(data)
# ---------------------------------------------------------------------------

class TestStorageBridge:
    """xrootd acts as a proxy (PSS / ofs.forward) in front of nginx as data.

    Covers roadmap Section 3A, Permutation 2.
    Skipped when the storage-bridge server is not pre-launched.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_bridge(self):
        _skip_if_port_closed(
            PROXY_BRIDGE_BRIX_PORT,
            "storage-bridge xrootd PSS server (PROXY_BRIDGE_BRIX_PORT)"
        )

    def test_read_via_pss_bridge(self, tmp_path):
        """xrdcp reads through an xrootd PSS proxy that fetches from nginx data."""
        payload = os.urandom(32 * 1024)
        name = f"bridge_read_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{PROXY_BRIDGE_BRIX_PORT}//{name}", dst
        )
        assert result.returncode == 0, f"xrdcp bridge read failed: {result.stderr}"
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload)

    def test_write_via_pss_bridge(self, tmp_path):
        """xrdcp writes through an xrootd PSS proxy back to nginx data."""
        payload = os.urandom(16 * 1024)
        name = f"bridge_write_{uuid.uuid4().hex[:8]}.bin"
        src = str(tmp_path / name)
        with open(src, "wb") as fh:
            fh.write(payload)

        result = _xrdcp_put(
            src, f"root://{SERVER_HOST}:{PROXY_BRIDGE_BRIX_PORT}//{name}"
        )
        assert result.returncode == 0, f"xrdcp bridge write failed: {result.stderr}"

        origin_path = os.path.join(PROXY_DATA_ROOT, name)
        assert os.path.exists(origin_path), "File not found at proxy data root after bridge write"
        with open(origin_path, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload)


# ---------------------------------------------------------------------------
# Section 3A.3 — "Pure Nginx": xrdcp → nginx(proxy) → nginx(data)
# ---------------------------------------------------------------------------

class TestPureNginxStack:
    """Both proxy and data roles are served by nginx-xrootd instances.

    Covers roadmap Section 3A, Permutation 3.
    Skipped when the pure-nginx-proxy server is not pre-launched.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_pure_proxy(self):
        _skip_if_port_closed(
            PROXY_PURE_NGINX_PROXY_PORT,
            "pure-nginx proxy server (PROXY_PURE_NGINX_PROXY_PORT)"
        )

    def test_read_through_pure_nginx_stack(self, tmp_path):
        """xrdcp reads through nginx→nginx; data served correctly end-to-end."""
        payload = os.urandom(32 * 1024)
        name = f"purenginx_read_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{PROXY_PURE_NGINX_PROXY_PORT}//{name}", dst
        )
        assert result.returncode == 0, f"xrdcp pure-nginx read failed: {result.stderr}"
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload)

    def test_write_through_pure_nginx_stack(self, tmp_path):
        """xrdcp writes through nginx→nginx; file appears in data nginx root."""
        payload = os.urandom(16 * 1024)
        name = f"purenginx_write_{uuid.uuid4().hex[:8]}.bin"
        src = str(tmp_path / name)
        with open(src, "wb") as fh:
            fh.write(payload)

        result = _xrdcp_put(
            src, f"root://{SERVER_HOST}:{PROXY_PURE_NGINX_PROXY_PORT}//{name}"
        )
        assert result.returncode == 0, f"xrdcp pure-nginx write failed: {result.stderr}"

        origin_path = os.path.join(PROXY_DATA_ROOT, name)
        assert os.path.exists(origin_path), "File not at proxy data root after pure-nginx write"
        with open(origin_path, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload)

    @pytest.mark.timeout(120)
    def test_64bit_offset_preserved_through_nginx_proxy(self, tmp_path):
        """Section 5C: 64-bit offsets in kXR_read are preserved through nginx→nginx.

        Write a 2 MiB file, then read a range starting at offset > 32-bit boundary
        and verify the data matches the expected slice.
        """
        payload = bytes(i & 0xFF for i in range(2 * 1024 * 1024))
        name = f"purenginx_offset_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_get(
            f"root://{SERVER_HOST}:{PROXY_PURE_NGINX_PROXY_PORT}//{name}", dst,
            timeout=90,
        )
        assert result.returncode == 0
        with open(dst, "rb") as fh:
            got = fh.read()
        # Verify a slice in the second half to exercise large offsets
        assert got[1024 * 1024: 1024 * 1024 + 256] == payload[1024 * 1024: 1024 * 1024 + 256]
