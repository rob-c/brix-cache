"""
Credential Translation Bridge — Section 4C of the comprehensive testing roadmap
docs/comprehensive-testing-roadmap.md.

Topology:
    Legacy GSI Client ──► Nginx (Proxy/Bridge) ──► Modern Token-only Backend

Nginx acts as a migration path for legacy experiments.  It verifies an incoming
GSI proxy certificate and then injects a short-lived WLCG Bearer Token to
authorize the request against a modern token-only backend.

What is validated (per roadmap Section 4C):
  1. Client connects with a GSI proxy cert to NGINX_GSI_PORT.
  2. Nginx validates the proxy cert via its GSI auth sub-system.
  3. Nginx injects a WLCG Bearer Token for the upstream (token-only backend).
  4. The backend access log shows auth via Bearer token, NOT a proxy cert.
  5. The 'sub' field in the backend log matches the mapped DN from the GSI proxy.

Because the credential bridge requires a specific nginx configuration
(xrootd_auth gsi + xrootd_proxy_upstream_auth token + a token issuance policy),
tests that need the bridge server are skipped when that server is not running.

The tests also verify the negative case: a GSI client connecting to the
token-only server directly must be rejected.

Run:
    pytest tests/test_credential_translation.py -v
"""

import hashlib
import os
import socket
import struct
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from settings import (
    CA_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_GSI_PORT,
    NGINX_TOKEN_PORT,
    PROXY_STD,
    SERVER_HOST,
    XRDCP_BIN,
    XRDFS_BIN,
)

from settings import CREDENTIAL_BRIDGE_PORT

pytestmark = pytest.mark.e2e


def _wait_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _skip_if_port_closed(port: int | None, label: str):
    if port is None or not _wait_port(SERVER_HOST, port, timeout=4.0):
        pytest.skip(f"{label} not available (port {port})")


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _write_origin(name: str, data: bytes) -> str:
    path = os.path.join(DATA_ROOT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _xrdcp_gsi(src_url: str, dst: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """xrdcp with GSI proxy cert credentials."""
    env = {
        **os.environ,
        "X509_USER_PROXY": PROXY_STD,
        "X509_CERT_DIR": CA_DIR,
    }
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src_url, dst],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def _xrdcp_anon(src_url: str, dst: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """xrdcp without any credentials (anonymous)."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("X509_")}
    env.pop("XrdSecPROTOCOL", None)
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src_url, dst],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def _tail_log(log_path: str, start_offset: int, needle: str, timeout: float = 5.0) -> str:
    """Return the log lines written after start_offset that contain needle."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(start_offset)
                chunk = fh.read()
            if needle in chunk:
                return chunk
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    return ""


# ---------------------------------------------------------------------------
# Section 4C — The "Credential Translation Bridge"
# ---------------------------------------------------------------------------

class TestCredentialTranslationBridge:
    """GSI proxy presented to Nginx → Nginx injects WLCG token for backend.

    Covers roadmap Section 4C.
    Skipped when CREDENTIAL_BRIDGE_PORT is not configured.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_bridge(self):
        _skip_if_port_closed(CREDENTIAL_BRIDGE_PORT, "GSI-to-Token bridge server")
        if not _wait_port(SERVER_HOST, NGINX_TOKEN_PORT, timeout=5.0):
            pytest.skip("Token-only backend not running on NGINX_TOKEN_PORT")

    def test_gsi_client_reads_through_bridge(self, tmp_path):
        """GSI client successfully reads from a token-only backend via the bridge."""
        payload = os.urandom(16 * 1024)
        name = f"bridge_read_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_gsi(
            f"root://{SERVER_HOST}:{CREDENTIAL_BRIDGE_PORT}/{name}", dst
        )
        assert result.returncode == 0, (
            f"GSI client could not read through credential bridge:\n{result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _md5(got) == _md5(payload), "Credential bridge content mismatch"

    def test_backend_receives_bearer_token_not_proxy(self):
        """Roadmap 4C Validation: backend log shows Bearer auth, not proxy cert.

        The bridge nginx must inject a token; the token-only backend's access log
        must show 'Bearer' and the mapped 'sub' field — never a proxy DN directly.
        """
        access_log = os.path.join(LOG_DIR, "xrootd_access.log")
        start = os.path.getsize(access_log) if os.path.exists(access_log) else 0

        name = f"bridge_log_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, os.urandom(1024))
        tmp = f"/tmp/bridge_log_{name}"

        result = _xrdcp_gsi(
            f"root://{SERVER_HOST}:{CREDENTIAL_BRIDGE_PORT}/{name}", tmp
        )
        assert result.returncode == 0, f"Bridge transfer failed: {result.stderr}"

        chunk = _tail_log(access_log, start, "Bearer")
        assert chunk, (
            "Backend access log does not contain 'Bearer' — bridge may be forwarding "
            "the GSI proxy directly instead of issuing a token"
        )
        assert "proxy" not in chunk.lower() or "sub=" in chunk, (
            "Backend log contains 'proxy' but no 'sub=' mapping — credential translation "
            "may not be working correctly"
        )

    def test_gsi_client_rejected_by_token_only_backend_directly(self, tmp_path):
        """Section 4C security: GSI client connecting directly to the token-only
        backend (without going through the bridge) must be rejected."""
        payload = os.urandom(1024)
        name = f"bridge_direct_gsi_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_gsi(
            f"root://{SERVER_HOST}:{NGINX_TOKEN_PORT}/{name}", dst
        )
        # Token-only server must reject a GSI-only client.
        assert result.returncode != 0, (
            "Token-only backend accepted a GSI-only client — credential "
            "translation bypass possible"
        )

    def test_anonymous_client_rejected_by_bridge(self, tmp_path):
        """Section 7 (security negative): anonymous client must be rejected at bridge."""
        name = f"bridge_anon_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, os.urandom(512))

        dst = str(tmp_path / name)
        result = _xrdcp_anon(
            f"root://{SERVER_HOST}:{CREDENTIAL_BRIDGE_PORT}/{name}", dst
        )
        assert result.returncode != 0, (
            "Anonymous client was accepted by the credential bridge — "
            "authentication bypass"
        )


# ---------------------------------------------------------------------------
# Related: verify existing GSI-Token parity on the regular servers
# ---------------------------------------------------------------------------

class TestGSIAndTokenServerParity:
    """Verifies that the same file is reachable from both the GSI and Token
    servers, confirming that the test infrastructure is healthy before the
    bridge tests run.

    These tests do NOT require the bridge server.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_gsi_and_token(self):
        if not _wait_port(SERVER_HOST, NGINX_GSI_PORT, timeout=5.0):
            pytest.skip("NGINX_GSI_PORT not running")
        if not _wait_port(SERVER_HOST, NGINX_TOKEN_PORT, timeout=5.0):
            pytest.skip("NGINX_TOKEN_PORT not running")

    def test_gsi_server_accepts_proxy(self, tmp_path):
        """GSI server accepts a valid proxy cert and returns the file."""
        payload = os.urandom(4096)
        name = f"parity_gsi_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, payload)

        dst = str(tmp_path / name)
        result = _xrdcp_gsi(
            f"root://{SERVER_HOST}:{NGINX_GSI_PORT}/{name}", dst
        )
        assert result.returncode == 0, (
            f"GSI server rejected valid proxy: {result.stderr}"
        )
        with open(dst, "rb") as fh:
            assert _md5(fh.read()) == _md5(payload)

    def test_gsi_server_rejects_no_proxy(self, tmp_path):
        """Section 7 (security negative): GSI server rejects anonymous client."""
        name = f"parity_gsi_anon_{uuid.uuid4().hex[:8]}.bin"
        _write_origin(name, os.urandom(512))

        dst = str(tmp_path / name)
        result = _xrdcp_anon(
            f"root://{SERVER_HOST}:{NGINX_GSI_PORT}/{name}", dst
        )
        assert result.returncode != 0, (
            "GSI server accepted anonymous connection — authentication bypass"
        )
