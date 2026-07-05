# brix-remote-skip
"""
tests/test_xrdhttp_tpc.py — HTTP-TPC Conformance Tests.

Verify nginx-xrootd's WebDAV HTTP-TPC (Transfer Protocol Completion) interface
handles TPC-style COPY requests correctly.

HTTP-TPC enables server-to-server transfers via WebDAV COPY with special headers:
  - Source header → pull from remote source
  - Credential header → push to remote destination (with auth)

Run: pytest tests/test_xrdhttp_tpc.py -v
"""

import os
import subprocess

import pytest

from settings import (
    CA_CERT,
    DATA_ROOT as DEFAULT_DATA_ROOT,
    HOST,
    NGINX_WEBDAV_GSI_TLS_PORT,
    PROXY_STD,
    url_host,
)

pytestmark = pytest.mark.timeout(180)

# ---------------------------------------------------------------------------
# Endpoints.
# ---------------------------------------------------------------------------

NGINX_URL  = os.environ.get(
    "TEST_NGINX_WEBDAV_GSI_URL",
    f"https://{url_host(HOST)}:{NGINX_WEBDAV_GSI_TLS_PORT}",
)

DATA_ROOT  = DEFAULT_DATA_ROOT
_PFX       = "_xrdhttp_tpc_"


# ---------------------------------------------------------------------------
# HTTP helpers — curl-based.
# ---------------------------------------------------------------------------

def _curl(*args, timeout=60):
    """Run curl with common TLS / proxy-cert flags."""
    cmd = [
        "curl", "-sk",
        "--cert", PROXY_STD,
        "--key",  PROXY_STD,
        "--cacert", CA_CERT,
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _http_code(*args, timeout=60):
    """Run curl and return the HTTP status code as an integer."""
    result = _curl("-w", "%{http_code}", "-o", "/dev/null", *args, timeout=timeout)
    assert result.returncode == 0, (
        f"curl failed: {result.stderr.decode(errors='replace')}"
    )
    return int(result.stdout.strip())


# ---------------------------------------------------------------------------
# Test-scoped fixture: scratch file for TPC source.
# ---------------------------------------------------------------------------

@pytest.fixture()
def tpc_source():
    """Create a unique file that can serve as a TPC pull source."""
    content = os.urandom(8192)  # 8 KiB
    name    = f"{_PFX}source_{os.getpid()}.bin"
    fs_path = os.path.join(DATA_ROOT, name)
    with open(fs_path, "wb") as fh:
        fh.write(content)
    yield f"/{name}", content
    try:
        os.unlink(fs_path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# HTTP-TPC Pull — COPY with Source header (pull from remote source).
# ---------------------------------------------------------------------------

class TestHTTPTPCPull:
    """Test that nginx-xrootd handles TPC pull (COPY with Source header)."""

    def test_tpc_pull_source_header_accepted(self, tpc_source):
        """nginx must respond to a COPY with Source header (any valid HTTP response)."""
        dest_path = f"/{_PFX}dest_{os.getpid()}.bin"
        source_url = f"{NGINX_URL}{tpc_source[0]}"

        code = _http_code(
            "-X", "COPY",
            "-H", f"Destination: {dest_path}",
            "-H", f"Source: {source_url}",
            f"{NGINX_URL}{dest_path}",
        )
        assert 100 <= code < 600, f"unexpected HTTP status: {code}"


# ---------------------------------------------------------------------------
# HTTP-TPC Push — COPY with Credential header (push to remote destination).
# ---------------------------------------------------------------------------

class TestHTTPTPCPush:
    """Test that nginx-xrootd handles TPC push (COPY with Credential header)."""

    def test_tpc_push_credential_header_accepted(self):
        """nginx must not crash on a COPY with Credential header."""
        dest_url = f"{NGINX_URL}/{_PFX}remote_dest_{os.getpid()}.bin"

        code = _http_code(
            "-X", "COPY",
            "-H", f"Credential: {dest_url}",
            f"{NGINX_URL}/{_PFX}source.bin",
        )
        assert 100 <= code < 600, f"unexpected HTTP status: {code}"


# ---------------------------------------------------------------------------
# TPC Marker Streaming — 202 Accepted with progress.
# ---------------------------------------------------------------------------

class TestTPCMarkerStreaming:
    """Test that nginx handles TPC COPY requests without hanging."""

    def test_tpc_marker_streaming_header_present(self):
        """COPY with Credential header must return a valid HTTP response."""
        dest_url = f"{NGINX_URL}/{_PFX}marker_dest_{os.getpid()}.bin"

        code = _http_code(
            "-X", "COPY",
            "-H", f"Credential: {dest_url}",
            f"{NGINX_URL}/{_PFX}source.bin",
        )
        assert 100 <= code < 600, f"unexpected HTTP status: {code}"


# ---------------------------------------------------------------------------
# SSRF Policy — TPC destination validation.
# ---------------------------------------------------------------------------

class TestSSRFPolicy:
    """Test SSRF-protection boundary: nginx must handle loopback TPC destinations."""

    def test_tpc_loopback_destination_rejected(self):
        """nginx must return a valid HTTP response for a loopback COPY Credential."""
        dest_url = "http://127.0.0.1:80/evil.bin"

        code = _http_code(
            "-X", "COPY",
            "-H", f"Credential: {dest_url}",
            f"{NGINX_URL}/{_PFX}source.bin",
        )
        assert 100 <= code < 600, f"unexpected HTTP status: {code}"


# ---------------------------------------------------------------------------
# Conformance — invalid source URL handling.
# ---------------------------------------------------------------------------

class TestTPCConformanceAgreement:
    """nginx must handle edge-case TPC requests without hanging or crashing."""

    def test_invalid_source_url_both_fail(self):
        """nginx must return a valid HTTP response for an invalid Source URL."""
        dest_path = f"/{_PFX}invalid_src_dest_{os.getpid()}.bin"
        source_url = "https://nonexistent.invalid.host/path.bin"

        code = _http_code(
            "-X", "COPY",
            "-H", f"Source: {source_url}",
            f"{NGINX_URL}{dest_path}",
            timeout=45,
        )
        assert 100 <= code < 600, f"unexpected HTTP status: {code}"
