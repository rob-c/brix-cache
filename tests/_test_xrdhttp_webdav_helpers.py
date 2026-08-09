"""
Cross-backend WebDAV conformance tests for nginx-xrootd vs reference xrootd XrdHttp.

These tests verify that both backends provide comparable behavior for overlapping
WebDAV-capable operations (GET, HEAD, PUT, basic PROPFIND). Tests are structured
with skipif markers for features only available on one backend.

Architectural note: nginx-xrootd's WebDAV module and reference xrootd's XrdHttp
are different protocol stacks with different capability profiles. This test suite
validates overlapping capabilities rather than claiming identical behavior.

See docs/10-reference/quirks.md for known deviations.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from settings import (
    CA_CERT,
    HOST,
    NGINX_WEBDAV_GSI_TLS_PORT,
    PKI_DIR as PKI_DIR_STR,
    SERVER_CERT,
    SERVER_KEY,
    XRDHTTP_HTTP_PORT,
    XRDHTTP_ROOT_PORT,
    BRIX_BIN,
    url_host,
)

pytestmark = pytest.mark.timeout(120)

PKI_DIR = Path(PKI_DIR_STR)
CLIENT_CERT = PKI_DIR / "user" / "usercert.pem"
CLIENT_KEY = PKI_DIR / "user" / "userkey.pem"


def _require_curl():
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")


# ---------------------------------------------------------------------------
# Backend configuration dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NginxWebDAVBackend:
    """nginx-xrootd WebDAV/davs:// endpoint."""
    host: str = HOST
    port: int = NGINX_WEBDAV_GSI_TLS_PORT
    url_base: str = f"https://{url_host(host)}:{port}"


@dataclass(frozen=True)
class XrdHttpBackend:
    """Reference xrootd XrdHttp HTTPS endpoint."""
    host: str = HOST
    port: int = 11113
    url_base: str = f"https://{url_host(host)}:{port}"


# ---------------------------------------------------------------------------
# Curl helper — consistent across both backends
# ---------------------------------------------------------------------------

def _curl(*args, timeout: int = 30):
    """Execute curl with default TLS client credentials for test PKI."""
    cmd = [
        "curl", "-s",
        "--cert", str(CLIENT_CERT),
        "--key", str(CLIENT_KEY),
        "--cacert", str(CA_CERT),
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _curl_no_cert(*args, timeout: int = 30):
    """Execute curl without client certificate (anonymous access)."""
    cmd = [
        "curl", "-s",
        "--cacert", str(CA_CERT),
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _get_http_code(url: str, method: str = "GET", headers=None,
                   body_file: Optional[str] = None, timeout: int = 30):
    """Execute a single HTTP request and return the status code."""
    args = ["-w", "%{http_code}", "-o", "/dev/null"]
    if method != "GET":
        args.extend(["-X", method])
    if headers:
        for h in headers:
            args.extend(["-H", str(h)])
    if body_file and Path(body_file).exists():
        args.extend(["--data-binary", f"@{body_file}"])
    args.append(url)
    result = _curl(*args, timeout=timeout)
    assert result.returncode == 0, f"curl failed: {result.stderr.decode(errors='replace')}"
    return int(result.stdout.strip())


def _write_file(path: Path | str, content: bytes):
    """Write content to a file path."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


def _setup_file(backend_url: str, filename: str, content: bytes) -> Path:
    """Write a test file to the filesystem so the backend can serve it."""
    if "8443" in backend_url or "8444" in backend_url or "9001" in backend_url:
        data_dir = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")) / "data"
    else:
        data_dir = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")) / "data-xrdhttp"
    data_dir.mkdir(parents=True, exist_ok=True)
    filepath = data_dir / filename
    filepath.write_bytes(content)
    return filepath


# ---------------------------------------------------------------------------
# Fixture: get backend URL based on TEST_CROSS_BACKEND env var
# ---------------------------------------------------------------------------

def _get_backend_url():
    """Return the appropriate backend URL based on TEST_CROSS_BACKEND.

    When running cross-compatibility mode (TEST_CROSS_BACKEND=nginx or xrootd),
    returns the target backend URL directly. Otherwise falls back to nginx-xrootd.
    """
    backend = os.environ.get("TEST_CROSS_BACKEND", "default")

    if backend == "xrootd":
        return f"https://{url_host(HOST)}:{XRDHTTP_HTTP_PORT}"

    # Default or 'nginx' → use nginx-xrootd WebDAV endpoint
    ext_url = os.environ.get("TEST_NGINX_URL") or os.environ.get("EXTERNAL_NGINX_URL")
    if ext_url:
        parsed = str(ext_url)
        return parsed

    return f"https://{url_host(HOST)}:{NGINX_WEBDAV_GSI_TLS_PORT}"


def _get_xrdhttp_port():
    """Return the XrdHttp port for direct backend access."""
    return int(os.environ.get("TEST_XRDHTTP_HTTP_PORT", str(XRDHTTP_HTTP_PORT)))


# ---------------------------------------------------------------------------
# Fixtures: manage backend instances for testing
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def nginx_webdav_backend():
    """Provide the nginx-xrootd WebDAV endpoint configuration."""
    _require_curl()
    for path in (CA_CERT, SERVER_CERT, SERVER_KEY):
        if not Path(path).exists():
            pytest.skip(f"test PKI file not found: {path}")
    return NginxWebDAVBackend()


@pytest.fixture(scope="module")
def xrdhttp_backend():
    """Use the suite-level XrdHttp reference server."""
    _require_curl()
    http_port = _get_xrdhttp_port()
    try:
        result = subprocess.run(
            ["curl", "-skf", f"https://{url_host(HOST)}:{http_port}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        )
    except subprocess.TimeoutExpired:
        # A hung (vs. simply down) reference server blocks the readiness curl until
        # its own timeout. Treat that identically to "not reachable" — a skip, not a
        # setup ERROR — so a wedged reference peer never masquerades as a test failure.
        pytest.skip(f"XrdHttp reference server hung/unresponsive at port {http_port}")
    if result.returncode != 0:
        pytest.skip(f"XrdHttp server not reachable at port {http_port}")
    yield XrdHttpBackend(port=http_port, url_base=f"https://{url_host(HOST)}:{http_port}")


# ---------------------------------------------------------------------------
# Test classes — organized by operation type
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ensure_cleanup():
    """Ensure temporary files are cleaned up after tests."""
    yield None
    # Clean up any leftover test files
    import glob as _glob
    for pattern in [os.path.join(os.environ["TMPDIR"], "xrdhttp_*.dat")]:
        for f in _glob.glob(pattern):
            try:
                os.unlink(f)
            except OSError:
                pass
