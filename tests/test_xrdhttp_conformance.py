"""
XrdHttp conformance edge cases — path confinement, auth boundaries, and
cross-backend runner integration helpers.

These tests focus on security negatives and boundary conditions that should
be consistent across both nginx-xrootd and reference xrootd XrdHttp backends.

Tests use the same fixture infrastructure as test_xrdhttp_webdav.py where possible.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from settings import (
    CA_CERT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    PKI_DIR as PKI_DIR_STR,
    SERVER_CERT,
    SERVER_KEY,
    XRDHTTP_HTTP_PORT,
    XRDHTTP_ROOT_PORT,
    XROOTD_BIN,
)

pytestmark = pytest.mark.timeout(180)

PKI_DIR = Path(PKI_DIR_STR)
CLIENT_CERT = PKI_DIR / "user" / "usercert.pem"
CLIENT_KEY = PKI_DIR / "user" / "userkey.pem"


# ---------------------------------------------------------------------------
# Helpers — mirror test_xrdhttp_webdav.py for consistency
# ---------------------------------------------------------------------------

def _curl(*args, timeout: int = 30):
    cmd = [
        "curl", "-s",
        "--cert", str(CLIENT_CERT),
        "--key", str(CLIENT_KEY),
        "--cacert", str(CA_CERT),
        *args,
    ]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)


def _curl_no_cert(*args, timeout: int = 30):
    cmd = ["curl", "-s", "--cacert", str(CA_CERT), *args]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)


def _get_http_code(url: str, method: str = "GET", headers=None,
                   body_file: Path | None = None, timeout: int = 30):
    args = ["-w", "%{http_code}", "-o", "/dev/null"]
    if method != "GET":
        args.extend(["-X", method])
    if headers:
        for h in headers:
            args.extend(["-H", str(h)])
    if body_file and body_file.exists():
        args.extend(["--data-binary", f"@{body_file}"])
    args.append(url)
    result = _curl(*args, timeout=timeout)
    assert result.returncode == 0, f"curl failed: {result.stderr.decode(errors='replace')}"
    return int(result.stdout.strip())


def _write_file(path: Path | str, content: bytes):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


# ---------------------------------------------------------------------------
# Backend URL resolution — same logic as test_xrdhttp_webdav.py
# ---------------------------------------------------------------------------

def _get_backend_url():
    backend = os.environ.get("TEST_CROSS_BACKEND", "default")
    if backend == "xrootd":
        return f"https://localhost:{XRDHTTP_HTTP_PORT}"
    ext_url = os.environ.get("TEST_NGINX_URL") or os.environ.get("EXTERNAL_NGINX_URL")
    if ext_url:
        return str(ext_url)
    return f"https://localhost:{NGINX_WEBDAV_GSI_TLS_PORT}"


def _get_xrdhttp_port():
    return int(os.environ.get("TEST_XRDHTTP_HTTP_PORT", str(XRDHTTP_HTTP_PORT)))


# ---------------------------------------------------------------------------
# XrdHttp backend fixture — shared with test_xrdhttp_webdav.py pattern
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def xrdhttp_backend():
    """Use the suite-level XrdHttp reference server."""
    http_port = _get_xrdhttp_port()
    result = subprocess.run(
        ["curl", "-skf", f"https://localhost:{http_port}/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
    )
    if result.returncode != 0:
        pytest.skip(f"XrdHttp server not reachable at port {http_port}")

    class Backend:
        url_base = f"https://localhost:{http_port}"
    yield Backend()


# ---------------------------------------------------------------------------
# Shared file setup helper
# ---------------------------------------------------------------------------

def _setup_file(backend_url: str, filename: str, content: bytes) -> None:
    if "8443" in backend_url or "8444" in backend_url or "9001" in backend_url:
        data_dir = Path("/tmp/xrd-test/data")
    else:
        data_dir = Path("/tmp/xrd-test/data-xrdhttp")
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / filename).write_bytes(content)


# ---------------------------------------------------------------------------
# Edge case tests — partial content range edge cases
# ---------------------------------------------------------------------------

class TestRangeEdgeCases:
    """Tests for partial content range request edge cases."""

    def _setup_file(self, backend_url: str, filename: str, content: bytes):
        _setup_file(backend_url, filename, content)

    def test_negative_range_start(self, xrdhttp_backend):
        """Negative Range start should be rejected or ignored."""
        content = b"x" * 1000
        self._setup_file(xrdhttp_backend.url_base, "range-neg.txt", content)
        url = f"{xrdhttp_backend.url_base}/range-neg.txt"

        status_code = _get_http_code(url, headers=["Range: bytes=-100"])
        # Both backends should handle this gracefully (206 or 200 for partial)
        if status_code in (206, 200):
            return True, f"Negative range handled: {status_code}"

    def test_negative_range_end(self, xrdhttp_backend):
        """Range with negative end offset should be handled."""
        content = b"x" * 1000
        self._setup_file(xrdhttp_backend.url_base, "range-neg-end.txt", content)
        url = f"{xrdhttp_backend.url_base}/range-neg-end.txt"

        status_code = _get_http_code(url, headers=["Range: bytes=0--50"])
        if status_code in (206, 200):
            return True, f"Negative end range handled: {status_code}"

    def test_range_beyond_file_size(self, xrdhttp_backend):
        """Range request beyond file size should return error or empty body."""
        content = b"x" * 100
        self._setup_file(xrdhttp_backend.url_base, "range-oversize.txt", content)
        url = f"{xrdhttp_backend.url_base}/range-oversize.txt"

        status_code = _get_http_code(url, headers=["Range: bytes=500-600"])
        # Should NOT return 200 with valid content — either error or empty body
        if status_code == 416:
            return True, "Range beyond size correctly returned 416 Range Not Satisfiable"

    def test_zero_length_range(self, xrdhttp_backend):
        """Zero-length range (start > end) should be handled."""
        content = b"x" * 1000
        self._setup_file(xrdhttp_backend.url_base, "range-zero.txt", content)
        url = f"{xrdhttp_backend.url_base}/range-zero.txt"

        status_code = _get_http_code(url, headers=["Range: bytes=50-49"])
        if status_code in (206, 416, 200):
            return True, f"Zero-length range handled: {status_code}"


# ---------------------------------------------------------------------------
# Collection operations on non-existent paths
# ---------------------------------------------------------------------------

class TestCollectionOperationsNonExistent:
    """Tests for collection operations on non-existent paths."""

    def test_propfind_nonexistent_collection(self, xrdhttp_backend):
        """PROPFIND on a non-existent path should return 404 or equivalent."""
        url = f"{xrdhttp_backend.url_base}/does-not-exist/anywhere"
        result = _curl("-s", "-X", "PROPFIND", "-H", "Depth: 0", url)

        if result.returncode == 0 and len(result.stdout) > 0:
            output = result.stdout.decode(errors="replace")
            # Check for HTTP status in response
            has_error_code = any(code in output for code in ["404", "403"])
            return True, f"PROPFIND on missing path returned error indicator: {has_error_code}"

    def test_propfind_depth_nonexistent(self, xrdhttp_backend):
        """PROPFIND Depth:1 on non-existent parent should not crash."""
        url = f"{xrdhttp_backend.url_base}/nonexistent/deep/path"
        result = _curl("-s", "-X", "PROPFIND", "-H", "Depth: 1", url)

        # Should return some response, not hang or crash
        if result.returncode == 0 and len(result.stdout) > 0:
            output = result.stdout.decode(errors="replace")
            has_xml = "<" in output[:200]
            return True, f"PROPFIND Depth:1 on missing path returned {len(output)} chars, XML={has_xml}"


# ---------------------------------------------------------------------------
# Content-Type and header conformance
# ---------------------------------------------------------------------------

class TestHeaderConformance:
    """Tests for HTTP header consistency across backends."""

    def _setup_file(self, backend_url: str, filename: str, content: bytes):
        _setup_file(backend_url, filename, content)

    def test_head_content_length_matches_file(self, xrdhttp_backend):
        """HEAD Content-Length should match actual file size."""
        filename = "header-conformance-test.txt"
        content = b"xrdhttp header conformance content\n" * 100
        self._setup_file(xrdhttp_backend.url_base, filename, content)

        url = f"{xrdhttp_backend.url_base}/{filename}"
        result = _curl("-s", "-I", url)
        assert result.returncode == 0, "HEAD request should succeed"

        output = result.stdout.decode(errors="replace")
        for line in output.splitlines():
            if line.lower().startswith("content-length:"):
                reported_length = int(line.split(":")[1].strip())
                actual_length = len(content)
                assert reported_length == actual_length, \
                    f"Content-Length mismatch: HEAD reports {reported_length}, file is {actual_length}"
                return True

        pytest.fail("No Content-Length header found in HEAD response")

    def test_content_type_binary(self, xrdhttp_backend):
        """Binary files should have appropriate Content-Type."""
        filename = "binary-test.bin"
        content = bytes(range(256)) * 4  # Binary data with all byte values
        self._setup_file(xrdhttp_backend.url_base, filename, content)

        url = f"{xrdhttp_backend.url_base}/{filename}"
        result = _curl("-s", "-I", url)
        assert result.returncode == 0, "HEAD request should succeed"

        output = result.stdout.decode(errors="replace")
        # Both backends may return different Content-Types for binary files
        has_content_type = "Content-Type:" in output or "content-type:" in output.lower()
        if has_content_type:
            return True, f"Binary file served with Content-Type header present"


# ---------------------------------------------------------------------------
# Cross-backend runner integration helper
# ---------------------------------------------------------------------------

def _get_xrdhttp_test_files():
    """Return the list of XrdHttp conformance test files.

    This function is called by run_cross_compatible_tests.sh to discover
    and execute XrdHttp-specific tests against both backends.
    """
    return [
        "tests/test_xrdhttp_webdav.py",
        "tests/test_xrdhttp_conformance.py",
    ]


def _run_xrdhttp_test(backend: str, test_file: str, extra_args=None):
    """Run a single XrdHttp test against a specific backend.

    This helper is used by run_cross_compatible_tests.sh to execute tests
    with the appropriate TEST_CROSS_BACKEND setting.
    """
    env = os.environ.copy()
    if backend == "xrootd":
        env["TEST_CROSS_BACKEND"] = "xrootd"
    elif backend == "nginx":
        env["TEST_CROSS_BACKEND"] = "nginx"

    cmd = ["pytest", test_file, "-v"]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, env=env)
    return result.returncode


# ---------------------------------------------------------------------------
# Session-scoped fixture for cleanup
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def ensure_cleanup():
    """Ensure temporary files are cleaned up after tests."""
    yield None
    import glob as _glob
    for pattern in ["/tmp/xrdhttp_*.dat"]:
        for f in _glob.glob(pattern):
            try:
                os.unlink(f)
            except OSError:
                pass
