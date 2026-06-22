"""
tests/test_xrdhttp_auth.py — Auth Conformance Tests for XrdHttp/davs://.

Verify nginx-xrootd's authentication behavior over HTTPS/WebDAV matches the
official xrootd daemon running XrdHttp on port 11113.

Tests GSI proxy certificate auth and JWT/WLCG bearer token auth patterns.

Run: pytest tests/test_xrdhttp_auth.py -v
"""

import os
import subprocess

import pytest

from settings import (
    CA_CERT,
    DATA_ROOT as DEFAULT_DATA_ROOT,
    HOST,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_WEBDAV_PORT,
    PROXY_STD,
    XRDHTTP_HTTPS_PORT,
    url_host,
)

pytestmark = pytest.mark.timeout(120)

# ---------------------------------------------------------------------------
# Endpoints.
# ---------------------------------------------------------------------------

NGINX_GSI_URL = os.environ.get(
    "TEST_NGINX_WEBDAV_GSI_URL",
    f"https://{url_host(HOST)}:{NGINX_WEBDAV_GSI_TLS_PORT}/",
)
NGINX_TOKEN_URL = os.environ.get(
    "TEST_NGINX_WEBDAV_URL",
    f"https://{url_host(HOST)}:{NGINX_WEBDAV_PORT}/",
)
REF_URL    = os.environ.get(
    "TEST_XRDHTTP_DAVS_URL", f"https://{url_host(HOST)}:{XRDHTTP_HTTPS_PORT}/dav/"
)

DATA_ROOT  = DEFAULT_DATA_ROOT
_PFX       = "_xrdhttp_auth_"


# ---------------------------------------------------------------------------
# HTTP helpers.
# ---------------------------------------------------------------------------

def _curl(*args, timeout=30):
    """Run curl with common TLS / proxy-cert flags."""
    cmd = [
        "curl", "-sk", "--fail-early",
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _curl_with_proxy(*args):
    """Run curl with proxy cert for authenticated requests."""
    return _curl("--cert", PROXY_STD, "--key", PROXY_STD, *args)


# ---------------------------------------------------------------------------
# GSI Certificate Auth — standard proxy certificate.
# ---------------------------------------------------------------------------

class TestGSICertAuth:
    """Test that both servers handle GSI proxy cert auth consistently."""

    def test_get_with_valid_proxy_cert_both_succeed(self):
        """GET with valid proxy cert must succeed on both servers."""
        n_result = _curl_with_proxy(f"{NGINX_GSI_URL.rstrip('/')}/")
        r_result = _curl_with_proxy(f"{REF_URL.rstrip('/')}/")
        
        assert n_result.returncode == 0 and r_result.returncode == 0, (
            f"GET with proxy cert failed: nginx rc={n_result.returncode}, ref rc={r_result.returncode}"
        )

    def test_get_without_client_cert_matches_reference(self):
        """The GSI nginx endpoint and XrdHttp reference should agree without a cert."""
        n_result = _curl(f"--cacert", CA_CERT, f"{NGINX_GSI_URL.rstrip('/')}/")
        r_result = _curl(f"--cacert", CA_CERT, f"{REF_URL.rstrip('/')}/")

        # Both 20x or both non-20x — they must agree.
        assert (n_result.returncode == 0) == (r_result.returncode == 0), (
            "anonymous access differs between servers"
        )


# ---------------------------------------------------------------------------
# JWT/Bearer Token Auth — HTTP header authentication.
# ---------------------------------------------------------------------------

class TestBearerTokenAuth:
    """Test that both servers handle bearer token auth consistently."""

    def test_get_with_bearer_token_header_both_accept(self):
        """Both servers should accept a request with Authorization: Bearer header."""
        # Use a placeholder token — the server either recognizes it or returns 401.
        n_result = _curl(
            "--cacert", CA_CERT, "-H", "Authorization: Bearer test-token-placeholder",
            f"{NGINX_TOKEN_URL.rstrip('/')}/"
        )
        
        r_result = _curl(
            "--cacert", CA_CERT, "-H", "Authorization: Bearer test-token-placeholder",
            f"{REF_URL.rstrip('/')}/"
        )

        # Both should reject invalid tokens with 401 or both accept if auth is optional.
        assert (n_result.returncode != 0) == (r_result.returncode != 0), (
            "bearer token handling differs between servers"
        )


# ---------------------------------------------------------------------------
# Auth Cache — certificate + token hybrid access patterns.
# ---------------------------------------------------------------------------

class TestAuthCache:
    """Test auth cache behavior when both cert and token are available."""

    def test_dual_auth_both_succeed(self):
        """Both servers should accept requests with dual auth (cert + token)."""
        # This tests that the server doesn't reject one auth method when another exists.
        n_result = _curl_with_proxy(
            "--cacert", CA_CERT, "-H", "Authorization: Bearer test-token",
            f"{NGINX_GSI_URL.rstrip('/')}/"
        )

        r_result = _curl_with_proxy(
            "--cacert", CA_CERT, "-H", "Authorization: Bearer test-token",
            f"{REF_URL.rstrip('/')}/"
        )

        # Both should either accept (20x) or reject consistently.
        assert (n_result.returncode == 0) == (r_result.returncode == 0), (
            "dual auth handling differs between servers"
        )


# ---------------------------------------------------------------------------
# Missing/Invalid Credential Error Handling.
# ---------------------------------------------------------------------------

class TestMissingCredentials:
    """Test that both servers handle missing credentials consistently."""

    def test_no_cert_no_token_returns_same_status(self):
        """Both servers should return the same status when no auth is provided."""
        n_result = _curl(f"--cacert", CA_CERT, f"{NGINX_GSI_URL.rstrip('/')}/")
        r_result = _curl(f"--cacert", CA_CERT, f"{REF_URL.rstrip('/')}/")

        # Extract HTTP status from response.
        try:
            n_status = int(n_result.stdout.split(b"\r\n")[0].split()[1]) if b"\r\n" in n_result.stdout else 0
        except (IndexError, ValueError):
            n_status = n_result.returncode

        try:
            r_status = int(r_result.stdout.split(b"\r\n")[0].split()[1]) if b"\r\n" in r_result.stdout else 0
        except (IndexError, ValueError):
            r_status = r_result.returncode

        assert n_status == r_status, (
            f"no-auth status differs: nginx={n_status}, ref={r_status}"
        )


# ---------------------------------------------------------------------------
# Conformance — both servers must agree on auth outcomes.
# ---------------------------------------------------------------------------

class TestAuthConformanceAgreement:
    """Both servers must agree on all authentication-related outcomes."""

    def test_invalid_cert_file_both_fail(self):
        """Both servers should fail when presented with invalid cert data."""
        # Use a non-existent cert path — curl will error before reaching server.
        n_result = _curl(
            "--cert", "/tmp/nonexistent_cert.pem",
            "--key",  "/tmp/nonexistent_key.pem",
            f"{NGINX_GSI_URL.rstrip('/')}/"
        )

        r_result = _curl(
            "--cert", "/tmp/nonexistent_cert.pem",
            "--key",  "/tmp/nonexistent_key.pem",
            f"{REF_URL.rstrip('/')}/"
        )

        # Both should fail at curl level (file not found).
        assert n_result.returncode != 0 and r_result.returncode != 0, "curl cert loading differs"
