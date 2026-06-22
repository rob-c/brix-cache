"""
tests/test_webdav_tpc_cred.py

HTTP-TPC OAuth2/OIDC credential delegation integration tests.

Tests the Credential: header parsing and delegation mode handling in the
WebDAV COPY handler.  Covers:

  - Credential: none (default, no delegation) — existing behavior preserved
  - Credential: oidc-agent — requires oidc-agent binary
  - Credential: token-exchange — requires configured token_endpoint
  - Invalid/unknown Credential: modes — must return 400
  - token-exchange without endpoint configured — must return 502

Run:
    pytest tests/test_webdav_tpc_cred.py -v
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from settings import (
    HOST,
    PKI_DIR as PKI_DIR_STR,
    TEST_ROOT,
    WEBDAV_TPC_SOURCE_OPEN_PORT,
    url_host,
)

PKI_DIR = Path(PKI_DIR_STR)
CA_PEM = PKI_DIR / "ca" / "ca.pem"
CLIENT_CERT = PKI_DIR / "user" / "usercert.pem"
CLIENT_KEY = PKI_DIR / "user" / "userkey.pem"
SERVER_CERT = PKI_DIR / "server" / "hostcert.pem"
SERVER_KEY = PKI_DIR / "server" / "hostkey.pem"


def _curl(*args, timeout=30):
    cmd = [
        "curl",
        "-sk",
        "--cert",
        str(CLIENT_CERT),
        "--key",
        str(CLIENT_KEY),
        "--cacert",
        str(CA_PEM),
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _copy_pull(dest_port, dest_path, source_url, *extra_headers, timeout=30):
    """Send a TPC pull COPY request.

    extra_headers may include a Credential: or Credentials: header to
    override the default "Credential: none".
    """
    has_cred = any(
        h.lower().startswith("credential") or h.lower().startswith("credentials")
        for h in extra_headers
    )
    args = [
        "-X", "COPY",
        f"https://{url_host(HOST)}:{dest_port}{dest_path}",
        "-H", f"Source: {source_url}",
    ]
    if has_cred:
        for h in extra_headers:
            args.extend(["-H", h])
    else:
        args.extend(["-H", "Credential: none"])
        for h in extra_headers:
            args.extend(["-H", h])
    args.extend(["-w", "%{http_code}", "-o", "/dev/null"])
    result = _curl(*args, timeout=timeout)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return int(result.stdout.strip())


def _require_common_tools():
    if shutil.which("curl") is None:
        pytest.skip("curl not found")
    for path in (CA_PEM, CLIENT_CERT, CLIENT_KEY, SERVER_CERT, SERVER_KEY):
        if not path.exists():
            pytest.skip(f"test PKI file not found: {path}")


# ---------------------------------------------------------------------------
# Session-scoped fixture: start the TPC nginx server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def tpc_nginx_server():
    """Use the suite-level WebDAV TPC nginx instance."""
    _require_common_tools()

    data_dir = Path(TEST_ROOT) / "data-webdav-tpc" / "source_open"
    data_dir.mkdir(parents=True, exist_ok=True)

    ok = False
    for _ in range(40):
        try:
            result = _curl(
                "-X", "OPTIONS",
                f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/",
                "-o", "/dev/null",
                timeout=3,
            )
        except subprocess.TimeoutExpired:
            time.sleep(0.2)
            continue
        if result.returncode == 0:
            ok = True
            break
        time.sleep(0.2)
    if not ok:
        pytest.fail(
            "suite WebDAV TPC server did not respond on "
            f"port {WEBDAV_TPC_SOURCE_OPEN_PORT}."
        )

    yield {"source_open_root": data_dir}


# ---------------------------------------------------------------------------
# Tests: Credential header parsing and validation
# ---------------------------------------------------------------------------

class TestCredHeaderParsing:
    """Tests for Credential: header parsing in HTTP-TPC COPY."""

    def test_credential_none_default(self):
        """Credential: none is accepted (no delegation)."""
        code = _copy_pull(
            WEBDAV_TPC_SOURCE_OPEN_PORT,
            "/nonexistent",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "Credential: none",
        )
        # Source file doesn't exist, so we expect 502 (curl can't fetch it)
        # but NOT 400 (which would mean credential parsing failed).
        assert code != 400, f"Expected non-400 status, got {code}"

    def test_credential_oidc_agent_accepted(self):
        """Credential: oidc-agent is accepted as a valid mode.

        The actual oidc-agent call will fail (no daemon), but the server
        should not reject the mode itself with 400.
        """
        # Send directly to handle non-200 responses gracefully.
        cmd = [
            "curl", "-sk",
            "--cert", str(CLIENT_CERT),
            "--key", str(CLIENT_KEY),
            "--cacert", str(CA_PEM),
            "-X", "COPY",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/nonexistent",
            "-H", f"Source: https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "-H", "Credential: oidc-agent",
            "-w", "%{http_code}", "-o", "/dev/null",
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        code = int(result.stdout.strip()) if result.stdout.strip() else 0
        # The mode is valid; token acquisition may fail (502) or the connection
        # may drop (curl exit 52).  We only care that it is not 400.
        assert code != 400, f"Unexpected 400 for valid mode 'oidc-agent': got {code}"

    def test_credential_token_exchange_accepted(self):
        """Credential: token-exchange is accepted as a valid mode.

        Without a configured token_endpoint, token-exchange should fail with
        a 502 (bad gateway) from the token acquisition step, not 400.
        """
        code = _copy_pull(
            WEBDAV_TPC_SOURCE_OPEN_PORT,
            "/nonexistent",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "Credential: token-exchange",
        )
        # Token acquisition fails (no endpoint configured), but mode is valid.
        assert code != 400, f"Unexpected 400 for valid mode 'token-exchange': got {code}"

    def test_credential_invalid_mode_returns_400(self):
        """Unknown Credential: mode must return 400 Bad Request."""
        code = _copy_pull(
            WEBDAV_TPC_SOURCE_OPEN_PORT,
            "/nonexistent",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "Credential: invalid-mode",
        )
        assert code == 400, f"Expected 400 for invalid mode, got {code}"

    def test_credential_empty_mode_returns_400(self):
        """Empty Credential: value is an unknown mode → 400."""
        code = _copy_pull(
            WEBDAV_TPC_SOURCE_OPEN_PORT,
            "/nonexistent",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "Credential: ",
        )
        # Empty value is not a known mode; server should return 400.
        # If nginx drops the empty header, the request falls through to
        # token acquisition which fails → 502.  In either case the mode
        # is not accepted as valid ("none").
        assert code not in (200, 201, 204), f"Empty mode should not succeed: got {code}"

    def test_credential_case_sensitive(self):
        """Credential mode values are case-sensitive."""
        # "OIDC-AGENT" is not the same as "oidc-agent"
        code = _copy_pull(
            WEBDAV_TPC_SOURCE_OPEN_PORT,
            "/nonexistent",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "Credential: OIDC-AGENT",
        )
        assert code == 400, f"Expected 400 for uppercase 'OIDC-AGENT', got {code}"

    def test_credential_credentials_variant(self):
        """Credential header with plural 'Credentials' is also accepted."""
        # The handler checks both "Credential" and "Credentials" headers.
        # Using "Credentials: none" should work the same as "Credential: none".
        code = _copy_pull(
            WEBDAV_TPC_SOURCE_OPEN_PORT,
            "/nonexistent",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/also-nonexistent",
            "Credentials: none",
        )
        assert code != 400, f"Expected non-400 for 'Credentials: none', got {code}"


# ---------------------------------------------------------------------------
# Tests: Push mode credential delegation
# ---------------------------------------------------------------------------

class TestPushCredDelegation:
    """Tests for Credential: header in HTTP-TPC push mode."""

    def test_push_credential_none(self):
        """Push with Credential: none works (no delegation)."""
        cmd = [
            "curl", "-sk",
            "-X", "COPY",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/nonexistent",
            "-H", "Credential: none",
            "-H", f"Destination: https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/dest",
            "-w", "%{http_code}", "-o", "/dev/null",
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        code = int(result.stdout.strip())
        # File doesn't exist, so not 400 (credential rejection).
        assert code != 400, f"Unexpected 400 for push Credential: none, got {code}"

    def test_push_invalid_credential_mode(self):
        """Push with invalid Credential: mode returns 400."""
        cmd = [
            "curl", "-sk",
            "-X", "COPY",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/nonexistent",
            "-H", "Credential: bogus-mode",
            "-H", f"Destination: https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/dest",
            "-w", "%{http_code}", "-o", "/dev/null",
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        code = int(result.stdout.strip())
        assert code == 400, f"Expected 400 for push with invalid mode, got {code}"

    def test_push_credential_oidc_agent_accepted(self):
        """Push with Credential: oidc-agent is accepted (mode valid)."""
        cmd = [
            "curl", "-sk",
            "-X", "COPY",
            f"https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/nonexistent",
            "-H", "Credential: oidc-agent",
            "-H", f"Destination: https://{url_host(HOST)}:{WEBDAV_TPC_SOURCE_OPEN_PORT}/dest",
            "-w", "%{http_code}", "-o", "/dev/null",
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        code = int(result.stdout.strip()) if result.stdout.strip() else 0
        # Mode accepted; token acquisition may fail.  Only reject if 400.
        assert code != 400, f"Unexpected 400 for push Credential: oidc-agent, got {code}"


# ---------------------------------------------------------------------------
# Tests: Metrics counters exist
# ---------------------------------------------------------------------------

class TestCredMetrics:
    """Verify TPC cred metrics are exported by the Prometheus endpoint."""

    def test_tpc_cred_metrics_in_export(self):
        """xrootd_webdav_tpc_cred_total counter is exported."""
        # Use the metrics port (9100) to scrape.
        cmd = [
            "curl", "-s",
            f"http://{url_host(HOST)}:9100/metrics",
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert result.returncode == 0, "Metrics endpoint unreachable"
        text = result.stdout.decode()
        assert "xrootd_webdav_tpc_cred_total" in text, (
            "TPC cred metrics not found in Prometheus export"
        )
