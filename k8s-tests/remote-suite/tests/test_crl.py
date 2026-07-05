# brix-remote-skip
"""
tests/test_crl.py

Certificate Revocation List (CRL) tests.

Verifies that when brix_crl is configured, revoked user certificates
are rejected by both the XRootD stream (GSI) and WebDAV (HTTPS) auth
paths.

Test infrastructure:
  - Generates a CRL signed by the test CA that revokes the test user cert
  - Starts a dedicated nginx listener with CRL checking enabled
  - Verifies that the revoked proxy is rejected while a non-revoked cert
    would succeed (baseline sanity via the existing non-CRL listener)

Run:
    pytest tests/test_crl.py -v
"""

import datetime
import os
import signal
import socket
import subprocess
import time

import pytest
import urllib3
import requests

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
)
from settings import (
    CA_CERT,
    CA_KEY,
    CRL_DIR_PORT,
    CRL_PORT,
    CRL_RELOAD_PORT,
    HOST,
    PKI_DIR,
    PROXY_STD,
    TEST_ROOT,
    USER_CERT,
    WEBDAV_CRL_PORT,
    WEBDAV_DIR_PORT,
    url_host,
)

# Suppress InsecureRequestWarning — test certs have no SAN
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROXY_PEM  = PROXY_STD

CRL_DIR    = os.path.join(TEST_ROOT, "generated-crl")
CRL_PEM    = os.path.join(CRL_DIR, "crl.pem")

CRL_HOST   = HOST

# Directory-mode test paths
CRL_DIR_TEST      = os.path.join(TEST_ROOT, "crls")
CRL_DIR_CRLS      = CRL_DIR_TEST   # directory of CRLs

# Reload-mode test paths
CRL_RELOAD_DIR    = os.path.join(TEST_ROOT, "crl-reload")
CRL_RELOAD_CRLS   = CRL_RELOAD_DIR
RELOAD_INTERVAL   = 2  # seconds — keep short for testing

# ---------------------------------------------------------------------------
# CRL generation
# ---------------------------------------------------------------------------

def generate_crl(ca_cert_path, ca_key_path, revoked_cert_path, crl_path):
    """Generate a CRL that revokes the given certificate."""
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(revoked_cert_path, "rb") as f:
        revoked_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.datetime.now(datetime.timezone.utc)

    revoked = (
        RevokedCertificateBuilder()
        .serial_number(revoked_cert.serial_number)
        .revocation_date(now - datetime.timedelta(hours=1))
        .build()
    )

    crl = (
        CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=30))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(crl_path), exist_ok=True)
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))


# ---------------------------------------------------------------------------
# Wait for port
# ---------------------------------------------------------------------------

def _wait_for_port(host, port, timeout=5):
    """Block until a TCP port accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def crl_file():
    """Generate a CRL revoking the test user certificate."""
    generate_crl(CA_CERT, CA_KEY, USER_CERT, CRL_PEM)
    return CRL_PEM


@pytest.fixture(scope="session", autouse=True)
def crl_nginx(crl_file):
    """Use the suite-level nginx with CRL checking enabled."""
    if not _wait_for_port(HOST, WEBDAV_CRL_PORT):
        pytest.fail("CRL nginx did not start (HTTPS port not reachable)")

    yield {
        "conf": os.path.join(TEST_ROOT, "dedicated", "crl", "conf", "nginx.conf"),
        "log_dir": os.path.join(TEST_ROOT, "dedicated", "crl", "logs"),
    }


@pytest.fixture(scope="session", autouse=True)
def crl_dir_nginx(crl_file):
    """Use the suite-level nginx with brix_crl pointing at a directory."""
    os.makedirs(CRL_DIR_CRLS, exist_ok=True)
    import shutil
    shutil.copy2(crl_file, os.path.join(CRL_DIR_CRLS, "ca.r0"))

    ok_stream = _wait_for_port(HOST, CRL_DIR_PORT)
    ok_https = _wait_for_port(HOST, WEBDAV_DIR_PORT)

    if not ok_stream or not ok_https:
        pytest.fail(f"CRL dir nginx did not start. stream={ok_stream} https={ok_https}")

    yield {
        "conf": os.path.join(TEST_ROOT, "dedicated", "crl-dir", "conf", "nginx.conf"),
        "log_dir": os.path.join(TEST_ROOT, "dedicated", "crl-dir", "logs"),
    }


@pytest.fixture(scope="session", autouse=True)
def crl_reload_nginx(crl_file):
    """Use the suite-level nginx with CRL reload enabled.

    The test will copy the CRL into the directory after nginx starts,
    wait for the reload timer to fire, then verify rejection.
    """
    os.makedirs(CRL_RELOAD_CRLS, exist_ok=True)

    # Remove any stale CRL files left by a previous test run so that
    # test_initially_accepts_revoked_cert sees a clean (CRL-free) state.
    for fname in os.listdir(CRL_RELOAD_CRLS):
        try:
            os.unlink(os.path.join(CRL_RELOAD_CRLS, fname))
        except OSError:
            pass

    # Signal nginx to reload config so it drops any in-memory CRL state.
    pid_file = os.path.join(TEST_ROOT, "dedicated", "crl-reload", "logs", "nginx.pid")
    if os.path.exists(pid_file):
        for line in open(pid_file).read().split():
            try:
                os.kill(int(line.strip()), signal.SIGHUP)
            except (OSError, ValueError):
                pass
        time.sleep(1.0)

    if not _wait_for_port(CRL_HOST, CRL_RELOAD_PORT):
        pytest.fail("CRL reload nginx did not start.")

    yield {
        "crl_src": crl_file,
        "log_dir": os.path.join(TEST_ROOT, "dedicated", "crl-reload", "logs"),
    }


# =========================================================================
# Tests
# =========================================================================


class TestCRLGeneration:
    """Validate the generated CRL."""

    def test_crl_file_exists(self, crl_file):
        assert os.path.exists(crl_file)

    def test_crl_contains_revoked_serial(self, crl_file):
        """CRL should list the user cert serial number."""
        with open(crl_file, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        with open(USER_CERT, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        revoked = crl.get_revoked_certificate_by_serial_number(
            user_cert.serial_number
        )
        assert revoked is not None, "user cert should be in the CRL"


class TestCRLStreamRejection:
    """XRootD GSI auth should reject a revoked user certificate."""

    def test_baseline_non_crl_server_accepts(self, test_env):
        """Sanity check: the normal GSI listener (no CRL) still accepts."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", test_env["gsi_url"], "stat", "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode == 0, (
            f"baseline GSI stat failed: {result.stderr}"
        )

    def test_revoked_cert_rejected_by_crl_server(self, crl_nginx):
        """The CRL-enabled listener should reject the revoked proxy."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://{url_host(HOST)}:{CRL_PORT}", "stat", "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode != 0, (
            f"revoked cert should be rejected but stat succeeded"
        )


class TestCRLWebDAVRejection:
    """WebDAV/HTTPS should reject a revoked client certificate."""

    def test_revoked_cert_rejected_by_webdav(self, crl_nginx):
        """HTTPS request with revoked client cert should fail auth."""
        # We need to present the client cert for mutual TLS.
        # requests uses cert= for client certs.
        # The proxy_std.pem has cert+key+chain in one file.
        resp = requests.get(
            f"https://{url_host(HOST)}:{WEBDAV_CRL_PORT}/test.txt",
            cert=PROXY_PEM,
            verify=False,
        )
        # Should be 403 (forbidden) because the cert is revoked
        assert resp.status_code == 403, (
            f"expected 403, got {resp.status_code}: {resp.text}"
        )


class TestCRLConfigDirectives:
    """Verify CRL configuration is accepted and operational."""

    def test_nginx_config_accepted(self, crl_nginx):
        """Server reachability confirms the CRL config was accepted by nginx."""
        assert _wait_for_port(CRL_HOST, CRL_PORT), (
            f"CRL nginx not reachable on port {CRL_PORT}"
        )

    def test_crl_loaded_in_logs(self, crl_nginx):
        """Error log should contain a message confirming the CRL was loaded."""
        log_path = os.path.join(crl_nginx["log_dir"], "error.log")
        if not os.path.exists(log_path):
            pytest.skip("error.log not found")
        with open(log_path) as f:
            log_content = f.read()
        assert "CRL" in log_content and "loaded" in log_content, (
            f"expected CRL loaded message in error.log:\n{log_content[:500]}"
        )


class TestCRLDirectoryMode:
    """Verify brix_crl with a directory of CRL files."""

    def test_revoked_cert_rejected_stream(self, crl_dir_nginx):
        """Stream: revoked cert should fail via directory-loaded CRL."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://{url_host(HOST)}:{CRL_DIR_PORT}", "stat", "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode != 0, (
            "revoked cert should be rejected via directory CRL"
        )

    def test_revoked_cert_rejected_webdav(self, crl_dir_nginx):
        """WebDAV: revoked cert should fail via directory-loaded CRL."""
        resp = requests.get(
            f"https://{url_host(HOST)}:{WEBDAV_DIR_PORT}/test.txt",
            cert=PROXY_PEM,
            verify=False,
        )
        assert resp.status_code == 403, (
            f"expected 403, got {resp.status_code}: {resp.text}"
        )

    def test_directory_crl_config_accepted(self, crl_dir_nginx):
        """Server reachability confirms the directory-mode CRL config was accepted."""
        assert _wait_for_port(CRL_HOST, CRL_DIR_PORT), (
            f"CRL dir nginx not reachable on port {CRL_DIR_PORT}"
        )

    def test_directory_crl_loaded_in_logs(self, crl_dir_nginx):
        """Error log should confirm CRL files were loaded from the directory."""
        log_path = os.path.join(crl_dir_nginx["log_dir"], "error.log")
        if not os.path.exists(log_path):
            pytest.skip("error.log not found")
        with open(log_path) as f:
            log_content = f.read()
        assert "CRL" in log_content and "loaded" in log_content, (
            f"expected CRL loaded message in error.log:\n{log_content[:500]}"
        )


class TestCRLReload:
    """Verify brix_crl_reload picks up new CRLs without restart."""

    def test_initially_accepts_revoked_cert(self, crl_reload_nginx):
        """Before CRL is placed, revoked cert should be accepted."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://{url_host(HOST)}:{CRL_RELOAD_PORT}", "stat",
             "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode == 0, (
            f"should accept before CRL is loaded: {result.stderr}"
        )

    def test_rejects_after_crl_reload(self, crl_reload_nginx):
        """After CRL is copied into directory and timer fires, cert rejected."""
        import shutil

        info = crl_reload_nginx
        # Copy CRL into the reload directory
        shutil.copy2(info["crl_src"],
                     os.path.join(CRL_RELOAD_CRLS, "ca.r0"))

        # Wait for the reload interval + margin
        time.sleep(RELOAD_INTERVAL + 2)

        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://{url_host(HOST)}:{CRL_RELOAD_PORT}", "stat",
             "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode != 0, (
            "revoked cert should be rejected after CRL reload"
        )

    def test_reload_timer_log_message(self, crl_reload_nginx):
        """The error log should contain the CRL reload timer message."""
        info = crl_reload_nginx
        log_path = os.path.join(info["log_dir"], "error.log")

        if not os.path.exists(log_path):
            pytest.skip("error.log not found")

        with open(log_path) as f:
            log_content = f.read()

        assert "CRL reload timer fired" in log_content, (
            "expected 'CRL reload timer fired' in error.log"
        )
