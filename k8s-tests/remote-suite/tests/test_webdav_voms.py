# brix-remote-skip
"""Section 2.2 — VOMS VO/FQAN extraction for WebDAV tests.

Verifies the behaviour introduced in Section 2.2: ``webdav_extract_voms_ctx()``
in ``src/protocols/webdav/auth_cert.c`` attempts VOMS extraction after every successful
GSI cert verification path and populates ``ctx->primary_vo`` /
``ctx->vo_list``.

The dedicated ``webdav-voms`` server (port 18458) is configured with:

    brix_webdav_auth         required
    brix_webdav_vomsdir      /tmp/xrd-test/pki/vomsdir
    brix_webdav_voms_cert_dir /tmp/xrd-test/pki/ca

The test PKI produces standard proxy certs **without** VOMS attributes, so
``brix_extract_voms_info()`` returns ``NGX_DECLINED`` on every request.
Tests verify:

  1. ``success_no_voms_attrs`` — GSI auth still succeeds when VOMS extraction
     is skipped (NGX_DECLINED is treated as non-fatal).
  2. ``error_no_client_cert`` — requests without a client certificate are
     rejected (401/403) even when vomsdir is configured.
  3. ``security_neg_untrusted_cert`` — a self-signed cert not issued by the
     test CA is rejected; vomsdir config must not introduce an auth bypass.

Three test cases (per AGENTS.md: success + error + security-neg).
"""

import os
import ssl
import tempfile
import uuid

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from settings import (
    NGINX_WEBDAV_VOMS_PORT,
    PROXY_STD,
    SERVER_HOST,
    PKI_DIR,
    DATA_ROOT,
)

VOMS_DATA = os.path.join(os.path.dirname(DATA_ROOT), "data-webdav-voms")
VOMS_BASE_URL = f"https://{SERVER_HOST}:{NGINX_WEBDAV_VOMS_PORT}"


def _session_with_proxy():
    """requests.Session authenticated with the test GSI proxy (no VOMS attrs)."""
    s = requests.Session()
    s.cert = (PROXY_STD, PROXY_STD)
    s.verify = False
    return s


def _session_no_cert():
    """requests.Session without client certificate."""
    s = requests.Session()
    s.verify = False
    return s


# ---------------------------------------------------------------------------
# 1. Success — VOMS extraction gracefully skipped; GSI auth still passes
# ---------------------------------------------------------------------------

def test_success_no_voms_attrs():
    """Proxy cert with no VOMS attributes: VOMS extraction returns NGX_DECLINED.

    ``webdav_extract_voms_ctx()`` returns immediately when
    ``brix_extract_voms_info()`` finds no VOMS extension.  The auth flow
    must continue normally and return 200/201 for a valid GSI proxy.
    """
    uid = uuid.uuid4().hex
    rel = f"voms_test_{uid}.txt"
    origin_path = os.path.join(VOMS_DATA, rel)

    try:
        # Seed the origin file directly so GET is guaranteed to find it
        os.makedirs(VOMS_DATA, exist_ok=True)
        with open(origin_path, "wb") as f:
            f.write(b"voms-test-content-" + uid.encode())

        s = _session_with_proxy()
        r = s.get(f"{VOMS_BASE_URL}/{rel}", timeout=10)
        # Auth succeeds; VOMS extraction absent is non-fatal
        assert r.status_code == 200, (
            f"Expected 200 for authenticated request, got {r.status_code} — "
            "VOMS extraction failure must not block GSI auth"
        )
    finally:
        try:
            os.unlink(origin_path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# 2. Error — no client certificate → request rejected
# ---------------------------------------------------------------------------

def test_error_no_client_cert():
    """Requests without a client cert must be rejected even when vomsdir is set.

    ``brix_webdav_auth required`` means the SSL handshake will fail or the
    module will return 401/403 when no client certificate is presented.
    Configuring vomsdir must not weaken this requirement.
    """
    s = _session_no_cert()
    r = s.get(f"{VOMS_BASE_URL}/test.txt", timeout=10)
    assert r.status_code in (400, 401, 403, 495, 496), (
        f"Expected auth failure without client cert, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# 3. Security-neg — self-signed cert not trusted by CA → rejected
# ---------------------------------------------------------------------------

def test_security_neg_untrusted_cert():
    """A self-signed cert must be rejected; vomsdir must not bypass CA check.

    If ``brix_webdav_vomsdir`` were consulted before the CA chain check, an
    attacker could use a self-signed cert that happens to have a crafted VOMS
    extension to gain access.  The module checks cert validity FIRST via
    ``webdav_verify_proxy_cert()``; VOMS extraction only happens AFTER the
    cert is verified.  An untrusted cert must produce 401/403/SSL error.
    """
    # Generate a self-signed cert in memory using the standard library
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
        import tempfile

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil-user")])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)          # self-signed: issuer == subject
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(cert_pem + key_pem)
            tmp_cert = cf.name

        try:
            s = requests.Session()
            s.cert = (tmp_cert, tmp_cert)
            s.verify = False
            r = s.get(f"{VOMS_BASE_URL}/test.txt", timeout=10)
            assert r.status_code in (400, 401, 403, 495, 496), (
                f"Self-signed cert must be rejected, got {r.status_code} — "
                "vomsdir must not bypass CA chain verification"
            )
        finally:
            os.unlink(tmp_cert)

    except ImportError:
        pytest.skip("cryptography package not available for self-signed cert test")
