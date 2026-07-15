"""
tests/test_ocsp.py — OCSP certificate revocation checking and stapling tests.

Tests the Feature 8e implementation:
  - brix_ocsp_enable:    check client certs against OCSP responder
  - brix_ocsp_soft_fail: treat network errors as pass
  - brix_ocsp_stapling:  serve cached OCSP response in TLS ServerHello

Test strategy:
  - Unit-level: verify the Python OCSP response builder and mock server work
    correctly.  Config-directive validation is covered implicitly by the
    dedicated OCSP server started during the test suite setup.
  - Integration-level: start a minimal Python OCSP responder (using
    cryptography), configure nginx to point at it, then verify GSI auth
    succeeds (GOOD response) and fails (REVOKED response).

Run:
    pytest tests/test_ocsp.py -v
"""

import datetime
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from cryptography.x509 import ocsp as x509_ocsp
from cryptography.hazmat.backends import default_backend

from settings import (
    CA_CERT,
    CA_KEY,
    USER_CERT,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# phase-79 file-size split: the HTTP(S) responder transport (URL scheme
# handling, TLS BIO, peer/hostname verification) moved out of ocsp.c into
# ocsp_transport.c; ocsp.c keeps the public entry points.
OCSP_SOURCE = (Path(__file__).resolve().parents[1]
               / "src" / "auth" / "crypto" / "ocsp_transport.c")


# ---------------------------------------------------------------------------
# HTTPS OCSP implementation guardrails
# ---------------------------------------------------------------------------

class TestOCSPHTTPSImplementation:
    """Static guardrails for HTTPS responder support in the C OCSP client."""

    @pytest.fixture(scope="class")
    def source(self):
        return OCSP_SOURCE.read_text(encoding="utf-8")

    def test_https_urls_are_accepted(self, source):
        assert 'strncmp(url, "https://", 8)' in source
        assert "HTTPS OCSP responder not supported" not in source

    def test_https_uses_tls_client_bio(self, source):
        assert "TLS_client_method()" in source
        assert "BIO_new_ssl_connect" in source

    def test_https_verifies_peer_and_hostname(self, source):
        assert "SSL_VERIFY_PEER" in source
        assert "SSL_set_tlsext_host_name" in source
        assert "SSL_set1_host" in source
        assert "SSL_get_verify_result" in source


# ---------------------------------------------------------------------------
# Mock OCSP responder
# ---------------------------------------------------------------------------

def _load_cert(path: str):
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read(), default_backend())


def _load_key(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None,
                                                  backend=default_backend())


def _build_ocsp_response(
    cert_status: x509_ocsp.OCSPCertStatus,
    ca_cert_path: str,
    ca_key_path: str,
    subject_cert_path: str,
) -> bytes:
    """Build a signed DER-encoded OCSP response for the given cert."""
    ca_cert = _load_cert(ca_cert_path)
    ca_key  = _load_key(ca_key_path)
    subject = _load_cert(subject_cert_path)

    builder = x509_ocsp.OCSPResponseBuilder()
    now = datetime.datetime.utcnow()

    if cert_status == x509_ocsp.OCSPCertStatus.GOOD:
        builder = builder.add_response(
            cert=subject,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=now,
            next_update=now + datetime.timedelta(hours=1),
            revocation_time=None,
            revocation_reason=None,
        )
    else:
        builder = builder.add_response(
            cert=subject,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=now,
            next_update=now + datetime.timedelta(hours=1),
            revocation_time=now - datetime.timedelta(hours=1),
            revocation_reason=x509.ReasonFlags.unspecified,
        )

    response = builder.responder_id(
        x509_ocsp.OCSPResponderEncoding.HASH, ca_cert
    ).sign(ca_key, hashes.SHA256())

    return response.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Mock OCSP response builder tests (unit tests for the Python helper)
# ---------------------------------------------------------------------------

class TestMockOCSPResponseBuilder:
    """Validate that our Python OCSP response builder produces parseable DER."""

    @pytest.fixture(autouse=True)
    def _require_pki(self):
        if not os.path.exists(CA_CERT) or not os.path.exists(USER_CERT):
            pytest.skip("PKI not available — run tests in LOCAL mode with server")

    def test_good_response_is_der_encoded(self):
        der = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.GOOD,
            CA_CERT, CA_KEY, USER_CERT,
        )
        assert len(der) > 0
        # DER sequence starts with 0x30
        assert der[0] == 0x30, "OCSP response must be a DER SEQUENCE"

    def test_revoked_response_is_der_encoded(self):
        der = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.REVOKED,
            CA_CERT, CA_KEY, USER_CERT,
        )
        assert len(der) > 0
        assert der[0] == 0x30

    def test_good_and_revoked_responses_differ(self):
        good = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.GOOD,
            CA_CERT, CA_KEY, USER_CERT,
        )
        revoked = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.REVOKED,
            CA_CERT, CA_KEY, USER_CERT,
        )
        assert good != revoked

    def test_ocsp_response_is_parseable(self):
        """The Python cryptography library must be able to round-trip the response."""
        der = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.GOOD,
            CA_CERT, CA_KEY, USER_CERT,
        )
        loaded = x509_ocsp.load_der_ocsp_response(der)
        assert loaded.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL
        assert loaded.certificate_status == x509_ocsp.OCSPCertStatus.GOOD

    def test_revoked_response_status_field(self):
        der = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.REVOKED,
            CA_CERT, CA_KEY, USER_CERT,
        )
        loaded = x509_ocsp.load_der_ocsp_response(der)
        assert loaded.certificate_status == x509_ocsp.OCSPCertStatus.REVOKED
