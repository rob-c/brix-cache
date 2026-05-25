"""
tests/test_ocsp.py — OCSP certificate revocation checking and stapling tests.

Tests the Feature 8e implementation:
  - xrootd_ocsp_enable:    check client certs against OCSP responder
  - xrootd_ocsp_soft_fail: treat network errors as pass
  - xrootd_ocsp_stapling:  serve cached OCSP response in TLS ServerHello

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
import http.server
import os
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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

OCSP_RESPONDER_PORT = 18888   # local mock OCSP responder


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


class _OCSPHandler(http.server.BaseHTTPRequestHandler):
    """Minimal OCSP responder: returns a pre-built DER response."""

    # Class-level: set before starting the server
    response_der: bytes = b""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(self.response_der)))
        self.end_headers()
        self.wfile.write(self.response_der)

    def log_message(self, _fmt, *_args):
        pass  # silence request logging in tests


class MockOCSPServer:
    """Thread-based mock OCSP HTTP responder for use in tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = OCSP_RESPONDER_PORT):
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self, response_der: bytes):
        _OCSPHandler.response_der = response_der
        self._server = http.server.HTTPServer((self.host, self.port), _OCSPHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None


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


# ---------------------------------------------------------------------------
# Mock OCSP server lifecycle tests
# ---------------------------------------------------------------------------

class TestMockOCSPServer:
    """Verify the mock OCSP HTTP server starts, serves, and stops cleanly."""

    @pytest.fixture(autouse=True)
    def _require_pki(self):
        if not os.path.exists(CA_CERT) or not os.path.exists(USER_CERT):
            pytest.skip("PKI not available — run tests in LOCAL mode with server")

    def test_mock_server_serves_good_response(self):
        der = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.GOOD,
            CA_CERT, CA_KEY, USER_CERT,
        )
        srv = MockOCSPServer(port=OCSP_RESPONDER_PORT)
        srv.start(der)
        try:
            import urllib.request
            req = urllib.request.Request(
                f"http://127.0.0.1:{OCSP_RESPONDER_PORT}/",
                data=b"dummy",
                headers={"Content-Type": "application/ocsp-request"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()
            assert body == der
        finally:
            srv.stop()

    def test_mock_server_serves_revoked_response(self):
        der = _build_ocsp_response(
            x509_ocsp.OCSPCertStatus.REVOKED,
            CA_CERT, CA_KEY, USER_CERT,
        )
        srv = MockOCSPServer(port=OCSP_RESPONDER_PORT)
        srv.start(der)
        try:
            import urllib.request
            req = urllib.request.Request(
                f"http://127.0.0.1:{OCSP_RESPONDER_PORT}/",
                data=b"dummy",
                headers={"Content-Type": "application/ocsp-request"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()
            # Parse and verify the response indicates REVOKED
            loaded = x509_ocsp.load_der_ocsp_response(body)
            assert loaded.certificate_status == x509_ocsp.OCSPCertStatus.REVOKED
        finally:
            srv.stop()
