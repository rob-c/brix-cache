"""Verified TLS transport for the delegated-credential renewal fixtures."""

import ssl

from settings import CA_CERT, CA_DIR, HOST, SERVER_CERT, SERVER_KEY
from test_tls_require import _connect, _protocol_flags, _xrd_login, kXR_gotoTLS


def tls_knobs():
    """Use the session PKI for both incoming TLS and outbound peer validation."""
    return ("brix_tls on;",
            f"brix_certificate {SERVER_CERT};",
            f"brix_certificate_key {SERVER_KEY};",
            f"brix_trusted_ca {CA_DIR};")


def tls_login(port):
    """Negotiate TLS, verify the source identity, then log in on that channel."""
    raw = _connect(port)
    try:
        assert _protocol_flags(raw) & kXR_gotoTLS
        context = ssl.create_default_context(cafile=CA_CERT)
        secured = context.wrap_socket(raw, server_hostname=HOST)
    except BaseException:
        raw.close()
        raise
    try:
        status, body = _xrd_login(secured)
        assert status == 0, ("TLS login refused", status, body)
        return secured
    except BaseException:
        secured.close()
        raise
