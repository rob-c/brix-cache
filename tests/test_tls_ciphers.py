"""
test_tls_ciphers.py — §5.10 xrd.tlsciphers for the root:// in-protocol TLS
context: brix_tls_ciphers (wave 18) pins the TLSv1.2-and-below cipher list
(SSL_CTX_set_cipher_list, same scope as nginx ssl_ciphers), and
brix_tls_ciphersuites (wave 20) pins the TLSv1.3 suites
(SSL_CTX_set_ciphersuites) — the latter matters because TLSv1.3 is today's
default protocol, so tls_ciphers alone cannot restrict a modern connection.

The root:// TLS is an IN-PROTOCOL upgrade (kXR_wantTLS after login), not a raw
TLS listener, so a bare s_client handshake can't probe it. But the cipher list
is applied at config init (brix_configure_tls, postconfiguration), and a list
matching NO ciphers is made a HARD config error — so `nginx -t` accept/reject is
a genuine end-to-end proof that the list reaches (and constrains) the SSL_CTX,
not merely that the directive parses:

  * success       — a valid cipher list: config init succeeds and logs that the
                    list was pinned onto the context.
  * error         — an unmatched cipher token: config init FAILS with the
                    brix_tls_ciphers diagnostic (SSL_CTX_set_cipher_list == 0),
                    proving the list is actually applied, not stored-and-ignored.
  * default/compat— no directive: config init succeeds with no cipher message —
                    OpenSSL defaults, byte-identical to before the knob.

Run:
    PYTHONPATH=tests pytest tests/test_tls_ciphers.py -v
"""

import os
import subprocess
import textwrap

import pytest

from settings import NGINX_BIN, SERVER_CERT, SERVER_KEY


def _nginx_t(tmp_path, ciphers_line):
    conf = tmp_path / "nginx.conf"
    conf.write_text(textwrap.dedent(f"""\
        daemon off;
        error_log {tmp_path}/err.log info;
        pid {tmp_path}/nginx.pid;
        events {{ worker_connections 64; }}
        stream {{
            server {{
                listen 127.0.0.1:19743;
                brix_root on;
                brix_storage_backend posix:/tmp;
                brix_auth none;
                brix_tls on;
                brix_certificate {SERVER_CERT};
                brix_certificate_key {SERVER_KEY};
                {ciphers_line}
            }}
        }}
    """))
    return subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True, timeout=30)


def _requirements():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
        pytest.skip("test host cert/key PKI not present")


def test_valid_cipher_list_is_pinned(tmp_path):
    """(success) a valid list is accepted and pinned onto the TLS context."""
    _requirements()
    r = _nginx_t(tmp_path,
                 'brix_tls_ciphers "ECDHE-RSA-AES256-GCM-SHA384:'
                 'ECDHE-ECDSA-AES256-GCM-SHA384";')
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"valid cipher list rejected:\n{out}"
    assert "test is successful" in out, out
    assert "TLS cipher list pinned" in out, \
        "cipher list accepted but never applied to the context"


def test_unmatched_cipher_list_is_a_config_error(tmp_path):
    """(error) a token matching no ciphers fails config init — proving the list
    is applied to the SSL_CTX (an ignored list could never reject)."""
    _requirements()
    r = _nginx_t(tmp_path, 'brix_tls_ciphers "NOTAREALCIPHERSUITE";')
    out = r.stdout + r.stderr
    assert r.returncode != 0, "an unmatched cipher list was accepted"
    assert "brix_tls_ciphers" in out and "matched no ciphers" in out, \
        f"expected the brix_tls_ciphers diagnostic, got:\n{out}"


def test_default_leaves_openssl_ciphers(tmp_path):
    """(default/compat) no directive: config init succeeds and never touches the
    cipher list — byte-identical to a server without the knob."""
    _requirements()
    r = _nginx_t(tmp_path, "")
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"tls config without the knob failed:\n{out}"
    assert "TLS cipher list pinned" not in out, \
        "the cipher list was pinned even though no directive was set"


# ---------------------------------------------------------------------------
# brix_tls_ciphersuites — the TLSv1.3 companion (SSL_CTX_set_ciphersuites).
# Same config-init accept/reject proof: TLSv1.3 is today's default protocol, so
# a compliance profile that restricts it needs this knob (tls_ciphers governs
# only TLSv1.2-and-below).
# ---------------------------------------------------------------------------

def test_valid_ciphersuites_are_pinned(tmp_path):
    """(success) a valid TLSv1.3 suite list is accepted and pinned."""
    _requirements()
    r = _nginx_t(tmp_path,
                 'brix_tls_ciphersuites "TLS_AES_256_GCM_SHA384:'
                 'TLS_AES_128_GCM_SHA256";')
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"valid ciphersuites rejected:\n{out}"
    assert "test is successful" in out, out
    assert "TLSv1.3 cipher suites pinned" in out, \
        "ciphersuites accepted but never applied to the context"


def test_unmatched_ciphersuites_is_a_config_error(tmp_path):
    """(error) a suite token matching no TLSv1.3 suites fails config init —
    proving the list is applied via SSL_CTX_set_ciphersuites."""
    _requirements()
    r = _nginx_t(tmp_path, 'brix_tls_ciphersuites "TLS_NOT_A_REAL_SUITE";')
    out = r.stdout + r.stderr
    assert r.returncode != 0, "an unmatched ciphersuites list was accepted"
    assert "brix_tls_ciphersuites" in out and "matched no TLSv1.3 suites" in out, \
        f"expected the brix_tls_ciphersuites diagnostic, got:\n{out}"


def test_default_leaves_openssl_ciphersuites(tmp_path):
    """(default/compat) no directive: config init succeeds and never touches the
    TLSv1.3 suites — byte-identical to a server without the knob."""
    _requirements()
    r = _nginx_t(tmp_path, "")
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"tls config without the knob failed:\n{out}"
    assert "TLSv1.3 cipher suites pinned" not in out, \
        "the TLSv1.3 suites were pinned even though no directive was set"
