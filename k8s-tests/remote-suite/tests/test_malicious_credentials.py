"""
tests/test_malicious_credentials.py

Cross-protocol "malicious credential" hardening tests.  A bad actor controls the
credential it presents — the token header, the token claims, the credential
*type*, or the client certificate — and tries to (a) authenticate as someone it
is not, (b) crash/hang the auth parser (DoS), or (c) leak host data.

These complement test_token_security.py (which already covers alg=none, alg
confusion, exp/nbf/aud/iss, bad-sig, token structure, oversized, scope
boundaries) by attacking the auth surface from angles that had NO test:

  * JWT *header* abuse — the alg/kid are jansson-parsed BEFORE the signature is
    checked, so a malicious header reaches the parser regardless of signature:
    deeply-nested JSON, non-object/array headers, alg as a non-string, alg with
    whitespace/case tricks, a huge kid, duplicate keys.
  * Validly-SIGNED tokens with abusive claims — wrong-typed exp, a huge aud
    array (DoS), a non-object payload.
  * Cross-protocol credential confusion — a GSI cert PEM, an S3 SigV4 string, or
    an HTTP Basic header presented where a WLCG bearer is expected (INVARIANT:
    S3 SigV4 != WLCG token; one credential type must not satisfy another).
  * Untrusted / self-signed TLS client certificates.

Test design: the assertions run against the auth-REQUIRED HTTPS WebDAV endpoint
(8444), which gives a clean oracle — a *valid* token returns 2xx (positive
control), so a malicious credential returning 403 is a genuine rejection, not a
blanket failure.  Every probe must additionally never 5xx (crash), never hang,
and never leak host content.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_malicious_credentials.py -v
"""

import json
import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer, b64url_encode   # noqa: E402

from cryptography.hazmat.primitives import hashes          # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402

from settings import (                                      # noqa: E402
    SERVER_HOST,
    TOKENS_DIR,
    NGINX_WEBDAV_GSI_TLS_PORT,   # https WebDAV, auth REQUIRED (8444)
    NGINX_S3_PORT,
)

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:                                            # pragma: no cover
    _HAVE_REQUESTS = False

HOST_SECRET = b"root:x:0:0:"
REQ_URL = f"https://{SERVER_HOST}:{NGINX_WEBDAV_GSI_TLS_PORT}/test.txt"
BUCKET = "testbucket"


def _port_up(port):
    try:
        with socket.create_connection((SERVER_HOST, port), timeout=2):
            return True
    except OSError:
        return False


_REQ_SKIP = pytest.mark.skipif(
    not (_HAVE_REQUESTS and _port_up(NGINX_WEBDAV_GSI_TLS_PORT)),
    reason="requests unavailable or https WebDAV (8444) not reachable")


@pytest.fixture(scope="module")
def issuer():
    iss = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(iss.key_path):
        pytest.skip(f"signing key not found at {iss.key_path}")
    return iss


def _sign_raw(iss, header_bytes, payload_obj):
    """Sign a token over a VERBATIM header byte string (so we can express
    headers that json.dumps can't: duplicate keys, non-objects, etc.).  The
    signature is valid — only the header/payload *content* is hostile."""
    h_b64 = b64url_encode(header_bytes)
    if isinstance(payload_obj, (bytes, bytearray)):
        p_b64 = b64url_encode(bytes(payload_obj))
    else:
        p_b64 = b64url_encode(json.dumps(payload_obj, separators=(",", ":")).encode())
    sig = iss.private_key.sign(f"{h_b64}.{p_b64}".encode("ascii"),
                               padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def _valid_payload():
    now = int(time.time())
    return {"iss": TokenIssuer.DEFAULT_ISSUER, "sub": "testuser",
            "aud": TokenIssuer.DEFAULT_AUDIENCE, "exp": now + 3600,
            "iat": now, "nbf": now, "scope": "storage.read:/", "wlcg.ver": "1.0"}


def _get(token=None, headers=None, timeout=15):
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    r = requests.get(REQ_URL, headers=h, verify=False, timeout=timeout)
    return r.status_code, r.content


def _assert_rejected_clean(status, body, label):
    """A malicious credential must be rejected (not 2xx), must not crash the
    server (not 5xx), and must not leak host content."""
    assert status not in range(200, 300), \
        f"{label}: malicious credential was ACCEPTED (status={status})"
    assert status < 500, f"{label}: crashed the auth handler (status={status})"
    assert HOST_SECRET not in body, f"{label}: leaked host content"


# ===========================================================================
# Positive control — proves the endpoint actually authenticates
# ===========================================================================

@_REQ_SKIP
def test_positive_control_valid_token_accepted(issuer):
    token = issuer.generate(scope="storage.read:/")
    status, _ = _get(token)
    assert status in (200, 206), \
        f"valid token should authenticate (got {status}); endpoint oracle broken"


# ===========================================================================
# Malicious JWT headers (parsed before signature verification)
# ===========================================================================

@_REQ_SKIP
class TestMaliciousJwtHeaders:

    def _send_header(self, issuer, header_bytes):
        token = _sign_raw(issuer, header_bytes, _valid_payload())
        return _get(token)

    def test_alg_as_array_rejected(self, issuer):
        st, b = self._send_header(
            issuer, b'{"alg":["RS256"],"typ":"JWT","kid":"test-key-1"}')
        _assert_rejected_clean(st, b, "alg-as-array")

    def test_alg_as_object_rejected(self, issuer):
        st, b = self._send_header(
            issuer, b'{"alg":{"x":"RS256"},"kid":"test-key-1"}')
        _assert_rejected_clean(st, b, "alg-as-object")

    def test_alg_whitespace_rejected(self, issuer):
        st, b = self._send_header(
            issuer, b'{"alg":" RS256 ","kid":"test-key-1"}')
        _assert_rejected_clean(st, b, "alg-with-whitespace")

    def test_alg_case_variant_rejected(self, issuer):
        st, b = self._send_header(
            issuer, b'{"alg":"rs256","kid":"test-key-1"}')
        _assert_rejected_clean(st, b, "alg-lowercase")

    def test_duplicate_alg_key_safe(self, issuer):
        # Two alg keys: a downgrade attempt (none "wins" if last-key-wins).
        st, b = self._send_header(
            issuer, b'{"alg":"RS256","alg":"none","kid":"test-key-1"}')
        _assert_rejected_clean(st, b, "duplicate-alg")

    def test_header_not_object_rejected(self, issuer):
        st, b = self._send_header(issuer, b'["RS256","JWT"]')
        _assert_rejected_clean(st, b, "header-is-array")

    def test_huge_kid_rejected(self, issuer):
        st, b = self._send_header(
            issuer, b'{"alg":"RS256","kid":"' + b"A" * 8000 + b'"}')
        _assert_rejected_clean(st, b, "huge-kid")

    def test_deeply_nested_header_no_dos(self, issuer):
        # ~3000-deep nested object reachable BEFORE signature verification.
        depth = 3000
        nested = b'{"a":' * depth + b'1' + b'}' * depth
        header = b'{"alg":"RS256","kid":"test-key-1","x":' + nested + b'}'
        t0 = time.time()
        st, b = self._send_header(issuer, header)
        elapsed = time.time() - t0
        assert elapsed < 10, f"nested-header parse took {elapsed:.1f}s (DoS?)"
        _assert_rejected_clean(st, b, "deeply-nested-header")

    def test_kid_path_traversal_not_used_as_path(self, issuer):
        # kid selects a key from the in-memory JWKS array — it must NEVER be
        # treated as a filesystem path (no open of /etc/passwd, no crash).  With
        # a single configured key the non-matching kid falls back to that key,
        # so this validly-signed token may authenticate — what matters is that
        # the traversal kid leaks nothing and does not crash the handler.
        st, b = self._send_header(
            issuer, b'{"alg":"RS256","kid":"../../../../etc/passwd"}')
        assert st < 500, f"kid traversal crashed the handler (status={st})"
        assert HOST_SECRET not in b, "kid was dereferenced as a filesystem path"


# ===========================================================================
# Validly-signed tokens with abusive CLAIMS
# ===========================================================================

@_REQ_SKIP
class TestMaliciousJwtClaims:

    HDR = b'{"alg":"RS256","typ":"JWT","kid":"test-key-1"}'

    def _send_payload(self, issuer, payload_bytes_or_obj):
        token = _sign_raw(issuer, self.HDR, payload_bytes_or_obj)
        return _get(token)

    # NOTE — these assert only the guaranteed-safe invariants (no crash, no
    # leak). The rejection path is asserted directly below.
    def test_exp_as_string_no_crash_no_leak(self, issuer):
        p = _valid_payload(); p["exp"] = "9999999999"
        st, b = self._send_payload(issuer, p)
        assert st < 500 and HOST_SECRET not in b, f"exp-as-string (status={st})"

    def test_exp_as_array_no_crash_no_leak(self, issuer):
        p = _valid_payload(); p["exp"] = [9999999999]
        st, b = self._send_payload(issuer, p)
        assert st < 500 and HOST_SECRET not in b, f"exp-as-array (status={st})"

    def test_nonpositive_or_malformed_exp_is_rejected(self, issuer):
        for bad_exp in (-1, 0, "9999999999", [1]):
            p = _valid_payload(); p["exp"] = bad_exp
            st, b = self._send_payload(issuer, p)
            assert st not in range(200, 300), \
                f"token with exp={bad_exp!r} was ACCEPTED (status={st})"

    def test_payload_not_object_rejected(self, issuer):
        st, b = self._send_payload(issuer, b'["not","an","object"]')
        _assert_rejected_clean(st, b, "payload-is-array")

    def test_huge_aud_array_no_dos(self, issuer):
        p = _valid_payload()
        p["aud"] = ["wrong-aud-%d" % i for i in range(10000)]
        t0 = time.time()
        st, b = self._send_payload(issuer, p)
        elapsed = time.time() - t0
        assert elapsed < 10, f"huge-aud-array took {elapsed:.1f}s (DoS?)"
        _assert_rejected_clean(st, b, "huge-aud-array")

    def test_deeply_nested_payload_no_dos(self, issuer):
        depth = 3000
        nested = '{"a":' * depth + '1' + '}' * depth
        # valid claims + a deeply nested extra member
        raw = ('{"iss":"%s","aud":"%s","exp":%d,"x":%s}'
               % (TokenIssuer.DEFAULT_ISSUER, TokenIssuer.DEFAULT_AUDIENCE,
                  int(time.time()) + 3600, nested)).encode()
        t0 = time.time()
        st, b = self._send_payload(issuer, raw)
        assert time.time() - t0 < 10, "nested-payload DoS"
        _assert_rejected_clean(st, b, "deeply-nested-payload")


# ===========================================================================
# Cross-protocol credential confusion (one credential type must not satisfy
# another)
# ===========================================================================

@_REQ_SKIP
class TestCrossProtocolCredentialConfusion:

    def test_gsi_cert_pem_as_bearer_rejected(self):
        # Feed an entire X.509 cert PEM as if it were a bearer token.
        pem = ""
        for p in ("/tmp/xrd-test/pki/user/proxy_std.pem",
                  "/tmp/xrd-test/pki/user/usercert.pem"):
            if os.path.exists(p):
                with open(p) as fh:
                    pem = fh.read().replace("\n", "")
                break
        if not pem:
            pytest.skip("no cert PEM fixture available")
        st, b = _get(pem)
        _assert_rejected_clean(st, b, "gsi-pem-as-bearer")

    def test_aws_sigv4_as_bearer_rejected(self):
        aws = ("AWS4-HMAC-SHA256 Credential=AKIA/20260101/us-east-1/s3/"
               "aws4_request, SignedHeaders=host, Signature=" + "0" * 64)
        st, b = _get(headers={"Authorization": aws})
        _assert_rejected_clean(st, b, "aws-sigv4-as-bearer")

    def test_http_basic_auth_rejected(self):
        # admin:admin — must not be accepted as a WLCG bearer / proxy identity.
        st, b = _get(headers={"Authorization": "Basic YWRtaW46YWRtaW4="})
        _assert_rejected_clean(st, b, "http-basic-auth")

    def test_bearer_with_garbage_scheme_rejected(self):
        st, b = _get(headers={"Authorization": "Token deadbeef"})
        _assert_rejected_clean(st, b, "non-bearer-scheme")

    @pytest.mark.skipif(not _port_up(NGINX_S3_PORT),
                        reason="S3 (9001) not reachable")
    def test_wlcg_bearer_not_honored_as_s3_auth(self, issuer):
        # A real WLCG token presented to the S3 endpoint must not crash the
        # SigV4 parser or leak host content.
        token = issuer.generate()
        r = requests.get(f"http://{SERVER_HOST}:{NGINX_S3_PORT}/{BUCKET}/test.txt",
                         headers={"Authorization": f"Bearer {token}"},
                         timeout=15)
        assert r.status_code < 500, f"bearer crashed S3 auth ({r.status_code})"
        assert HOST_SECRET not in r.content


# ===========================================================================
# Untrusted / self-signed TLS client certificates
# ===========================================================================

@_REQ_SKIP
class TestUntrustedClientCert:

    @pytest.fixture(scope="class")
    def selfsigned(self, tmp_path_factory):
        if not _have_curl() or not _have_openssl():
            pytest.skip("curl/openssl not available")
        d = tmp_path_factory.mktemp("evilcert")
        key = str(d / "evil.key")
        crt = str(d / "evil.crt")
        rc = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", crt, "-days", "1",
             "-subj", "/CN=admin/O=evil"],
            capture_output=True, timeout=30)
        if rc.returncode != 0:
            pytest.skip("openssl could not generate a self-signed cert")
        return crt, key

    def _curl_cert(self, cert, key):
        out = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "--cert", cert, "--key", key, "--max-time", "15", REQ_URL],
            capture_output=True, timeout=30)
        return out.stdout.decode().strip()

    def test_selfsigned_cert_not_authenticated(self, selfsigned):
        crt, key = selfsigned
        code = self._curl_cert(crt, key)
        # An untrusted, self-signed cert (not issued by the test CA) must not be
        # accepted as an authenticated identity — auth=required → 403 (or the
        # TLS layer refuses the cert).  It must NOT return 200.
        assert code not in ("200", "206"), \
            f"self-signed/untrusted client cert was AUTHENTICATED (code={code})"


def _have_curl():
    return subprocess.run(["which", "curl"], capture_output=True).returncode == 0


def _have_openssl():
    return subprocess.run(["which", "openssl"], capture_output=True).returncode == 0
