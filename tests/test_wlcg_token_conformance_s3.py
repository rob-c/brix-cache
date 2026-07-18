"""WLCG bearer-token conformance suite for the S3 endpoint.

Spec: WLCG AuthZ Interoperability Profile v1.0
Scope: S3 protocol only (brix_s3_token on port 9002).
Cases: S3-01 through S3-10

WHAT: 10 targeted test cases that verify the enforcing S3 token port
      (NGINX_S3_TOKEN_PORT=9002, brix_s3_token on) correctly:
      - accepts valid JWTs with appropriate scope (S3-01, S3-07)
      - rejects tokens with invalid algorithm / wrong issuer / wrong audience /
        expired / missing scope (S3-02 through S3-06, S3-08)
      - rejects requests with no Authorization header (S3-09)
      - leaves the non-enforcing port (9001) unaffected (S3-10)
WHY:  INVARIANT §6: S3 SigV4 and WLCG bearer are mutually exclusive per
      request; the enforcing port proves the bearer path is wired end-to-end
      without touching SigV4 semantics.
HOW:  All cases use plain HTTP to NGINX_S3_TOKEN_PORT.  Requests carry
      Authorization: Bearer <token> (or no auth header for S3-09).
      S3 URL format: http://HOST:PORT/BUCKET/key (bucket in path).
      Verdicts are mapped to "accept" / "reject" / "notfound" by HTTP status
      code; the non-enforcing port test (S3-10) targets NGINX_S3_PORT (9001).
"""

import os

import pytest
import requests
import urllib3

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from settings import (
    NGINX_S3_PORT,
    NGINX_S3_TOKEN_PORT,
    S3_BUCKET,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
)
from tokenforge import TokenForge

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The dedicated s3-token instance uses TEST_ROOT/data-s3-token (see
# start_dedicated_nginx in tests/lib/nginx.sh — DATA_DIR = data-<name>).
_TOKEN_DATA_ROOT = os.path.join(TEST_ROOT, "data-s3-token")
# The anon port 9001 serves the main data directory.
_ANON_DATA_ROOT = os.path.join(TEST_ROOT, "data")


# ---------------------------------------------------------------------------
# Fixture: provision test fixture files in both data roots.
# ---------------------------------------------------------------------------

_FIXTURES = {
    "test.txt":     b"hello from nginx-xrootd\n",
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}


@pytest.fixture(scope="module", autouse=True)
def s3_token_fixtures():
    """Create the test fixture files in both data roots if absent."""
    for root in (_TOKEN_DATA_ROOT, _ANON_DATA_ROOT):
        for rel, body in _FIXTURES.items():
            path = os.path.join(root, rel)
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fh:
                    fh.write(body)


# ---------------------------------------------------------------------------
# Helpers: thin HTTP client targeting the S3 token port.
# ---------------------------------------------------------------------------

def _get(key, *, token=None, port=None, bucket=None):
    """Issue GET /bucket/key optionally with Authorization: Bearer.

    S3 URL layout: http://HOST:PORT/BUCKET/KEY
    Returns the HTTP status code.
    """
    bkt    = bucket if bucket is not None else S3_BUCKET
    target = port if port is not None else NGINX_S3_TOKEN_PORT
    url    = f"http://{SERVER_HOST}:{target}/{bkt}/{key}"
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(url, headers=headers, timeout=5)
    return resp.status_code


def _verdict(status_code):
    """Map an HTTP status code to an accept/reject/notfound verdict string."""
    if status_code in (200, 206):
        return "accept"
    if status_code in (401, 403):
        return "reject"
    if status_code == 404:
        return "notfound"
    return "accept" if 200 <= status_code < 300 else "reject"


@pytest.fixture(scope="module")
def forge():
    """Return a TokenForge using the test PKI in TOKENS_DIR."""
    return TokenForge(TOKENS_DIR)


# ---------------------------------------------------------------------------
# S3-01: valid read token, valid scope — must accept.
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_01_valid_read_accept(forge):
    """S3-01: Bearer with storage.read:/ on test.txt → 200 accept.

    Verifies the happy path: a correctly-signed JWT with the right issuer,
    audience, and a broad storage.read:/ scope reaches the file.
    """
    token = forge.scope("storage.read:/")
    code = _get("test.txt", token=token)
    assert _verdict(code) == "accept", (
        f"S3-01: expected accept (200) for valid read token, got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-02: alg=none — must reject (no signature).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_02_alg_none_reject(forge):
    """S3-02: alg=none (unsigned) JWT → 403 reject.

    The S3 gateway MUST reject unsigned tokens (WLCG §4.1 and RFC 7515 §4.1.1).
    """
    token = forge.alg_none()
    code = _get("test.txt", token=token)
    assert _verdict(code) == "reject", (
        f"S3-02: expected reject (403) for alg=none token, got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-03: wrong issuer — must reject (iss mismatch).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_03_wrong_issuer_reject(forge):
    """S3-03: Token from a different issuer → 403 reject.

    The brix_s3_token_issuer directive binds the gateway to a single trusted
    issuer; tokens from any other issuer are rejected.
    """
    token = forge.for_issuer("https://attacker.example.com")
    code = _get("test.txt", token=token)
    assert _verdict(code) == "reject", (
        f"S3-03: expected reject (403) for wrong-issuer token, got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-04: wrong audience — must reject (aud mismatch).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_04_wrong_audience_reject(forge):
    """S3-04: Token with a different audience value → 403 reject.

    WLCG §3.2: the 'aud' claim must match the resource server's identifier.
    """
    token = forge.aud_value("wrong-audience")
    code = _get("test.txt", token=token)
    assert _verdict(code) == "reject", (
        f"S3-04: expected reject (403) for wrong-aud token, got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-05: expired token — must reject (exp in the past).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_05_expired_reject(forge):
    """S3-05: exp = now − 3600 (already expired) → 403 reject.

    Temporal validation must reject tokens whose 'exp' claim is in the past
    (beyond the configured clock-skew window).
    """
    token = forge.temporal(-3600)
    code = _get("test.txt", token=token)
    assert _verdict(code) == "reject", (
        f"S3-05: expected reject (403) for expired token, got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-06: out-of-scope token — must reject (scope doesn't cover the path).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_06_out_of_scope_reject(forge):
    """S3-06: scope=storage.read:/atlas, key=cms/ok.txt → 403 reject.

    The token grants access only under /atlas; a request for /cms/ok.txt is
    outside that scope and must be denied.
    """
    token = forge.scope("storage.read:/atlas")
    code = _get("cms/ok.txt", token=token)
    assert _verdict(code) == "reject", (
        f"S3-06: expected reject (403) for out-of-scope GET /cms/ok.txt, "
        f"got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-07: in-scope token — must accept (scope exactly covers the path).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_07_in_scope_accept(forge):
    """S3-07: scope=storage.read:/atlas, key=atlas/ok.txt → 200 accept.

    Same token as S3-06, but requesting a file that IS under /atlas.
    """
    token = forge.scope("storage.read:/atlas")
    code = _get("atlas/ok.txt", token=token)
    assert _verdict(code) == "accept", (
        f"S3-07: expected accept (200) for in-scope GET /atlas/ok.txt, "
        f"got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-08: no-scope token — must reject (scope claim absent).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_08_no_scope_reject(forge):
    """S3-08: JWT with no 'scope' claim → 403 reject.

    A bearer token without a scope claim cannot grant any access;
    the gateway must reject it.
    """
    token = forge.no_scope()
    code = _get("test.txt", token=token)
    assert _verdict(code) == "reject", (
        f"S3-08: expected reject (403) for no-scope token, got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-09: no token on enforcing port — must reject (token mode is enforcing).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_09_no_token_reject():
    """S3-09: Request with no Authorization header on enforcing port → 403.

    brix_s3_token on makes the port enforcing: every request MUST carry a
    valid Bearer JWT.  A request with no auth header at all is rejected.
    """
    code = _get("test.txt", token=None)
    assert _verdict(code) == "reject", (
        f"S3-09: expected reject (403) for no-auth request on token port, "
        f"got HTTP {code}")


# ---------------------------------------------------------------------------
# S3-10: anonymous port still works (non-enforcing port 9001).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("s3-token")
def test_s3_10_anon_port_unaffected():
    """S3-10: Plain GET on non-enforcing S3 port (9001) → 200 accept.

    Enabling brix_s3_token on port 9002 must NOT affect the anon port 9001.
    Files accessible anonymously on 9001 should still be accessible.
    """
    code = _get("test.txt", token=None, port=NGINX_S3_PORT)
    assert _verdict(code) == "accept", (
        f"S3-10: expected accept (200) for anonymous GET on anon port "
        f"{NGINX_S3_PORT}, got HTTP {code}")
