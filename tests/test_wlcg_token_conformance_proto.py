"""WLCG token conformance — PROTO family (token transport modes).

WHAT: Verifies all supported token-transport paths on the enforcing WebDAV
      port (8446) and the root:// token port (11097).

      PROTO-01  header bearer, valid token              → accept  (baseline)
      PROTO-02  query ?authz=Bearer <tok>               → accept
      PROTO-03  query ?authz=<tok>  (no "Bearer " pfx)  → accept
      PROTO-04  query ?access_token=<tok>               → accept
      PROTO-05  query ?authz= with alg=none token        → reject  (sig check)
      PROTO-06  query ?authz=, token scope /atlas,
                path /cms/ok.txt                        → reject  (scope check)
      PROTO-07  header valid + ?authz=garbage (both)    → characterise precedence
      PROTO-08  root:// ztn transport (only transport)  → accept  (N/A for query)

WHY:  brix_http_query_token (default ON) extracts JWT from the query string;
      the same validation pipeline runs regardless of transport.  PROTO-05/06
      confirm that query delivery does not bypass signature or scope checks.
      PROTO-07 characterises server behaviour when both transports are present.

HOW:  Tests use webdav_bearer() for header-only cases, webdav_query_token()
      for query-param cases, and root_ztn() for the root:// case.  No JSON
      manifest — forge+helper calls directly, like multikey/issuer tests.
"""

import os
import sys

import pytest
import requests
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import (
    DATA_ROOT,
    NGINX_WEBDAV_TOKEN_PORT as WD,
    NGINX_TOKEN_PORT,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
)
from tokenforge import TokenForge
from lib.tokenconf import (
    ensure_conformance_data,
    webdav_bearer,
    webdav_query_token,
    root_ztn,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Data provisioning
# ---------------------------------------------------------------------------

# The dedicated webdav-token nginx instance uses data-webdav-token as its
# brix_storage_backend root (same as the parity test suite).
_WD_DATA_ROOT = os.path.join(TEST_ROOT, "data-webdav-token")

_WD_FIXTURE_FILES = {
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}


def _ensure_wd_data():
    """Provision subdirectory fixture files in the webdav-token data root.

    WHAT: Creates atlas/ok.txt and cms/ok.txt in data-webdav-token if absent.
    WHY:  Scope tests targeting /atlas/ok.txt and /cms/ok.txt need those files
          to exist so that a scope-rejected request returns 403 rather than 404
          (scope is checked before file lookup, but defence-in-depth dictates
          the files are present so the test verdict is unambiguous).
    HOW:  Idempotent — skips paths that already exist; creates parent dirs.
    """
    for rel, body in _WD_FIXTURE_FILES.items():
        path = os.path.join(_WD_DATA_ROOT, rel)
        if os.path.exists(path):
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)


@pytest.fixture(autouse=True)
def _provision():
    """Idempotently provision all fixture data before every test in this module."""
    ensure_conformance_data()
    _ensure_wd_data()


# ---------------------------------------------------------------------------
# Shared forge factory
# ---------------------------------------------------------------------------

def _forge():
    """Return a TokenForge loaded from the fleet token directory."""
    return TokenForge(TOKENS_DIR)


# ---------------------------------------------------------------------------
# PROTO family test cases
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_proto_01_header_bearer_accept():
    """PROTO-01: valid token via Authorization: Bearer header → accept (baseline).

    WHAT: Confirms the enforcing WebDAV port (8446) accepts a well-formed token
          delivered in the standard HTTP Authorization header.
    WHY:  Establishes the positive baseline; every subsequent PROTO case is a
          variation of this reference.
    HOW:  webdav_bearer(tok, port=WD) issues GET with Authorization: Bearer.
    """
    tok = _forge().generate(scope="storage.read:/")
    assert webdav_bearer(tok, "/test.txt", port=WD) == "accept"


@pytest.mark.tokenconf
def test_proto_02_query_authz_bearer_accept():
    """PROTO-02: valid token via ?authz=Bearer%20<tok> → accept.

    WHAT: Verifies query-parameter transport with a "Bearer " prefix, matching
          the common client encoding used by tools that embed the full
          Authorization value in the query string.
    WHY:  brix_http_query_token must strip the "Bearer " prefix before handing
          the raw JWT to the validation pipeline.
    HOW:  webdav_query_token with prefix="Bearer " (the default).
    """
    tok = _forge().generate(scope="storage.read:/")
    assert webdav_query_token(tok, "/test.txt", param="authz",
                              prefix="Bearer ") == "accept"


@pytest.mark.tokenconf
def test_proto_03_query_authz_raw_accept():
    """PROTO-03: valid token via ?authz=<raw-JWT> (no "Bearer " prefix) → accept.

    WHAT: Verifies that a bare JWT in ?authz= (without "Bearer " prefix) is
          accepted — this is the most common curl/wget encoding.
    WHY:  Some clients put only the JWT, not "Bearer JWT", in the authz param.
          The server must handle both forms.
    HOW:  webdav_query_token with prefix="" (empty — raw JWT in query value).
    """
    tok = _forge().generate(scope="storage.read:/")
    assert webdav_query_token(tok, "/test.txt", param="authz",
                              prefix="") == "accept"


@pytest.mark.tokenconf
def test_proto_04_query_access_token_accept():
    """PROTO-04: valid token via ?access_token=<JWT> → accept.

    WHAT: Verifies the OAuth2 standard query parameter name access_token
          (RFC6750 §2.3) is accepted alongside the WLCG-specific authz param.
    WHY:  Some clients (e.g. Python xrootd client versions) use access_token
          rather than authz in the query string.
    HOW:  webdav_query_token with param="access_token", prefix="".
    """
    tok = _forge().generate(scope="storage.read:/")
    assert webdav_query_token(tok, "/test.txt", param="access_token",
                              prefix="") == "accept"


@pytest.mark.tokenconf
def test_proto_05_query_bad_token_reject():
    """PROTO-05: alg=none token via ?authz= → reject (signature check applies).

    WHAT: An unsigned token (alg=none) delivered via query parameter must be
          rejected by the same validation pipeline that rejects it in the header.
    WHY:  If query-parameter delivery bypassed signature validation it would be
          a CVE-class bug — alg=none would grant access to an arbitrary path.
    HOW:  webdav_query_token with forge.alg_none(); expected "reject".
    """
    tok = _forge().alg_none()
    assert webdav_query_token(tok, "/test.txt", param="authz") == "reject"


@pytest.mark.tokenconf
def test_proto_06_query_out_of_scope_reject():
    """PROTO-06: storage.read:/atlas token, path /cms/ok.txt via ?authz= → reject.

    WHAT: Scope enforcement must apply to query-parameter tokens exactly as for
          header tokens.  An /atlas-scoped token must not reach /cms.
    WHY:  If query delivery bypassed scope checks an attacker could access any
          path by embedding a narrowly-scoped token in the query string.
    HOW:  scope("storage.read:/atlas") on /cms/ok.txt via webdav_query_token.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_query_token(tok, "/cms/ok.txt", param="authz",
                              prefix="") == "reject"


@pytest.mark.tokenconf
def test_proto_07_header_and_query_precedence():
    """PROTO-07: header valid + ?authz=garbage — characterise precedence.

    WHAT: Both transport modes are present simultaneously.  This test observes
          which one the server uses and records the finding.
    WHY:  RFC6750 §2 recommends that if multiple transports are present the
          server SHOULD reject with 400 or use a documented precedence.  We
          characterise actual behaviour here; header-wins is the correct
          outcome (more-specific, harder to forge by URL injection).
    HOW:  GET with Authorization: Bearer <valid> and ?authz=garbage in the
          URL.  "accept" means header won; "reject" means query won.

    Finding: header-wins → accept is the expected and correct behaviour.
    """
    tok = _forge().generate(scope="storage.read:/")
    url = f"https://{SERVER_HOST}:{WD}/test.txt?authz=garbage_not_a_jwt"
    headers = {"Authorization": f"Bearer {tok}"}
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=5)
        code = resp.status_code
        if code in (200, 206):
            observed = "accept"
        elif code in (401, 403):
            observed = "reject"
        elif code == 404:
            observed = "notfound"
        else:
            observed = "accept" if 200 <= code < 300 else "reject"
    except requests.RequestException:
        observed = "reject"

    # Characterisation: header-wins is correct per RFC6750 §2 recommendation.
    # Assert the expected behaviour and document the finding.
    assert observed == "accept", (
        f"PROTO-07 precedence finding: observed={observed!r}. "
        "Expected 'accept' (header-wins): valid Authorization header should "
        "take precedence over malformed ?authz= query parameter. "
        f"HTTP status={resp.status_code if 'resp' in dir() else 'N/A'}"
    )


@pytest.mark.tokenconf
def test_proto_08_root_ztn_accept():
    """PROTO-08: root:// ztn transport — the only valid token transport on root://.

    WHAT: A valid token delivered via kXR_auth ztn (the root:// token mechanism)
          is accepted on port 11097.
    WHY:  root:// has no query-parameter token transport — tokens are delivered
          exclusively in the auth handshake (kXR_auth credtype=ztn).  This case
          documents that fact and confirms the ztn path works correctly.
    HOW:  root_ztn(tok, port=11097) runs handshake→protocol→login→auth-ztn→stat.
          Note: ?authz= / ?access_token= are N/A on root:// — no URL involved.
    """
    tok = _forge().generate(scope="storage.read:/")
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"
