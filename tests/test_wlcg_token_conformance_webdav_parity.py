"""WLCG token conformance — WebDAV parity wire family (port 8446).

WHAT: Proves that the enforcing WebDAV port (8446, brix_webdav_auth required)
      applies the same token rules as the root:// enforcing port (11097).
WHY:  Closing a real per-protocol asymmetry: prior conformance tests covered
      root:// exclusively.  This module targets the dedicated webdav-token
      nginx instance which is configured with brix_webdav_auth required,
      jwks.json, issuer https://test.example.com, and audience nginx-xrootd.
HOW:  Each test mints a token via TokenForge and calls webdav_bearer(...,
      port=WD) which issues an HTTPS GET against port 8446.  Verdicts:
        200/206 → "accept", 401/403 → "reject", 404 → "notfound".

Parity findings (2026-07-06):
  PASS  WD-01: valid token           → accept    (correct)
  PASS  WD-02: alg=none              → reject    (correct)
  PASS  WD-03: HS256-confusion       → reject    (correct)
  PASS  WD-04: expired               → reject    (correct)
  PASS  WD-05: wrong audience        → reject    (correct)
  PASS  WD-06: wrong issuer          → reject    (correct)
  XFAIL WD-07: out-of-scope path     → ACCEPT    (BUG — scope not enforced)
  PASS  WD-08: in-scope path         → accept    (correct)
  XFAIL WD-09: traversal (§3.5)      → ACCEPT    (BUG — scope not enforced;
               client + nginx both normalise /atlas/../cms → /cms before the
               handler sees the path, so brix_reject_dotdot_path is not
               exercised on WebDAV; the server-level defence is nginx URL
               normalisation, but scope must still reject /cms for an
               /atlas-scoped token)
  XFAIL WD-10: missing scope         → ACCEPT    (BUG — scope not enforced)

Root cause of WD-07/09/10: WebDAV auth_token.c validates signature, expiry,
audience and issuer but does NOT call brix_token_check_scope(token, path).
root:// port 11097 correctly gates on scope via src/auth/token/scopes.c.
Fix: call brix_token_check_scope after token verification in the WebDAV
request handler.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import TEST_ROOT, NGINX_WEBDAV_TOKEN_PORT as WD, TOKENS_DIR
from tokenforge import TokenForge
from lib.tokenconf import webdav_bearer, ensure_conformance_data

# ---------------------------------------------------------------------------
# Data provisioning
# ---------------------------------------------------------------------------

# Dedicated data root for the webdav-token nginx instance.
_WD_DATA_ROOT = os.path.join(TEST_ROOT, "data-webdav-token")

_WD_EXTRA_FILES = {
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}


def _ensure_wd_data():
    """Provision subdirectory fixture files in the webdav-token data root.

    WHAT: Creates atlas/ok.txt and cms/ok.txt in data-webdav-token if absent.
    WHY:  start_dedicated_nginx creates test.txt automatically, but the scope
          test paths (/atlas, /cms) need explicit provisioning.
    HOW:  Idempotent — each path is skipped if it already exists.
    """
    for rel, body in _WD_EXTRA_FILES.items():
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
# WD family test cases
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_wd_01_valid_accept():
    """WD-01: valid RS256 token with storage.read:/ scope → accept.

    WHAT: Baseline positive case — a well-formed token with the correct issuer,
          audience, and a root-level read scope must be accepted on port 8446.
    WHY:  Confirms that the enforcing port grants access when auth is valid.
    HOW:  generate(scope="storage.read:/") emits a standard RS256 JWT.
    """
    tok = _forge().generate(scope="storage.read:/")
    assert webdav_bearer(tok, "/test.txt", port=WD) == "accept"


@pytest.mark.tokenconf
def test_wd_02_alg_none_reject():
    """WD-02: alg=none unsigned token → reject (RFC8725 §2).

    WHAT: Unsigned JWTs (alg=none) must be blocked before any claim checks.
    WHY:  Accepting alg=none bypasses all signature verification — CVE-class.
    HOW:  alg_none() produces a header+payload with no signature segment.
    """
    tok = _forge().alg_none()
    assert webdav_bearer(tok, "/test.txt", port=WD) == "reject"


@pytest.mark.tokenconf
def test_wd_03_hs256_confusion_reject():
    """WD-03: HS256 algorithm-confusion attack → reject (RFC8725).

    WHAT: A token signed with HMAC using the RSA *public* key as the secret.
    WHY:  A verifier that accepts HS256 and uses the RSA public key as the HMAC
          secret is vulnerable to the classic key-confusion attack.
    HOW:  alg_hs256_confusion() signs with hmac.new(rsa_pub_pem, ..., sha256).
    """
    tok = _forge().alg_hs256_confusion()
    assert webdav_bearer(tok, "/test.txt", port=WD) == "reject"


@pytest.mark.tokenconf
def test_wd_04_expired_reject():
    """WD-04: expired token (exp = now − 3600) → reject (RFC7519 §4.1.4).

    WHAT: A token whose exp is 1 hour in the past must be rejected.
    WHY:  Stale credentials must not grant access beyond their expiry.
    HOW:  temporal(-3600) sets exp=now-3600, well outside the 30s clock-skew
          window.
    """
    tok = _forge().temporal(-3600)
    assert webdav_bearer(tok, "/test.txt", port=WD) == "reject"


@pytest.mark.tokenconf
def test_wd_05_wrong_aud_reject():
    """WD-05: wrong audience claim → reject (RFC7519 §4.1.3).

    WHAT: A token with aud="wrong-aud" must be rejected by the nginx-xrootd
          audience verifier.
    WHY:  Audience validation prevents tokens issued for other services from
          being replayed against this endpoint.
    HOW:  aud_value("wrong-aud") sets a scalar audience that does not match
          the configured brix_webdav_token_audience "nginx-xrootd".
    """
    tok = _forge().aud_value("wrong-aud")
    assert webdav_bearer(tok, "/test.txt", port=WD) == "reject"


@pytest.mark.tokenconf
def test_wd_06_wrong_issuer_reject():
    """WD-06: wrong issuer → reject (WLCG Token Profile §3.1).

    WHAT: A token with iss="https://evil.example.com" must be rejected.
    WHY:  Issuer pinning prevents tokens from untrusted issuers from granting
          access even if they carry a valid signature.
    HOW:  for_issuer("https://evil.example.com") sets a wrong iss claim; the
          token is signed by the test key, so this tests iss-matching only.
    """
    tok = _forge().for_issuer("https://evil.example.com")
    assert webdav_bearer(tok, "/test.txt", port=WD) == "reject"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG (WebDAV scope enforcement asymmetry): "
        "storage.read:/atlas token ACCEPTS /cms/ok.txt on port 8446 (returns 200). "
        "root:// port 11097 correctly rejects the same case via "
        "brix_token_check_scope (src/auth/token/scopes.c). "
        "WebDAV auth_token.c validates sig/exp/aud/iss but does NOT call "
        "brix_token_check_scope(token, path), so any authenticated token "
        "regardless of scope can access any path. "
        "Fix: call brix_token_check_scope after token verification in the "
        "WebDAV request handler. Spec ref: WLCG Token Profile §4."
    ),
)
@pytest.mark.tokenconf
def test_wd_07_out_of_scope_reject():
    """WD-07: storage.read:/atlas token must NOT access /cms/ok.txt → reject.

    WHAT: The /atlas scope prefix must not cover the /cms subtree.
    WHY:  Path-prefix scope rules are the core access-control mechanism of the
          WLCG token profile.  Cross-path leakage is a security bug.
    HOW:  scope("storage.read:/atlas") on /cms/ok.txt — scope boundary check.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_bearer(tok, "/cms/ok.txt", port=WD) == "reject"


@pytest.mark.tokenconf
def test_wd_08_in_scope_accept():
    """WD-08: storage.read:/atlas token → /atlas/ok.txt → accept.

    WHAT: Positive case — an /atlas-scoped token must reach /atlas/ok.txt.
    WHY:  Confirms that scope enforcement does not over-restrict valid access.
    HOW:  scope("storage.read:/atlas") on /atlas/ok.txt — in-prefix check.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", port=WD) == "accept"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG (WebDAV traversal + scope enforcement gap): "
        "storage.read:/atlas token ACCEPTS /cms/ok.txt reached via "
        "/atlas/../cms/ok.txt (returns 200). "
        "TRAVERSAL NOTE: the requests HTTP library normalises "
        "/atlas/../cms/ok.txt → /cms/ok.txt before sending; nginx also "
        "normalises the URL before the handler sees it, so "
        "brix_reject_dotdot_path (root:// binary-protocol defence) is not "
        "exercised on WebDAV. The server-level HTTP traversal defence is "
        "nginx URL normalisation. "
        "The test is still REJECT because an /atlas-scoped token must not "
        "serve /cms regardless of how the path was specified. "
        "Root cause: same WebDAV scope-enforcement gap as WD-07 — "
        "brix_token_check_scope is not called on the WebDAV path. "
        "Spec ref: WLCG Token Profile §3.5 + §4."
    ),
)
@pytest.mark.tokenconf
def test_wd_09_traversal_reject():
    """WD-09: §3.5 traversal — /atlas/../cms/ok.txt with /atlas-scoped token → reject.

    WHAT: A dot-dot escape from the /atlas subtree into /cms must be rejected.
    WHY:  Without this defence an attacker with a narrowly-scoped token can
          escape its scope boundary by inserting .. components.
    HOW:  requests normalises /atlas/../cms/ok.txt → /cms/ok.txt before
          sending; the server also normalises; the scope check (once
          implemented) must then reject /cms for an /atlas-scoped token.
          The raw-socket traversal path (/atlas/../cms sent literally) also
          returns 200 because nginx normalises before the handler runs.
    """
    tok = _forge().scope("storage.read:/atlas")
    # requests normalises /atlas/../cms/ok.txt → /cms/ok.txt before sending.
    # The server receives /cms/ok.txt and must reject on scope.
    assert webdav_bearer(tok, "/atlas/../cms/ok.txt", port=WD) == "reject"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "BUG (WebDAV scope enforcement asymmetry): "
        "token with no scope claim ACCEPTS /test.txt on port 8446 (returns 200). "
        "root:// port 11097 correctly rejects no-scope tokens via scopes.c. "
        "WebDAV does not gate access on scope presence: a token that passes "
        "sig/exp/aud/iss checks but carries no scope claim grants full access. "
        "Fix: require a scope claim covering the request path. "
        "Spec ref: WLCG Token Profile §4."
    ),
)
@pytest.mark.tokenconf
def test_wd_10_missing_scope_reject():
    """WD-10: authenticated token with no scope claim → reject.

    WHAT: A token that passes all structural checks but carries no scope claim
          must be rejected.
    WHY:  Scope is the access-control grant.  A scopeless token is an identity
          assertion only — it must not imply any storage permission.
    HOW:  no_scope() strips the scope claim from an otherwise-valid token.
    """
    tok = _forge().no_scope()
    assert webdav_bearer(tok, "/test.txt", port=WD) == "reject"
