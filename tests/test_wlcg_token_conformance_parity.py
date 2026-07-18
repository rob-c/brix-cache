"""WLCG token conformance — PAR family (cross-protocol parity, WebDAV + S3).

WHAT: Verifies 20 RFC/WLCG rules uniformly across the two HTTP enforcing token
      ports — WebDAV HTTPS 8446 (``NGINX_WEBDAV_TOKEN_PORT``) and S3 HTTP 9002
      (``NGINX_S3_TOKEN_PORT``).  Each test is parametrized over proto in
      ["webdav","s3"] so every rule runs twice and produces 40 tests in total.

WHY:  The same token validation pipeline (validate.c + scopes.c) backs all three
      protocol stacks.  Recently landed fixes — crit-header rejection, fractional
      NumericDate acceptance, WLCG aud wildcard acceptance — must hold uniformly
      across protocols.  This suite is the cross-protocol oracle.

HOW:  ``probe(proto, token, path, write)`` dispatches to webdav_bearer or
      s3_bearer with the enforcing port.  Cases are pure forge+assert; no JSON
      manifest is needed.  Data files (/test.txt, /atlas/ok.txt, /cms/ok.txt)
      are provisioned idempotently in both server data roots via
      ``_ensure_parity_data()``.

Fixed behaviours asserted as plain (non-xfail) PASSes:
  PAR-08  WLCG aud wildcard ``https://wlcg.cern.ch/jwt/v1/any`` → accept
  PAR-09  crit unknown extension → reject  (RFC 7515 §4.1.11)
  PAR-10  fractional NumericDate exp → accept  (RFC 7519 §2)
"""

import os
import sys

import pytest
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import (
    NGINX_WEBDAV_TOKEN_PORT,
    NGINX_S3_TOKEN_PORT,
    S3_BUCKET,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
)
from tokenforge import TokenForge
from lib.tokenconf import (
    ensure_conformance_data,
    webdav_bearer,
    s3_bearer,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Data provisioning
#
# Both enforcing HTTP token servers expose dedicated data roots.  Provision the
# same small fixture set in each so accept-path tests land on real files.
# ---------------------------------------------------------------------------

_PAR_FIXTURE_FILES = {
    "test.txt":     b"hello from nginx-xrootd\n",
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}

_PAR_DATA_ROOTS = [
    os.path.join(TEST_ROOT, "data-webdav-token"),
    os.path.join(TEST_ROOT, "data-s3-token"),
]


def _ensure_parity_data():
    """Provision fixture files in both HTTP token server data roots.

    WHAT: Creates test.txt, atlas/ok.txt, cms/ok.txt in data-webdav-token and
          data-s3-token if they are absent.
    WHY:  Accept-path and scope-boundary tests must land on real files so that a
          token-acceptance decision is not confused with a 404 not-found response.
    HOW:  Idempotent; skips existing files; creates parent directories.
    """
    for root in _PAR_DATA_ROOTS:
        for rel, body in _PAR_FIXTURE_FILES.items():
            path = os.path.join(root, rel)
            if os.path.exists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(body)


@pytest.fixture(autouse=True)
def _provision():
    """Idempotently provision all fixture data before every test in this module."""
    ensure_conformance_data()
    _ensure_parity_data()


# ---------------------------------------------------------------------------
# Shared forge factory and probe dispatcher
# ---------------------------------------------------------------------------

def _forge():
    """Return a TokenForge loaded from the fleet token directory."""
    return TokenForge(TOKENS_DIR)


def probe(proto, token, path="/test.txt", write=False):
    """Dispatch to the enforcing token port for the given protocol.

    WHAT: Routes to webdav_bearer (8446, HTTPS) or s3_bearer (9002, HTTP) with
          the enforcing port so both checks share one call site.
    WHY:  Centralises port selection; every parametrized body calls probe() and
          asserts verdict without knowing which protocol is under test.
    HOW:  proto="webdav" → webdav_bearer with NGINX_WEBDAV_TOKEN_PORT;
          proto="s3"     → s3_bearer with NGINX_S3_TOKEN_PORT; S3 URL layout is
          /{bucket}/{key} so the key is prefixed with S3_BUCKET ("testbucket").
          write flag is forwarded unchanged.

    Args:
        proto: "webdav" or "s3".
        token: JWT string.
        path:  URL path (must start with /).
        write: If True, issue a write (PUT) probe instead of a read (GET).

    Returns:
        "accept", "reject", or "notfound".
    """
    if proto == "webdav":
        return webdav_bearer(token, path, write, port=NGINX_WEBDAV_TOKEN_PORT)
    key = f"{S3_BUCKET}/{path.lstrip('/')}"
    return s3_bearer(token, key, write, port=NGINX_S3_TOKEN_PORT)


# ---------------------------------------------------------------------------
# PAR-01  valid root-scoped token → accept (baseline)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_01_valid_accept(proto):
    """PAR-01: valid storage.read:/ token → accept (positive baseline).

    WHAT: A well-formed RS256 JWT with storage.read:/ scope, correct issuer,
          audience, and expiry must be accepted on both enforcing HTTP ports.
    WHY:  Establishes the positive baseline; every other PAR case is a variation
          of this reference.  If this fails the fleet is not up or misconfigured.
    HOW:  forge.generate(scope="storage.read:/") → probe → assert "accept".
    """
    tok = _forge().generate(scope="storage.read:/")
    assert probe(proto, tok) == "accept"


# ---------------------------------------------------------------------------
# PAR-02  alg=none → reject (SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_02_alg_none_reject(proto):
    """PAR-02: alg=none unsigned token → reject (CVE-class, SEC).

    WHAT: A three-segment JWT with alg=none and an empty signature segment must
          be rejected.  Accepting it would grant access to any path with no
          cryptographic proof of token integrity.
    WHY:  RFC 7518 §3.6 / RFC 8725 §2.1 — alg=none MUST be rejected by any
          verifier that does not explicitly support it; our verifier is
          asymmetric-only.
    """
    tok = _forge().alg_none()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-03  HS256 HMAC-confusion → reject (SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_03_hs256_confusion_reject(proto):
    """PAR-03: HS256-keyed-with-RSA-public-key token → reject (confusion attack, SEC).

    WHAT: A JWT bearing alg=HS256 HMAC-signed with the RSA public key PEM bytes.
          A broken verifier that accepts symmetric tokens would compute the same
          HMAC and accept — this is the classic alg-confusion attack.
    WHY:  RFC 8725 §2.1 — servers MUST NOT accept alg values they do not
          explicitly support.  Our verifier accepts only RS256/ES256; HS256
          must be rejected regardless of HMAC validity.
    """
    tok = _forge().alg_hs256_confusion()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-04  wrong issuer → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_04_wrong_issuer_reject(proto):
    """PAR-04: token issued by https://evil.example.com → reject (issuer mismatch).

    WHAT: The iss claim names an issuer not in the server's scitokens.cfg; the
          JWKS lookup fails → token must be rejected.
    WHY:  RFC 7519 §4.1.1 / WLCG Token Profile §3 — iss must match a registered
          issuer entry.  An unrecognised issuer must not be trusted.
    """
    tok = _forge().for_issuer("https://evil.example.com")
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-05  expired token → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_05_expired_reject(proto):
    """PAR-05: token expired 3600 s ago → reject.

    WHAT: exp = now - 3600, which is well outside the 30 s clock-skew tolerance.
    WHY:  RFC 7519 §4.1.4 — exp is a REQUIRED claim; now > exp + skew must
          cause rejection on all protocols.
    """
    tok = _forge().temporal(-3600)
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-06  wrong audience scalar → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_06_wrong_aud_reject(proto):
    """PAR-06: aud="wrong-aud" → reject (audience mismatch).

    WHAT: The aud claim does not match the server's configured audience
          ("nginx-xrootd") and is not the WLCG wildcard URI.
    WHY:  RFC 7519 §4.1.3 — if the aud claim is present the server MUST
          reject if its identifier is not in the audience list.
    """
    tok = _forge().aud_value("wrong-aud")
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-07  aud as JSON array containing the server audience → accept
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_07_aud_array_accept(proto):
    """PAR-07: aud=["nginx-xrootd","other"] array containing server audience → accept.

    WHAT: RFC 7519 §4.1.3 permits aud to be either a string or a JSON array of
          strings.  The server must accept if its identifier is any element.
    WHY:  Multi-audience tokens are common in federation; the scalar-only check
          would incorrectly reject all of them.
    """
    tok = _forge().aud_value(["nginx-xrootd", "other"])
    assert probe(proto, tok) == "accept"


# ---------------------------------------------------------------------------
# PAR-08  WLCG wildcard audience → accept  (recently fixed, now uniform)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_08_aud_wildcard_accept(proto):
    """PAR-08: aud="https://wlcg.cern.ch/jwt/v1/any" wildcard → accept.

    WHAT: WLCG Token Profile §3 / rules 104/105 — the special URI
          ``https://wlcg.cern.ch/jwt/v1/any`` is a WLCG-wide wildcard that
          any conformant WLCG endpoint MUST accept regardless of its locally
          configured audience string.
    WHY:  Recently fixed (commit e842cf3); now uniform across root://, WebDAV,
          and S3.  This test proves the fix holds on both HTTP enforcing ports.
    """
    tok = _forge().aud_wildcard()
    assert probe(proto, tok) == "accept"


# ---------------------------------------------------------------------------
# PAR-09  crit unknown extension → reject  (recently fixed, now uniform)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_09_crit_unknown_reject(proto):
    """PAR-09: crit=["http://example.com/UNKNOWN"] → reject (RFC 7515 §4.1.11).

    WHAT: Header carries crit with an unrecognised extension parameter.  RFC 7515
          §4.1.11 / rule 36 MUST: an unrecognised critical extension MUST cause
          the JWS to be rejected.
    WHY:  Recently fixed (commit e842cf3); now uniform across root://, WebDAV,
          and S3.  This test proves the fix holds on both HTTP enforcing ports.
    """
    tok = _forge().crit_unknown()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-10  fractional NumericDate exp → accept  (recently fixed, now uniform)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_10_numericdate_fractional_accept(proto):
    """PAR-10: exp as fractional NumericDate (now+3600.5) → accept (RFC 7519 §2).

    WHAT: RFC 7519 §2 / rule 2 — NumericDate is a JSON numeric value representing
          seconds; fractional seconds are permitted.  A conformant implementation
          must not reject a float exp that is still in the future.
    WHY:  Recently fixed (commit e842cf3); json_get_int64 was failing on json_real
          (float), treating exp=0 as expired.  Now uniform across all protocols.
    """
    tok = _forge().numericdate_fractional()
    assert probe(proto, tok) == "accept"


# ---------------------------------------------------------------------------
# PAR-11  embedded JWK injection → reject (SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_11_jwk_injection_reject(proto):
    """PAR-11: token with embedded 'jwk' header param signed by attacker key → reject (SEC).

    WHAT: Header carries a jwk member containing a throwaway attacker public key;
          the token is signed by the matching attacker private key (NOT the main
          key configured in the JWKS).
    WHY:  RFC 7515 §4.1.3 / rules 29/150 — the server MUST NOT trust the key
          embedded in the jwk header; it must verify against its configured JWKS.
          The attacker key is absent from the JWKS → reject.
    """
    tok = _forge().header_jwk_injection()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-12  truncated signature → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_12_truncated_sig_reject(proto):
    """PAR-12: signature truncated to half its length → reject.

    WHAT: A valid token whose signature segment has been cut to 50% of its
          original length — the resulting base64url decodes to a partial RSA
          signature that will never verify.
    WHY:  Basic structural integrity: a truncated signature is simply invalid
          and must not be accepted on any protocol.
    """
    tok = _forge().truncated_sig()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-13  bad signature → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_13_bad_signature_reject(proto):
    """PAR-13: first 8 signature bytes XOR'd with 0xFF → reject (signature verification).

    WHAT: A structurally valid JWT (correct alg, kid, claims) whose RSA signature
          has been corrupted in the first 8 bytes.  The cryptographic verify step
          must catch this.
    WHY:  Any conformant implementation must reject tokens that fail signature
          verification; accepting them would allow forgery.
    """
    tok = _forge().generate_bad_signature()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-14  no scope claim → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_14_no_scope_reject(proto):
    """PAR-14: valid JWT with no scope claim → reject (authenticated, no storage grant).

    WHAT: The token passes signature, expiry, issuer, and audience checks but
          carries no scope claim.  Without a storage.read scope the server must
          deny access to any storage path.
    WHY:  WLCG Token Profile §4 / rule 112 — storage access requires an explicit
          storage scope; absence of scope means no storage permission.
    """
    tok = _forge().no_scope()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-15  in-scope path → accept
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_15_in_scope_accept(proto):
    """PAR-15: scope="storage.read:/atlas", path=/atlas/ok.txt → accept.

    WHAT: The token's scope covers exactly the requested path prefix; the request
          must be accepted.
    WHY:  Positive scope case — confirms that narrowly-scoped tokens do grant
          access to paths within their scope prefix.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert probe(proto, tok, path="/atlas/ok.txt") == "accept"


# ---------------------------------------------------------------------------
# PAR-16  out-of-scope path → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_16_out_of_scope_reject(proto):
    """PAR-16: scope="storage.read:/atlas", path=/cms/ok.txt → reject.

    WHAT: The token's scope only covers /atlas; /cms/ok.txt is outside that
          prefix.  The server must reject the request.
    WHY:  Core scope enforcement: a narrowly-scoped token must NOT reach paths
          outside its scope, even if the token is otherwise fully valid.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert probe(proto, tok, path="/cms/ok.txt") == "reject"


# ---------------------------------------------------------------------------
# PAR-17  dot-dot traversal via scope boundary → reject (§3.5)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_17_traversal_reject(proto):
    """PAR-17: scope=/atlas token, path=/atlas/../cms/ok.txt → reject (§3.5).

    WHAT: An /atlas-scoped token attempts to reach /cms/ok.txt via a dot-dot
          path traversal.  The path normalises to /cms/ok.txt before (or at)
          the server's scope check; scope does not cover /cms → reject.
    WHY:  WLCG Token Profile §3.5 traversal defense — a dot-dot sequence must not
          allow a token to escape its scope boundary.  Both the requests HTTP
          client and nginx normalise the path before the handler runs, so the
          effective path is /cms/ok.txt, which is outside /atlas scope → reject.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert probe(proto, tok, path="/atlas/../cms/ok.txt") == "reject"


# ---------------------------------------------------------------------------
# PAR-18  oversized token → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_18_oversized_reject(proto):
    """PAR-18: token with 9000-byte pad claim → reject (token size limit).

    WHAT: The JWT payload carries a large padding claim that pushes the total
          token length well beyond the 8192-byte limit enforced in validate.c.
    WHY:  A size limit prevents denial-of-service via excessively large JWTs that
          consume CPU (base64 decode + RSA verify) for tokens that can never be
          legitimate.  Uniform rejection across protocols is required.
    """
    tok = _forge().oversized(9000)
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-19  ES256 on RSA-only JWKS → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_19_es256_reject(proto):
    """PAR-19: ES256 token on RSA-only JWKS → reject (no matching key).

    WHAT: The token is signed with an EC P-256 key (kid=ec-key-1).  Ports 8446
          and 9002 serve the MAIN RSA-only JWKS (jwks.json, one RSA entry,
          kid=test-key-1).  The ec-key-1 kid is absent → no key match → reject.
    WHY:  EC accept is confirmed on root:// multikey port 11250 (where the JWKS
          includes both RSA and EC entries).  HTTP token ports are RSA-only by
          design; rejecting an unknown kid is the correct JWKS lookup failure
          path, not an algorithm policy failure.
    NOTE: HTTP token ports serve RSA-only JWKS; ES256 accept is covered on
          root:// multikey 11250.
    """
    tok = _forge().es256()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-20  unknown extra claims → accept (RFC 7519 §4.3)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_20_unknown_claims_accept(proto):
    """PAR-20: token with extra unknown claims (custom_x, https://ex/z) → accept.

    WHAT: RFC 7519 §4.3 / rule 16 — unrecognised claim names MUST be ignored;
          their presence MUST NOT cause rejection.  An implementation that errors
          on unknown claim names would break forward compatibility.
    WHY:  WLCG tokens routinely carry additional VO or service-specific claims
          (wlcg.groups, VO extensions, etc.); rejecting unknown claims is
          operationally disruptive and non-conformant.
    """
    tok = _forge().unknown_claims_ok()
    assert probe(proto, tok) == "accept"
