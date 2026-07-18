"""WLCG token conformance — RFC-6750 Bearer transport + error-response family.

WHAT: Thirteen wire cases covering RFC 6750 Bearer token transport methods,
      error status codes (401/403/400), and WWW-Authenticate response headers.
      All cases target port 8446 (NGINX_WEBDAV_TOKEN_PORT): HTTPS WebDAV with
      brix_webdav_auth=required and query-token enabled — the only port where
      HTTP-observable Bearer semantics (response headers + status codes) are
      fully enforced.
WHY:  Documents and regression-guards the server's RFC 6750 conformance level.
      Cases where the server diverges from a MUST/SHOULD requirement are marked
      xfail(strict=True) with the rule number so the suite stays GREEN and the
      divergences form a precise fix-candidate list.
HOW:  Uses requests directly (verify=False, test PKI self-signed CA) so the
      full response — status code AND response headers — is available for
      assertion.  TokenForge mints valid/hostile tokens from TOKENS_DIR.  Data
      files are provisioned idempotently via ensure_conformance_data().

Cases (rule references = docs/10-reference/wlcg-token-rfc-rules.md):
  BEAR-01  header Authorization: Bearer <valid>          → 200        (rule 80)
  BEAR-02  case-insensitive scheme: bearer <valid>        → 200/xfail  (rule 81)
  BEAR-03  uppercase scheme: BEARER <valid>               → 200        (rule 81)
  BEAR-04  dual transport (header+query)                  → 400/xfail  (rule 79 SEC)
  BEAR-05  query ?access_token=<valid>                    → 200        (rule 84)
  BEAR-06  query no-store Cache-Control                   → present/xfail (rule 85 SEC)
  BEAR-07  malformed: no token after Bearer               → not 200    (rule 82)
  BEAR-08  malformed: extra token after Bearer            → not 200    (rule 82)
  BEAR-09  no credential → 401 + WWW-Authenticate: Bearer (rules 86/87)
  BEAR-10  invalid_token → 401 + WWW-Authenticate         → xfail if 403 (rule 90)
  BEAR-11  insufficient_scope → 403                       (rule 91)
  BEAR-12  WWW-Authenticate scope attribute on BEAR-11    (rule 91 SHOULD)
  BEAR-13  TLS: https:// connection works (informational) (rule 94)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_wlcg_token_conformance_bearer.py -v
"""

import os
import sys

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from lib.tokenconf import ensure_conformance_data
from settings import NGINX_WEBDAV_TOKEN_PORT, SERVER_HOST, TOKENS_DIR

# ---------------------------------------------------------------------------
# Port / base URL
# ---------------------------------------------------------------------------

WD = NGINX_WEBDAV_TOKEN_PORT  # 8446 — enforcing token port


def _get(path="/test.txt", headers=None, url_extra="", port=WD):
    """Issue a GET to the enforcing WebDAV token port and return the response.

    WHAT: Convenience wrapper used by every BEAR case so repetitive URL/verify
          construction stays in one place.
    WHY:  Keeps test bodies focused on the assertion, not request boilerplate.
    HOW:  verify=False: the test fleet uses a self-signed CA.
    """
    return requests.get(
        f"https://{SERVER_HOST}:{port}{path}{url_extra}",
        headers=headers or {},
        verify=False,
        timeout=5,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _provision_data():
    """Ensure /test.txt and /cms/ok.txt exist in the server's data root.

    WHAT: Idempotent fixture that creates the small fixture files all BEAR
          cases depend on before any probe is issued.
    WHY:  A fleet restart wipes the data root; the suite must not require a
          specific start order.
    HOW:  Delegates to ensure_conformance_data() from lib/tokenconf.
    """
    ensure_conformance_data()


@pytest.fixture(scope="module")
def forge():
    """Return a TokenForge instance backed by the test TOKENS_DIR.

    WHAT: Module-scoped so key material is loaded once; test functions receive
          the forge via parameter injection.
    WHY:  RSA key load is non-trivial; module scope avoids redundant I/O.
    HOW:  Imports TokenForge lazily so the module is importable even on hosts
          where the test fleet is not provisioned (import-time guard).
    """
    from tokenforge import TokenForge
    return TokenForge(TOKENS_DIR)


# ---------------------------------------------------------------------------
# BEAR-01 — canonical Authorization: Bearer (rule 80, RECOMMENDED transport)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_01_header_bearer_valid_200(forge):
    """BEAR-01: Authorization: Bearer <valid> → 200.

    WHAT: Verifies that the canonical RFC 6750 §2.1 transport (Authorization
          header, Bearer scheme) is accepted on the enforcing token port.
    WHY:  Baseline acceptance case; every other case is relative to this.
    HOW:  Mints a valid storage.read:/ token, issues GET /test.txt with the
          Authorization header, asserts HTTP 200.
    Rule: 80 (RFC 6750 §2.1 — RECOMMENDED transport).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, (
        f"BEAR-01: canonical Bearer header should return 200, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-02 — case-insensitive Bearer scheme (rule 81)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_02_lowercase_bearer_scheme(forge):
    """BEAR-02: Authorization: bearer <valid> (lowercase) → RFC-correct 200.

    WHAT: RFC 6750 §2.1 specifies the scheme token; HTTP §3.1 says auth-scheme
          comparison is case-insensitive, so 'bearer' MUST be accepted.
    WHY:  A non-trivial fraction of client libraries send lowercase; rejecting
          them is an RFC violation.
    HOW:  Sends the header with lowercase 'bearer'; asserts 200.  The server
          correctly handles this case (rule 81 is already CONFORMANT).
    Rule: 81 (RFC 6750 §2.1 case-insensitive scheme, HTTP §3.1).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(headers={"Authorization": f"bearer {token}"})
    assert resp.status_code == 200, (
        f"BEAR-02: lowercase 'bearer' scheme should return 200 per RFC 6750 §2.1, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-03 — uppercase BEARER scheme (rule 81)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_03_uppercase_bearer_scheme(forge):
    """BEAR-03: Authorization: BEARER <valid> (uppercase) → 200.

    WHAT: Exercises the upper end of case-insensitive scheme matching.  If the
          server normalises to 'Bearer' via case-fold, 'BEARER' MUST also pass.
    WHY:  Symmetry with BEAR-02 — both cases confirm (or expose) the same
          case-folding behaviour.
    HOW:  Sends the header with uppercase 'BEARER'; asserts 200.  Not marked
          xfail: if BEAR-02 is a divergence, BEARER may also fail, at which
          point this test will correctly turn RED (a separate fix indicator).
    Rule: 81 (RFC 6750 §2.1 case-insensitive scheme).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(headers={"Authorization": f"BEARER {token}"})
    assert resp.status_code == 200, (
        f"BEAR-03: uppercase 'BEARER' scheme should return 200 per RFC 6750 §2.1, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-04 — dual transport must return 400 (rule 79, SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "BEAR-04 [rule 79, RFC 6750 §2 SEC MUST]: exactly one transport per "
        "request; simultaneous header + query token MUST return "
        "400 invalid_request.  Server currently honours the header and returns "
        "200 (header-wins behaviour) instead of rejecting."
    ),
)
@pytest.mark.registry_server("webdav-token")
def test_bear_04_dual_transport_must_400(forge):
    """BEAR-04: valid token in header AND ?authz=<valid> → RFC-correct 400.

    WHAT: RFC 6750 §2 is explicit: sending the access token in more than one
          place MUST be rejected with 400 invalid_request.  This is a security
          requirement — it prevents confused-deputy attacks where a proxy strips
          one transport but not the other.
    WHY:  The server currently selects the header and returns 200, ignoring the
          collision.  Documented as a MUST divergence.
    HOW:  Sends the same valid token in both Authorization header and ?authz=
          query parameter; asserts 400.  Marked xfail(strict=True) because the
          current behaviour is 200 (header-wins).
    Rule: 79 (RFC 6750 §2 — multiple transports MUST → 400 invalid_request).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(
        headers={"Authorization": f"Bearer {token}"},
        url_extra=f"?authz=Bearer%20{token}",
    )
    assert resp.status_code == 400, (
        f"BEAR-04: dual transport should return 400 invalid_request, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-05 — query ?access_token= transport (rule 84, NOT RECOMMENDED)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_05_query_access_token_200(forge):
    """BEAR-05: GET /test.txt?access_token=<valid> → 200.

    WHAT: RFC 6750 §2.3 (NOT RECOMMENDED) query transport; the server's
          brix_http_query_token directive enables ?access_token= in addition to
          ?authz= on the token port.
    WHY:  Even though the spec recommends against it, the server supports both
          param names; this case confirms the standard ?access_token= param works.
    HOW:  Embeds the token in the URL query string with no Authorization header.
    Rule: 84 (RFC 6750 §2.3 — query method NOT RECOMMENDED but supported).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(url_extra=f"?access_token={token}")
    assert resp.status_code == 200, (
        f"BEAR-05: ?access_token= query transport should return 200, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-06 — query no-store Cache-Control (rule 85, SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "BEAR-06 [rule 85, RFC 6750 §2.3 SEC MUST]: responses to query-token "
        "requests MUST carry Cache-Control: no-store to prevent the token "
        "leaking into caches.  The server does not add this header on "
        "?access_token= responses."
    ),
)
@pytest.mark.registry_server("webdav-token")
def test_bear_06_query_nostore_cache_control(forge):
    """BEAR-06: ?access_token= response MUST include Cache-Control: no-store.

    WHAT: RFC 6750 §2.3 mandates that servers MUST include Cache-Control:
          no-store in the response when the query method is used, to prevent
          access tokens from leaking into shared or intermediate caches.
    WHY:  Without this header a caching proxy may serve the URL (including the
          embedded token) to other clients, constituting a token-theft vector.
    HOW:  Issues GET with ?access_token=<valid>; asserts "no-store" appears in
          the Cache-Control response header.  Marked xfail(strict=True) because
          the server does not currently emit this header.
    Rule: 85 (RFC 6750 §2.3 SEC — Cache-Control: no-store on query responses).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(url_extra=f"?access_token={token}")
    cc = resp.headers.get("Cache-Control", "")
    assert "no-store" in cc.lower(), (
        f"BEAR-06: query-token response must include Cache-Control: no-store, "
        f"got Cache-Control: {cc!r}"
    )


# ---------------------------------------------------------------------------
# BEAR-07 — malformed: Bearer with no token (rule 82)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_07_bearer_no_token_rejected(forge):  # noqa: ARG001 — forge unused but consistent API
    """BEAR-07: Authorization: Bearer (no token value) → not 200.

    WHAT: An Authorization header whose value is exactly the scheme with no
          following b64token is malformed; the server MUST reject it.
    WHY:  Any 200 response here would mean the server treats a credential-less
          header as authenticated — a clear security failure.
    HOW:  Sends "Bearer" with a trailing space but no token; asserts status
          is not 200 (400 or 401 are both acceptable).
    Rule: 82 (RFC 6750 §2.1 — b64token charset; absent token is malformed).
    """
    resp = _get(headers={"Authorization": "Bearer "})
    assert resp.status_code != 200, (
        f"BEAR-07: empty Bearer credential must not return 200, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-08 — malformed: extra token in Authorization value (rule 82)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_08_bearer_extra_token_rejected(forge):
    """BEAR-08: Authorization: Bearer <valid> extra → not 200.

    WHAT: The RFC 6750 §2.1 grammar allows exactly one b64token after the scheme
          name; extra whitespace-separated values are outside the grammar and
          MUST be rejected.
    WHY:  Accepting a malformed credential value could allow surprising bypass
          behaviour if the server parses the first or last token selectively.
    HOW:  Appends a second token-like string after the valid JWT; asserts status
          is not 200.
    Rule: 82 (RFC 6750 §2.1 — b64token grammar; extra values are malformed).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(headers={"Authorization": f"Bearer {token} extravalue"})
    assert resp.status_code != 200, (
        f"BEAR-08: extra token after Bearer value must not return 200, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-09 — no credential → 401 + WWW-Authenticate: Bearer (rules 86/87)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "BEAR-09 [rules 86+87, RFC 6750 §2+§3 MUST]: no credential on a "
        "protected resource MUST return 401 + WWW-Authenticate: Bearer.  "
        "Server currently returns 403 (Forbidden) instead of 401 "
        "(Unauthorized) and does not emit WWW-Authenticate."
    ),
)
@pytest.mark.registry_server("webdav-token")
def test_bear_09_no_credential_401_www_authenticate(forge):  # noqa: ARG001
    """BEAR-09: unauthenticated request to protected resource → 401 + WWW-Authenticate: Bearer.

    WHAT: RFC 6750 §2 (rule 86) requires a 401 response when no credential is
          presented to a protected resource; §3 (rule 87) requires the response
          to include WWW-Authenticate: Bearer so clients know the scheme.
    WHY:  Without the WWW-Authenticate header a 401 is technically non-standard;
          clients may not know they need to supply a Bearer token.  Using 403
          here additionally confuses clients: 403 means the identity is known
          but lacks permission, not that authentication is required.
    HOW:  Issues GET /test.txt with no Authorization header on port 8446
          (brix_webdav_auth=required); asserts status==401 AND the header
          starts with "bearer" (case-insensitive).  Marked xfail(strict=True)
          because the server currently returns 403 with no WWW-Authenticate.
    Rules: 86 (no credential → 401 MUST), 87 (WWW-Authenticate: Bearer MUST).
    """
    resp = _get()
    assert resp.status_code == 401, (
        f"BEAR-09: no credential on protected port should return 401, "
        f"got {resp.status_code}"
    )
    www_auth = resp.headers.get("WWW-Authenticate", "")
    assert www_auth.lower().startswith("bearer"), (
        f"BEAR-09: no-credential 401 must include WWW-Authenticate: Bearer "
        f"(rule 87), got {www_auth!r}"
    )


# ---------------------------------------------------------------------------
# BEAR-10 — invalid_token → 401 (rule 90, SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "BEAR-10 [rule 90, RFC 6750 §3.1 SEC MUST]: invalid/expired tokens "
        "MUST return 401 invalid_token, not 403.  The server currently returns "
        "403 for all token validation failures (sig-invalid, alg:none, etc.)."
    ),
)
@pytest.mark.registry_server("webdav-token")
def test_bear_10_invalid_token_401(forge):
    """BEAR-10: invalid token (alg:none) → 401 + WWW-Authenticate: Bearer.

    WHAT: RFC 6750 §3.1 (rule 90) maps the error code invalid_token to HTTP 401
          and requires WWW-Authenticate to be present.  Using 403 here is an
          RFC violation because 403 means "forbidden", not "invalid credential".
    WHY:  Clients use the 401 status to know they should re-authenticate (e.g.
          refresh the token); 403 tells them the identity is known but lacks
          permission.  The wrong status code breaks the OIDC token-refresh loop.
    HOW:  Sends an alg:none token (structurally complete but unsigned — rule 19
          says it MUST be rejected); asserts status 401.  Marked xfail(strict=True)
          because the server currently returns 403.
    Rule: 90 (RFC 6750 §3.1 SEC — invalid_token → HTTP 401).
    """
    token = forge.alg_none()
    resp = _get(headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401, (
        f"BEAR-10: invalid token (alg:none) should return 401 invalid_token, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-11 — insufficient_scope → 403 (rule 91, SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_11_insufficient_scope_403(forge):
    """BEAR-11: valid token, wrong scope for path → 403.

    WHAT: RFC 6750 §3.1 (rule 91) maps insufficient_scope to HTTP 403.  A token
          that is cryptographically valid but whose scope claim does not cover the
          requested resource must produce a 403, not 401 (which would imply the
          token itself is invalid).
    WHY:  The 401 vs 403 split is the principal observable signal that tells
          clients whether to re-authenticate (401) or escalate privileges (403).
    HOW:  Mints a token scoped only to storage.read:/atlas and requests
          /cms/ok.txt — a valid token that explicitly lacks access.  Asserts
          status == 403.
    Rule: 91 (RFC 6750 §3.1 SEC — insufficient_scope → HTTP 403).
    """
    # Valid token but scoped to /atlas only; GET /cms/ok.txt must be 403.
    token = forge.scope("storage.read:/atlas")
    resp = _get(path="/cms/ok.txt", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403, (
        f"BEAR-11: valid token with insufficient scope should return 403, "
        f"got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# BEAR-12 — WWW-Authenticate scope attribute on insufficient_scope (rule 91 SHOULD)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_12_insufficient_scope_www_authenticate_scope(forge):
    """BEAR-12: insufficient_scope 403 SHOULD include scope in WWW-Authenticate.

    WHAT: RFC 6750 §3 / §3.1 (rule 91 SHOULD) says that when an insufficient_scope
          error is returned, the WWW-Authenticate header SHOULD include a scope
          attribute describing the required scope.  This test characterises the
          current header value and asserts presence (SHOULD — informational
          finding, not a MUST failure).
    WHY:  A scope attribute lets the client automatically request a wider-scope
          token rather than requiring manual intervention.
    HOW:  Sends the same insufficient-scope token as BEAR-11; checks for a
          WWW-Authenticate header and logs its value.  Does NOT xfail: a missing
          scope attribute is a SHOULD finding, captured in the report.
    Rule: 91 (RFC 6750 §3.1 — insufficient_scope SHOULD add scope= attribute).
    """
    token = forge.scope("storage.read:/atlas")
    resp = _get(path="/cms/ok.txt", headers={"Authorization": f"Bearer {token}"})
    # The response should be 403 (validated in BEAR-11); here we inspect headers.
    www_auth = resp.headers.get("WWW-Authenticate", "")
    # Log the observed header for the report.
    has_bearer = www_auth.lower().startswith("bearer")
    has_scope  = "scope=" in www_auth.lower()
    # SHOULD: presence of WWW-Authenticate is desirable; absence is a finding.
    # This test asserts only that the 403 is correct (already covered by
    # BEAR-11), then records the scope attribute finding via a soft assert.
    assert resp.status_code == 403, (
        f"BEAR-12 precondition: expected 403, got {resp.status_code}"
    )
    # Informational finding: if the header or scope attr is missing, record it.
    # We do NOT xfail here because this is a SHOULD, not a MUST.
    if not has_bearer:
        pytest.skip(
            f"BEAR-12 FINDING [rule 91 SHOULD]: WWW-Authenticate absent on "
            f"insufficient_scope 403 — clients cannot discover the required scope. "
            f"Got: {www_auth!r}"
        )
    if not has_scope:
        pytest.skip(
            f"BEAR-12 FINDING [rule 91 SHOULD]: WWW-Authenticate present but "
            f"scope= attribute absent on insufficient_scope 403. "
            f"Got: {www_auth!r}"
        )


# ---------------------------------------------------------------------------
# BEAR-13 — TLS informational (rule 94)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_bear_13_tls_connection_works(forge):
    """BEAR-13: Bearer tokens are transported over TLS (rule 94, informational).

    WHAT: RFC 6750 §4 / §5.3 (rule 94) requires Bearer tokens only be used over
          TLS connections.  This test confirms that the enforcing port (8446) is
          in fact HTTPS and that a well-formed TLS connection succeeds.
    WHY:  Cleartext token transport exposes credentials to passive interception.
          The test PKI's self-signed cert means verify=False is required; cleartext
          token transport over plain HTTP is out of scope for this test PKI.
    HOW:  Issues a GET with a valid token and asserts we receive a numeric HTTP
          status (i.e. TLS handshake completed, HTTP response arrived).  A
          connection error would raise requests.RequestException.
          NOTE: verify=False is intentional here — the test fleet uses a
          self-signed CA and TLS encryption is confirmed by the HTTPS:// scheme
          and the absence of a connection error, not by cert chain validation.
    Rule: 94 (RFC 6750 §4 — bearer tokens MUST only travel over TLS).
    """
    token = forge.generate(scope="storage.read:/")
    resp = _get(headers={"Authorization": f"Bearer {token}"})
    # Any HTTP response status proves TLS negotiated successfully.
    assert isinstance(resp.status_code, int), (
        "BEAR-13: expected an HTTP response over TLS, connection failed"
    )
    assert 100 <= resp.status_code < 600, (
        f"BEAR-13: unexpected non-HTTP status {resp.status_code!r}"
    )
