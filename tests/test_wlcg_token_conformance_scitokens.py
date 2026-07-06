"""WLCG token conformance — SCITOK family (SciTokens profile on a WLCG server).

Probes port 11097 (NGINX_TOKEN_PORT) which enforces the WLCG capability-scope
model (storage.*) against the main RSA JWKS.

This family documents the profile boundary between SciTokens and WLCG tokens.
Both share the same JWT container format and can use the same signing key, but
they differ in scope syntax and audience semantics:

  WLCG scope:      storage.read:/path  (namespaced verb)
  SciTokens scope: read:/path          (bare verb — rule 135)

  WLCG wildcard:   https://wlcg.cern.ch/jwt/v1/any   (rules 104/105)
  SciTokens ANY:   "ANY"                              (rule 132)

Ground truth (this server's implementation):
  - 'read:/path' SciTokens scope: not recognised by the WLCG storage.* engine
    → no grant → reject.  This is correct behaviour for a WLCG server — it does
    not implement the SciTokens scope model.  Not a bug; documented boundary.
  - ver='scitokens:2.0' claim: ignored (unknown claim; rule 16 ignore-unknown);
    the WLCG storage.read:/ scope in the same token still authorises → accept.
  - aud='ANY' (SciTokens wildcard): our WLCG server performs exact-match →
    reject.  RFC-correct-for-SciTokens would be accept (rule 132) but this
    server is not a SciTokens endpoint → xfail(strict); documented boundary.

Test cases:
  SCITOK-01  scitokens_scope("read","/atlas"), GET /atlas/ok.txt → reject
             (SciTokens read:/atlas scope not supported on WLCG server;
             documented profile boundary).
  SCITOK-02  scitokens_ver() (ver='scitokens:2.0' + default storage.read:/),
             GET /test.txt → accept (ver ignored; WLCG scope authorises).
  SCITOK-03  aud_any() (aud='ANY'), GET /test.txt → RFC-correct-for-SciTokens
             accept (rule 132); ACTUAL=reject (exact-match WLCG audience) →
             xfail(strict) + documented boundary.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data
from settings import NGINX_TOKEN_PORT as PORT, TOKENS_DIR


def _f():
    return TokenForge(TOKENS_DIR)


@pytest.fixture(autouse=True)
def _data():
    ensure_conformance_data()


@pytest.mark.tokenconf
def test_scitok_01_scitokens_read_scope_reject():
    """SciTokens scope 'read:/atlas', GET /atlas/ok.txt → reject.

    WHY:  This server implements the WLCG storage.* scope model only.  The
          SciTokens bare-verb form 'read:/atlas' (rule 135) is not recognised
          by the WLCG capability-scope engine; it carries no storage.read grant
          → reject.
    DOCUMENTED BOUNDARY: This is not a bug.  A WLCG-only server is not required
          to implement SciTokens scope syntax.  Sites that need SciTokens
          interoperability should use a SciTokens-aware endpoint or translate
          scopes at the IAM/token-exchange layer.
    """
    tok = _f().scitokens_scope("read", "/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scitok_02_scitokens_ver_with_wlcg_scope_accept():
    """Token with ver='scitokens:2.0' and default storage.read:/, GET /test.txt → accept.

    WHY:  The 'ver' claim (SciTokens profile version) is an unknown claim to
          this WLCG server; RFC 7519 §4.3 / rule 16 requires that unrecognised
          claims be ignored.  The WLCG storage.read:/ scope in the same token
          still covers /test.txt and authorises the request → accept.
    CHARACTERIZE: confirms that a SciTokens ver claim does not interfere with
          WLCG scope processing when the storage.* scope is also present.
    """
    tok = _f().scitokens_ver()
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "DIVERGENCE rule 132: SciTokens §2 / rule 132 requires that the "
        "special audience value 'ANY' be accepted by any conformant SciTokens "
        "endpoint. Our server is a WLCG endpoint, not a SciTokens endpoint; "
        "it performs exact-match audience comparison → actual=reject. "
        "This is a documented profile boundary, not a bug: 'ANY' is a "
        "SciTokens-specific wildcard. WLCG uses "
        "'https://wlcg.cern.ch/jwt/v1/any' instead (rules 104/105)."
    ),
)
def test_scitok_03_aud_any_reject():
    """aud='ANY' (SciTokens wildcard), GET /test.txt → RFC-correct-for-SciTokens accept.

    WHY:  SciTokens §2 / rule 132 — the audience value 'ANY' is a SciTokens
          convention meaning the token is valid for any endpoint.  A conformant
          SciTokens validator MUST accept 'ANY' without requiring an audience
          match.  Our WLCG server performs exact-match against the configured
          audience ('nginx-xrootd') — 'ANY' does not match → reject.
    DOCUMENTED BOUNDARY: This server is not a SciTokens endpoint.  The WLCG
          equivalent wildcard is 'https://wlcg.cern.ch/jwt/v1/any'; see
          WLCG-01 for that case.  SciTokens ANY tokens should be directed to a
          SciTokens-aware server or exchanged for WLCG tokens first.
    """
    tok = _f().aud_any()
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"
