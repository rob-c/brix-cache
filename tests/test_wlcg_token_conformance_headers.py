"""WLCG token conformance — HDR family (RFC 7515 JWS header parameters).

Probes port 11097 (NGINX_TOKEN_PORT) which enforces token auth against the
main RSA JWKS (jwks.json, kid test-key-1).  All forged tokens in this family
are signed by the main key (except the injection cases which use attacker keys
specifically not in the JWKS).

Test cases:

  HDR-01  crit_unknown        → RFC MUST reject (rule 36).  DIVERGENCE: accept.
  HDR-02  crit_empty          → RFC MUST reject (rule 37).  DIVERGENCE: accept.
  HDR-03  crit_non_array      → RFC MUST reject (rule 37).  DIVERGENCE: accept.
  HDR-04  crit_lists_alg      → RFC MUST reject (rule 38).  DIVERGENCE: accept.
  HDR-05  crit_missing_name   → RFC MUST reject (rule 37).  DIVERGENCE: accept.
  HDR-06  typ=at+jwt          → accept (rule 75; at+jwt is a valid access-token type).
  HDR-07  typ_wrong           → accept (rule 75 is SHOULD; typ enforcement not required).
  HDR-08  typ_missing         → accept (rule 70 is SHOULD; typ not enforced).
  HDR-09  cty=JWT             → accept (rule 35 is SHOULD; cty not enforced).
  HDR-10  header_jku          → accept (rule 28 SEC PASS: jku correctly ignored, not fetched).
  HDR-11  header_jwk_injection → reject (rule 29 SEC PASS: embedded jwk not trusted).
  HDR-12  header_x5c_injection → reject (rule 32 SEC PASS: x5c not trusted).
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


# ---------------------------------------------------------------------------
# crit header — all five shapes must reject per RFC 7515 §4.1.11
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_hdr01_crit_unknown_rejects():
    """crit lists an unrecognised extension — MUST reject (RFC 7515 §4.1.11, rule 36).

    WHY:  An unrecognised critical header parameter MUST cause the JWS to be
          rejected by a conformant processor.  The implementation now checks for
          the presence of any `crit` header and rejects immediately, since we
          implement no `crit` extension parameters.
    FIXED: json_has_member("crit") check added to validate.c.
    """
    assert root_ztn(_f().crit_unknown(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_hdr02_crit_empty_rejects():
    """crit is an empty array [] — MUST reject (rule 37).

    WHY:  The crit array MUST NOT be empty per RFC 7515 §4.1.11; an empty
          array is a structural error.  The implementation now rejects any
          token carrying a `crit` member (we implement no extensions).
    FIXED: json_has_member("crit") check added to validate.c.
    """
    assert root_ztn(_f().crit_empty(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_hdr03_crit_non_array_rejects():
    """crit is a string rather than an array — MUST reject (rule 37).

    WHY:  RFC 7515 §4.1.11 requires crit to be a JSON array; a scalar value
          is a type violation that a conformant processor must reject.  The
          implementation now rejects any token whose header contains a `crit`
          member (regardless of its value type).
    FIXED: json_has_member("crit") check added to validate.c.
    """
    assert root_ztn(_f().crit_non_array(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_hdr04_crit_lists_alg_rejects():
    """crit lists 'alg', a registered JWS parameter — MUST reject (rule 38).

    WHY:  The crit array MUST NOT include header parameters whose semantics are
          defined in the JWS/JWA specifications.  Listing 'alg' is a structural
          violation.  The implementation now rejects any token carrying a `crit`
          member.
    FIXED: json_has_member("crit") check added to validate.c.
    """
    assert root_ztn(_f().crit_lists_alg(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_hdr05_crit_missing_name_rejects():
    """crit lists 'kid' but the header has no kid member — MUST reject (rule 37).

    WHY:  Every name in the crit array MUST also appear as a header parameter;
          a named-but-absent parameter is a structural error.  The implementation
          now rejects any token carrying a `crit` member (we implement no
          extension parameters).
    FIXED: json_has_member("crit") check added to validate.c.
    """
    assert root_ztn(_f().crit_missing_name(), "/test.txt", port=PORT) == "reject"


# ---------------------------------------------------------------------------
# typ / cty — SHOULD-level rules characterised as accept
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_hdr06_typ_at_jwt_accepted():
    """typ=at+jwt — valid OAuth 2.0 access-token type designator (rule 75).

    WHY:  RFC 9068 registers 'at+jwt' as the media type for access tokens; a
          conformant validator must accept it equivalently to 'JWT'.
    """
    assert root_ztn(_f().typ_at_jwt(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_hdr07_typ_wrong_accepted():
    """typ=id_token+jwt — cross-JWT confusion type (rule 75 SHOULD; characterize).

    WHY:  RFC 8725 §2.8 SHOULD reject tokens bearing a typ from a different
          profile to prevent cross-JWT confusion.  This implementation does not
          enforce typ, so the token is accepted.  Characterised as accept.
    """
    assert root_ztn(_f().typ_wrong(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_hdr08_typ_missing_accepted():
    """typ absent from the header (rule 70 SHOULD; characterize).

    WHY:  RFC 8725 §2.9 SHOULD require typ to prevent confusion; this
          implementation does not enforce its presence.  Characterised as accept.
    """
    assert root_ztn(_f().typ_missing(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_hdr09_cty_set_accepted():
    """cty=JWT on a non-nested token (rule 35 SHOULD; characterize).

    WHY:  RFC 7515 §4.1.10 SHOULD omit cty on non-nested JWS; its presence
          here causes no rejection.  Characterised as accept.
    """
    assert root_ztn(_f().cty_set(), "/test.txt", port=PORT) == "accept"


# ---------------------------------------------------------------------------
# Security: jku / jwk / x5c injection
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_hdr10_header_jku_accepted():
    """jku with attacker URL in header, signed by the main key (rule 28 SEC PASS).

    WHY:  RFC 7515 §4.1.2 / rule 28 — the verifier MUST NOT fetch or trust the
          jku value; it must verify against the statically configured JWKS.
          The main-key signature verifies → accept confirms jku is ignored.
          Fetching the attacker URL would be a critical security regression.
    """
    assert root_ztn(_f().header_jku(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_hdr11_header_jwk_injection_rejected():
    """Attacker public key embedded in jwk header, signed by attacker key (rule 29 SEC PASS).

    WHY:  RFC 7515 §4.1.3 / rules 29/150 — the server MUST NOT trust the key
          embedded in the jwk header parameter; it must verify only against the
          configured JWKS.  The attacker key is not in the JWKS → must reject.
          Security-critical: acceptance would allow token forgery.
    """
    assert root_ztn(_f().header_jwk_injection(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_hdr12_header_x5c_injection_rejected():
    """Attacker cert chain in x5c header, signed by attacker key (rule 32 SEC PASS).

    WHY:  RFC 7515 §4.1.6 / rules 32/150 — the server MUST NOT trust key
          material presented in the x5c header parameter; it must verify only
          against the configured JWKS.  The attacker key is absent → must reject.
          Security-critical: acceptance would allow certificate-chain forgery.
    """
    assert root_ztn(_f().header_x5c_injection(), "/test.txt", port=PORT) == "reject"
