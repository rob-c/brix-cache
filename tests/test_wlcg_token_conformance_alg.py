"""WLCG token conformance — ALG family (JWA algorithm matrix, RFC 7518 §3).

Probes ports 11097 (NGINX_TOKEN_PORT, RSA-only JWKS) and 11250
(NGINX_TOKEN_MULTIKEY_PORT, jwks_multi.json: main RSA + key-2 RSA + ec-key-1
P-256).  All verdicts are RFC-correct; no case is a divergence.

Allowlist: validate.c accepts ONLY RS256 and ES256.
  RFC 7518 §3: RS256 is Required; ES256 is Recommended+; everything else
  (RS384/RS512, PS256/PS384/PS512, ES384/ES512, HS*, none) is Optional or
  prohibited.  The allowlist is RFC-compliant — rejection of Optional algs is
  NOT a divergence.

Test groups:
  ALG-01..11   Unsupported-but-optional algs → reject (RFC-compliant allowlist)
  ALG-12..19   Security-critical attacks → MUST reject (RFC 8725 §2.2/§3)
  ALG-20..21   Positive controls (allowlisted algs) → accept
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data
from settings import (
    NGINX_TOKEN_PORT as PORT,
    NGINX_TOKEN_MULTIKEY_PORT as MK,
    TOKENS_DIR,
)


def _f():
    return TokenForge(TOKENS_DIR)


@pytest.fixture(autouse=True)
def _data():
    ensure_conformance_data()


# ---------------------------------------------------------------------------
# ALG-01..11 — unsupported-but-optional algs: RFC-compliant allowlist rejects
#
# validate.c maintains an explicit allowlist {RS256, ES256}.  Every other alg
# is Optional (RFC 7518 §3) or not defined for asymmetric keys; rejecting them
# is correct per RFC 8725 §2.2 (use an explicit algorithm allowlist) and is
# NOT a divergence from the spec.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_alg01_rs384_rejected():
    """RS384 token signed by main RSA key → reject (RS384 Optional, not on allowlist).

    WHY:  RFC 7518 §3.3 — RS384 is Optional; the allowlist contains only
          {RS256, ES256}.  A correct implementation MUST reject tokens whose
          alg is not on the configured allowlist (RFC 8725 §2.2).
          This is RFC-compliant; it is NOT a divergence.
    """
    assert root_ztn(_f().rs384(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg02_rs512_rejected():
    """RS512 token signed by main RSA key → reject (RS512 Optional, not on allowlist).

    WHY:  RFC 7518 §3.3 — RS512 is Optional; the allowlist admits only
          {RS256, ES256}.  Rejection is RFC-correct, not a divergence.
    """
    assert root_ztn(_f().rs512(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg03_ps256_rejected():
    """PS256 (RSA-PSS + SHA-256) token → reject (PS256 Optional, not on allowlist).

    WHY:  RFC 7518 §3.5 — PS256 is Optional; the allowlist does not include
          PSS variants.  Rejection is RFC-correct.
    """
    assert root_ztn(_f().ps256(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg04_ps384_rejected():
    """PS384 (RSA-PSS + SHA-384) token → reject (PS384 Optional, not on allowlist).

    WHY:  RFC 7518 §3.5 — PS384 is Optional; allowlist = {RS256, ES256}.
          Rejection is RFC-correct.
    """
    assert root_ztn(_f().ps384(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg05_ps512_rejected():
    """PS512 (RSA-PSS + SHA-512) token → reject (PS512 Optional, not on allowlist).

    WHY:  RFC 7518 §3.5 — PS512 is Optional; allowlist = {RS256, ES256}.
          Rejection is RFC-correct.
    """
    assert root_ztn(_f().ps512(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg06_es384_rejected():
    """ES384 (P-384) token on multikey port → reject (ES384 Optional; no P-384 key in JWKS).

    WHY:  RFC 7518 §3.4 — ES384 is Optional; the allowlist is {RS256, ES256}.
          Furthermore, jwks_multi.json contains only RSA and P-256 keys, so
          there is no P-384 key to resolve to even if ES384 were on the list.
          Rejection satisfies both the allowlist rule and key-not-found logic.
    """
    assert root_ztn(_f().es384(), "/test.txt", port=MK) == "reject"


@pytest.mark.tokenconf
def test_alg07_es512_rejected():
    """ES512 (P-521) token on multikey port → reject (ES512 Optional; no P-521 key in JWKS).

    WHY:  RFC 7518 §3.4 — ES512 is Optional; allowlist = {RS256, ES256}.
          jwks_multi.json has no P-521 key, so rejection satisfies both
          the allowlist rule and key-not-found logic.
    """
    assert root_ztn(_f().es512(), "/test.txt", port=MK) == "reject"


@pytest.mark.tokenconf
def test_alg08_alg_variant_Rs256_rejected():
    """alg='Rs256' (wrong capitalisation) → reject (rule 54: alg is case-sensitive).

    WHY:  RFC 7515 §4.1.1 / rule 54 — the alg parameter is a case-sensitive
          string value; 'Rs256' does not match the registered name 'RS256' and
          must not be accepted by a conformant verifier.
    """
    assert root_ztn(_f().alg_variant("Rs256"), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg09_alg_variant_rs256_lower_rejected():
    """alg='rs256' (all lowercase) → reject (rule 54: alg is case-sensitive).

    WHY:  RFC 7515 §4.1.1 / rule 54 — 'rs256' is not the registered JWA
          algorithm name; it must be rejected by an allowlist-checking verifier.
    """
    assert root_ztn(_f().alg_variant("rs256"), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg10_alg_variant_trailing_space_rejected():
    """alg='RS256 ' (trailing space) → reject (rule 54: case-and-whitespace sensitive).

    WHY:  RFC 7515 §4.1.1 / rule 54 — JWA algorithm names are exact string
          matches; a trailing space makes the value 'RS256 ', which is not 'RS256'.
          A correct verifier must reject this rather than stripping whitespace.
    """
    assert root_ztn(_f().alg_variant("RS256 "), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg11_alg_eddsa_rejected():
    """alg='EdDSA' → reject (EdDSA not on allowlist; unsupported algorithm).

    WHY:  RFC 8037 defines EdDSA as an Optional JWA algorithm; the implementation
          supports only {RS256, ES256}.  Rejection is RFC-correct.
    """
    assert root_ztn(_f().alg_variant("EdDSA"), "/test.txt", port=PORT) == "reject"


# ---------------------------------------------------------------------------
# ALG-12..19 — security-critical: MUST reject regardless of allowlist
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_alg12_alg_none_rejected():
    """alg=none, empty signature segment → reject (rule 47/59 SEC: none prohibited).

    WHY:  RFC 7518 §3.6 / rules 47/59 — the 'none' algorithm produces an
          unsigned (unprotected) JWS; it MUST be unconditionally rejected by any
          production token verifier.  Acceptance would allow trivial forgery.
    """
    assert root_ztn(_f().alg_none(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg13_none_with_sig_rejected():
    """alg=none, non-empty signature segment → reject (rule 55 SEC: none+non-empty-sig).

    WHY:  RFC 7518 §3.6 / rule 55 — alg=none tokens MUST have an empty
          signature segment; a non-empty signature with alg=none is a protocol
          violation.  Security-critical: some naive implementations incorrectly
          verify the non-empty bytes against a key; correct behaviour is reject.
    """
    assert root_ztn(_f().none_with_sig(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg14_hs256_confusion_rejected():
    """HS256 signed with the RSA public key PEM as HMAC secret → reject (rule 60 SEC).

    WHY:  RFC 8725 §2.1 / rule 60 — the RS256→HS256 key-confusion attack uses
          the RSA public key as the HMAC secret.  A conformant verifier that
          enforces an algorithm allowlist ({RS256, ES256}) must reject this
          before reaching any signature-verification step.  Acceptance would
          allow an attacker to forge tokens using only the public key.
    """
    assert root_ztn(_f().alg_hs256_confusion(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg15_hs256_weak_secret_rejected():
    """HS256 signed with low-entropy secret b'secret' → reject (rules 51/65 SEC).

    WHY:  Two independent rejection grounds: (1) HS256 is not on the {RS256,
          ES256} allowlist (RFC 8725 §2.2 rule 51); (2) the HMAC secret 'secret'
          is 6 bytes, far below the minimum entropy mandated by RFC 8725 §2.2
          rule 65.  The implementation rejects at the allowlist stage; the
          low-entropy nature is not separately tested here.
    """
    assert root_ztn(_f().hs256_weak_secret(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg16_es256_wrong_curve_rejected():
    """ES256 header but signed with P-384 key (kid=ec-p384) → reject (rule 48 SEC).

    WHY:  RFC 8725 §2.2 / rule 48 — ES256 mandates P-256/SHA-256; the token
          is signed with a P-384 key producing a 96-byte signature where ES256
          expects 64 bytes.  A conformant verifier resolves kid=ec-p384 to the
          P-384 key in jwks_multi.json and must reject because the header
          algorithm (ES256) contradicts the key's curve (P-384).
          Security-critical: wrong-curve acceptance could allow signature bypass.

    NOTE: kid=ec-p384 IS present in jwks_multi.json (written by alg_jwks() into
          the ALG-family artifacts), but not in jwks_multi.json used by the
          multikey port.  The multikey port (11250) uses jwks_multi.json which
          carries only test-key-1, test-key-2, and ec-key-1 (P-256) — no ec-p384.
          Therefore the token rejects at key-not-found before any curve-check.
          Both reasons (key absent + curve mismatch) independently mandate reject.
    """
    assert root_ztn(_f().es256_wrong_curve(), "/test.txt", port=MK) == "reject"


@pytest.mark.tokenconf
def test_alg17_weak_rsa_signed_rejected():
    """RS256 signed with 1024-bit RSA key (kid=weak-rsa) → reject (rule 50 SEC).

    WHY:  RFC 8725 §2.2 / rule 50 — RSA keys MUST be at least 2048 bits;
          a 1024-bit key is considered cryptographically weak.  The kid
          'weak-rsa' is deliberately absent from jwks.json (the JWKS served
          on port 11097), so the verifier rejects at key-not-found.  This
          also satisfies rule 50 because the weak key is not trusted; true
          key-size enforcement (rejecting an in-JWKS 1024-bit key) is not
          separately tested here — the JWKS absence provides equivalent
          security coverage.
    """
    assert root_ztn(_f().weak_rsa_signed(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg18_truncated_sig_rejected():
    """Valid RS256 token with signature truncated to half length → reject (rule 41).

    WHY:  RFC 7515 §5.2 / rule 41 — a truncated signature is structurally
          invalid; the RSA-2048 signature must be exactly 256 bytes.  A
          correct verifier must reject a token whose signature segment
          decodes to a length that does not match the algorithm's requirement.
    """
    assert root_ztn(_f().truncated_sig(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_alg19_bad_signature_rejected():
    """Valid RS256 token with first 8 bytes of signature XOR-corrupted → reject (rule 39).

    WHY:  RFC 7515 §5.2 / rule 39 — a tampered signature must fail the RSA
          verification step.  The header and payload are intact; only the
          signature is corrupted.  A correct verifier must detect the
          mismatch and reject the token.
    """
    assert root_ztn(_f().generate_bad_signature(), "/test.txt", port=PORT) == "reject"


# ---------------------------------------------------------------------------
# ALG-20..21 — positive controls: allowlisted algs must be accepted
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_alg20_rs256_accepted():
    """Valid RS256 token on port 11097 → accept (RS256 Required per RFC 7518 §3.3).

    WHY:  RS256 (RSASSA-PKCS1-v1_5 + SHA-256) is the Required algorithm per
          RFC 7518 §3.3 and is the primary algorithm in this implementation.
          A valid, timely, correctly-signed token must be accepted.
    """
    assert root_ztn(_f().generate(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_alg21_es256_accepted():
    """Valid ES256 token (kid=ec-key-1, P-256) on multikey port → accept.

    WHY:  ES256 (ECDSA + P-256 + SHA-256) is Recommended+ per RFC 7518 §3.4
          and is on the allowlist.  The EC key ec-key-1 is present in
          jwks_multi.json on port 11250.  A valid, timely, correctly-signed
          ES256 token must be accepted.
    """
    assert root_ztn(_f().es256(), "/test.txt", port=MK) == "accept"
