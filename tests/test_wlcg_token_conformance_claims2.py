"""WLCG token conformance — CLM2 family (claim types and interactions).

Probes port 11097 (NGINX_TOKEN_PORT) which enforces token auth against the
main RSA JWKS (jwks.json, kid test-key-1).  All forged tokens are signed by
the main key and use the configured issuer / audience so the only divergence
is in the claim-type or claim-interaction property under test.

Ground truth (src/auth/token/validate.c):
  - iss string comparison against issuer_registry: non-string 12345 won't match → reject
  - sub is read for logging/mapping only; sub type is not enforced → array accepted
  - exp: json_get_int64 parses the timestamp; exp in past (> skew) → reject
  - nbf: json_get_int64 on nbf; nbf in future → reject immediately (no skew on nbf)
  - Clock skew tolerance: BRIX_TOKEN_CLOCK_SKEW_SECS = 30s on exp only

Test cases:

  CLM2-01  dup_claim_names   → reject (rule 21; aud='evil' last → aud mismatch).
  CLM2-02  iss_non_string    → reject (rule 4; numeric iss won't match issuer_registry).
  CLM2-03  sub_non_string    → RFC MUST reject (rules 4/6).  DIVERGENCE: accept.
  CLM2-04  iat_after_exp     → accept (exp=now-10 within 30s clock-skew window; not expired).
  CLM2-05  nbf_after_exp     → reject (nbf=now+3600 far in future → not-yet-valid).
  CLM2-06  unknown_claims_ok → accept (rule 16; unknown claims MUST be ignored).
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
def test_clm2_01_dup_claim_names_rejected():
    """Duplicate 'aud' keys in payload JSON — reject (rule 21).

    WHY:  RFC 7159 §4 / rule 21 — duplicate member names SHOULD be rejected.
          In practice the last aud='evil' causes an audience mismatch against the
          configured 'nginx-xrootd' audience → reject regardless of parse strategy.
    """
    assert root_ztn(_f().dup_claim_names(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_clm2_02_iss_non_string_rejected():
    """iss is a numeric value 12345 — reject (rule 4).

    WHY:  RFC 7519 §4.1.1 / rule 4 — iss MUST be a StringOrURI; a numeric value
          violates the type constraint.  The validator performs a string match of
          iss against the issuer registry → numeric 12345 won't match → reject.
    """
    assert root_ztn(_f().iss_non_string(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.xfail(strict=True,
                   reason="DIVERGENCE rules 4/6: RFC 7519 §4.1.2 requires sub to be "
                          "a StringOrURI; array sub should be rejected; validator does "
                          "not enforce sub type → actual=accept")
def test_clm2_03_sub_non_string_rejected():
    """sub is an array ["a","b"] — MUST reject (rules 4/6).

    WHY:  RFC 7519 §4.1.2 / rules 4/6 — the sub claim MUST be a StringOrURI;
          an array value violates the type constraint.  The implementation reads
          sub for logging/mapping only and does not enforce its type → accepts.
    DIVERGENCE: actual=accept; RFC-correct=reject.
    """
    assert root_ztn(_f().sub_non_string(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_clm2_04_iat_after_exp_accepted():
    """iat > exp (iat=now+10, exp=now-10) — accept due to 30s clock-skew window.

    WHY:  The forge sets exp=now-10, iat=now+10, nbf=now-20.  The server applies
          a 30s clock-skew tolerance: rejection requires now > exp + 30s.  With
          exp=now-10, exp+30=now+20 > now, so the token is within the skew
          window and accepted.  The iat > exp logical inconsistency is not
          independently checked.  RFC 7519 does not mandate rejection based on
          iat > exp; the exp check controls, and the implementation's skew
          policy governs that.
    """
    assert root_ztn(_f().iat_after_exp(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_clm2_05_nbf_after_exp_rejected():
    """nbf > exp (nbf=now+3600) — reject (not-yet-valid, rule 155).

    WHY:  RFC 7519 §4.1.5 / rule 155 — nbf in the future means the token is
          not yet valid and MUST be rejected.  The implementation applies no
          skew tolerance to nbf → the far-future nbf causes immediate rejection.
    """
    assert root_ztn(_f().nbf_after_exp(), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_clm2_06_unknown_claims_ok_accepted():
    """Valid token with extra unknown claims — accept (rule 16).

    WHY:  RFC 7519 §4.3 / rule 16 — unrecognised claim names MUST be ignored;
          their presence MUST NOT cause rejection.
    """
    assert root_ztn(_f().unknown_claims_ok(), "/test.txt", port=PORT) == "accept"
