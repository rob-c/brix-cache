"""WLCG token conformance — NDT family (RFC 7519 §2 NumericDate edge cases).

Probes port 11097 (NGINX_TOKEN_PORT) which enforces token auth against the
main RSA JWKS (jwks.json, kid test-key-1).

NumericDate ground truth (src/auth/token/validate.c):
  - Timestamps are extracted via json_get_int64() which parses JSON integer
    types only; it refuses json_real (float) → float exp treated as 0 → expired.
  - Large integers (> INT64_MAX) wrap or truncate on json_integer_value()
    → huge exp value lands in the past → rejected as expired.
  - Negative integers: parsed correctly by json_get_int64; nbf=-1 is in the
    past → token immediately valid.
  - null: json_get_int64 returns 0 for non-integer types → exp=0 → expired.

Test cases:

  NDT-01  numericdate_fractional → RFC MUST accept (rule 2).  DIVERGENCE: reject.
  NDT-02  numericdate_negative   → accept (nbf=-1 is in past; rule 3).
  NDT-03  numericdate_huge       → RFC MUST accept (rule 3).  DIVERGENCE: reject (int64 overflow).
  NDT-04  exp_null               → reject (rule 1; null is not a NumericDate).
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
@pytest.mark.xfail(strict=True,
                   reason="DIVERGENCE rule 2: RFC 7519 §2 states fractional seconds "
                          "are permitted in NumericDate; json_get_int64() refuses "
                          "json_real so float exp is treated as 0 (expired) → "
                          "actual=reject; RFC-correct=accept")
def test_ndt01_numericdate_fractional_accepted():
    """exp as a fractional NumericDate (now+3600.5) — MUST accept (rule 2).

    WHY:  RFC 7519 §2 / rule 2 — NumericDate is "a JSON numeric value
          representing the number of seconds"; fractional seconds are explicitly
          permitted and MUST be accepted.  The implementation uses
          json_get_int64() which refuses JSON float (json_real) values → exp
          falls back to 0 → token treated as expired.
    DIVERGENCE: actual=reject; RFC-correct=accept.
    """
    assert root_ztn(_f().numericdate_fractional(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_ndt02_numericdate_negative_accepted():
    """nbf as a negative NumericDate (-1) — accept (rule 3).

    WHY:  RFC 7519 §2 / rule 3 — NumericDate may be negative (representing a
          time before the Unix epoch); nbf=-1 is 1970-01-01T00:00:00Z minus one
          second, which is in the past, so the token is immediately valid.
          json_get_int64() correctly parses negative JSON integers.
    """
    assert root_ztn(_f().numericdate_negative(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.xfail(strict=True,
                   reason="DIVERGENCE rule 3: RFC 7519 §2 requires huge NumericDate "
                          "values to be accepted (far-future exp); json_integer_value() "
                          "overflows int64 wrapping 99999999999999999999 to a negative "
                          "or past value → actual=reject; RFC-correct=accept")
def test_ndt03_numericdate_huge_accepted():
    """exp as a huge integer (99999999999999999999) — MUST accept (rule 3).

    WHY:  RFC 7519 §2 / rule 3 — a very large NumericDate represents a far-future
          expiry and MUST be accepted.  The Jansson json_integer_value() call
          wraps 99999999999999999999 at the int64 boundary, landing the value
          in the past → treated as expired.
    DIVERGENCE: actual=reject; RFC-correct=accept.
    """
    assert root_ztn(_f().numericdate_huge(), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_ndt04_exp_null_rejected():
    """exp is JSON null — reject (rule 1).

    WHY:  RFC 7519 §4.1.4 / rule 1 — exp MUST be a NumericDate (integer or
          float); null is not a number.  json_get_int64() returns 0 for a JSON
          null value → exp treated as epoch 0 (long past) → rejected as expired.
    """
    assert root_ztn(_f().exp_null(), "/test.txt", port=PORT) == "reject"
