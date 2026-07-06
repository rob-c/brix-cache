"""test_wlcg_token_conformance_skew — configurable brix_token_clock_skew wire tests.

WHAT: Three wire cases that prove brix_token_clock_skew=0 enforces exact expiry
      while the default 30s port tolerates a token expired 20s ago.
WHY:  Regression guard and TDD evidence for the configurable clock-skew feature
      (fixes the hardcoded BRIX_TOKEN_CLOCK_SKEW_SECS constant).
HOW:  Mints tokens with exp in the past via tokenforge.temporal(), probes both
      NGINX_TOKEN_PORT (default 30s skew) and NGINX_TOKEN_STRICT_PORT (skew=0)
      using raw root:// framing from tokenconf.root_ztn, asserts the divergent
      behaviour.

Cases:
  CLM-SKEW-01  expired 20s ago — default port ACCEPT (within 30s grace),
               strict port REJECT (no grace)
  CLM-SKEW-02  expired 5s ago  — strict port REJECT (skew=0, 5s past exp)
  CLM-SKEW-03  valid token     — strict port ACCEPT
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from tokenconf import NGINX_TOKEN_STRICT_PORT, root_ztn
from settings import NGINX_TOKEN_PORT, TOKENS_DIR


def _forge():
    """Return a TokenForge pointed at the test TOKENS_DIR."""
    from tokenforge import TokenForge
    return TokenForge(TOKENS_DIR)


def test_clm_skew_01_default_port_accepts_20s_expired():
    """CLM-SKEW-01: token expired 20s ago is accepted on the default port (30s skew).

    WHAT: Proves the default brix_token_clock_skew=30 allows tokens whose exp is
          at most 30s in the past.
    WHY:  Validates the backwards-compatible default behaviour is preserved after
          the skew parameter was threaded through to validate.c.
    HOW:  Mints temporal(-20), probes NGINX_TOKEN_PORT; expects "accept".
    """
    token = _forge().temporal(-20)
    result = root_ztn(token, port=NGINX_TOKEN_PORT)
    assert result == "accept", (
        f"CLM-SKEW-01: default port (30s skew) should accept a 20s-expired token, "
        f"got {result!r}"
    )


def test_clm_skew_01_strict_port_rejects_20s_expired():
    """CLM-SKEW-01: token expired 20s ago is rejected on the strict port (skew=0).

    WHAT: Proves brix_token_clock_skew=0 enforces exact expiry — a token 20s past
          its exp is rejected with no grace window.
    WHY:  Core correctness case: the strict port must reject what the default port
          accepts, proving the per-server directive is being honoured.
    HOW:  Mints temporal(-20), probes NGINX_TOKEN_STRICT_PORT; expects "reject".
    """
    token = _forge().temporal(-20)
    result = root_ztn(token, port=NGINX_TOKEN_STRICT_PORT)
    assert result == "reject", (
        f"CLM-SKEW-01: strict port (skew=0) should reject a 20s-expired token, "
        f"got {result!r}"
    )


def test_clm_skew_02_strict_port_rejects_5s_expired():
    """CLM-SKEW-02: token expired 5s ago is rejected on the strict port (skew=0).

    WHAT: Proves brix_token_clock_skew=0 leaves no tolerance even for very recent
          expiry — 5s past exp is sufficient to reject.
    WHY:  Edge-case coverage: even a tiny clock difference must be rejected at
          skew=0, confirming the bound is exp+0 not exp+epsilon.
    HOW:  Mints temporal(-5), probes NGINX_TOKEN_STRICT_PORT; expects "reject".
    """
    token = _forge().temporal(-5)
    result = root_ztn(token, port=NGINX_TOKEN_STRICT_PORT)
    assert result == "reject", (
        f"CLM-SKEW-02: strict port (skew=0) should reject a 5s-expired token, "
        f"got {result!r}"
    )


def test_clm_skew_03_strict_port_accepts_valid_token():
    """CLM-SKEW-03: a valid (future-exp) token is accepted on the strict port.

    WHAT: Proves the strict port does not over-reject — a token with exp=+3600s
          passes cleanly through skew=0 validation.
    WHY:  Sanity check: skew=0 is not a blanket reject; it is strict-expiry
          enforcement only.
    HOW:  Mints temporal(3600), probes NGINX_TOKEN_STRICT_PORT; expects "accept".
    """
    token = _forge().temporal(3600)
    result = root_ztn(token, port=NGINX_TOKEN_STRICT_PORT)
    assert result == "accept", (
        f"CLM-SKEW-03: strict port (skew=0) should accept a valid token (+3600s), "
        f"got {result!r}"
    )
