"""WLCG token conformance — multi-key JWKS / SIG-10..14 cases.

Probes port 11250 (nginx_token_multikey.conf) which is backed by
jwks_multi.json (test-key-1 main RSA, test-key-2 second RSA, ec-key-1 EC).
Tests cover:
  SIG-10  kid=test-key-2, signed by test-key-2          → accept
  SIG-11  kid=does-not-exist, signed by main key         → reject
  SIG-12  no kid, signed by test-key-2                   → accept  (§3.3 rotation grace)
  SIG-13  ES256 with kid=ec-key-1                        → accept
  SIG-14  ES256 with corrupted signature                 → reject
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data
from settings import NGINX_TOKEN_MULTIKEY_PORT as MK, TOKENS_DIR


def _f():
    return TokenForge(TOKENS_DIR)


@pytest.fixture(autouse=True)
def _data():
    ensure_conformance_data()


@pytest.mark.tokenconf
def test_sig10_kid_hit_second_key():
    """RS256 token with kid=test-key-2, signed by test-key-2 — exact kid match."""
    assert root_ztn(_f().signed_by_key2(), "/test.txt", port=MK) == "accept"


@pytest.mark.tokenconf
def test_sig11_wrong_kid_multikey_rejected():
    """RS256 token with kid=does-not-exist — no JWKS key matches, must reject."""
    assert root_ztn(_f().wrong_kid_multikey(), "/test.txt", port=MK) == "reject"


@pytest.mark.tokenconf
def test_sig12_no_kid_signed_by_second_key_accepted():
    """§3.3 rotation grace: kid-less token signed by test-key-2.

    When no kid is present the verifier must try all JWKS keys in order; the
    token is valid and must be accepted even though test-key-2 is not keys[0].
    """
    assert root_ztn(_f().no_kid_key2(), "/test.txt", port=MK) == "accept"


@pytest.mark.tokenconf
def test_sig13_es256_accepted():
    """ES256 token with kid=ec-key-1, signed by the EC key — must accept."""
    assert root_ztn(_f().es256(), "/test.txt", port=MK) == "accept"


@pytest.mark.tokenconf
def test_sig14_es256_bad_sig_rejected():
    """ES256 token with one bit flipped in signature — must reject."""
    assert root_ztn(_f().es256_bad_sig(), "/test.txt", port=MK) == "reject"
