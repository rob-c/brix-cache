"""Token issuance, validation, and tamper resistance (021-030)."""

import pytest

from brixtest import decode_token, issue_token, token_auth, verify_token
from brixtest.errors import SpecError


def _token(**overrides):
    values = {
        "secret": "secret", "issuer": "https://issuer.test", "audience": "storage",
        "subject": "alice", "scopes": ("storage.read:/",), "now": 100,
    }
    values.update(overrides)
    return issue_token(**values)


def test_021_issued_token_has_hs256_header():
    header, _ = decode_token(_token())
    assert header == {"alg": "HS256", "typ": "JWT"}


def test_022_verified_token_returns_standard_claims():
    claims = verify_token(_token(), secret="secret", now=101)
    assert claims["sub"] == "alice" and claims["exp"] == 3700


def test_023_scopes_are_space_delimited():
    token = _token(scopes=("read:/", "write:/tmp"))
    assert verify_token(token, secret="secret", now=101)["scope"] == "read:/ write:/tmp"


def test_024_custom_claims_roundtrip():
    token = _token(claims={"wlcg.ver": "1.0", "groups": ["atlas"]})
    assert verify_token(token, secret="secret", now=101)["groups"] == ["atlas"]


def test_025_wrong_secret_rejects_signature():
    with pytest.raises(SpecError, match="signature"):
        verify_token(_token(), secret="wrong", now=101)


def test_026_expired_token_is_rejected():
    with pytest.raises(SpecError, match="expired"):
        verify_token(_token(lifetime=1), secret="secret", now=101)


def test_027_future_issue_time_is_rejected():
    with pytest.raises(SpecError, match="future"):
        verify_token(_token(now=200), secret="secret", now=100)


def test_028_issuer_and_audience_are_enforced():
    token = _token()
    with pytest.raises(SpecError, match="issuer"):
        verify_token(token, secret="secret", issuer="https://wrong.test", now=101)
    with pytest.raises(SpecError, match="audience"):
        verify_token(token, secret="secret", audience="wrong", now=101)


def test_029_malformed_compact_token_is_rejected():
    with pytest.raises(SpecError, match="three"):
        decode_token("only.two")


def test_030_standard_claims_cannot_be_overridden():
    with pytest.raises(SpecError, match="standard claims"):
        token_auth(claims={"exp": 0})
