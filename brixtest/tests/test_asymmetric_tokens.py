"""Asymmetric JWT signing, verification, key-policy, and materialization tests."""

import json

import pytest

from brixtest import decode_token, issue_token, token_auth, verify_token
from brixtest.auth.store import AuthStore
from brixtest.auth.token_keys import generate_keypair
from brixtest.errors import SpecError


@pytest.mark.parametrize("algorithm,key_bits", [("ES256", 2048), ("RS256", 2048)])
def test_asymmetric_tokens_roundtrip_with_pinned_algorithm(algorithm, key_bits):
    pytest.importorskip("cryptography")
    private, public = generate_keypair(algorithm, key_bits)
    token = issue_token(
        issuer="https://issuer.test", audience="storage", subject="alice",
        algorithm=algorithm, private_key=private, key_id="active", now=100,
    )
    header, _payload = decode_token(token)
    assert header == {"alg": algorithm, "kid": "active", "typ": "JWT"}
    claims = verify_token(token, public_key=public, algorithms=(algorithm,), now=101)
    assert claims["sub"] == "alice"


def test_asymmetric_token_requires_an_explicitly_allowed_algorithm():
    pytest.importorskip("cryptography")
    private, public = generate_keypair("ES256", 2048)
    token = issue_token(
        issuer="https://issuer.test", audience="storage", subject="alice",
        algorithm="ES256", private_key=private, now=100,
    )
    with pytest.raises(SpecError, match="unaccepted"):
        verify_token(token, public_key=public, now=101)


def test_asymmetric_recipe_rejects_ambiguous_shared_secret():
    with pytest.raises(SpecError, match="only valid for HS256"):
        token_auth(algorithm="RS256", secret="must-not-be-ignored")


@pytest.mark.parametrize("algorithm", ["HS256", "ES256"])
def test_non_rsa_recipe_rejects_ignored_key_size(algorithm):
    with pytest.raises(SpecError, match="configurable for RS256 only"):
        token_auth(algorithm=algorithm, key_bits=4096)


@pytest.mark.parametrize("algorithm", ["ES256", "RS256"])
def test_asymmetric_authority_materializes_public_only_jwks(tmp_path, algorithm):
    pytest.importorskip("cryptography")
    item = AuthStore(tmp_path / "auth").materialize(
        token_auth(algorithm=algorithm, key_id="rotation-1"),
    )
    jwks = json.loads(item.path("jwks").read_text())
    assert jwks["keys"][0]["alg"] == algorithm
    assert jwks["keys"][0]["kid"] == "rotation-1"
    assert "d" not in jwks["keys"][0]
    assert item.path("private_key").stat().st_mode & 0o077 == 0
    assert "BRIXTEST_TOKEN_PUBLIC_KEY_FILE" in item.server_env
    assert "private_key" not in item.client_env
    assert json.loads(item.path("discovery").read_text())["jwks_uri"].endswith(
        "/jwks.json",
    )
