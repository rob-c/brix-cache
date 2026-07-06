"""Self-test for the credential factory (needs the test CA + openssl + tokens; no root)."""
import base64
import json
import os

import pytest

from mu_authz_lib import creds, ports


@pytest.fixture(scope="module", autouse=True)
def _pki():
    if not os.path.exists(os.path.join(ports.MU.CA_DIR, "ca.pem")):
        from pki_helpers import blitz_test_pki
        blitz_test_pki()
    os.makedirs(os.path.join(ports.MU.PKI_DIR, "user"), exist_ok=True)
    os.makedirs(ports.MU.TOKENS_DIR, exist_ok=True)


def _decode_claims(token_path: str) -> dict:
    payload = open(token_path).read().strip().split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def test_user_cert_and_gsi_proxy():
    cert, key = creds.gen_user_cert("/DC=test/CN=selftest-alice", "selftest_alice")
    assert os.path.exists(cert) and os.path.exists(key)
    proxy = creds.gen_gsi_proxy(cert, key, "selftest_alice")
    body = open(proxy).read()
    assert body.count("BEGIN CERTIFICATE") >= 2 and "PRIVATE KEY" in body


def test_token_carries_sub_and_scope():
    tok = creds.mint_token("selftest-bob", "storage.read:/cms", "selftest_bob")
    claims = _decode_claims(tok)
    assert claims["sub"] == "selftest-bob"
    assert "storage.read:/cms" in claims["scope"]
    assert claims["iss"] == "https://test.example.com"
    assert claims["aud"] == "nginx-xrootd"


def test_voms_proxy_builds():
    cert, key = creds.gen_user_cert("/DC=test/CN=selftest-carol", "selftest_carol")
    proxy = creds.gen_voms_proxy(cert, key, "selftest_carol", "cms")
    assert os.path.exists(proxy)
    # vomsdir LSC was created for cms
    assert os.path.exists(os.path.join(ports.MU.VOMSDIR, "cms", "voms.test.local.lsc"))


def test_s3_key_deterministic_and_distinct():
    a1 = creds.s3_key_for("alice")
    a2 = creds.s3_key_for("alice")
    assert a1 == a2
    assert a1[0] != creds.s3_key_for("bob")[0]
    assert a1[0].startswith("AKIA")
