"""Minimal examples of BriXTest-managed credentials and authentication stacks."""

import json
import os
import subprocess
import urllib.request

from brixtest import (
    case,
    checksum_credential,
    host_mapping,
    kerberos_auth,
    noise,
    signed_credential,
    tls_auth,
    token_auth,
    verify_token,
    voms_auth,
)

PAYLOAD = noise("protected_input", size=1024, seed=7)
CHECKSUM = checksum_credential(
    "payload_checksum", PAYLOAD, env="PAYLOAD_CHECKSUM_FILE", targets=("test", "client"),
)
SIGNED = signed_credential(
    "request_proof", "read:/data", secret="example-only-secret",
    env="REQUEST_PROOF", targets=("test",),
)


@case(artifacts=[PAYLOAD], credentials=[CHECKSUM, SIGNED], keep="never")
def test_custom_credentials(run):
    assert str(run.credential(CHECKSUM).path) == os.environ["PAYLOAD_CHECKSUM_FILE"]
    assert os.environ["REQUEST_PROOF"] == run.credential(SIGNED).content


TOKENS = token_auth(secret="example-token-secret", audience="storage.example")


@case(auth=[TOKENS], keep="never")
def test_managed_token_stack(run):
    stack = run.auth(TOKENS)
    claims = verify_token(
        stack.path("token").read_text(), secret=stack.path("secret").read_text(),
        issuer=TOKENS.issuer, audience=TOKENS.audience,
    )
    assert claims["sub"] == TOKENS.subject


OIDC = token_auth(algorithm="ES256", managed=True, rotate_on_restart=True)


@case(auth=[OIDC], keep="never")
def test_live_oidc_jwks_rotation(run):
    authority = run.auth(OIDC)
    with urllib.request.urlopen(authority.metadata["jwks_url"]) as response:
        first_key = json.load(response)["keys"][0]["kid"]
    authority.stop()
    authority.start()
    with urllib.request.urlopen(authority.metadata["jwks_url"]) as response:
        second_key = json.load(response)["keys"][0]["kid"]
    assert first_key != second_key


TLS = tls_auth(hostname="origin.auth.test", aliases=("alias.auth.test",))


@case(auth=[TLS], keep="never")
def test_disposable_tls_ca_crl_reload_and_host_certificate(run):
    stack = run.auth(TLS)
    verify = [
        "openssl", "verify", "-CAfile", str(stack.path("ca_cert")),
        "-verify_hostname", TLS.hostname, str(stack.path("host_cert")),
    ]
    result = subprocess.run(verify, capture_output=True, text=True, check=True)
    assert result.stdout.strip().endswith(": OK")
    stack.revoke("host_cert")
    revoked = subprocess.run(
        [*verify[:4], "-CRLfile", str(stack.path("crl")), "-crl_check", *verify[4:]],
        capture_output=True, text=True, check=False,
    )
    assert revoked.returncode != 0 and "revoked" in revoked.stderr.lower()


VOMS = voms_auth(vo="brixtest", hostname="voms.auth.test")


@case(auth=[VOMS], keep="never")
def test_managed_voms_gsi_proxy(run):
    result = subprocess.run([
        "voms-proxy-info", "--file", str(run.auth(VOMS).path("proxy")), "--fqan",
    ], capture_output=True, text=True, check=True)
    assert result.stdout.strip().startswith("/brixtest/")


KERBEROS = kerberos_auth(
    realm="BRIXTEST.AUTH.TEST", domain="auth.test", hostname="kdc.auth.test",
    service="host/origin.auth.test",
)


@case(auth=[KERBEROS], timeout=30, keep="never")
def test_managed_kerberos_realm_and_ticket(run):
    stack = run.auth(KERBEROS)
    result = subprocess.run(
        ["klist", "-c", str(stack.path("cache"))],
        capture_output=True, text=True, check=True,
    )
    assert "test-user@BRIXTEST.AUTH.TEST" in result.stdout


AUTH_HOST = host_mapping(
    "origin", "origin.auth.test", address="127.0.0.77",
    aliases=("alias.auth.test",),
)


@case(hosts=[AUTH_HOST], keep="never")
def test_backend_neutral_forward_and_reverse_names(run):
    assert run.resolve("alias.auth.test") == "127.0.0.77"
    assert run.reverse("127.0.0.77") == "origin.auth.test"
