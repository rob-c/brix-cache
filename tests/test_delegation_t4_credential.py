"""T4 (GridSite two-step) delegation must store a COMPLETE credential.

Regression for the proxy_req_assemble fix: brix_gsi_assemble_proxy used to
concatenate certs only, so a two-step-delegated x5h-<hash>.pem carried no
private key and could never authenticate a downstream TLS handshake — the
credential store's whole purpose.  The fix serializes the server-generated
request key (the private half of the CSR, which correctly never leaves this
process) into the assembled PEM after the cert chain.

Proof here is end-to-end against the minimal config in
tests/configs/nginx_t4_delegation_handshake.conf (one delegation server, one
mTLS verifier server):

  1. run the two-step flow, assert the stored PEM holds proxy + chain + KEY;
  2. complete a real TLS handshake with the stored PEM as the client
     credential and get the delegated proxy's DN echoed back;
  3. (error) a signed proxy whose key does not match the outstanding CSR is
     rejected 400 and nothing is stored;
  4. (security-negative) the certs-only form of the same credential — the
     pre-fix on-disk content — cannot even load as a client credential.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_delegation_t4_credential.py -v -p no:xdist
"""

import http.client
import re
import ssl
import subprocess

import pytest

from cmdscripts.delegation_twostep import (
    curl,
    delegation_id,
    ensure_pki,
    key_for_dn,
    mint_certs,
    sign_csr,
)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import CA_CERT, SERVER_CERT, SERVER_KEY

pytestmark = pytest.mark.uses_lifecycle_harness

CERT_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)
KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC )?PRIVATE KEY-----", re.S
)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    base = tmp_path_factory.mktemp("t4pki")
    ok, message = ensure_pki(base)
    if not ok:
        pytest.skip(message)
    ok, message, dns = mint_certs(base)
    if not ok:
        pytest.skip(message)
    certs = base / "certs"
    return {
        "a_cert": certs / "a_eec_cert.pem",
        "a_key": certs / "a_eec_key.pem",
        "a_dn": dns["A_DN"],
    }


@pytest.fixture(scope="module")
def front(tmp_path_factory, pki):
    base = tmp_path_factory.mktemp("t4front")
    creds = base / "creds"
    creds.mkdir()
    from settings import free_ports
    (verify_port,) = free_ports(1)
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name="lc-t4-delegation",
            template="nginx_t4_delegation_handshake.conf",
            protocol="https", readiness="tcp",
            extra_ports={"VERIFY_PORT": verify_port},
            template_values={"HOST_CERT": str(SERVER_CERT),
                             "HOST_KEY": str(SERVER_KEY),
                             "CA_CERT": str(CA_CERT),
                             "CRED_DIR": str(creds)}))
    except Exception:
        harness.close()
        raise
    yield {
        "base": base,
        "creds": creds,
        "deleg_url": (f"https://127.0.0.1:{ep.port}"
                      "/.well-known/brix-delegation"),
        "verify_port": verify_port,
    }
    harness.close()


def _twostep_getreq(front, pki, tag):
    """GET .../request authenticated as A -> (delegation id, CSR path)."""
    base = front["base"]
    hdrs = base / f"hdrs_{tag}.txt"
    csr = base / f"csr_{tag}.pem"
    code, _ = curl(front["deleg_url"] + "/request", pki["a_cert"], pki["a_key"],
                   output=csr, headers=hdrs)
    assert code == "200", f"getProxyReq rejected (code={code})"
    did = delegation_id(hdrs)
    assert did, "no X-Brix-Delegation-Id header"
    assert "BEGIN CERTIFICATE REQUEST" in csr.read_text(), "response is not a CSR"
    return did, csr


@pytest.fixture(scope="module")
def delegated(front, pki):
    """Complete the happy-path two-step delegation; return the stored PEM."""
    base = front["base"]
    did, csr = _twostep_getreq(front, pki, "ok")
    signed = base / "signed_ok.pem"
    assert sign_csr(csr, pki["a_cert"], pki["a_key"], signed), "CSR signing failed"
    body = base / "body_ok.pem"
    body.write_bytes(signed.read_bytes() + pki["a_cert"].read_bytes())
    code, _ = curl(f"{front['deleg_url']}/{did}", pki["a_cert"], pki["a_key"],
                   output=base / "resp_ok.txt", upload=body)
    assert code in ("200", "201"), f"putProxy rejected (code={code})"
    stored = front["creds"] / (key_for_dn(pki["a_dn"]) + ".pem")
    assert stored.is_file(), f"credential file not stored: {stored}"
    return stored


def _handshake(port, cert_file):
    """One TLS-client-authenticated GET / against the verifier server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(str(cert_file))
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def test_stored_credential_is_complete(delegated):
    """The stored PEM must be proxy + chain + PRIVATE KEY, key matching the proxy."""
    text = delegated.read_text()
    certs = CERT_BLOCK.findall(text)
    keys = KEY_BLOCK.findall(text)
    assert len(certs) >= 2, f"expected proxy+chain, found {len(certs)} cert(s)"
    assert len(keys) == 1, f"expected exactly one private key, found {len(keys)}"

    def pubkey(openssl_args, stdin):
        return subprocess.run(
            ["openssl"] + openssl_args,
            input=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True,
        ).stdout
    proxy_pub = pubkey(["x509", "-noout", "-pubkey"], certs[0])
    key_pub = pubkey(["pkey", "-pubout"], keys[0])
    assert proxy_pub and proxy_pub == key_pub, \
        "embedded private key does not match the delegated proxy certificate"


def test_stored_credential_completes_tls_handshake(front, pki, delegated):
    """The stored credential alone must authenticate a real mTLS handshake."""
    status, body = _handshake(front["verify_port"], delegated)
    assert status == 200, f"handshake-authenticated request failed: {status} {body!r}"
    # the delegated proxy's DN = the user's DN plus one serial CN level
    assert body.startswith("dn=" + pki["a_dn"] + "/CN="), \
        f"verifier saw wrong identity: {body!r}"


def test_mismatched_proxy_rejected_nothing_stored(front, pki, delegated):
    """A proxy whose key does not match the outstanding CSR is refused (400)."""
    base = front["base"]
    did, _csr = _twostep_getreq(front, pki, "bad")
    before = delegated.read_bytes()
    # upload A's own EEC as the "signed proxy": trusted cert, right DN, but its
    # public key cannot match the server-generated request key
    code, _ = curl(f"{front['deleg_url']}/{did}", pki["a_cert"], pki["a_key"],
                   output=base / "resp_bad.txt", upload=pki["a_cert"])
    assert code == "400", f"expected 400 for key-mismatched proxy, got {code}"
    assert delegated.read_bytes() == before, \
        "stored credential was altered by a rejected delegation"


def test_certs_only_credential_cannot_handshake(front, delegated, tmp_path):
    """Security-negative: the pre-fix on-disk form (certs, no key) is unusable."""
    certs_only = tmp_path / "certs_only.pem"
    certs_only.write_text("\n".join(CERT_BLOCK.findall(delegated.read_text())) + "\n")
    with pytest.raises(ssl.SSLError):
        _handshake(front["verify_port"], certs_only)
