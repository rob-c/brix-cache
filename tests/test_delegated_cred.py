"""$brix_delegated_cred — the verified client's delegated-credential path.

The variable maps the TLS-verified client chain's END-ENTITY DN through the
same ucred key derivation the delegation endpoint uses when it stores a
credential ("x5h-" + SHA-256 prefix), and resolves
<brix_storage_credential_dir>/<key>.pem with an expiry check.  It replaces
the hand-maintained `map $ssl_client_s_dn_legacy $cred` block in
credential-forwarding gateways: no per-user entries, no reload on new users.
Empty means "no usable credential" — FAIL CLOSED.

Covers the mandated triplet:
  success           — user A authenticates; A's stored .pem path is echoed
                      back verbatim;
  error             — a malformed .pem and a bearer .token (wrong kind for
                      proxy_ssl_certificate) both yield the empty value;
  security-negative — user B authenticates with NO stored credential: empty,
                      and in particular NOT user A's path.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_delegated_cred.py -v -p no:xdist
"""

import pytest

from cmdscripts.delegation_twostep import curl, ensure_pki, key_for_dn, mint_certs
from settings import CA_CERT, SERVER_CERT, SERVER_KEY
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    base = tmp_path_factory.mktemp("delegcredpki")
    ok, message = ensure_pki(base)
    if not ok:
        pytest.skip(message)
    ok, message, dns = mint_certs(base)
    if not ok:
        pytest.skip(message)
    certs = base / "certs"
    return {
        "a_cert": certs / "a_eec_cert.pem", "a_key": certs / "a_eec_key.pem",
        "b_cert": certs / "b_eec_cert.pem", "b_key": certs / "b_eec_key.pem",
        "a_dn": dns["A_DN"], "b_dn": dns["B_DN"],
    }


def _spec(name, cred_dir):
    return NginxInstanceSpec(
        name=name,
        template="nginx_lc_delegated_cred.conf",
        protocol="webdav",
        readiness="tcp",
        template_values={
            "HOST_CERT": SERVER_CERT,
            "HOST_KEY": SERVER_KEY,
            "CA_CERT": CA_CERT,
            "CRED_DIR": str(cred_dir),
        },
    )


def _fetch(ep, cert, key, out):
    code, _err = curl(f"https://127.0.0.1:{ep.port}/", cert, key, output=out)
    body = out.read_text(encoding="utf-8") if out.exists() else ""
    return code, body


def test_delegated_cred_resolves_stored_pem(lifecycle, pki, tmp_path):
    """Success: A's credential stored under the delegation-endpoint key is
    echoed back as the variable's value — path verbatim, no map block."""
    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    stored = cred_dir / f"{key_for_dn(pki['a_dn'])}.pem"
    stored.write_bytes(pki["a_cert"].read_bytes())

    ep = lifecycle.start(_spec("lc-delegcred-ok", cred_dir))
    code, body = _fetch(ep, pki["a_cert"], pki["a_key"], tmp_path / "a.txt")
    assert code == "200", f"verified client must reach the location (got {code})"
    assert body == str(stored), \
        f"variable must name A's stored credential (got {body!r})"


def test_delegated_cred_rejects_unusable_files(lifecycle, pki, tmp_path):
    """Error: a malformed .pem is treated as missing, and a bearer .token is
    the wrong credential kind for proxy_ssl_certificate — both yield ""."""
    key = key_for_dn(pki["a_dn"])

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / f"{key}.pem").write_text("this is not a certificate\n")
    ep = lifecycle.start(_spec("lc-delegcred-badpem", malformed))
    code, body = _fetch(ep, pki["a_cert"], pki["a_key"], tmp_path / "m.txt")
    assert code == "200" and body == "", \
        f"a malformed .pem must resolve to the empty value (got {body!r})"

    token_only = tmp_path / "token-only"
    token_only.mkdir()
    (token_only / f"{key}.token").write_text("bearer-opaque-value\n")
    ep = lifecycle.start(_spec("lc-delegcred-token", token_only))
    code, body = _fetch(ep, pki["a_cert"], pki["a_key"], tmp_path / "t.txt")
    assert code == "200" and body == "", \
        f"a bearer .token must never feed proxy_ssl_certificate (got {body!r})"


def test_delegated_cred_is_per_identity(lifecycle, pki, tmp_path):
    """Security-negative: B authenticates fine but has delegated nothing —
    the variable is empty, and never leaks A's credential path."""
    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    stored = cred_dir / f"{key_for_dn(pki['a_dn'])}.pem"
    stored.write_bytes(pki["a_cert"].read_bytes())

    ep = lifecycle.start(_spec("lc-delegcred-deny", cred_dir))
    code, body = _fetch(ep, pki["b_cert"], pki["b_key"], tmp_path / "b.txt")
    assert code == "200", f"B is a verified client (got {code})"
    assert body == "", \
        f"an identity with no stored credential must get \"\" (got {body!r})"
    assert body != str(stored), "B must never receive A's credential"
