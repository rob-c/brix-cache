"""brix_ssl_client_capath — hashed CA directory for the TLS client-verify store.

Regression for the webdav postconfig change: `brix_ssl_client_capath <dir>`
adds an OpenSSL hashed-directory lookup (the /etc/grid-security/certificates
IGTF layout) to a server's client-verify trust store, so a fail-closed
`ssl_verify_client on` front leg can trust a hash dir that stock nginx's
file-only ssl_client_certificate cannot express.

Covers the mandated triplet:
  success           — client CA present only in the hashed dir (the file
                      directive points at an unrelated CA): handshake verifies
                      and the request reaches the location (204);
  error             — nonexistent dir / plain file: nginx -t fails with a
                      message naming the directive (fatal, not a warning —
                      the directive IS the trust perimeter);
  security-negative — hashed dir WITHOUT the client's CA: the handshake is
                      rejected, no response is served.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_ssl_client_capath.py -v -p no:xdist
"""

import pathlib
import subprocess

import pytest

from cmdscripts.delegation_twostep import curl, ensure_pki, mint_certs
from settings import CA_CERT, SERVER_CERT, SERVER_KEY
from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    base = tmp_path_factory.mktemp("capathpki")
    ok, message = ensure_pki(base)
    if not ok:
        pytest.skip(message)
    ok, message, _dns = mint_certs(base)
    if not ok:
        pytest.skip(message)
    certs = base / "certs"
    return {"a_cert": certs / "a_eec_cert.pem", "a_key": certs / "a_eec_key.pem"}


@pytest.fixture(scope="module")
def decoy_ca(tmp_path_factory):
    """A self-signed CA unrelated to the fleet PKI — fills the mandatory
    ssl_client_certificate slot without trusting the test clients."""
    base = tmp_path_factory.mktemp("capathdecoy")
    cert, key = base / "decoy_ca.pem", base / "decoy_ca.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-subj", "/O=brix-test/CN=capath decoy CA",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True)
    return cert


def _hashed_ca_dir(path: pathlib.Path, *ca_pems: pathlib.Path) -> pathlib.Path:
    """Build an OpenSSL hashed CA directory (<subject_hash>.N links) —
    the same layout the IGTF distribution installs."""
    path.mkdir(parents=True, exist_ok=True)
    for pem in ca_pems:
        res = subprocess.run(
            ["openssl", "x509", "-subject_hash", "-noout", "-in", str(pem)],
            check=True, capture_output=True, text=True)
        subject_hash = res.stdout.strip()
        (path / f"{subject_hash}.0").write_bytes(pem.read_bytes())
    return path


def _spec(name, capath, advert_ca):
    return NginxInstanceSpec(
        name=name,
        template="nginx_lc_ssl_capath.conf",
        protocol="webdav",
        readiness="tcp",
        template_values={
            "HOST_CERT": SERVER_CERT,
            "HOST_KEY": SERVER_KEY,
            "ADVERT_CA": str(advert_ca),
            "CAPATH": str(capath),
        },
    )


def _nginx_t(lifecycle, name, capath, advert_ca):
    """Render + nginx -t via the harness; return (exit code, combined output).
    The launcher raises on a failing nginx -t — expected here, so unwrap it."""
    reg = lifecycle.register(_spec(name, capath, advert_ca))
    lifecycle.launcher.render_nginx(reg)
    try:
        res = lifecycle.launcher.nginx_test(reg)
    except RegistryCommandFailure as failure:
        return failure.returncode, failure.stdout_tail + failure.stderr_tail
    return res.returncode, res.stdout + res.stderr


def test_capath_trusts_hashed_dir(lifecycle, pki, decoy_ca, tmp_path):
    """Success: client CA lives ONLY in the hashed dir -> handshake OK, 204."""
    capath = _hashed_ca_dir(tmp_path / "igtf", pathlib.Path(CA_CERT))
    ep = lifecycle.start(_spec("lc-capath-ok", capath, decoy_ca))
    code, _err = curl(f"https://127.0.0.1:{ep.port}/", pki["a_cert"],
                      pki["a_key"], output=tmp_path / "out.txt")
    assert code == "204", \
        f"client signed by a hash-dir CA must pass ssl_verify_client (got {code})"


def test_capath_missing_dir_is_fatal(lifecycle, decoy_ca, tmp_path):
    """Error: nonexistent dir and plain file both fail nginx -t loudly."""
    code, out = _nginx_t(lifecycle, "lc-capath-missing",
                         tmp_path / "no-such-dir", decoy_ca)
    assert code != 0, "a missing trust dir must be a fatal config error"
    assert "brix_ssl_client_capath" in out and "not accessible" in out, out

    code, out = _nginx_t(lifecycle, "lc-capath-file", decoy_ca, decoy_ca)
    assert code != 0, "a plain file must be rejected (hash dir required)"
    assert "is not a directory" in out, out


def test_capath_without_client_ca_rejects(lifecycle, pki, decoy_ca, tmp_path):
    """Security-negative: hashed dir lacking the client's CA -> no service."""
    capath = _hashed_ca_dir(tmp_path / "decoy-only", decoy_ca)
    ep = lifecycle.start(_spec("lc-capath-deny", capath, decoy_ca))
    code, _err = curl(f"https://127.0.0.1:{ep.port}/", pki["a_cert"],
                      pki["a_key"], output=tmp_path / "out.txt")
    assert code != "204", \
        "a client whose CA is absent from the hash dir must be rejected"
