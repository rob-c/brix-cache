"""brix_client_certificate_folder — parse-time auto-pick of the client-CA file.

`brix_client_certificate_folder <dir>` reads the server's own ssl_certificate
leaf, hashes its ISSUER, and resolves the matching <hash>.N file out of an
OpenSSL hashed CA directory (the /etc/grid-security/certificates IGTF layout),
assigning it as the stock ssl_client_certificate value.  A grid host that
ships only the hashed dir gets `ssl_verify_client on` with zero hand-picked
hash files in the config.

Covers the mandated triplet:
  success           — no ssl_client_certificate line anywhere; the folder
                      holds the fleet CA (plus a decoy): the handshake
                      verifies and the request reaches the location (204);
  error             — folder lacking the hostcert's issuer, nonexistent
                      folder, and the directive placed BEFORE ssl_certificate
                      all fail nginx -t with messages naming the cause;
  security-negative — a client whose CA is NOT the auto-picked file is
                      rejected at the handshake.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_client_certificate_folder.py -v -p no:xdist
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
    base = tmp_path_factory.mktemp("certfolderpki")
    ok, message = ensure_pki(base)
    if not ok:
        pytest.skip(message)
    ok, message, _dns = mint_certs(base)
    if not ok:
        pytest.skip(message)
    certs = base / "certs"
    return {"a_cert": certs / "a_eec_cert.pem", "a_key": certs / "a_eec_key.pem"}


@pytest.fixture(scope="module")
def outsider(tmp_path_factory):
    """A self-signed client identity unrelated to the fleet PKI — its issuer
    is absent from the auto-picked trust file, so it must be rejected."""
    base = tmp_path_factory.mktemp("certfolderoutsider")
    cert, key = base / "outsider.pem", base / "outsider.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-subj", "/O=brix-test/CN=cert-folder outsider",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True)
    return {"cert": cert, "key": key}


def _hashed_ca_dir(path: pathlib.Path, *ca_pems: pathlib.Path) -> pathlib.Path:
    """Build an OpenSSL hashed CA directory (<subject_hash>.N files) — the
    same layout the IGTF distribution installs."""
    path.mkdir(parents=True, exist_ok=True)
    for pem in ca_pems:
        res = subprocess.run(
            ["openssl", "x509", "-subject_hash", "-noout", "-in", str(pem)],
            check=True, capture_output=True, text=True)
        subject_hash = res.stdout.strip()
        (path / f"{subject_hash}.0").write_bytes(pem.read_bytes())
    return path


def _spec(name, folder, template="nginx_lc_cert_folder.conf"):
    return NginxInstanceSpec(
        name=name,
        template=template,
        protocol="webdav",
        readiness="tcp",
        template_values={
            "HOST_CERT": SERVER_CERT,
            "HOST_KEY": SERVER_KEY,
            "CERT_FOLDER": str(folder),
        },
    )


def _nginx_t(lifecycle, spec):
    """Render + nginx -t via the harness; return (exit code, combined output).
    The launcher raises on a failing nginx -t — expected here, so unwrap it."""
    reg = lifecycle.register(spec)
    lifecycle.launcher.render_nginx(reg)
    try:
        res = lifecycle.launcher.nginx_test(reg)
    except RegistryCommandFailure as failure:
        return failure.returncode, failure.stdout_tail + failure.stderr_tail
    return res.returncode, res.stdout + res.stderr


def test_cert_folder_auto_picks_issuer(lifecycle, pki, outsider, tmp_path):
    """Success: NO ssl_client_certificate anywhere — the directive resolves
    the fleet CA out of the hashed dir (ignoring a decoy) and clients signed
    by it pass ssl_verify_client."""
    folder = _hashed_ca_dir(tmp_path / "igtf",
                            pathlib.Path(CA_CERT), outsider["cert"])
    ep = lifecycle.start(_spec("lc-certfolder-ok", folder))
    code, _err = curl(f"https://127.0.0.1:{ep.port}/", pki["a_cert"],
                      pki["a_key"], output=tmp_path / "out.txt")
    assert code == "204", \
        f"auto-picked issuer file must satisfy ssl_verify_client (got {code})"


def test_cert_folder_config_errors_are_fatal(lifecycle, outsider, tmp_path):
    """Error: issuer missing from the folder, nonexistent folder, and the
    directive placed before ssl_certificate each fail nginx -t loudly."""
    decoy_only = _hashed_ca_dir(tmp_path / "decoy-only", outsider["cert"])
    code, out = _nginx_t(lifecycle,
                         _spec("lc-certfolder-nomatch", decoy_only))
    assert code != 0, "a folder without the hostcert issuer must be fatal"
    assert "brix_client_certificate_folder" in out and "matches the issuer" in out, out

    code, out = _nginx_t(lifecycle,
                         _spec("lc-certfolder-missing", tmp_path / "no-such"))
    assert code != 0, "a missing folder must be a fatal config error"
    assert "not an accessible directory" in out, out

    good = _hashed_ca_dir(tmp_path / "good", pathlib.Path(CA_CERT))
    code, out = _nginx_t(lifecycle,
                         _spec("lc-certfolder-misorder", good,
                               template="nginx_lc_cert_folder_misorder.conf"))
    assert code != 0, "directive before ssl_certificate must be fatal"
    assert "AFTER ssl_certificate" in out, out


def test_cert_folder_rejects_unrelated_ca(lifecycle, outsider, tmp_path):
    """Security-negative: trust is EXACTLY the auto-picked issuer file — a
    client from any other CA fails the handshake."""
    folder = _hashed_ca_dir(tmp_path / "igtf",
                            pathlib.Path(CA_CERT), outsider["cert"])
    ep = lifecycle.start(_spec("lc-certfolder-deny", folder))
    code, _err = curl(f"https://127.0.0.1:{ep.port}/", outsider["cert"],
                      outsider["key"], output=tmp_path / "out.txt")
    assert code != "204", \
        "a client whose CA is not the auto-picked file must be rejected"
