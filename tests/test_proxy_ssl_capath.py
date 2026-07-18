"""brix_proxy_ssl_capath — hashed CA directory for the proxy back leg.

`brix_proxy_ssl_capath <dir>` makes `proxy_ssl_verify on` consume an OpenSSL
hashed CA directory (the /etc/grid-security/certificates IGTF layout):
at parse time it seeds the stock proxy_ssl_trusted_certificate with one
<hash>.N file from the dir (satisfying nginx's mandatory-file check), and at
postconfiguration it adds the whole directory to the location's upstream
SSL_CTX as a hashed lookup.  No bundle file is ever needed or synthesized.

Covers the mandated triplet:
  success           — front leg verifies a TLS backend with ONLY the hashed
                      dir configured: the request proxies through (204);
  error             — missing dir, dir without <hash>.N files, and the
                      directive in a location lacking an https proxy_pass
                      all fail nginx -t with messages naming the cause;
  security-negative — a dir holding only an unrelated CA: upstream cert
                      verification fails and the client gets 502.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_proxy_ssl_capath.py -v -p no:xdist
"""

import pathlib
import socket
import subprocess
import urllib.request

import pytest

from settings import CA_CERT, SERVER_CERT, SERVER_KEY
from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture(scope="module")
def outsider_ca(tmp_path_factory):
    """A self-signed CA unrelated to the fleet PKI — a hashed dir holding
    only this must make backend verification fail."""
    base = tmp_path_factory.mktemp("proxycapathoutsider")
    cert, key = base / "outsider.pem", base / "outsider.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-subj", "/O=brix-test/CN=proxy-capath outsider CA",
         "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True)
    return cert


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


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _spec(name, capath, template="nginx_lc_proxy_ssl_capath.conf"):
    values = {"CAPATH": str(capath)}
    if template == "nginx_lc_proxy_ssl_capath.conf":
        values.update({
            "HOST_CERT": SERVER_CERT,
            "HOST_KEY": SERVER_KEY,
            "BACKEND_PORT": str(_free_port()),
        })
    return NginxInstanceSpec(
        name=name,
        template=template,
        protocol="webdav",
        readiness="tcp",
        template_values=values,
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


def _get_status(port: int) -> int:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/",
                                    timeout=5) as res:
            return res.status
    except urllib.error.HTTPError as err:
        return err.code


def test_proxy_capath_verifies_backend(lifecycle, tmp_path):
    """Success: proxy_ssl_verify on with ONLY the hashed dir — the fleet CA
    resolved out of it verifies the backend and the request proxies (204)."""
    capath = _hashed_ca_dir(tmp_path / "igtf", pathlib.Path(CA_CERT))
    ep = lifecycle.start(_spec("lc-proxycapath-ok", capath))
    assert _get_status(ep.port) == 204, \
        "hashed-dir trust must satisfy proxy_ssl_verify end to end"


def test_proxy_capath_config_errors_are_fatal(lifecycle, tmp_path):
    """Error: nonexistent dir, dir without <hash>.N files, and a location
    with no https proxy_pass each fail nginx -t loudly."""
    code, out = _nginx_t(lifecycle,
                         _spec("lc-proxycapath-missing", tmp_path / "no-such"))
    assert code != 0, "a missing directory must be a fatal config error"
    assert "not an accessible directory" in out, out

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README").write_text("no hashed CA files here\n")
    code, out = _nginx_t(lifecycle, _spec("lc-proxycapath-empty", empty))
    assert code != 0, "a dir without <hash>.N CA files must be fatal"
    assert "contains no" in out, out

    good = _hashed_ca_dir(tmp_path / "good", pathlib.Path(CA_CERT))
    code, out = _nginx_t(lifecycle,
                         _spec("lc-proxycapath-noproxy", good,
                               template="nginx_lc_proxy_ssl_capath_noproxy.conf"))
    assert code != 0, "the directive without an https proxy_pass must be fatal"
    assert "proxy_pass https" in out, out


def test_proxy_capath_rejects_unrelated_backend_ca(lifecycle, outsider_ca,
                                                   tmp_path):
    """Security-negative: trust is EXACTLY the dir's contents — a dir holding
    only an unrelated CA fails upstream verification (502), it never falls
    back to system trust or skips the check."""
    decoy_only = _hashed_ca_dir(tmp_path / "decoy-only", outsider_ca)
    ep = lifecycle.start(_spec("lc-proxycapath-deny", decoy_only))
    assert _get_status(ep.port) == 502, \
        "an untrusted backend cert must fail the back-leg handshake"
