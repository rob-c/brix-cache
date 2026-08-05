"""
gsiftp:// / ftp:// support in the NATIVE brix xrdcp client (phase-91 client leg).

The client engine lives in ``client/lib/protocols/ftp`` (control dialogue, RFC
2228 AUTH GSSAPI/ADAT with a real GSI proxy, EPSV/PASV data channel, the
FTP-bounce screen) and is driven by ``client/lib/xfer/copy_gsiftp.c``.  Every
case here runs the shipped ``client/bin/xrdcp`` binary against a real brix
GridFTP gateway started through the phase-81 registry, so the assertions cover
the wire, not a mock.

Covered (success + error + security-negative per surface, per CLAUDE.md):
  * ftp://   download / upload round-trip byte-identical (cleartext gateway)
  * ftp://   GET of an absent object -> rc 54 (ENOENT), no partial destination
  * gsiftp:// download / upload round-trip byte-identical (GSI control channel,
             ADAT handshake with the test proxy, delegation round completed)
  * gsiftp:// against a gateway whose trust store lacks the client CA
             (security-neg) -> rc 53, no bytes moved
  * gsiftp:// with no X.509 proxy at all (security-neg) -> rc 53; the GSI
             endpoint is NEVER silently downgraded to anonymous
  * ftp://->ftp:// remote-to-remote (usage-neg) -> rc 50, refused up front

Requirements (any missing one skips the module):
  * the brix client build (client/bin/xrdcp)
  * the brix nginx build (NGINX_BIN, default /tmp/nginx-1.28.3/objs/nginx)
  * the test PKI at $TEST_ROOT/pki for the GSI cases

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_xrdcp_gsiftp.py -v -p no:xdist
"""

import os
import subprocess

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from gridftp_client_env import gsi_client_env

# Stands up its own throwaway gsiftp gateways through the phase-81 registry
# (LifecycleHarness); the marker keeps it out of the registry-lint
# direct-launch/inline-config scope, as with the other gridftp suites.
pytestmark = [pytest.mark.serial, pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness]

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
CA_DIR = os.path.join(PKI_DIR, "ca")
USER_PROXY = os.path.join(PKI_DIR, "user", "proxy_std.pem")

# xrdcp exit codes (client/lib/core/status.h): usage / auth / not-found.
RC_EUSAGE = 50
RC_EAUTH = 53
RC_ENOENT = 54


def _require():
    if not os.access(XRDCP, os.X_OK):
        pytest.skip(f"brix xrdcp not built: {XRDCP}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


def _require_pki():
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR, USER_PROXY):
        if not os.path.exists(p):
            pytest.skip(f"test PKI incomplete: missing {p}")


class _Gateway:
    """A registry-owned GridFTP gateway, torn down on close()."""

    def __init__(self, name, template, values):
        self.harness = LifecycleHarness()
        endpoint = self.harness.start(NginxInstanceSpec(
            name=name,
            template=template,
            protocol="root",
            readiness="tcp",
            template_values=values,
        ))
        self.port = endpoint.port
        self.export = endpoint.data_root
        self._log = os.path.join(endpoint.prefix, "logs", "error.log")

    def close(self):
        self.harness.close()

    def error_log(self):
        try:
            with open(self._log) as fh:
                return fh.read()
        except FileNotFoundError:
            return ""


def _plain_gateway(name):
    return _Gateway(name, "nginx_gridftp_plain.conf", {"BIND_HOST": BIND_HOST})


def _gsi_gateway(name, ca_dir):
    return _Gateway(name, "nginx_gridftp_gsiftp_ev.conf", {
        "BIND_HOST": BIND_HOST,
        "SERVER_CERT": SERVER_CERT,
        "SERVER_KEY": SERVER_KEY,
        "CA_DIR": ca_dir,
    })


def _xrdcp(*args, env=None, timeout=60):
    return subprocess.run([XRDCP, *args], capture_output=True, text=True,
                          env=env, timeout=timeout)


def _gsi_env():
    """Grid client environment minus the server-side cert/key: the client must
    authenticate from the proxy alone."""
    env = gsi_client_env(CA_DIR, USER_PROXY)
    env.pop("X509_USER_CERT", None)
    env.pop("X509_USER_KEY", None)
    return env


@pytest.fixture(scope="module")
def plain_gw():
    _require()
    gw = _plain_gateway("xrdcp-gsiftp-plain")
    yield gw
    gw.close()


@pytest.fixture(scope="module")
def gsi_gw():
    _require()
    _require_pki()
    gw = _gsi_gateway("xrdcp-gsiftp-gsi", CA_DIR)
    yield gw
    gw.close()


# ---------------------------------------------------------------- ftp:// plain

def test_plain_download_roundtrip(plain_gw, tmp_path):
    """RETR over a cleartext control channel lands byte-identical locally."""
    payload = b"brix xrdcp ftp GET \x00\x01\xfe" + os.urandom(40000)
    with open(os.path.join(plain_gw.export, "dl.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "got.bin")
    r = _xrdcp(f"ftp://{SERVER_HOST}:{plain_gw.port}/dl.bin", dst)
    assert r.returncode == 0, (
        f"rc={r.returncode}\n{r.stderr}\n{plain_gw.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_plain_upload_roundtrip(plain_gw, tmp_path):
    """STOR pushes the local file through the gateway's VFS byte-identical."""
    payload = os.urandom(33333)
    src = os.path.join(str(tmp_path), "up.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _xrdcp(src, f"ftp://{SERVER_HOST}:{plain_gw.port}/up-landed.bin")
    assert r.returncode == 0, (
        f"rc={r.returncode}\n{r.stderr}\n{plain_gw.error_log()}")
    with open(os.path.join(plain_gw.export, "up-landed.bin"), "rb") as fh:
        assert fh.read() == payload


def test_plain_missing_source_is_enoent(plain_gw, tmp_path):
    """Error path: a GET of an absent object reports ENOENT (550 -> rc 54) and
    leaves no destination behind."""
    dst = os.path.join(str(tmp_path), "never.bin")
    r = _xrdcp(f"ftp://{SERVER_HOST}:{plain_gw.port}/no-such-object.bin", dst)
    assert r.returncode == RC_ENOENT, (
        f"rc={r.returncode} stderr={r.stderr}\n{plain_gw.error_log()}")
    assert not os.path.exists(dst), "failed GET must not leave a destination"


def test_remote_to_remote_refused(plain_gw, tmp_path):
    """Usage negative: ftp:// -> ftp:// has no third-party leg in the client, so
    it is refused up front rather than silently staging through the local disk."""
    url = f"ftp://{SERVER_HOST}:{plain_gw.port}"
    r = _xrdcp(f"{url}/dl.bin", f"{url}/copy.bin")
    assert r.returncode == RC_EUSAGE, f"rc={r.returncode} stderr={r.stderr}"
    assert not os.path.exists(os.path.join(plain_gw.export, "copy.bin"))


# ------------------------------------------------------------------- gsiftp://

def test_gsi_download_roundtrip(gsi_gw, tmp_path):
    """RETR after a full RFC 2228 AUTH GSSAPI / ADAT handshake with the test
    proxy (including the delegation round) round-trips byte-identical."""
    payload = b"brix xrdcp gsiftp GET " + os.urandom(50000)
    with open(os.path.join(gsi_gw.export, "sec-dl.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "sec-got.bin")
    r = _xrdcp(f"gsiftp://{SERVER_HOST}:{gsi_gw.port}/sec-dl.bin", dst,
               env=_gsi_env())
    assert r.returncode == 0, (
        f"rc={r.returncode}\n{r.stderr}\n{gsi_gw.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_gsi_upload_roundtrip(gsi_gw, tmp_path):
    """STOR under the GSI-authenticated identity lands byte-identical."""
    payload = os.urandom(21000)
    src = os.path.join(str(tmp_path), "sec-up.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _xrdcp(src, f"gsiftp://{SERVER_HOST}:{gsi_gw.port}/sec-landed.bin",
               env=_gsi_env())
    assert r.returncode == 0, (
        f"rc={r.returncode}\n{r.stderr}\n{gsi_gw.error_log()}")
    with open(os.path.join(gsi_gw.export, "sec-landed.bin"), "rb") as fh:
        assert fh.read() == payload


def test_gsi_untrusted_ca_rejected(tmp_path):
    """Security negative: a gateway whose trust store lacks the client's CA must
    fail the handshake — the client reports an auth failure and moves no bytes."""
    _require()
    _require_pki()
    empty_ca = os.path.join(str(tmp_path), "empty-ca")
    os.makedirs(empty_ca, exist_ok=True)
    gw = _gsi_gateway("xrdcp-gsiftp-untrusting", empty_ca)
    try:
        dst = os.path.join(str(tmp_path), "nope.bin")
        r = _xrdcp(f"gsiftp://{SERVER_HOST}:{gw.port}/anything.bin", dst,
                   env=_gsi_env(), timeout=45)
        assert r.returncode == RC_EAUTH, (
            f"rc={r.returncode} stdout={r.stdout} stderr={r.stderr}")
        assert not os.path.exists(dst)
    finally:
        gw.close()


def test_gsi_without_proxy_is_not_downgraded(gsi_gw, tmp_path):
    """Security negative: with no X.509 proxy available, a gsiftp:// URL fails
    with an auth error.  It is never downgraded to an anonymous login — the
    gateway would happily serve one, so the refusal has to come from the client."""
    env = _gsi_env()
    env["X509_USER_PROXY"] = os.path.join(str(tmp_path), "absent-proxy.pem")
    dst = os.path.join(str(tmp_path), "unauth.bin")
    r = _xrdcp(f"gsiftp://{SERVER_HOST}:{gsi_gw.port}/sec-dl.bin", dst, env=env)
    assert r.returncode == RC_EAUTH, (
        f"rc={r.returncode} stdout={r.stdout} stderr={r.stderr}")
    assert not os.path.exists(dst)
