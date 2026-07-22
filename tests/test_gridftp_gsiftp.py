"""
gsiftp:// GridFTP gateway — GSI-secured control channel end to end.

Drives the real `globus-url-copy` client against the brix GridFTP gateway
(`brix_gridftp` STREAM module) with the RFC 2228 security layer enabled
(`brix_gridftp_gsi on`).  This exercises the whole gsiftp path in C:

    AUTH GSSAPI  -> 334
    ADAT <b64>   -> 335 ADAT=... (TLS 1.2 handshake carried in base64
                    tokens) ... -> 235  (GSI credential delegation folded in)
    then every control command travels wrapped (ENC/MIC -> 633 <b64>).

Identity is a GSI X.509 proxy (X509_USER_PROXY); the gateway PKIX-verifies
the proxy chain against the trusted grid CA (X509_V_FLAG_ALLOW_PROXY_CERTS),
pins the end-entity DN into the request identity, and stores the delegated
credential.  Transfers then land in the exported tree through the VFS seam.

With ``-dcpriv`` (DCAU A + PROT P) the data channel is *also* GSI-secured: the
server brings the data socket up as a TLS connection presenting the delegated
user credential, and globus verifies the data peer identity against the
control-channel identity before accepting the transfer.

Covered:
  * LIST  (success)   -- MLSD/NLST directory listing over the wrapped channel
  * GET   (success)   -- RETR round-trips byte-identical out of the export
  * PUT   (success)   -- STOR round-trips byte-identical into the export
  * GET dcpriv (success) -- RETR over a GSI-encrypted data channel round-trips
  * PUT dcpriv (success) -- STOR over a GSI-encrypted data channel round-trips
  * GET missing       (error)        -- absent object -> nonzero client rc
  * untrusted proxy CA (security-neg) -- a gateway whose trust store does not
                                         contain the client's CA rejects the
                                         GSSAPI handshake; no transfer occurs.

Requirements (any missing one skips the module):
  * globus-url-copy on PATH (globus-gass-copy / gridftp client tools)
  * the brix nginx build (NGINX_BIN, default /tmp/nginx-1.28.3/objs/nginx)
  * the test PKI at $TEST_ROOT/pki (server hostcert/key, grid CA, a proxy)

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_gridftp_gsiftp.py -v -s -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from gridftp_client_env import gsi_client_env

# This suite stands up its own throwaway gsiftp gateway(s) through the phase-81
# registry (LifecycleHarness) rather than launching nginx directly; the marker
# keeps it out of the registry-lint direct-launch/inline-config scope.
pytestmark = [pytest.mark.slow, pytest.mark.serial,
              pytest.mark.timeout(300), pytest.mark.uses_lifecycle_harness]

GUC = shutil.which("globus-url-copy")
SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
CA_DIR = os.path.join(PKI_DIR, "ca")
USER_PROXY = os.path.join(PKI_DIR, "user", "proxy_std.pem")


def _require():
    if GUC is None:
        pytest.skip("globus-url-copy not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR, USER_PROXY):
        if not os.path.exists(p):
            pytest.skip(f"test PKI incomplete: missing {p}")


class _Gateway:
    """A registry-owned nginx gsiftp gateway, torn down on close().

    Thin adapter over the phase-81 LifecycleHarness so the test bodies keep the
    same ``.port`` / ``.export`` / ``.error_log()`` surface the direct-launch
    ``_Gateway`` exposed."""

    def __init__(self, harness, name, ca_dir):
        self.harness = harness
        # Render the shared template; nginx -t (harness.start) rejects a broken
        # config as an error, the auto-created data_root is the export tree, and
        # start() waits TCP-ready before returning.
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_gsiftp.conf",
            protocol="root",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
                "CA_DIR": ca_dir,
            },
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


def _launch(name, ca_dir):
    return _Gateway(LifecycleHarness(), name, ca_dir)


def _guc(*args, timeout=60, dc="nodcau"):
    """Run globus-url-copy with the standard grid client environment.

    ``dc`` selects the data-channel security mode:
      * "nodcau"  -- data-channel authentication off; the data leg stays
                     cleartext (the control channel is still fully GSI-secured).
      * "dcpriv"  -- DCAU on + PROT P: the data channel is a GSI-authenticated,
                     encrypted TLS connection the server brings up with the
                     delegated user credential.
    """
    env = gsi_client_env(CA_DIR, USER_PROXY)
    flag = {"nodcau": "-nodcau", "dcpriv": "-dcpriv"}[dc]
    cmd = [GUC, flag, *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=timeout)


@pytest.fixture(scope="module")
def gateway():
    _require()
    gw = _launch("gridftp-gsiftp-trusting", CA_DIR)
    yield gw
    gw.close()


def test_list_directory(gateway):
    """LIST over the wrapped control channel returns exported entries."""
    with open(os.path.join(gateway.export, "greeting.txt"), "w") as fh:
        fh.write("hello gsiftp\n")
    r = _guc("-list", f"gsiftp://{SERVER_HOST}:{gateway.port}/")
    assert r.returncode == 0, f"list failed rc={r.returncode}\n{r.stderr}"
    assert "greeting.txt" in r.stdout, r.stdout


def test_get_roundtrip(gateway, tmp_path):
    """RETR pulls a byte-identical copy out of the export tree."""
    payload = b"gsiftp GET payload \x00\x01\x02 " + os.urandom(4096)
    with open(os.path.join(gateway.export, "download.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "got.bin")
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/download.bin", f"file://{dst}")
    assert r.returncode == 0, f"get failed rc={r.returncode}\n{r.stderr}"
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_put_roundtrip(gateway, tmp_path):
    """STOR lands a byte-identical copy in the export tree through the VFS."""
    payload = os.urandom(20000)
    src = os.path.join(str(tmp_path), "upload.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc(f"file://{src}", f"gsiftp://{SERVER_HOST}:{gateway.port}/uploaded.bin")
    assert r.returncode == 0, f"put failed rc={r.returncode}\n{r.stderr}"
    with open(os.path.join(gateway.export, "uploaded.bin"), "rb") as fh:
        assert fh.read() == payload


def test_get_roundtrip_dcpriv(gateway, tmp_path):
    """RETR over a GSI-encrypted data channel (DCAU + PROT P) round-trips.

    The server brings the data socket up as a TLS connection presenting the
    delegated user credential, and globus verifies the data peer identity
    against the control-channel identity before accepting the transfer."""
    payload = b"gsiftp dcpriv GET \x00\x01\x02 " + os.urandom(8192)
    with open(os.path.join(gateway.export, "secure-dl.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "secure-got.bin")
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/secure-dl.bin",
             f"file://{dst}", dc="dcpriv")
    assert r.returncode == 0, (
        f"dcpriv get failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_put_roundtrip_dcpriv(gateway, tmp_path):
    """STOR over a GSI-encrypted data channel lands byte-identical in the export."""
    payload = os.urandom(24000)
    src = os.path.join(str(tmp_path), "secure-up.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc(f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/secure-uploaded.bin",
             dc="dcpriv")
    assert r.returncode == 0, (
        f"dcpriv put failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(os.path.join(gateway.export, "secure-uploaded.bin"), "rb") as fh:
        assert fh.read() == payload


def test_get_missing_object_fails(gateway, tmp_path):
    """A RETR of an absent object fails the client (error path)."""
    dst = os.path.join(str(tmp_path), "nope.bin")
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/does-not-exist.bin",
             f"file://{dst}")
    assert r.returncode != 0, "expected nonzero rc for missing object"
    assert not os.path.exists(dst) or os.path.getsize(dst) == 0


def test_third_party_copy_gsiftp_to_gsiftp(tmp_path):
    """gsiftp↔gsiftp third-party copy: two brix gateways move a file directly
    server-to-server over a GSI-secured (DCAU A + PROT P) data channel, with no
    bytes flowing through the client.

    The destination gateway is passive (TLS server on the data socket); the
    source gateway is active and connects out to the destination's listener as
    the TLS *client*, presenting the delegated user credential.  Because the
    connecting peer is the source *server* (not the control-channel client), the
    active-mode peer-IP pin is relaxed under DCAU A and the data-channel DN pin
    (peer DN == control DN) is the identity boundary that authorises the leg."""
    _require()
    src = _launch("gridftp-tpc-src", CA_DIR)
    dst = _launch("gridftp-tpc-dst", CA_DIR)
    try:
        payload = b"gsiftp TPC \x00\x01\x02 " + os.urandom(16384)
        with open(os.path.join(src.export, "tpc-src.bin"), "wb") as fh:
            fh.write(payload)

        r = _guc(f"gsiftp://{SERVER_HOST}:{src.port}/tpc-src.bin",
                 f"gsiftp://{SERVER_HOST}:{dst.port}/tpc-dst.bin",
                 dc="dcpriv", timeout=90)
        assert r.returncode == 0, (
            f"tpc copy failed rc={r.returncode}\n{r.stderr}\n"
            f"SRC log:\n{src.error_log()}\nDST log:\n{dst.error_log()}")

        with open(os.path.join(dst.export, "tpc-dst.bin"), "rb") as fh:
            assert fh.read() == payload
    finally:
        src.close()
        dst.close()


def test_get_mode_e_parallel(gateway, tmp_path):
    """RETR in MODE E over parallel streams (`-p N`) round-trips.

    `globus-url-copy -p N` negotiates `MODE E` and drives N parallel data
    connections; the gateway frames the file as offset-addressed extended-block
    (EBLOCK) records with a trailing EOD + EOF and globus reassembles them."""
    payload = os.urandom(3 << 20)  # 3 MiB, striped across the streams
    with open(os.path.join(gateway.export, "mode-e-dl.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "mode-e-got.bin")
    r = _guc("-p", "4", f"gsiftp://{SERVER_HOST}:{gateway.port}/mode-e-dl.bin",
             f"file://{dst}", dc="dcpriv")
    assert r.returncode == 0, (
        f"mode-E get failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_put_mode_e_parallel(gateway, tmp_path):
    """STOR in MODE E over parallel streams reassembles byte-identical.

    globus opens N data connections at once and hands the gateway EBLOCK records
    out of order across them; the passive receiver polls across every stream,
    writes each block at its absolute offset through the VFS, and rejects any
    block overlapping a committed range."""
    payload = os.urandom(3 << 20)
    src = os.path.join(str(tmp_path), "mode-e-up.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc("-p", "4", f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/mode-e-up.bin", dc="dcpriv")
    assert r.returncode == 0, (
        f"mode-E put failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(os.path.join(gateway.export, "mode-e-up.bin"), "rb") as fh:
        assert fh.read() == payload


def test_get_mode_e_missing_object_fails(gateway, tmp_path):
    """A parallel-stream RETR of an absent object fails the client (error path).

    MODE E RETR must reject a missing source the same as stream mode — no data
    connection is framed and globus sees a nonzero completion."""
    dst = os.path.join(str(tmp_path), "mode-e-nope.bin")
    r = _guc("-p", "4", f"gsiftp://{SERVER_HOST}:{gateway.port}/mode-e-absent.bin",
             f"file://{dst}", dc="dcpriv")
    assert r.returncode != 0, "expected nonzero rc for missing MODE E object"
    assert not os.path.exists(dst) or os.path.getsize(dst) == 0


def test_untrusted_ca_rejected(tmp_path):
    """Security negative: a gateway whose trust store lacks the client's CA
    rejects the GSSAPI handshake — the delegated identity is never verified,
    so no listing or transfer succeeds."""
    _require()
    empty_ca = os.path.join(str(tmp_path), "empty-ca")
    os.makedirs(empty_ca, exist_ok=True)
    gw = _launch("gridftp-gsiftp-untrusting", empty_ca)
    try:
        r = _guc("-list", f"gsiftp://{SERVER_HOST}:{gw.port}/", timeout=45)
        assert r.returncode != 0, (
            f"untrusted CA must reject auth, got rc=0\n{r.stdout}")
    finally:
        gw.close()
