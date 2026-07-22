"""
gsiftp:// GridFTP gateway — GSI control channel *and* PROT P data channel on the
NON-BLOCKING event engine (phase-82 §2, P82.3).

Parity oracle: tests/test_gridftp_gsiftp.py drives the same globus-url-copy
client against the shipped *synchronous* gateway.  This suite renders the
identical topology through the ``_ev`` template (``brix_gridftp_engine event``),
so the RFC 2228 AUTH GSSAPI / ADAT handshake, the wrapped control dialogue, and
— the P82.3 deliverable — the DCAU A / PROT P data channel all run under the
STREAM event loop instead of blocking the worker inside SSL_accept/SSL_connect.

With ``-dcpriv`` the server brings the data socket up as a non-blocking TLS
connection (ngx_ssl_handshake) presenting the delegated user credential; nginx
swaps the connection recv/send vtable to ngx_ssl_recv/ngx_ssl_write once the
handshake settles, so the event RETR/STOR/LIST pumps move TLS records unchanged.
globus verifies the data peer identity against the control-channel identity
before accepting the transfer, and the gateway pins the peer proxy DN back to
the control DN after the handshake.

Covered (mirrors every sync dcpriv case, including the P82.4 MODE E `-p N` and
gsiftp↔gsiftp TPC legs now running on the event engine):
  * LIST  dcpriv (success)   -- directory listing, control wrapped + data PROT P
  * GET   dcpriv (success)   -- RETR round-trips byte-identical over PROT P TLS
  * PUT   dcpriv (success)   -- STOR round-trips byte-identical over PROT P TLS
  * GET/PUT MODE E `-p 4` dcpriv (success) -- parallel extended-block streams,
                                         each a PROT P TLS child, reassembled
                                         byte-identical (P82.4)
  * gsiftp↔gsiftp TPC dcpriv (success)     -- two event gateways move a file
                                         server-to-server over PROT P (P82.4)
  * GET missing dcpriv (error)        -- absent object -> nonzero client rc, no
                                         data channel framed
  * untrusted proxy CA (security-neg) -- a gateway whose trust store lacks the
                                         client's CA rejects the GSSAPI
                                         handshake; no transfer occurs.

Requirements (any missing one skips the module):
  * globus-url-copy on PATH (globus-gass-copy / gridftp client tools)
  * the brix nginx build (NGINX_BIN, default /tmp/nginx-1.28.3/objs/nginx)
  * the test PKI at $TEST_ROOT/pki (server hostcert/key, grid CA, a proxy)

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_gridftp_gsiftp_ev.py -v -s -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from gridftp_client_env import gsi_client_env

# Stands up its own throwaway event-engine gsiftp gateway(s) through the phase-81
# registry (LifecycleHarness); the marker keeps it out of the registry-lint
# direct-launch/inline-config scope, same as the sync oracle.
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
    """A registry-owned event-engine gsiftp gateway, torn down on close().

    Same ``.port`` / ``.export`` / ``.error_log()`` surface as the sync oracle's
    adapter, but renders the ``_ev`` template so the gateway runs the
    non-blocking engine (brix_gridftp_engine event)."""

    def __init__(self, harness, name, ca_dir):
        self.harness = harness
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_gsiftp_ev.conf",
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


def _guc(*args, timeout=60, dc="dcpriv"):
    """Run globus-url-copy with the standard grid client environment.

    Defaults to ``dc="dcpriv"`` (DCAU A + PROT P) — the event PROT P data channel
    is exactly what this suite exercises.  ``dc="nodcau"`` keeps the data leg
    cleartext (control still fully GSI-secured) for the error/negative cases."""
    env = gsi_client_env(CA_DIR, USER_PROXY)
    flag = {"nodcau": "-nodcau", "dcpriv": "-dcpriv"}[dc]
    cmd = [GUC, flag, *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=timeout)


@pytest.fixture(scope="module")
def gateway():
    _require()
    gw = _launch("gridftp-gsiftp-ev-trusting", CA_DIR)
    yield gw
    gw.close()


def test_list_directory_dcpriv(gateway):
    """LIST over the wrapped control channel + PROT P data channel returns
    exported entries on the event engine."""
    with open(os.path.join(gateway.export, "greeting.txt"), "w") as fh:
        fh.write("hello gsiftp event\n")
    r = _guc("-list", f"gsiftp://{SERVER_HOST}:{gateway.port}/")
    assert r.returncode == 0, (
        f"list failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    assert "greeting.txt" in r.stdout, r.stdout


def test_get_roundtrip_dcpriv(gateway, tmp_path):
    """RETR over a GSI-encrypted (PROT P) data channel round-trips byte-identical
    on the event engine.

    The server brings the data socket up as a non-blocking TLS connection
    presenting the delegated user credential, and globus verifies the data peer
    identity against the control-channel identity before accepting."""
    payload = b"gsiftp(ev) dcpriv GET \x00\x01\x02 " + os.urandom(8192)
    with open(os.path.join(gateway.export, "secure-dl.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "secure-got.bin")
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/secure-dl.bin",
             f"file://{dst}")
    assert r.returncode == 0, (
        f"dcpriv get failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_put_roundtrip_dcpriv(gateway, tmp_path):
    """STOR over a GSI-encrypted (PROT P) data channel lands byte-identical in the
    export through the VFS on the event engine."""
    payload = os.urandom(24000)
    src = os.path.join(str(tmp_path), "secure-up.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc(f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/secure-uploaded.bin")
    assert r.returncode == 0, (
        f"dcpriv put failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(os.path.join(gateway.export, "secure-uploaded.bin"), "rb") as fh:
        assert fh.read() == payload


def test_get_missing_object_fails_dcpriv(gateway, tmp_path):
    """A PROT P RETR of an absent object fails the client (error path): the RETR
    is rejected before any data channel is brought up, so globus sees a nonzero
    completion and no file is written."""
    dst = os.path.join(str(tmp_path), "nope.bin")
    r = _guc(f"gsiftp://{SERVER_HOST}:{gateway.port}/does-not-exist.bin",
             f"file://{dst}")
    assert r.returncode != 0, "expected nonzero rc for missing object"
    assert not os.path.exists(dst) or os.path.getsize(dst) == 0


def test_get_mode_e_parallel_dcpriv(gateway, tmp_path):
    """RETR in MODE E over parallel PROT P streams (`-p 4`) round-trips.

    ``globus-url-copy -p 4`` negotiates MODE E and opens four parallel data
    connections; the event gateway frames the file as offset-addressed extended
    blocks over the single data connection globus accepts, each a non-blocking
    PROT P TLS session, and globus reassembles them byte-identical."""
    payload = os.urandom(3 << 20)  # 3 MiB striped across the streams
    with open(os.path.join(gateway.export, "mode-e-dl.bin"), "wb") as fh:
        fh.write(payload)
    dst = os.path.join(str(tmp_path), "mode-e-got.bin")
    r = _guc("-p", "4", f"gsiftp://{SERVER_HOST}:{gateway.port}/mode-e-dl.bin",
             f"file://{dst}")
    assert r.returncode == 0, (
        f"mode-E get failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == payload


def test_put_mode_e_parallel_dcpriv(gateway, tmp_path):
    """STOR in MODE E over parallel PROT P streams reassembles byte-identical.

    globus opens all four data connections at once and handshakes their TLS
    concurrently; the event receiver accepts every stream, brings each up as a
    PROT P child, and folds the out-of-order extended blocks into the VFS writer
    at their absolute offsets, completing on the EOF-declared EOD count."""
    payload = os.urandom(3 << 20)
    src = os.path.join(str(tmp_path), "mode-e-up.bin")
    with open(src, "wb") as fh:
        fh.write(payload)
    r = _guc("-p", "4", f"file://{src}",
             f"gsiftp://{SERVER_HOST}:{gateway.port}/mode-e-uploaded.bin")
    assert r.returncode == 0, (
        f"mode-E put failed rc={r.returncode}\n{r.stderr}\n{gateway.error_log()}")
    with open(os.path.join(gateway.export, "mode-e-uploaded.bin"), "rb") as fh:
        assert fh.read() == payload


def test_third_party_copy_gsiftp_to_gsiftp(tmp_path):
    """gsiftp↔gsiftp third-party copy between two *event-engine* gateways.

    Mirrors the sync oracle's TPC: the destination gateway is passive (event PROT
    P TLS server on the data socket); the source gateway is active and connects
    out to the destination's listener as the non-blocking TLS *client*, presenting
    the delegated user credential.  The active-mode peer-IP pin is relaxed under
    DCAU A and the data-channel DN pin (peer DN == control DN) authorises the leg;
    no bytes flow through the client."""
    _require()
    src = _launch("gridftp-tpc-ev-src", CA_DIR)
    dst = _launch("gridftp-tpc-ev-dst", CA_DIR)
    try:
        payload = b"gsiftp(ev) TPC \x00\x01\x02 " + os.urandom(16384)
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


def test_untrusted_ca_rejected(tmp_path):
    """Security negative: an event-engine gateway whose trust store lacks the
    client's CA rejects the GSSAPI handshake — the delegated identity is never
    verified, so no listing or transfer succeeds."""
    _require()
    empty_ca = os.path.join(str(tmp_path), "empty-ca")
    os.makedirs(empty_ca, exist_ok=True)
    gw = _launch("gridftp-gsiftp-ev-untrusting", empty_ca)
    try:
        r = _guc("-list", f"gsiftp://{SERVER_HOST}:{gw.port}/", timeout=45)
        assert r.returncode != 0, (
            f"untrusted CA must reject auth, got rc=0\n{r.stdout}")
    finally:
        gw.close()
