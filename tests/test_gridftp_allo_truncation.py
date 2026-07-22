"""
GridFTP stream-mode STOR truncation integrity via ALLO (fault-hardening finding #9).

THE BREAK: in stream mode a STOR ends when the client closes the data channel —
there is no length framing, so a bare close is the *only* completion signal and
is indistinguishable from a hostile middlebox dropping the connection mid-flight.
brix answered `200 ALLO ok` to the client's `ALLO <size>` (RFC 959, the one
completion signal the protocol offers) and then **discarded** the size, so a
truncated upload committed the short prefix and answered `226` (complete) — a
silently short object served as whole (the stream-mode analogue of #1/#8).

THE FIX: new opt-in `brix_gridftp_require_allo_size on` records the ALLO size and
holds the stream-mode STOR to exactly that many bytes; a short (or over-long)
delivery fails `550` instead of committing a truncated object.  The clean prefix
is left in place for a REST-resume (a truncation is a resumable interruption, not
the declared-complete poison MODE E unlinks).  Off by default because RFC 959
permits ALLO as an advisory reservation — strict equality is opt-in for the HEP
clients (globus-url-copy / FTS) that send the exact file size.

CONTRACT proven here (driven over the cleartext stream event engine with a raw
PASV data socket, so the on-wire dialogue is exactly a real client's):
  * knob on,  ALLO=N, deliver N bytes  -> 226 + byte-exact stored     [no false pos]
  * knob on,  ALLO=N, deliver N-K, close early -> 550, never a 226    [the fix fires]
  * knob off, ALLO=N, deliver N-K, close early -> 226 (truncation accepted — the
    documented inherent stream-mode default the knob exists to override) [opt-in]

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_allo_truncation.py -v -p no:xdist
"""

import ftplib
import os
import socket

import pytest

from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _AlloGateway:
    """A cleartext stream-mode gateway with require_allo_size on or off."""

    def __init__(self, harness, name, require):
        extra = "brix_gridftp_require_allo_size on;" if require else ""
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_allo_ev.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST, "EXTRA_DIRECTIVES": extra},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gw_require():
    _require()
    gw = _AlloGateway(LifecycleHarness(), "gridftp-allo-require", require=True)
    yield gw
    gw.close()


@pytest.fixture(scope="module")
def gw_lenient():
    _require()
    gw = _AlloGateway(LifecycleHarness(), "gridftp-allo-lenient", require=False)
    yield gw
    gw.close()


def _final_code(ftp):
    try:
        return int(ftp.getresp()[:3])
    except (ftplib.error_temp, ftplib.error_perm) as exc:
        return int(str(exc)[:3])


def _stream_stor(gw, name, allo_size, send_bytes):
    """ALLO `allo_size`, then a stream-mode STOR of `send_bytes` (raw, no framing),
    closing the data channel after exactly len(send_bytes) bytes — a short
    send_bytes vs allo_size reproduces an in-flight truncation."""
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gw.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        if allo_size is not None:
            ftp.sendcmd(f"ALLO {allo_size}")
        host, port = ftp.makepasv()
        data = socket.create_connection((host, port), timeout=30)
        try:
            ftp.putcmd("STOR " + name)
            assert ftp.getresp().startswith("150"), "expected 150 before data"
            data.sendall(send_bytes)
            data.shutdown(socket.SHUT_WR)      # clean EOF after a short payload
            return _final_code(ftp)
        finally:
            data.close()
    finally:
        ftp.close()


def test_require_allo_full_transfer_commits(gw_require):
    """No false positive: knob on, ALLO matches the bytes actually sent → 226 and
    the object is stored byte-exact."""
    payload = os.urandom(48000)
    code = _stream_stor(gw_require, "allo-full.bin", len(payload), payload)
    assert code == 226, f"a complete ALLO-sized STOR must commit, got {code}"
    with open(os.path.join(gw_require.export, "allo-full.bin"), "rb") as fh:
        assert fh.read() == payload


def test_require_allo_short_transfer_rejected(gw_require):
    """The fix fires: knob on, ALLO declares 48000 but the sender delivers 30000
    then closes (a mid-flight truncation) → 550, never a 226 committing the short
    object as complete."""
    payload = os.urandom(48000)
    code = _stream_stor(gw_require, "allo-short.bin", 48000, payload[:30000])
    assert code == 550, f"a truncated ALLO-sized STOR must fail, got {code}"


def test_lenient_short_transfer_still_commits(gw_lenient):
    """Opt-in proof: with the knob off (default), the same truncation is accepted
    (226) — stream mode cannot tell a short transfer from a clean EOF, which is
    exactly the inherent behaviour the knob exists to override.  Confirms the
    guard is genuinely opt-in and the default path is unchanged."""
    payload = os.urandom(48000)
    code = _stream_stor(gw_lenient, "lenient-short.bin", 48000, payload[:30000])
    assert code == 226, (
        f"knob-off default must accept the short transfer (inherent stream-mode "
        f"behaviour), got {code}")
    with open(os.path.join(gw_lenient.export, "lenient-short.bin"), "rb") as fh:
        assert fh.read() == payload[:30000]
