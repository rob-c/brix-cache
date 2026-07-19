"""
GridFTP MODE E STOR gap/truncation integrity — the reassembler must never commit
a non-contiguous tiling as a complete file (fault-hardening finding #8).

THE BREAK: a MODE E STOR fans an object in as offset-addressed extended blocks
across one or more data streams; the receiver (``ev/ftp_ev_mode_e.c``) guards
against blocks whose ranges *overlap*, but completed the transfer purely on the
EOD tally declared by the EOF block — it never checked that the accepted ranges
*tile the object gaplessly from offset 0*.  Because each block is written at its
absolute offset into a sparse file, a set of blocks that leaves a hole (an
in-path bit-flip of a 17-byte EBLOCK header's OFFSET field past the TCP checksum,
or a hostile/short sender that still emits its EOD) committed a file whose gap
region was silently zero-filled — a 226 "complete" answer over poisoned bytes the
client never sent.  This is the MODE E analogue of a truncated cache object
being served as whole (finding #1).

THE FIX (fail-closed): before commit, coalesce the accepted ranges and require
exactly one span ``[0, high-water)`` whose length equals the bytes actually
received.  A gap leaves the staged object for the finish path to abort + unlink,
and the control channel answers 550 — a gapped reassembly is never a valid file.
No knob: a hole in a "complete" transfer is unambiguously wrong.

CONTRACT proven here:
  * a contiguous (gapless) out-of-order STOR still commits byte-exact  [no false pos]
  * an interior hole is rejected (550) and stores nothing            [the fix fires]
  * a leading gap (object does not start at 0) is rejected likewise  [error leg]

Driven over the cleartext MODE E event gateway with hand-crafted EBLOCK bytes, so
the framing exercised is identical to PROT P (only the TLS wrapper differs).  The
hand-forged offsets reproduce exactly the on-wire result a corrupter produces —
a deterministic stand-in for ``brix-fault-proxy corrupt`` on the data stream.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_mode_e_truncation.py -v -p no:xdist
"""

import ftplib
import os
import socket
import struct

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

# EBLOCK descriptor bits (GFD.020 §3.4); an EOF block carries the total EOD count
# in its OFFSET field and folds EOD in on the last stream.
EB_EOF = 0x40
EB_EOD = 0x08


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _EvGateway:
    """A registry-owned cleartext MODE E gateway on the event engine."""

    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_plain_ev.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def ev_gateway():
    _require()
    gw = _EvGateway(LifecycleHarness(), "gridftp-mode-e-truncation")
    yield gw
    gw.close()


def _eb(desc, count, offset):
    """Pack a 17-byte EBLOCK header (network byte order)."""
    return struct.pack("!B", desc) + struct.pack("!Q", count) + struct.pack("!Q", offset)


def _final_code(ftp):
    try:
        return int(ftp.getresp()[:3])
    except (ftplib.error_temp, ftplib.error_perm) as exc:
        return int(str(exc)[:3])


def _mode_e_stor_single(gw, name, frames, eod_total=1, close_eof=True):
    """STOR `name` over a single MODE E data stream, then a combined EOF|EOD."""
    ftp = ftplib.FTP()
    ftp.connect("localhost", gw.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        ftp.sendcmd("MODE E")
        host, port = ftp.makepasv()
        data = socket.create_connection((host, port), timeout=30)
        try:
            ftp.putcmd("STOR " + name)
            assert ftp.getresp().startswith("150"), "expected 150 before data"
            for frame in frames:
                data.sendall(frame)
            if close_eof:
                data.sendall(_eb(EB_EOF | EB_EOD, 0, eod_total))
            data.shutdown(socket.SHUT_WR)
            return _final_code(ftp)
        finally:
            data.close()
    finally:
        ftp.close()


def test_put_mode_e_contiguous_out_of_order_commits(ev_gateway):
    """No false positive: a gapless tiling delivered out of offset order still
    reassembles byte-exact and commits (226) — the fix rejects holes, not order."""
    payload = os.urandom(24576)   # 3 x 8192, delivered tail/mid/head
    frames = [
        _eb(0, 8192, 16384) + payload[16384:24576],
        _eb(0, 8192, 0)     + payload[0:8192],
        _eb(0, 8192, 8192)  + payload[8192:16384],
    ]
    code = _mode_e_stor_single(ev_gateway, "contig.bin", frames)
    assert code == 226, f"contiguous out-of-order STOR must commit, got {code}"
    with open(os.path.join(ev_gateway.export, "contig.bin"), "rb") as fh:
        assert fh.read() == payload


def test_put_mode_e_interior_hole_rejected(ev_gateway):
    """The fix fires: two blocks straddling a hole ([0,4096) + [8192,12288), gap at
    [4096,8192)) declare completion via EOF|EOD, but the reassembly is not
    contiguous — it must be rejected (550) and leave nothing on disk, never a 226
    over a silently zero-filled region."""
    name = "hole.bin"
    frames = [
        _eb(0, 4096, 0)    + b"\xa1" * 4096,
        _eb(0, 4096, 8192) + b"\xb2" * 4096,      # gap: [4096, 8192) never sent
    ]
    code = _mode_e_stor_single(ev_gateway, name, frames)
    assert code == 550, f"interior hole must be rejected, got {code}"
    assert not os.path.exists(os.path.join(ev_gateway.export, name)), (
        "a rejected gapped STOR must leave nothing committed")


def test_put_mode_e_leading_gap_rejected(ev_gateway):
    """Error leg: a single block that starts past offset 0 ([4096,8192)) leaves the
    head of the object undelivered; declaring EOD must not commit a file whose
    first 4096 bytes are phantom zeros — 550 and nothing stored."""
    name = "leadgap.bin"
    frames = [_eb(0, 4096, 4096) + b"\xc3" * 4096]   # bytes [0,4096) missing
    code = _mode_e_stor_single(ev_gateway, name, frames)
    assert code == 550, f"leading gap must be rejected, got {code}"
    assert not os.path.exists(os.path.join(ev_gateway.export, name)), (
        "a rejected leading-gap STOR must leave nothing committed")
