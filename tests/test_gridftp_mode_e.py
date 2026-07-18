"""
GridFTP MODE E extended-block reassembly — evil-actor corpus (phase-82 P82.5).

MODE E STOR reassembles offset-addressed EBLOCK records that arrive out of order
across parallel data streams (§4.4).  Because every block is self-addressed, a
malicious or buggy sender can aim a block at an *arbitrary* file offset — the
reassembly guards (risk R4) are the security boundary: a block overlapping an
already-committed range, an ``offset+count`` that overflows ``off_t``, or a
short-framed block must all fail the transfer rather than corrupt the file.

These run against the *cleartext* gateway (``nginx_gridftp_plain.conf``): with
the GSI security layer off the data channel is a raw socket (PROT C), so the
EBLOCK codec can be driven directly with hand-crafted bytes over ``socket`` —
no GSSAPI handshake or delegated credential needed.  The framing on the wire is
identical to the PROT P path; only the TLS wrapper differs.

Covered:
  * raw single-stream STOR round-trips              (success — proves the driver)
  * a block overlapping a committed range is rejected   (security-negative, R4)
  * an ``offset+count`` overflow is rejected            (security-negative, R4)
  * a block whose payload is shorter than its count fails (error path)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_mode_e.py -v -p no:xdist
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

# EBLOCK descriptor bits (GFD.020 §3.4); EOF carries the total EOD count in the
# OFFSET field (not count), and folds EOD in on the last stream.
EB_EOF = 0x40
EB_EOD = 0x08


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _Gateway:
    """A registry-owned cleartext FTP gateway, torn down on close()."""

    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_plain.conf",
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
def gateway():
    _require()
    gw = _Gateway(LifecycleHarness(), "gridftp-mode-e-evil")
    yield gw
    gw.close()


def _eb(desc, count, offset):
    """Pack a 17-byte EBLOCK header (network byte order)."""
    return struct.pack("!B", desc) + struct.pack("!Q", count) + struct.pack("!Q", offset)


def _final_code(ftp):
    """Read the final control reply and return its numeric code, whether it is a
    success (2xx) or a failure (ftplib raises error_temp/error_perm on 4xx/5xx)."""
    try:
        return int(ftp.getresp()[:3])
    except (ftplib.error_temp, ftplib.error_perm) as exc:
        return int(str(exc)[:3])


def _mode_e_stor(gw, name, frames, eod_total=1, close_eof=True):
    """Drive a MODE E STOR of `name`, writing the raw `frames` (a list of byte
    strings — headers and payloads already packed) to the data connection, then
    a combined EOF|EOD block (unless close_eof is False).  Returns the final
    control-channel reply code.

    The data connection is opened to the PASV listener *before* STOR so the
    server accepts it out of its listen backlog when the receiver starts."""
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


def test_mode_e_raw_stor_roundtrip(gateway):
    """A well-formed single-stream MODE E STOR lands byte-identical.

    Establishes that the raw EBLOCK driver and the reassembly path agree before
    the negative cases lean on the same driver to prove rejection."""
    payload = os.urandom(40000)
    # Two in-order, disjoint data blocks then the combined EOF|EOD terminator.
    frames = [
        _eb(0, 20000, 0) + payload[:20000],
        _eb(0, 20000, 20000) + payload[20000:],
    ]
    code = _mode_e_stor(gateway, "raw-ok.bin", frames)
    assert code == 226, f"expected 226, got {code}"
    with open(os.path.join(gateway.export, "raw-ok.bin"), "rb") as fh:
        assert fh.read() == payload


def test_mode_e_overlapping_block_rejected(gateway):
    """A block overlapping an already-committed range fails the transfer (R4).

    The first block commits [0,4096); the second aims at offset 2048 — an
    overwrite into committed data.  The receiver must reject it (550) rather than
    silently clobber the earlier bytes."""
    frames = [
        _eb(0, 4096, 0) + b"\xa1" * 4096,
        _eb(0, 4096, 2048) + b"\xb2" * 4096,   # overlaps [2048,4096)
    ]
    code = _mode_e_stor(gateway, "overlap.bin", frames)
    assert code == 550, f"overlapping block must be rejected, got {code}"


def test_mode_e_offset_overflow_rejected(gateway):
    """A block whose offset+count overflows off_t fails the transfer (R4).

    offset = INT64_MAX - 10, count = 1000 would wrap past the signed 64-bit file
    offset space; the receiver rejects it before any pwrite."""
    overflow_off = (1 << 63) - 10
    frames = [_eb(0, 1000, overflow_off)]     # no payload: rejected at the header
    code = _mode_e_stor(gateway, "overflow.bin", frames, close_eof=False)
    assert code == 550, f"offset+count overflow must be rejected, got {code}"


def test_mode_e_truncated_block_rejected(gateway):
    """A block whose payload is shorter than its declared count fails.

    Declares count=8192 but sends only 100 bytes then closes the stream: the
    receiver's exact-read must treat the short frame as an error (550), never a
    partial commit."""
    frames = [_eb(0, 8192, 0) + b"\xc3" * 100]
    code = _mode_e_stor(gateway, "short.bin", frames, close_eof=False)
    assert code == 550, f"short-framed block must be rejected, got {code}"
