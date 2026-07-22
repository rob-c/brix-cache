"""
GridFTP MODE E extended-block transfers — non-blocking event engine (phase-82 P82.4).

Mirrors the sync-engine MODE E coverage (``test_gridftp_mode_e.py`` evil corpus +
the round-trip cases in ``test_gridftp_gsiftp.py``) against a gateway configured
with ``brix_gridftp_engine event``, so the offset-addressed EBLOCK framing runs
through ``ev/ftp_ev_mode_e.c`` under the STREAM event loop:

  * RETR MODE E frames the source over one data connection as
    ``[17-byte header][payload]`` blocks terminated by a combined EOF|EOD block.
  * STOR MODE E reassembles blocks that arrive out of order across up to
    ``Parallelism`` passive data streams into the VFS writer, completing once the
    EOF-declared number of EODs has been seen.

Driven over the *cleartext* event gateway (``nginx_gridftp_plain_ev.conf``): with
GSI off the data channel is a raw PROT C socket, so the EBLOCK codec is exercised
directly with hand-crafted bytes — the on-wire framing is identical to PROT P,
only the TLS wrapper differs (covered separately by the gsiftp_ev suite).

Covered:
  * RETR MODE E single-stream round-trip                    (success)
  * STOR MODE E single-stream, out-of-order blocks          (success)
  * STOR MODE E across parallel data streams                (success — fan-in)
  * a block overlapping a committed range is rejected       (security-negative R4)
  * an offset+count overflow is rejected                    (security-negative R4)
  * a short-framed block fails the transfer                 (error path)
  * RETR MODE E of a missing file fails                     (error path)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_mode_e_event.py -v -p no:xdist
"""

import ftplib
import os
import socket
import struct

import pytest

from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

# EBLOCK descriptor bits (GFD.020 §3.4); an EOF block carries the total EOD count
# in its OFFSET field (not count) and folds EOD in on the last stream.
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
    gw = _EvGateway(LifecycleHarness(), "gridftp-mode-e-event")
    yield gw
    gw.close()


def _eb(desc, count, offset):
    """Pack a 17-byte EBLOCK header (network byte order)."""
    return struct.pack("!B", desc) + struct.pack("!Q", count) + struct.pack("!Q", offset)


def _final_code(ftp):
    """Read the final control reply and return its numeric code, whether success
    (2xx) or a failure ftplib raises error_temp/error_perm on."""
    try:
        return int(ftp.getresp()[:3])
    except (ftplib.error_temp, ftplib.error_perm) as exc:
        return int(str(exc)[:3])


def _reassemble(blob):
    """Parse a MODE E data stream (concatenated [header][payload] blocks) into the
    reconstructed object, stopping at the EOF block."""
    out = bytearray()
    i = 0
    while i + 17 <= len(blob):
        desc = blob[i]
        count = struct.unpack("!Q", blob[i + 1:i + 9])[0]
        offset = struct.unpack("!Q", blob[i + 9:i + 17])[0]
        i += 17
        if desc & EB_EOF:
            break
        payload = blob[i:i + count]
        assert len(payload) == count, "short EBLOCK payload from server"
        if offset + count > len(out):
            out.extend(b"\x00" * (offset + count - len(out)))
        out[offset:offset + count] = payload
        i += count
    return bytes(out)


# ---- RETR MODE E ------------------------------------------------------------

def test_get_mode_e_roundtrip(ev_gateway):
    """RETR in MODE E frames the file as extended blocks that reassemble byte-exact."""
    payload = os.urandom(50000)
    with open(os.path.join(ev_gateway.export, "get-me.bin"), "wb") as fh:
        fh.write(payload)

    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, ev_gateway.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        ftp.sendcmd("MODE E")
        host, port = ftp.makepasv()
        data = socket.create_connection((host, port), timeout=30)
        try:
            ftp.putcmd("RETR get-me.bin")
            assert ftp.getresp().startswith("150"), "expected 150 before data"
            blob = b""
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    break
                blob += chunk
        finally:
            data.close()
        assert _final_code(ftp) == 226
    finally:
        ftp.close()
    assert _reassemble(blob) == payload


def test_get_mode_e_missing_fails(ev_gateway):
    """RETR MODE E of a non-existent object fails on the control channel (550)."""
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, ev_gateway.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        ftp.sendcmd("MODE E")
        host, port = ftp.makepasv()
        data = socket.create_connection((host, port), timeout=30)
        try:
            ftp.putcmd("RETR nope-me.bin")
            code = _final_code(ftp)
        finally:
            data.close()
    finally:
        ftp.close()
    assert code == 550, f"expected 550, got {code}"


# ---- STOR MODE E (single stream) --------------------------------------------

def _mode_e_stor_single(gw, name, frames, eod_total=1, close_eof=True):
    """STOR `name` over a single MODE E data stream, then a combined EOF|EOD."""
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gw.port, timeout=30)
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


def test_put_mode_e_out_of_order(ev_gateway):
    """STOR MODE E lands byte-exact even when blocks arrive out of offset order."""
    payload = os.urandom(30000)
    frames = [
        _eb(0, 10000, 20000) + payload[20000:],   # tail first
        _eb(0, 20000, 0) + payload[:20000],        # head second
    ]
    code = _mode_e_stor_single(ev_gateway, "put-me.bin", frames)
    assert code == 226, f"expected 226, got {code}"
    with open(os.path.join(ev_gateway.export, "put-me.bin"), "rb") as fh:
        assert fh.read() == payload


def test_put_mode_e_overlap_rejected(ev_gateway):
    """A block overlapping a committed range fails the transfer (R4)."""
    frames = [
        _eb(0, 4096, 0) + b"\xa1" * 4096,
        _eb(0, 4096, 2048) + b"\xb2" * 4096,       # overlaps [2048,4096)
    ]
    code = _mode_e_stor_single(ev_gateway, "ev-overlap.bin", frames)
    assert code == 550, f"overlapping block must be rejected, got {code}"


def test_put_mode_e_overflow_rejected(ev_gateway):
    """offset+count wrapping past off_t is rejected before any write (R4)."""
    overflow_off = (1 << 63) - 10
    frames = [_eb(0, 1000, overflow_off)]
    code = _mode_e_stor_single(ev_gateway, "ev-overflow.bin", frames, close_eof=False)
    assert code == 550, f"offset+count overflow must be rejected, got {code}"


def test_put_mode_e_short_frame_rejected(ev_gateway):
    """A payload shorter than its declared count fails, never a partial commit."""
    frames = [_eb(0, 8192, 0) + b"\xc3" * 100]
    code = _mode_e_stor_single(ev_gateway, "ev-short.bin", frames, close_eof=False)
    assert code == 550, f"short-framed block must be rejected, got {code}"


# ---- STOR MODE E (parallel streams) -----------------------------------------

def test_put_mode_e_parallel_streams(ev_gateway):
    """STOR MODE E fans the file in across several concurrent data streams.

    Opens N passive connections to the same PASV listener (as globus does with
    ``-p N``), spreads disjoint offset-addressed blocks across them, ends each
    stream with an EOD, and declares the total EOD count in a final EOF block.
    The receiver must accept every stream, reassemble the blocks at their absolute
    offsets, and complete once all EODs are in."""
    nstreams = 4
    chunk = 16384
    payload = os.urandom(chunk * nstreams)

    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, ev_gateway.port, timeout=30)
    ftp.login()
    try:
        ftp.sendcmd("TYPE I")
        ftp.sendcmd("MODE E")
        host, port = ftp.makepasv()
        # Open all parallel streams up front — the listener stays open across them.
        conns = [socket.create_connection((host, port), timeout=30)
                 for _ in range(nstreams)]
        try:
            ftp.putcmd("STOR par-me.bin")
            assert ftp.getresp().startswith("150"), "expected 150 before data"
            # Stream i carries block i at offset i*chunk then its own EOD; the last
            # stream ends with a combined EOF|EOD (globus convention) declaring the
            # total EOD count, so it both terminates its own stream and announces
            # completion.  Reassembly and the EOD tally are order-independent.
            for i, sock in enumerate(conns):
                off = i * chunk
                sock.sendall(_eb(0, chunk, off) + payload[off:off + chunk])
                if i == nstreams - 1:
                    sock.sendall(_eb(EB_EOF | EB_EOD, 0, nstreams))
                else:
                    sock.sendall(_eb(EB_EOD, 0, 0))
                sock.shutdown(socket.SHUT_WR)
            code = _final_code(ftp)
        finally:
            for sock in conns:
                sock.close()
    finally:
        ftp.close()
    assert code == 226, f"expected 226, got {code}"
    with open(os.path.join(ev_gateway.export, "par-me.bin"), "rb") as fh:
        assert fh.read() == payload
