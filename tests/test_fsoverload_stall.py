"""brix_fsoverload_stall — configurable budget-overload backoff (parity §1.10).

A read (or readv) rejected by the process-wide brix_memory_budget used to send
a hardcoded kXR_wait(1). brix_fsoverload_stall <n> now sets those backoff
seconds (the xrootd.fsoverload stall analog); default 1 = the old value, and
the value is still clamped by brix_max_delay at the emission choke point.

The budget defers cross-connection (a connection never counts its own charge),
so the test uses TWO connections on one worker sharing the SHM budget: reader A
issues a large kXR_pgread and leaves it undrained (its ~window scratch stays
charged above the 256k budget), then reader B's small buffered read is deferred
— and B's kXR_wait carries the configured seconds.

Reader A must use kXR_pgread, not kXR_read: a large cleartext kXR_read of a
regular file is served zero-copy by sendfile and holds NO heap, so it can never
charge the memory budget. pgread's per-page CRC32c forces the memory path.
Reader B stays a plain kXR_read but below BRIX_READ_SENDFILE_MIN (32k), so it
takes the buffered memory path — the one that consults brix_budget_admit — and
its served response is a single kXR_ok frame the drain logic already handles.

Coverage (the change-class trio):
  * success      — brix_fsoverload_stall 7: B's overload kXR_wait says 7.
  * error/default— no directive: the overload kXR_wait still says 1 (the
                   historical hardcoded value — no behaviour change).
  * security-neg — brix_fsoverload_stall 30 + brix_max_delay 5: the stall is
                   CLAMPED to 5, proving the overload backoff can never exceed
                   the operator's global max-delay ceiling.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_fsoverload_stall.py -v
"""

import os
import socket
import struct

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-fsoverload")]

kXR_protocol, kXR_login, kXR_open, kXR_read = 3006, 3007, 3010, 3013
kXR_pgread = 3030
kXR_ok, kXR_oksofar, kXR_error, kXR_wait = 0, 4000, 4003, 4005
kXR_redirect = 4004
kXR_open_read = 0x0200          # kXR_open read mode... resolved below via retstat-free open

# A file big enough that a windowed read holds a >256k scratch while undrained.
BIG = 8 * 1024 * 1024


def _start(lifecycle, tmp_path, stall_line):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    with open(data / "big.bin", "wb") as fh:
        fh.truncate(BIG)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-fsoverload",
        template="nginx_lc_fsoverload.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "STALL_LINE": stall_line},
        reason="brix_fsoverload_stall budget-overload backoff"))
    return ep.port


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _resp(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed mid-response"
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _send(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack("!H", reqid)
    hdr += body.ljust(16, b"\x00") + struct.pack("!I", len(payload))
    sock.sendall(hdr + payload)


def _login(port, ability=0x04):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, port))
    # Shrink the socket receive buffer so reader A's undrained read backs up
    # quickly and the server's scratch stays charged.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _resp(sock)
    assert status == kXR_ok, "handshake failed"
    # Login body: pid[4] username[8] ability2[1] ability[1] capver[1] resv[1].
    # ability defaults to kXR_readrdok (0x04) so an overloaded read may be
    # answered with the §1.10 redirect; pass 0 to model a client that cannot
    # follow a mid-read redirect (§1.3 → it must get kXR_wait instead).
    body = b"\x00" * 13 + bytes([ability & 0xFF]) + b"\x00\x00"
    _send(sock, b"\x00\x01", kXR_login, body=body, payload=b"anonymous\x00")
    status, _ = _resp(sock)
    assert status == kXR_ok, "anon login failed"
    return sock


def _open_read(sock, path):
    # ClientOpenRequest: mode(2) options(2) reserved(12) + path. options 0 =
    # open for read (kXR_open_read is 0; retstat/etc. bits are higher).
    body = struct.pack("!HH", 0, 0) + b"\x00" * 12
    _send(sock, b"\x00\x01", kXR_open, body=body, payload=path.encode() + b"\x00")
    status, rbody = _resp(sock)
    assert status == kXR_ok, f"open failed: {status}"
    return rbody[:4]


def _read_req(sock, streamid, fh, offset, rlen):
    body = fh + struct.pack("!q", offset) + struct.pack("!i", rlen)
    _send(sock, streamid, kXR_read, body=body)


def _pgread_req(sock, streamid, fh, offset, rlen):
    # Same 16-byte body layout as kXR_read (fhandle[4] offset[8] rlen[4]).
    body = fh + struct.pack("!q", offset) + struct.pack("!i", rlen)
    _send(sock, streamid, kXR_pgread, body=body)


# Reader B's probe: below BRIX_READ_SENDFILE_MIN (32k) so it takes the buffered
# memory path (which admits against the budget) and is served as one kXR_ok.
B_READ = 16 * 1024


def _overload_wait_seconds(port):
    """Hold a big undrained read on A, then observe B's overload kXR_wait."""
    a = _login(port)
    b = _login(port)
    try:
        fa = _open_read(a, "/big.bin")
        fb = _open_read(b, "/big.bin")

        # Reader A: pgread the whole file but DO NOT drain it — pgread cannot
        # sendfile (per-page CRC32c is computed in heap), so the server holds a
        # windowed scratch (> the 256k budget) that stays charged while A's
        # shrunk socket buffer is full.
        _pgread_req(a, b"\x00\x02", fa, 0, BIG)
        # Pull just the first frame header so the server has started serving
        # and the scratch is charged; leave the rest buffered.  A itself must
        # be ADMITTED (anti-starvation): B's idle connection pins a few framing
        # bytes, and if that residue counted as pressure a want > budget read
        # would loop on kXR_wait forever.
        first = _recv_exact(a, 8)
        assert first is not None, "reader A got no response"
        a_status = struct.unpack("!H", first[2:4])[0]
        assert a_status not in (kXR_wait, kXR_redirect), (
            f"budget starved reader A (status {a_status}) — admission slack broken")

        # Reader B: a read now must be deferred by the budget (A's charge is
        # the cross-connection `others`). Retry briefly in case A's first
        # window has not charged yet.
        import time
        deadline = time.time() + 8
        while time.time() < deadline:
            _read_req(b, b"\x00\x03", fb, 0, B_READ)
            status, body = _resp(b)
            if status == kXR_wait:
                assert len(body) >= 4
                return struct.unpack("!i", body[:4])[0]
            # not deferred yet (A not charged) — drain B's data and retry
            if status in (kXR_ok, kXR_oksofar):
                # drain any continuation frames for this streamid
                while status == kXR_oksofar:
                    status, _ = _resp(b)
                time.sleep(0.2)
                continue
            raise AssertionError(f"reader B unexpected status {status}")
        raise AssertionError("budget never deferred reader B (no overload)")
    finally:
        a.close()
        b.close()


def _overload_response(port, reader_b_ability=0x04):
    """Like _overload_wait_seconds but returns the full (status, body) of reader
    B's first DEFERRED response — kXR_wait (stall) or kXR_redirect. Reader B's
    login ability governs whether the §1.10 redirect is offered (kXR_readrdok)."""
    a = _login(port)
    b = _login(port, ability=reader_b_ability)
    try:
        fa = _open_read(a, "/big.bin")
        fb = _open_read(b, "/big.bin")
        _pgread_req(a, b"\x00\x02", fa, 0, BIG)
        first = _recv_exact(a, 8)
        assert first is not None, "reader A got no response"
        a_status = struct.unpack("!H", first[2:4])[0]
        assert a_status not in (kXR_wait, kXR_redirect), (
            f"budget starved reader A (status {a_status}) — admission slack broken")

        import time
        deadline = time.time() + 8
        while time.time() < deadline:
            _read_req(b, b"\x00\x03", fb, 0, B_READ)
            status, body = _resp(b)
            if status in (kXR_wait, kXR_redirect):
                return status, body
            if status in (kXR_ok, kXR_oksofar):
                while status == kXR_oksofar:
                    status, _ = _resp(b)
                time.sleep(0.2)
                continue
            raise AssertionError(f"reader B unexpected status {status}")
        raise AssertionError("budget never deferred reader B (no overload)")
    finally:
        a.close()
        b.close()


def test_overload_redirect(lifecycle, tmp_path):
    """(§1.10 redirect) with brix_fsoverload_redirect set, an overloaded read
    from a readrdok-capable client is answered with a kXR_redirect to the
    sibling host+port instead of a kXR_wait — offloading the read rather than
    parking the client here."""
    port = _start(lifecycle, tmp_path,
                  "brix_fsoverload_redirect sibling.example 2094;")
    status, body = _overload_response(port)          # reader B advertises readrdok
    assert status == kXR_redirect, (
        f"expected kXR_redirect on overload, got status {status}")
    assert len(body) >= 4
    rport = struct.unpack("!I", body[:4])[0]
    host = body[4:].decode(errors="replace")
    assert rport == 2094, f"redirect port {rport} != 2094"
    assert host == "sibling.example", f"redirect host {host!r} != sibling.example"


def test_overload_redirect_needs_readrdok(lifecycle, tmp_path):
    """(§1.3 parity) a client that did NOT advertise kXR_readrdok cannot follow a
    mid-read redirect, so even with brix_fsoverload_redirect configured its
    overloaded read degrades to the safe kXR_wait backoff rather than a redirect
    it would mishandle."""
    port = _start(lifecycle, tmp_path,
                  "brix_fsoverload_redirect sibling.example 2094;")
    status, body = _overload_response(port, reader_b_ability=0x00)
    assert status == kXR_wait, (
        f"non-readrdok client got status {status}, expected kXR_wait "
        "(redirect must not be handed to a client that can't follow it)")
    assert len(body) >= 4


def test_configured_stall_seconds(lifecycle, tmp_path):
    """(success) brix_fsoverload_stall 7: the overload kXR_wait says 7."""
    port = _start(lifecycle, tmp_path, "brix_fsoverload_stall 7;")
    assert _overload_wait_seconds(port) == 7


def test_default_stall_is_one(lifecycle, tmp_path):
    """(default) no directive: the overload kXR_wait still says 1."""
    port = _start(lifecycle, tmp_path, "")
    assert _overload_wait_seconds(port) == 1


def test_stall_clamped_by_max_delay(lifecycle, tmp_path):
    """(security-neg) fsoverload_stall 30 + max_delay 5: the stall is clamped
    to 5 — the overload backoff can never exceed the global ceiling."""
    port = _start(lifecycle, tmp_path,
                  "brix_fsoverload_stall 30; brix_max_delay 5;")
    assert _overload_wait_seconds(port) == 5
