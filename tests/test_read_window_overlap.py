"""Round 12 — double-buffered windowed reads: mixed-size burst admission.

A kXR_read / kXR_pgread larger than one streaming window (BRIX_READ_WINDOW,
2 MiB) is served as a train of frames whose windows overlap read and send via
a worker-thread read-ahead (src/core/aio/reads_window.c).  A train owns the
connection's request/send state machine for its whole duration, so it must
START quiescent: the recv admission gate (brix_recv_should_defer,
src/protocols/root/connection/recv_process.c) defers a would-be train while
pipelined single-shot reads or writes are still in flight — a straggler
completion arriving mid-train would otherwise resume recv under it.

These tests drive that seam with hand-built wire bursts sent in ONE write:

  * success   — a burst mixing small pipelined reads (both opcodes) with a
                plain-read train AND a pgread train: every response byte-exact,
                trains contiguous per streamid, session alive
  * error     — a bad-handle WINDOWED pgread sandwiched between small ones:
                fails alone, neighbours intact, session alive
  * security  — kXR_close pipelined behind a small read + a train: the handle
                must survive both the straggler AND the whole train (drain
                barrier on rd.aio_inflight), data intact, close succeeds last

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_read_window_overlap.py -v
"""

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_pgread_wire_conformance_helpers")

kXR_oksofar = 4000
kXR_FinalResult = 0
STATUS_BODY_RESPTYPE_OFF = 7   # resptype byte in the 24-byte status body

OVL_NAME = "/test_read_window_overlap.bin"
OVL_SIZE = 7 * 1024 * 1024 + 12345         # tail keeps EOF non-page-aligned
_OVL_BLK = bytes((i * 197 + 43) & 0xFF for i in range(65536))
OVL_PATTERN = (_OVL_BLK * (OVL_SIZE // len(_OVL_BLK) + 1))[:OVL_SIZE]

TRAIN = 3 * 1024 * 1024                    # > BRIX_READ_WINDOW => 2-window train
SMALL = 8192                               # <= window => pipelined single frame


@pytest.fixture(scope="module")
def ovl_file():
    """A file big enough for two disjoint 3 MiB trains plus small reads."""
    try:
        os.makedirs(DATA_ROOT, exist_ok=True)
        full = os.path.join(DATA_ROOT, OVL_NAME.lstrip("/"))
        if not (os.path.exists(full) and os.path.getsize(full) == OVL_SIZE):
            with open(full, "wb") as f:
                f.write(OVL_PATTERN)
    except OSError as exc:
        pytest.skip(f"server data root {DATA_ROOT!r} not locally writable: "
                    f"{exc}")
    return OVL_NAME


@pytest.fixture
def ovl_handle(ovl_file):
    """Open the overlap data file read-only; yield (sock, fhandle)."""
    sock = _session()
    _, status, body = _open(sock, ovl_file, kXR_open_read)
    assert status == kXR_ok, "read-open of overlap data file failed"
    fhandle = body[:4]
    try:
        yield sock, fhandle
    finally:
        try:
            _close(sock, fhandle)
        except Exception:
            pass
        sock.close()


def _req(reqid, fhandle, offset, rlen, streamid):
    """Encode one read-family request frame (kXR_read and kXR_pgread share the
    fhandle/offset/rlen layout) without sending it."""
    return struct.pack("!2sH4sqiI", streamid, reqid, fhandle, offset, rlen, 0)


def _accum(got, sid, status, data):
    """Append data to sid's accumulated response under the latest status."""
    prev = got.get(sid)
    got[sid] = (status, (prev[1] if prev else b"") + data)


def _drain_status_frame(sock, got, sid, body):
    """One kXR_status frame: pull its separate page stream off the wire and
    accumulate it; True when resptype closes sid's train."""
    assert len(body) >= STATUS_BODY_MIN_LEN, "short status body"
    bdy_dlen = struct.unpack(
        "!i", body[STATUS_BODY_DLEN_OFF:STATUS_BODY_DLEN_OFF + 4])[0]
    _accum(got, sid, kXR_status,
           _recv_exact(sock, bdy_dlen) if bdy_dlen > 0 else b"")
    return body[STATUS_BODY_RESPTYPE_OFF] == kXR_FinalResult


def _drain_mixed(sock, n):
    """Collect n complete responses of MIXED framing into {sid: (status, data)}.

    kXR_status frames (pgread) accumulate their separate page stream per sid
    until resptype says final; kXR_oksofar frames (plain-read train) accumulate
    their body until the closing kXR_ok; a lone kXR_ok or kXR_error completes
    immediately.  Trains self-serialize on the stream, so per-sid accumulation
    reassembles each one exactly.
    """
    got = {}
    done = 0
    while done < n:
        sid, status, body = _read_response(sock)
        if status == kXR_status:
            done += _drain_status_frame(sock, got, sid, body)
        elif status in (kXR_oksofar, kXR_ok):
            _accum(got, sid, status, body)
            done += status == kXR_ok
        else:
            got[sid] = (status, body)
            done += 1
    return got


def _expect_extent(got, sid, offset, rlen, pgread):
    """One response must be a success of its opcode's framing and byte-exact
    against OVL_PATTERN at its own extent."""
    assert sid in got, f"no response for sid {sid.hex()}"
    status, data = got[sid]
    if pgread:
        assert status == kXR_status, f"sid {sid.hex()}: status {status}"
        data = _decode_pages(data, first_offset=offset)
    else:
        assert status == kXR_ok, f"sid {sid.hex()}: status {status}"
    assert data == OVL_PATTERN[offset:offset + rlen], (
        f"sid {sid.hex()}: data mismatch ({len(data)} bytes)")


class TestReadWindowOverlap:
    """Round-12 mixed-size burst admission + double-buffered train integrity."""

    def test_mixed_burst_trains_after_stragglers(self, ovl_handle):
        """SUCCESS: small pipelined reads of BOTH opcodes in flight when a
        plain-read train AND a pgread train arrive in the same burst: the
        trains defer until the stragglers drain, then stream contiguously;
        every one of the five responses is byte-exact."""
        sock, fh = ovl_handle
        reqs = [
            (kXR_pgread, b"\x00\x51", 0,               SMALL),
            (kXR_read,   b"\x00\x52", 64 * 1024,       SMALL),
            (kXR_read,   b"\x00\x53", 1024 * 1024,     TRAIN),
            (kXR_pgread, b"\x00\x54", 4 * 1024 * 1024, TRAIN),
            (kXR_pgread, b"\x00\x55", 128 * 1024,      SMALL),
        ]
        sock.sendall(b"".join(_req(op, fh, off, rl, sid)
                              for op, sid, off, rl in reqs))
        got = _drain_mixed(sock, len(reqs))
        for op, sid, off, rl in reqs:
            _expect_extent(got, sid, off, rl, pgread=(op == kXR_pgread))
        assert _ping(sock)[1] == kXR_ok

    def test_bad_handle_train_mid_burst_isolated(self, ovl_handle):
        """ERROR: a WINDOWED pgread on a bogus handle sandwiched between two
        small good ones: the deferred train fails alone with kXR_error; both
        neighbours deliver intact data and the session survives."""
        sock, fh = ovl_handle
        sock.sendall(_req(kXR_pgread, fh, 0, SMALL, b"\x00\x61")
                     + _req(kXR_pgread, b"\xde\xad\xbe\xef", 0, TRAIN,
                            b"\x00\x62")
                     + _req(kXR_pgread, fh, 256 * 1024, SMALL, b"\x00\x63"))
        got = _drain_mixed(sock, 3)
        assert got[b"\x00\x62"][0] == kXR_error, (
            f"bad handle: expected kXR_error, got {got[b'\x00\x62'][0]}")
        _expect_extent(got, b"\x00\x61", 0, SMALL, pgread=True)
        _expect_extent(got, b"\x00\x63", 256 * 1024, SMALL, pgread=True)
        assert _ping(sock)[1] == kXR_ok

    def test_close_behind_straggler_and_train(self, ovl_file):
        """SECURITY-NEG: kXR_close pipelined behind a small read AND a train
        in one burst must not retire the handle under either — the close's
        drain barrier waits on the straggler's worker (rd.aio_inflight) and
        the train's whole run.  Both reads land byte-exact, then the close
        succeeds as the LAST response."""
        sock = _session()
        _, status, body = _open(sock, ovl_file, kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        close_req = struct.pack("!2sH4s12sI", b"\x00\x73", kXR_close, fh,
                                b"\x00" * 12, 0)
        sock.sendall(_req(kXR_read, fh, 0, SMALL, b"\x00\x71")
                     + _req(kXR_pgread, fh, 1024 * 1024, TRAIN, b"\x00\x72")
                     + close_req)
        got = _drain_mixed(sock, 2)
        _expect_extent(got, b"\x00\x71", 0, SMALL, pgread=False)
        _expect_extent(got, b"\x00\x72", 1024 * 1024, TRAIN, pgread=True)
        sid, status, _ = _read_response(sock)
        assert sid == b"\x00\x73" and status == kXR_ok, (
            f"deferred close failed: sid {sid.hex()} status {status}")
        sock.close()
