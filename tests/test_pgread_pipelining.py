from split_continuation import reexport as _reexport
_reexport(globals(), "_test_pgread_wire_conformance_helpers")

# ---------------------------------------------------------------------------
# kXR_pgread pipelining (round-6): several pgreads sent back-to-back on one
# stream are admitted concurrently — each reads into its own rd_pool slot on a
# thread-pool worker while earlier responses drain (recv gates in
# src/protocols/root/connection/recv_process.c, per-slot AIO tasks in
# src/protocols/root/read/pgread.c).  Responses are multiplexed: the protocol
# guarantees matching by streamid, NOT arrival order, so every test here
# buckets responses by sid.
#
# A pgread larger than one streaming window (BRIX_READ_WINDOW, 2 MiB) is
# served as a TRAIN of kXR_status frames (kXR_PartialResult ... final,
# pgread_window.c) whose windows self-serialize on the stream: recv stays
# suspended for the whole train, so the burst's remaining requests queue in
# the socket and are answered train-after-train.  ≤ 2 MiB requests keep the
# classic pipelined single-frame path.  The drains below reassemble per-sid
# trains, so both shapes verify byte-exact.
# ---------------------------------------------------------------------------

PIPE_NAME = "/test_pgread_pipelining.bin"
PIPE_SIZE = 16 * 1024 * 1024 + 12345          # tail keeps EOF non-page-aligned
_PIPE_BLK = bytes((i * 131 + 17) & 0xFF for i in range(65536))
PIPE_PATTERN = (_PIPE_BLK * (PIPE_SIZE // len(_PIPE_BLK) + 1))[:PIPE_SIZE]

CHUNK = 3 * 1024 * 1024                # > BRIX_READ_WINDOW => windowed train

STATUS_BODY_RESPTYPE_OFF = 7           # resptype byte in the 24-byte status body
kXR_FinalResult   = 0
kXR_PartialResult = 1


@pytest.fixture(scope="module")
def pipe_file():
    """A file large enough that pipelined pgreads take the thread-pool path."""
    try:
        os.makedirs(DATA_ROOT, exist_ok=True)
        full = os.path.join(DATA_ROOT, PIPE_NAME.lstrip("/"))
        if not (os.path.exists(full)
                and os.path.getsize(full) == PIPE_SIZE):
            with open(full, "wb") as f:
                f.write(PIPE_PATTERN)
    except OSError as exc:
        pytest.skip(f"server data root {DATA_ROOT!r} not locally writable: "
                    f"{exc}")
    return PIPE_NAME


@pytest.fixture
def pipe_handle(pipe_file):
    """Open the large file read-only; yield (sock, fhandle); always clean up."""
    sock = _session()
    _, status, body = _open(sock, pipe_file, kXR_open_read)
    assert status == kXR_ok, "read-open of pipelining data file failed"
    fhandle = body[:4]
    try:
        yield sock, fhandle
    finally:
        try:
            _close(sock, fhandle)
        except Exception:
            pass
        sock.close()


def _pg_req(fhandle, offset, rlen, streamid):
    """Encode one ClientPgReadRequest frame without sending it."""
    return struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                       offset, rlen, 0)


def _drain_one(sock):
    """Read ONE pgread response frame (header + status body + page stream).

    Returns (sid, status, resptype, pages); resptype is only meaningful for
    kXR_status frames — kXR_FinalResult ends that sid's train (a classic
    single-frame reply carries it too), kXR_PartialResult promises more.
    """
    sid, status, body = _read_response(sock)
    pages = b""
    resptype = kXR_FinalResult
    if status == kXR_status and len(body) >= STATUS_BODY_MIN_LEN:
        resptype = body[STATUS_BODY_RESPTYPE_OFF]
        bdy_dlen = struct.unpack(
            "!i", body[STATUS_BODY_DLEN_OFF:STATUS_BODY_DLEN_OFF + 4])[0]
        if bdy_dlen > 0:
            pages = _recv_exact(sock, bdy_dlen)
    return sid, status, resptype, pages


def _drain_train(sock, want_sid):
    """Drain one sid's complete train; return its concatenated page bytes.
    Asserts every frame is kXR_status and belongs to want_sid."""
    pages = b""
    while True:
        sid, status, resptype, pg = _drain_one(sock)
        assert sid == want_sid, f"expected sid {want_sid.hex()}, got {sid.hex()}"
        assert status == kXR_status, f"train frame status {status}"
        pages += pg
        if resptype == kXR_FinalResult:
            return pages


def _drain_many(sock, n):
    """Collect n complete responses into {sid: (status, pages)}.

    Order-agnostic across responses; a windowed train's frames for one sid
    are contiguous (the train self-serializes), so per-sid accumulation until
    kXR_FinalResult reassembles it exactly.
    """
    got = {}
    done = 0
    while done < n:
        sid, status, resptype, pages = _drain_one(sock)
        if status == kXR_status:
            prev = got.get(sid)
            got[sid] = (status, (prev[1] if prev else b"") + pages)
            if resptype == kXR_FinalResult:
                done += 1
        else:
            got[sid] = (status, pages)
            done += 1
    return got


def _verify_burst(got, reqs):
    """Every request in the burst must have a kXR_status response whose
    decoded pages are byte-exact against PIPE_PATTERN at its own extent."""
    for sid, off, rl in reqs:
        assert sid in got, f"no response for sid {sid.hex()}"
        status, pages = got[sid]
        assert status == kXR_status, (
            f"sid {sid.hex()}: expected kXR_status, got {status}")
        data = _decode_pages(pages, first_offset=off)
        assert data == PIPE_PATTERN[off:off + rl], (
            f"sid {sid.hex()}: data mismatch ({len(data)} bytes)")


class TestPgreadPipelining:
    """Concurrency behaviour of back-to-back kXR_pgread requests."""

    def test_pipelined_burst_every_response_correct(self, pipe_handle):
        """SUCCESS: five over-window pgreads sent in one write are all
        answered, each as its own complete train with its own streamid and
        byte-exact CRC-verified data — no bleed between requests."""
        sock, fh = pipe_handle
        reqs = [(bytes([0, 0x40 + i]), i * CHUNK, CHUNK) for i in range(5)]
        sock.sendall(b"".join(_pg_req(fh, off, rl, sid)
                              for sid, off, rl in reqs))
        got = _drain_many(sock, len(reqs))
        _verify_burst(got, reqs)
        assert _ping(sock)[1] == kXR_ok

    def test_error_mid_burst_isolated(self, pipe_handle):
        """ERROR: a bad-handle pgread sandwiched between two good ones fails
        alone with kXR_error; both neighbours still deliver intact data and
        the session survives."""
        sock, fh = pipe_handle
        sock.sendall(_pg_req(fh, 0, CHUNK, b"\x00\x71")
                     + _pg_req(b"\xde\xad\xbe\xef", 0, PG_PAGESZ, b"\x00\x72")
                     + _pg_req(fh, CHUNK, CHUNK, b"\x00\x73"))
        got = _drain_many(sock, 3)
        assert got[b"\x00\x72"][0] == kXR_error, (
            f"bad handle: expected kXR_error, got {got[b'\x00\x72'][0]}")
        for sid, off in ((b"\x00\x71", 0), (b"\x00\x73", CHUNK)):
            status, pages = got[sid]
            assert status == kXR_status, (
                f"neighbour {sid.hex()} poisoned: status {status}")
            assert _decode_pages(pages, first_offset=off) \
                == PIPE_PATTERN[off:off + CHUNK]
        assert _ping(sock)[1] == kXR_ok

    def test_close_pipelined_behind_inflight_pgread(self, pipe_file):
        """SECURITY-NEG: a kXR_close sent back-to-back behind a large pgread
        must NOT retire the handle out from under the read — the windowed
        train suspends recv until its final frame (and the classic path's
        drain barrier holds likewise), so the close is only seen after the
        read lands.  The pgread's data must be intact and the close must
        still succeed afterwards."""
        sock = _session()
        _, status, body = _open(sock, pipe_file, kXR_open_read)
        assert status == kXR_ok
        fh = body[:4]
        close_req = struct.pack("!2sH4s12sI", b"\x00\x82", kXR_close, fh,
                                b"\x00" * 12, 0)
        sock.sendall(_pg_req(fh, 0, 2 * CHUNK, b"\x00\x81") + close_req)

        pages = _drain_train(sock, b"\x00\x81")
        assert _decode_pages(pages, first_offset=0) \
            == PIPE_PATTERN[:2 * CHUNK], "handle retired mid-read"

        sid, status, _ = _read_response(sock)
        assert sid == b"\x00\x82" and status == kXR_ok, (
            f"deferred close failed: sid {sid.hex()} status {status}")
        sock.close()

    def test_deep_burst_beyond_pipeline_depth(self, pipe_handle):
        """SUCCESS/backpressure: 20 pipelined pgreads — 2.5x the default
        pipeline depth — all complete correctly; the recv-loop bound
        (out.count + wr_inflight + aio_inflight < depth) throttles admission
        without dropping or corrupting anything."""
        sock, fh = pipe_handle
        reqs = [(bytes([1, i]), (i * 977 * 1024) % (PIPE_SIZE - 2 ** 20),
                 1024 * 1024) for i in range(20)]
        sock.sendall(b"".join(_pg_req(fh, off, rl, sid)
                              for sid, off, rl in reqs))
        got = _drain_many(sock, len(reqs))
        _verify_burst(got, reqs)
        assert _ping(sock)[1] == kXR_ok
