from split_continuation import reexport as _reexport
_reexport(globals(), "_test_session_bind_helpers")
_reexport(globals(), "_test_session_bind_helpers_b")

class TestBindValid:
    """Verify that a bind request with a valid primary session ID succeeds."""

    def test_bind_assigns_pathid(self, bind_nginx):
        """kXR_bind must return kXR_ok with a 1-byte pathid in the body."""
        primary_sock, sessid, _ = _establish_primary(bind_nginx)

        # Open a secondary connection and send bind
        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        # Handshake on secondary
        handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
        sec_sock.sendall(handshake)
        _recv_exact(sec_sock, 16)  # handshake response is 16 bytes

        # kXR_bind with primary sessid
        status, pathid_body = _send_req(sec_sock, b"\x00\x02", kXR_bind, body=sessid)
        assert status == kXR_ok, f"bind failed: status={status}"
        assert len(pathid_body) == 1, f"pathid body length {len(pathid_body)} != 1"

        pathid = pathid_body[0]
        assert 1 <= pathid <= 253, f"pathid {pathid} out of range [1, 253]"

        sec_sock.close()
        primary_sock.close()

    def test_bound_read_uses_primary_handle(self, bind_nginx):
        """A secondary may read a handle opened by the primary without login.

        This is the important xrdcp -S N behavior: the primary remains the
        control connection that opens the file, while bound data channels reuse
        that handle number for parallel reads.
        """
        content = b"hello-bind-test\x00"
        _write_data_file("bind-file.bin", content)

        primary_sock, sessid, primary_stream = _establish_primary(bind_nginx)
        primary_fh = _open_read(primary_sock, primary_stream, "/bind-file.bin")

        # Secondary connection — no login, just bind + read
        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
        sec_sock.sendall(handshake)
        _recv_exact(sec_sock, 16)  # handshake response is 16 bytes

        # Bind secondary to the primary session
        status, pathid_body = _send_req(sec_sock, b"\x00\x03", kXR_bind, body=sessid)
        assert status == kXR_ok

        status, data = _read_handle(sec_sock, b"\x00\x03", primary_fh,
                                    len(content))
        assert status == kXR_ok or status == kXR_oksofar
        assert data == content

        sec_sock.close()
        primary_sock.close()

    def test_bound_stream_cannot_open_its_own_file(self, bind_nginx):
        """Bound streams are read-only data channels, not independent sessions."""
        content = b"bound-open-forbidden\x00"
        _write_data_file("bind-open-forbidden.bin", content)

        primary_sock, sessid, _ = _establish_primary(bind_nginx)

        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
        sec_sock.sendall(handshake)
        _recv_exact(sec_sock, 16)

        status, _ = _send_req(sec_sock, b"\x00\x04", kXR_bind, body=sessid)
        assert status == kXR_ok

        open_body = struct.pack(">HH", 0o644, kXR_open_read) + b"\x00" * 12
        status, _ = _send_req(sec_sock, b"\x00\x04", kXR_open,
                              body=open_body,
                              payload=b"/bind-open-forbidden.bin\x00")
        assert status == kXR_error, "bound secondary unexpectedly opened a file"

        sec_sock.close()
        primary_sock.close()



class TestBindHandleSlotCache:

    def test_wiring_present(self):
        """The slot-hint cache + hinted lookup must be wired in."""
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]

        def rd(rel):
            return (root / rel).read_text(encoding="utf-8")

        assert "shared_handle_slot_hint" in rd("src/core/types/file.h")
        assert "shared_handle_slot_hint = -1" in rd("src/protocols/root/connection/handler.c")
        # Reset on free so a reopened/closed handle drops its stale slot.
        # phase-79 split: the free/teardown half of fd_table.c moved into
        # fd_table_teardown.c.
        assert "shared_handle_slot_hint = -1" in rd("src/protocols/root/connection/fd_table_teardown.c")
        # Hinted lookup keeps the full key check (in_use guards revocation).
        h = rd("src/protocols/root/session/handles.c")
        assert "brix_session_handle_lookup_hint" in h
        assert "brix_shared_handle_same_key" in h
        # The read path uses the hinted variant.
        assert "brix_session_handle_lookup_hint" in rd("src/protocols/root/connection/fd_table.c")

    def test_repeated_reads_cache_hit_byte_exact(self, bind_nginx):
        """Reads 2..N on a bound handle (the slot-hint fast path) stay byte-exact."""
        content = bytes(range(256)) * 8   # 2 KiB, non-trivial pattern
        _write_data_file("bind-cache.bin", content)

        primary_sock, sessid, pstream = _establish_primary(bind_nginx)
        primary_fh = _open_read(primary_sock, pstream, "/bind-cache.bin")

        sec_sock = _bind_secondary(bind_nginx, sessid, b"\x00\x31")
        try:
            # 12 successive reads exercise the hint cache repeatedly.
            for _ in range(12):
                status, data = _read_handle(sec_sock, b"\x00\x31", primary_fh,
                                            len(content))
                assert status in (kXR_ok, kXR_oksofar), status
                assert data == content, "cached-slot read returned wrong bytes"
        finally:
            sec_sock.close()
            primary_sock.close()

    def test_primary_close_revokes_cached_secondary(self, bind_nginx):
        """After the cache is warm, a primary close must revoke the secondary.

        This is the correctness invariant of the slot-hint cache: the hinted
        lookup still re-checks in_use under the lock, so unpublishing the handle
        (primary kXR_close) makes the cached slot fail the key match → the next
        secondary read is revoked instead of serving a stale handle.
        """
        content = b"revoke-after-warm-cache-9876543210\x00"
        _write_data_file("bind-revoke.bin", content)

        primary_sock, sessid, pstream = _establish_primary(bind_nginx)
        primary_fh = _open_read(primary_sock, pstream, "/bind-revoke.bin")

        sec_sock = _bind_secondary(bind_nginx, sessid, b"\x00\x32")
        try:
            # Warm the slot-hint cache with two good reads.
            for _ in range(2):
                status, data = _read_handle(sec_sock, b"\x00\x32", primary_fh,
                                            len(content))
                assert status in (kXR_ok, kXR_oksofar), status
                assert data == content

            # Primary closes the handle → unpublish clears the SHM slot in_use.
            status, _ = _send_req(primary_sock, pstream, kXR_close,
                                  body=primary_fh)
            assert status == kXR_ok, f"primary close failed: {status}"

            # The secondary's cached slot is now stale; its next read MUST be
            # revoked (not serve the file from the cached slot).
            status, data = _read_handle(sec_sock, b"\x00\x32", primary_fh,
                                        len(content))
            assert status == kXR_error, (
                f"stale cached handle served after primary close (status={status}, "
                f"{len(data)} bytes) — revocation invariant violated"
            )
        finally:
            sec_sock.close()
            primary_sock.close()


# ---------------------------------------------------------------------------
# Pathid cycling — multiple binds cycle through 1–253
# ---------------------------------------------------------------------------

class TestBindPathidCycling:
    """Verify that path IDs are assigned sequentially and cycle at 253."""

    def test_pathid_increments(self, bind_nginx):
        """Each successive bind must receive a different (incremented) pathid."""
        primary_sock, sessid, _ = _establish_primary(bind_nginx)

        pathids = []
        for i in range(5):
            sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sec_sock.connect((ANON_HOST, bind_nginx))

            handshake = struct.pack(">4I", 0, 0, 0, 4) + struct.pack(">I", 2012)
            sec_sock.sendall(handshake)
            _recv_exact(sec_sock, 16)  # handshake response is 16 bytes

            streamid = bytes([0, i + 10])
            status, pathid_body = _send_req(sec_sock, streamid, kXR_bind, body=sessid)
            assert status == kXR_ok
            pathids.append(pathid_body[0])
            sec_sock.close()
        primary_sock.close()

        # All pathids must be distinct and in range [1, 253]
        assert len(set(pathids)) == len(pathids), "duplicate pathids assigned"
        for p in pathids:
            assert 1 <= p <= 253, f"pathid {p} out of range"


# ---------------------------------------------------------------------------
# Invalid sessid — kXR_error response
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Secondary read with pathid tag
# ---------------------------------------------------------------------------

class TestBindWithPathidTag:
    """Verify that a secondary can read a primary handle after pathid assignment."""

    def test_read_with_pathid(self, bind_nginx):
        """A secondary connection must receive a pathid and still read the
        primary-published handle correctly.
        """
        content = b"bind-pathid-test-data\x00"
        _write_data_file("bind-pid.bin", content)

        primary_sock, sessid, primary_stream = _establish_primary(bind_nginx)
        primary_fh = _open_read(primary_sock, primary_stream, "/bind-pid.bin")

        # Secondary: bind + read with pathid tag
        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
        sec_sock.sendall(handshake)
        _recv_exact(sec_sock, 16)  # handshake response is 16 bytes

        status, pathid_body = _send_req(sec_sock, b"\x00\xBB", kXR_bind, body=sessid)
        assert status == kXR_ok
        pathid = pathid_body[0]
        assert 1 <= pathid <= 253

        status, data = _read_handle(sec_sock, b"\x00\xBB", primary_fh,
                                    len(content))
        assert status == kXR_ok or status == kXR_oksofar
        assert data == content

        sec_sock.close()
        primary_sock.close()


# ---------------------------------------------------------------------------
# Multiple binds on same primary — all succeed independently
# ---------------------------------------------------------------------------

class TestBindMultipleOnSamePrimary:
    """Verify that multiple secondary connections can bind to the same primary."""

    def test_multiple_secondaries_same_primary(self, bind_nginx):
        """Three secondary connections binding to the same primary must all
        receive distinct pathids and be able to operate independently.
        """
        primary_sock, sessid, _ = _establish_primary(bind_nginx)

        sec_socks = []
        pathids = []
        for i in range(3):
            sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sec_sock.connect((ANON_HOST, bind_nginx))

            handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
            sec_sock.sendall(handshake)
            _recv_exact(sec_sock, 16)  # handshake response is 16 bytes

            streamid = bytes([0, i + 1])
            status, pathid_body = _send_req(sec_sock, streamid, kXR_bind, body=sessid)
            assert status == kXR_ok
            pathids.append(pathid_body[0])
            sec_socks.append((sec_sock, streamid))

        # All must have distinct pathids
        assert len(set(pathids)) == 3, "pathids not distinct across secondaries"

        # Each secondary can independently ping (proves it's a valid session)
        for sock, sid in sec_socks:
            status, _ = _send_req(sock, sid, 3011)
            assert status == kXR_ok

        for sock, _ in sec_socks:
            sock.close()
        primary_sock.close()


# ---------------------------------------------------------------------------
# Ping constant used inline
# ---------------------------------------------------------------------------

kXR_ping = 3011


class TestReadPathidValidation:
    """§1.1 response-offloading slice 2a: a kXR_read's read_args pathid is now
    EXTRACTED and VALIDATED against the session's live kXR_bind paths, matching
    pgread/§1.2 — a read previously ignored the read_args entirely."""

    def test_read_pathid_zero_is_served(self, bind_nginx):
        """(baseline) a read whose read_args carry pathid 0 serves normally —
        pathid 0 is the primary/control stream, never validated away."""
        content = b"pathid-zero-ok__" * 4
        _write_data_file("pathid0.bin", content)
        primary, sessid, stream = _establish_primary(bind_nginx)
        try:
            fh = _open_read(primary, stream, "/pathid0.bin")
            status, data = _read_pathid(primary, stream, fh, len(content), 0)
            assert status in (kXR_ok, kXR_oksofar), f"status={status}"
            assert data == content
        finally:
            primary.close()

    def test_read_unbound_pathid_is_refused(self, bind_nginx):
        """(error) a read whose read_args name a pathid this session never bound
        is refused kXR_ArgInvalid ('invalid path ID'). Before this slice a read
        ignored the read_args and served it anyway (inconsistent with pgread)."""
        content = b"unbound-pathid__"
        _write_data_file("pathid-bad.bin", content)
        primary, sessid, stream = _establish_primary(bind_nginx)
        try:
            fh = _open_read(primary, stream, "/pathid-bad.bin")
            status, body = _read_pathid(primary, stream, fh, len(content), 99)
            assert status == kXR_error, f"expected kXR_error, got {status}"
            code = struct.unpack(">I", body[:4])[0]
            assert code == kXR_ArgInvalid, f"expected kXR_ArgInvalid, got {code}"
        finally:
            primary.close()

    # A read carrying a VALID bound pathid is accepted (not kXR_ArgInvalid) and
    # its response is routed over the secondary channel — that success path is
    # exercised end-to-end by TestReadResponseOffload below (slice 2b), which
    # supersedes the old "served on the primary" placeholder assertion.


class TestReadResponseOffload:
    """§1.1 slice 2b (do_Offload/do_OffloadIO parity): a read tagged with a live,
    same-worker bound pathid has its RESPONSE routed over the secondary data
    channel's socket — carrying the PRIMARY read request's streamid — instead of
    the primary control stream.  Ineligible reads (pathid 0, too large) stay on
    the primary."""

    def test_read_response_routed_to_secondary(self, bind_nginx):
        """(success) a small pathid-tagged read is answered on the secondary."""
        content = b"offload-payload-" * 64   # 1024 bytes, < one streaming window
        _write_data_file("offload.bin", content)
        primary, sessid, stream = _establish_primary(bind_nginx)
        sec = None
        try:
            fh = _open_read(primary, stream, "/offload.bin")
            sec, pathid = _bind_on(bind_nginx, sessid)
            assert pathid != 0

            read_stream = b"\x00\x07"
            _send_read_only(primary, read_stream, fh, len(content), pathid)

            # The response must arrive on the SECONDARY, tagged with the read's id.
            sec.settimeout(5)
            r_stream, r_status, data = _recv_response(sec)
            assert r_stream == read_stream, \
                f"offloaded resp streamid {r_stream!r} != read {read_stream!r}"
            assert r_status in (kXR_ok, kXR_oksofar), f"status={r_status}"
            assert data == content, "offloaded data mismatch"

            # ...and the primary control stream carried nothing for this read.
            primary.settimeout(0.3)
            try:
                leftover = primary.recv(1)
                assert leftover == b"", f"unexpected bytes on primary: {leftover!r}"
            except (BlockingIOError, socket.timeout):
                pass
        finally:
            if sec is not None:
                sec.close()
            primary.close()

    def test_pathid_zero_read_stays_on_primary(self, bind_nginx):
        """(control) offloading is strictly opt-in: a pathid-0 read serves on the
        primary even when the session has a live secondary channel."""
        content = b"stay-on-primary_" * 16
        _write_data_file("offload-zero.bin", content)
        primary, sessid, stream = _establish_primary(bind_nginx)
        sec = None
        try:
            fh = _open_read(primary, stream, "/offload-zero.bin")
            sec, pathid = _bind_on(bind_nginx, sessid)   # a channel EXISTS...
            assert pathid != 0

            read_stream = b"\x00\x0b"
            _send_read_only(primary, read_stream, fh, len(content), 0)  # ...but pathid 0

            primary.settimeout(5)
            r_stream, r_status, data = _recv_response(primary)
            assert r_stream == read_stream, f"streamid {r_stream!r}"
            assert r_status in (kXR_ok, kXR_oksofar), f"status={r_status}"
            assert data == content

            sec.settimeout(0.3)
            try:
                leftover = sec.recv(1)
                assert leftover == b"", f"unexpected bytes on secondary: {leftover!r}"
            except (BlockingIOError, socket.timeout):
                pass
        finally:
            if sec is not None:
                sec.close()
            primary.close()

    def test_large_read_falls_back_to_primary(self, bind_nginx):
        """(fallback) a read larger than one streaming window is ineligible for
        offload and is served (windowed) on the primary, not the secondary."""
        big = b"x" * (2 * 1024 * 1024 + 4096)   # > BRIX_READ_WINDOW (2 MiB)
        _write_data_file("offload-big.bin", big)
        with _offload_rig(bind_nginx, "/offload-big.bin") as (primary, sec,
                                                              pathid, fh):
            read_stream = b"\x00\x09"
            _send_read_only(primary, read_stream, fh, len(big), pathid)

            # Served on the PRIMARY as one or more windowed chunks.
            got = _recv_windowed(primary, read_stream, len(big))
            assert got == big, f"windowed primary read {len(got)} != {len(big)}"
            _assert_socket_quiet(sec, "secondary")


class TestReadvResponseOffload:
    """§1.1 for kXR_readv: the pathid rides the request HEADER body (byte 15),
    not the payload. It is validated like read/pgread, and an eligible readv's
    (multi-segment) response is routed over the bound secondary channel carrying
    the primary request's streamid."""

    def test_readv_unbound_pathid_is_refused(self, bind_nginx):
        """(error) a readv naming a pathid this session never bound is refused
        kXR_ArgInvalid — readv previously ignored the pathid entirely."""
        content = b"readv-unbound___" * 8
        _write_data_file("rv-bad.bin", content)
        primary, sessid, stream = _establish_primary(bind_nginx)
        try:
            fh = _open_read(primary, stream, "/rv-bad.bin")
            segs = [_readv_seg(fh, 32, 0), _readv_seg(fh, 32, 64)]
            _send_readv_only(primary, b"\x00\x21", segs, pathid=99)
            r_stream, r_status, body = _recv_response(primary)
            assert r_status == kXR_error, f"expected kXR_error, got {r_status}"
            code = struct.unpack(">I", body[:4])[0]
            assert code == kXR_ArgInvalid, f"expected kXR_ArgInvalid, got {code}"
        finally:
            primary.close()

    def test_readv_response_routed_to_secondary(self, bind_nginx):
        """(success) a small readv tagged with a bound pathid is answered on the
        secondary, carrying the read's streamid; the stripped payload matches."""
        content = bytes((i * 7) & 0xFF for i in range(300))
        _write_data_file("rv-ok.bin", content)
        with _offload_rig(bind_nginx, "/rv-ok.bin") as (primary, sec,
                                                        pathid, fh):
            segs = [_readv_seg(fh, 100, 0), _readv_seg(fh, 100, 100),
                    _readv_seg(fh, 100, 200)]
            read_stream = b"\x00\x23"
            _send_readv_only(primary, read_stream, segs, pathid=pathid)

            _, body = _assert_streamed_reply(sec, read_stream)
            assert _readv_payload_bytes(body, 3) == content, "readv payload mismatch"
            _assert_socket_quiet(primary, "primary")

    def test_readv_pathid_zero_stays_on_primary(self, bind_nginx):
        """(control) a pathid-0 readv serves on the primary even with a live
        secondary bound."""
        content = bytes((i * 3) & 0xFF for i in range(200))
        _write_data_file("rv-zero.bin", content)
        with _offload_rig(bind_nginx, "/rv-zero.bin") as (primary, sec,
                                                          pathid, fh):
            segs = [_readv_seg(fh, 100, 0), _readv_seg(fh, 100, 100)]
            read_stream = b"\x00\x25"
            _send_readv_only(primary, read_stream, segs, pathid=0)

            _, body = _assert_streamed_reply(primary, read_stream)
            assert _readv_payload_bytes(body, 2) == content
            _assert_socket_quiet(sec, "secondary")


class TestPgreadResponseOffload:
    """§1.1 for kXR_pgread: pgread already validates its pathid (§1.2); an
    eligible pgread reply — the [32B kXR_status frame | CRC-interleaved page
    data] — is now routed over the bound secondary carrying the primary
    request's streamid."""

    def test_pgread_unbound_pathid_is_refused(self, bind_nginx):
        """(error) an unbound pathid is still refused kXR_ArgInvalid (validation
        runs before offload)."""
        content = b"pgread-unbound__" * 8
        _write_data_file("pg-bad.bin", content)
        primary, sessid, stream = _establish_primary(bind_nginx)
        try:
            fh = _open_read(primary, stream, "/pg-bad.bin")
            _send_pgread_only(primary, b"\x00\x31", fh, len(content), pathid=99)
            r_stream, r_status, _ = _recv_pgread_response(primary)
            # An error reply is a plain kXR_error frame (not kXR_status).
            assert r_status == kXR_error, f"expected kXR_error, got {r_status}"
        finally:
            primary.close()

    def test_pgread_response_routed_to_secondary(self, bind_nginx):
        """(success) a small pgread tagged with a bound pathid is answered on the
        secondary; the stripped page data matches and the streamid is the read's."""
        content = bytes((i * 5 + 1) & 0xFF for i in range(500))   # < one page
        _write_data_file("pg-ok.bin", content)
        with _offload_rig(bind_nginx, "/pg-ok.bin") as (primary, sec,
                                                        pathid, fh):
            read_stream = b"\x00\x33"
            _send_pgread_only(primary, read_stream, fh, len(content), pathid=pathid)

            sec.settimeout(5)
            r_stream, r_status, data = _recv_pgread_response(sec)
            assert r_stream == read_stream, \
                f"offloaded pgread streamid {r_stream!r} != {read_stream!r}"
            assert r_status == kXR_status, f"status={r_status}"
            assert data == content, "offloaded pgread data mismatch"
            _assert_socket_quiet(primary, "primary")

    def test_pgread_pathid_zero_stays_on_primary(self, bind_nginx):
        """(control) a pathid-0 pgread serves on the primary even with a live
        secondary bound."""
        content = bytes((i * 9 + 2) & 0xFF for i in range(400))
        _write_data_file("pg-zero.bin", content)
        with _offload_rig(bind_nginx, "/pg-zero.bin") as (primary, sec,
                                                          pathid, fh):
            read_stream = b"\x00\x35"
            _send_pgread_only(primary, read_stream, fh, len(content), pathid=0)

            primary.settimeout(5)
            r_stream, r_status, data = _recv_pgread_response(primary)
            assert r_stream == read_stream, f"streamid {r_stream!r}"
            assert r_status == kXR_status, f"status={r_status}"
            assert data == content
            _assert_socket_quiet(sec, "secondary")


class TestOffloadPipelining:
    """§1.1: offloaded replies PIPELINE behind a secondary's existing responses
    (up to ring capacity) instead of only when the channel is idle — so a burst of
    pathid reads on the primary all land on the data channel even while an earlier
    large reply is still draining. This is what a real multi-stream data channel
    looks like."""

    def test_second_offload_queues_behind_a_parked_first(self, bind_nginx):
        # A large first reply parks on the server's out-ring (out.count>0) when it
        # can't be flushed inline; a second pathid read must then STILL offload
        # (queue behind it) under the relaxed ring-space gate — the old idle-only
        # gate fell it back to the primary. DISCRIMINATOR: the second reply arrives
        # on the SECONDARY, primary stays empty. NOTE: forcing the first reply to
        # park requires the SERVER's send buffer to be constrained (the offload
        # cap is < the autotuned 4 MiB sndbuf, so a normal server swallows the
        # whole reply inline and out.count stays 0). The standalone validation
        # harness sets `listen ... sndbuf=8k` for exactly this; against a default
        # server this still asserts pipelined offloads arrive byte-exact, just
        # without exercising the queued-behind boundary. The tiny client RCVBUF
        # closes the receive window so the constrained sndbuf fills promptly.
        big = bytes((i * 13 + 7) & 0xFF for i in range(512 * 1024))   # < WINDOW
        small = b"pipelined-second" * 4
        _write_data_file("pl-big.bin", big)
        _write_data_file("pl-small.bin", small)
        primary, sessid, stream = _establish_primary(bind_nginx)
        with contextlib.closing(primary):
            fh_big = _open_read(primary, stream, "/pl-big.bin")
            fh_small = _open_read(primary, stream, "/pl-small.bin")

            # Secondary with a tiny receive window so the big reply cannot drain.
            sec, pathid = _bind_small_window(bind_nginx, sessid)
            with contextlib.closing(sec):
                # read1 (big) parks on the secondary; read2 (small) must queue
                # behind it.
                _send_read_only(primary, b"\x00\x41", fh_big, len(big), pathid)
                _send_read_only(primary, b"\x00\x43", fh_small, len(small), pathid)

                # Neither reply may appear on the primary control stream.
                _assert_socket_quiet(primary, "primary (fallback)", timeout=0.5)

                # Drain the secondary: the big reply (head) then the small one.
                _, d1 = _assert_streamed_reply(sec, b"\x00\x41", timeout=15)
                assert d1 == big, f"big reply {len(d1)} != {len(big)}"
                _, d2 = _assert_streamed_reply(sec, b"\x00\x43", timeout=15)
                assert d2 == small, "second (pipelined) reply payload mismatch"
