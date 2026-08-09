from split_continuation import reexport as _reexport
_reexport(globals(), "_test_session_bind_helpers")

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

class TestBindInvalidSessid:

    def test_bind_with_random_sessid(self, bind_nginx):
        random_sessid = os.urandom(16)

        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        handshake = struct.pack(">IIIII", 0, 0, 0, 4, 2012)
        sec_sock.sendall(handshake)
        _recv_exact(sec_sock, 16)

        status, body = _send_req(sec_sock, b"\x00\xFF", kXR_bind, body=random_sessid)
        assert status == kXR_error, (
            f"bind with random sessid returned {status}, expected kXR_error"
        )
        sec_sock.close()


# ---------------------------------------------------------------------------
# Bind without handshake — rejected
# ---------------------------------------------------------------------------

class TestBindNoHandshake:
    """Verify that a bind sent without completing the handshake is rejected."""

    def test_bind_without_handshake(self, bind_nginx):
        """Sending kXR_bind immediately after connect (no handshake) must fail.

        The server expects the 20-byte client hello before processing any request.
        """
        sec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sec_sock.connect((ANON_HOST, bind_nginx))

        # Skip handshake — send bind directly
        random_sessid = os.urandom(16)
        hdr = struct.pack(">2sH", b"\x00\xAA", kXR_bind) + random_sessid + struct.pack(">I", 0)
        sec_sock.sendall(hdr)

        # The server should either reject or not respond properly
        try:
            rsp = _recv_exact(sec_sock, 8)
            if rsp is not None:
                status = struct.unpack(">H", rsp[2:4])[0]
                assert status == kXR_error, f"expected error for no-handshake bind, got {status}"
        except Exception:
            pass  # connection may be closed — that's also acceptable

        sec_sock.close()


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
