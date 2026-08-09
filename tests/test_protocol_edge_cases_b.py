from split_continuation import reexport as _reexport
_reexport(globals(), "_test_protocol_edge_cases_helpers")

class TestConnectionResilience:
    """The server should keep the connection alive after non-fatal errors."""

    def test_connection_survives_stat_nonexistent(self):
        """A stat on a nonexistent file should not close the connection."""
        with _raw_session() as sock:
            _login_anon(sock)

            # stat a missing file
            payload = b"/nonexistent_proto_resilience.txt"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
            assert status == kXR_ERROR

            # Connection should still work
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

    def test_connection_survives_invalid_handle(self):
        """Reading an invalid handle should not close the connection."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Read from invalid handle
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x02", kXR_read,
                b"\xfe\x00\x00\x00", 0, 100, 0,
            )
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_ERROR

            # Verify connection is still alive
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

    def test_connection_survives_multiple_errors(self):
        """Multiple consecutive errors should not accumulate state corruption."""
        with _raw_session() as sock:
            _login_anon(sock)

            for i in range(5):
                payload = f"/nonexistent_{i}.txt".encode()
                sid = struct.pack("!H", i + 2)
                req = struct.pack(
                    "!2sH1s7sI4sI",
                    sid, kXR_stat,
                    b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, _ = _read_response(sock)
                assert status == kXR_ERROR

            # Connection should still work after 5 errors
            req = struct.pack("!2sH16sI", b"\x00\x0a", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK


# ===========================================================================
# Query edge cases
# ===========================================================================

class TestQueryEdgeCases:
    """Edge cases for kXR_query infotypes."""

    def test_unsupported_query_infotype(self):
        """An unsupported query infotype should return an error."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/"
            req = struct.pack(
                "!2sHH2s4s8sI",
                b"\x00\x02", kXR_query,
                9999,             # invalid infotype
                b"\x00\x00",
                b"\x00" * 4,
                b"\x00" * 8,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        assert status == kXR_ERROR

    @pytest.mark.skipif(
        CROSS_BACKEND == "xrootd",
        reason="reference xrootd test fixture does not enable checksum queries by default",
    )
    def test_checksum_via_api(self):
        """Checksum query via XRootD API should work on test.txt."""
        fs = client.FileSystem(ANON_URL)
        status, resp = fs.query(QueryCode.CHECKSUM, "/test.txt")
        assert status.ok
        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "adler32"
        assert len(hexval) == 8

    def test_space_query_positive_values(self):
        """Space query should return positive numeric values."""
        fs = client.FileSystem(ANON_URL)
        status, resp = fs.query(QueryCode.SPACE, "/")
        assert status.ok
        text = resp.rstrip(b"\x00").decode()
        for pair in text.split("&"):
            if "=" in pair:
                key, val = pair.split("=", 1)
                if key in ("oss.space", "oss.free", "oss.used"):
                    assert int(val) >= 0, f"{key} has negative value: {val}"
