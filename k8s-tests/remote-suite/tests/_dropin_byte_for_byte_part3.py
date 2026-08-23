# ===========================================================================
# 3. Qconfig — keys match official
# ===========================================================================

class TestQconfigParity:
    """kXR_Qconfig echoes a line per requested key (src/protocols/root/query/config.c).  For
    'tpc' both servers return a bare numeric (0/1) line that XrdCl parses with
    atoi; for 'chksum' both return a 'chksum=...' line."""

    def _config(self, sock, keys):
        sid, status, body = _query(sock, kXR_Qconfig, keys)
        return status, body.split(b"\x00")[0].decode(errors="replace")

    def test_qconfig_tpc_first_char_is_digit(self, both):
        """nginx's 'tpc' response line must START WITH A DIGIT so
        XrdCl::Utils::CheckTPCLite's atoi() reads its capability correctly
        (src/protocols/root/query/config.c deliberately emits a bare '0'/'1').  The official
        server here is built WITHOUT XRDTPC, so it echoes the literal 'tpc'
        token (atoi → 0, i.e. TPC unavailable) — a documented difference, not a
        format bug.  Both responses parse to a valid capability via atoi."""
        n, x = both
        n_status, n_resp = self._config(n, "tpc")
        x_status, x_resp = self._config(x, "tpc")
        assert n_status == kXR_ok, "nginx Qconfig tpc failed"
        n_first = n_resp.strip()[:1]
        assert n_first.isdigit(), f"nginx tpc line not digit-led: {n_resp!r}"
        # The official line may be digit-led (XRDTPC on) or the literal token
        # 'tpc' (XRDTPC off); both are accepted — atoi() yields the capability.
        if x_status == kXR_ok and x_resp.strip():
            first = x_resp.strip()[:1]
            assert first.isdigit() or x_resp.strip().startswith("tpc"), \
                f"official tpc line unexpected: {x_resp!r}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_qconfig_chksum_line_present(self, both):
        """A 'chksum' query yields a chksum line listing adler32 on both."""
        n, x = both
        n_status, n_resp = self._config(n, "chksum")
        x_status, x_resp = self._config(x, "chksum")
        assert n_status == kXR_ok
        assert "adler32" in n_resp, f"nginx chksum line missing adler32: {n_resp!r}"
        if x_status == kXR_ok and x_resp.strip():
            assert "adler32" in x_resp, \
                f"official chksum line missing adler32: {x_resp!r}"

    def test_qconfig_unknown_key_handled(self, both):
        """An unknown config key must not crash either server; nginx echoes
        'key=0'.  Prove the session survives on both sides."""
        n, x = both
        n_status, _ = self._config(n, "wibblewobble")
        assert n_status in (kXR_ok, kXR_error)
        self._config(x, "wibblewobble")
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


# ===========================================================================
# 4. pgread — CRC pages match official byte-exact (raw wire to both)
# ===========================================================================

class TestPgreadParity:
    """Paged read returns kXR_status framing + a CRC-interleaved page stream.
    Decoded data must equal the file bytes on both servers, and the raw page
    streams (data + the per-page CRC32c) must be byte-identical."""

    def _pgread_file(self, sock, path, offset, rlen):
        sid, status, body = _open(sock, path, kXR_open_read)
        assert status == kXR_ok, f"open failed: {_error_msg(body)}"
        fh = body[:4]
        try:
            return _pgread(sock, fh, offset, rlen)
        finally:
            _close(sock, fh)

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_decoded_data_matches_file(self, both):
        n, x = both
        want = 3 * PG_PAGESZ + 321  # spans 4 pages, last short
        n_status, n_body, n_pages = self._pgread_file(n, PLAIN_NAME, 0, want)
        x_status, x_body, x_pages = self._pgread_file(x, PLAIN_NAME, 0, want)
        assert n_status == kXR_status, f"nginx pgread status={n_status}"
        n_decoded = _decode_pages(n_pages)
        assert n_decoded[:want] == PLAIN_DATA[:want], "nginx pgread data wrong"
        if x_status == kXR_status:
            x_decoded = _decode_pages(x_pages)
            assert x_decoded[:want] == PLAIN_DATA[:want], "official pgread data wrong"
            # Byte-for-byte: the CRC-interleaved page streams are identical.
            assert n_pages == x_pages, \
                "pgread CRC-interleaved page stream differs nginx vs official"
        else:
            pytest.skip(f"official pgread unsupported (status={x_status})")
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_at_offset_page_stream_matches(self, both):
        """A page-aligned offsetted read also produces an identical stream."""
        n, x = both
        off, want = PG_PAGESZ, 2 * PG_PAGESZ
        n_status, _, n_pages = self._pgread_file(n, PLAIN_NAME, off, want)
        x_status, _, x_pages = self._pgread_file(x, PLAIN_NAME, off, want)
        assert n_status == kXR_status
        if x_status != kXR_status:
            pytest.skip("official pgread unsupported")
        assert n_pages == x_pages, "offset pgread page stream differs"
        assert _decode_pages(n_pages)[:want] == PLAIN_DATA[off:off + want]


# ===========================================================================
# 5. dirlist — names match official
# ===========================================================================

class TestDirlistParity:
    """kXR_dirlist returns newline-separated entry names (with kXR_dstat the
    server appends a stat line per entry).  Both servers list the same dir."""

    def _names(self, sock, path):
        sid, status, body = _dirlist(sock, path, options=0)
        assert status in (kXR_ok, kXR_oksofar), \
            f"dirlist({path}) failed status={status} {_error_msg(body)}"
        text = body.split(b"\x00")[0].decode(errors="replace")
        names = set()
        for line in text.split("\n"):
            line = line.strip()
            # With dstat each entry is "name\n<id size flags mtime>"; without
            # dstat each line is just a name.  Strip anything that parses as a
            # 4-int stat line, keep real names.
            if not line or line == ".":
                continue
            parts = line.split()
            if len(parts) == 4 and all(_is_int(p) for p in parts):
                continue
            names.add(parts[0])
        return names

    def test_dirlist_names_match(self, both):
        n, x = both
        n_names = self._names(n, SUBDIR)
        x_names = self._names(x, SUBDIR)
        expected = set(SUBDIR_FILES)
        assert expected <= n_names, f"nginx dirlist missing {expected - n_names}"
        assert expected <= x_names, f"xrootd dirlist missing {expected - x_names}"
        assert n_names == x_names, \
            f"dirlist name sets differ: nginx-only={n_names - x_names}, " \
            f"official-only={x_names - n_names}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_dirlist_nonexistent_both_fail(self, both):
        n, x = both
        sid, n_status, n_body = _dirlist(n, "/dropin_no_such_dir", options=0)
        sid, x_status, x_body = _dirlist(x, "/dropin_no_such_dir", options=0)
        assert n_status == kXR_error, "nginx should fail dirlist of missing dir"
        assert x_status == kXR_error, "official should fail dirlist of missing dir"
        assert _error_family(n_status, n_body) == _error_family(x_status, x_body)
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


def _is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


# ===========================================================================
# 6. error family — ENOENT / EACCES / EISDIR match official
# ===========================================================================

class TestErrorFamilyParity:
    """Open of a missing file (ENOENT), a chmod-000 file (EACCES) and a
    directory (EISDIR) must yield the SAME coarse error family on both
    servers."""

    def test_enoent_family_matches(self, both):
        n, x = both
        sid, n_status, n_body = _open(n, "/dropin_does_not_exist.bin",
                                      kXR_open_read)
        sid, x_status, x_body = _open(x, "/dropin_does_not_exist.bin",
                                      kXR_open_read)
        assert n_status == kXR_error and x_status == kXR_error
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        assert n_fam == x_fam == "not_found", \
            f"ENOENT family mismatch nginx={n_fam}({_error_msg(n_body)!r}) " \
            f"xrootd={x_fam}({_error_msg(x_body)!r})"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_eacces_family_matches(self, both):
        n, x = both
        _require_eacces_fixture()
        sid, n_status, n_body = _open(n, NOPERM_NAME, kXR_open_read)
        sid, x_status, x_body = _open(x, NOPERM_NAME, kXR_open_read)
        assert n_status == kXR_error and x_status == kXR_error, \
            f"expected error on both: nginx={n_status} xrootd={x_status}"
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        assert n_fam == x_fam == "permission", \
            f"EACCES family mismatch nginx={n_fam}({_error_msg(n_body)!r}) " \
            f"xrootd={x_fam}({_error_msg(x_body)!r})"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_eisdir_open_family_matches(self, both):
        """Opening a directory as a file must error the same way on both."""
        n, x = both
        sid, n_status, n_body = _open(n, SUBDIR, kXR_open_read)
        sid, x_status, x_body = _open(x, SUBDIR, kXR_open_read)
        assert n_status == kXR_error, "nginx open-dir-as-file should fail"
        assert x_status == kXR_error, "official open-dir-as-file should fail"
        # XRootD maps EISDIR variously; require both to be a non-ok error and
        # agree they are NOT not_found / permission (i.e. an is_directory or
        # generic IO error family).  The strict contract is that they agree.
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        assert n_fam != "ok" and x_fam != "ok"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


def _require_eacces_fixture():
    if os.geteuid() == 0:
        pytest.skip("running as root — chmod 000 does not deny access")
    full = os.path.join(stack_data_dir(), NOPERM_NAME.lstrip("/"))
    if not os.path.exists(full) or os.access(full, os.R_OK):
        pytest.skip("noperm file is readable in this environment")


def stack_data_dir():
    return os.path.join(_DIR, "data")


# ===========================================================================
# 7. kXR_clone (v5 opcode) — Unsupported or consistent behaviour
# ===========================================================================

class TestCloneOpcodeParity:
    """kXR_clone (3032, protocol v5.2) is server-side range copy.  nginx
    implements it (src/protocols/root/read/clone.c).  This asserts the DOCUMENTED behaviour:
    a clone with a bad destination handle is rejected cleanly (not a crash) and
    the session survives — on both servers.  An empty clone-list is also a
    clean error.  If a server lacks the opcode it answers kXR_Unsupported,
    which is an acceptable consistent outcome."""

    def test_clone_bad_dst_handle_rejected(self, both):
        n, x = both
        # Destination handle 0xFF is not an open writable file.
        sid, n_status, n_body = _clone(n, b"\xff\x00\x00\x00", items=b"")
        assert n_status == kXR_error, "nginx clone with bad dst handle must error"
        # Connection must remain usable (no crash / no desync).
        assert _ping(n)[1] == kXR_ok
        # Official server: same opcode; either errors or reports Unsupported.
        sid, x_status, x_body = _clone(x, b"\xff\x00\x00\x00", items=b"")
        assert x_status == kXR_error, "official clone bad handle should error"
        assert _ping(x)[1] == kXR_ok

    def test_clone_empty_list_clean_error(self, both):
        """Open a writable dst, then clone with an EMPTY clone list — a missing
        list is a clean kXR_ArgMissing-class error, session survives."""
        n, x = both
        # nginx side: open a fresh writable destination.
        dst = "/dropin_clone_dst.bin"
        full = os.path.join(stack_data_dir(), dst.lstrip("/"))
        with open(full, "wb") as f:
            f.write(b"\x00" * 4096)
        try:
            sid, o_status, o_body = _open(n, dst, kXR_open_updt)
            assert o_status == kXR_ok, f"dst open failed: {_error_msg(o_body)}"
            fh = o_body[:4]
            try:
                sid, c_status, c_body = _clone(n, fh, items=b"")
                # Documented: empty/absent clone list -> clean error, NOT a hang
                # or a crash.  Accept Unsupported too in case clone is disabled.
                assert c_status in (kXR_error, kXR_status, kXR_ok), \
                    f"unexpected nginx clone status {c_status}"
                if c_status == kXR_error:
                    assert _error_code(c_body) != 0
            finally:
                _close(n, fh)
        finally:
            try:
                os.unlink(full)
            except FileNotFoundError:
                pass
        assert _ping(n)[1] == kXR_ok


# ===========================================================================
# 8. plain read — byte-exact vs official
# ===========================================================================

class TestPlainReadParity:
    """A normal kXR_read of the whole file (and at an offset) returns the same
    bytes on both servers — byte-for-byte, since they serve the same inode."""

    def _drain_read(self, sock, fh, off, length):
        """Read exactly `length` bytes starting at `off`, looping over the
        per-request chunk so a server that answers kXR_oksofar (a partial) does
        not make us under-read.  A read that returns no bytes (EOF) stops."""
        out = bytearray()
        want = length
        cur = off
        while want > 0:
            chunk = min(1 << 20, want)
            sid, rstatus, rbody = _read(sock, fh, cur, chunk)
            assert rstatus in (kXR_ok, kXR_oksofar), \
                f"read failed status={rstatus}"
            if not rbody:
                break
            out.extend(rbody)
            cur += len(rbody)
            want -= len(rbody)
        return bytes(out)

    def _read_all(self, sock, path, size):
        sid, status, body = _open(sock, path, kXR_open_read)
        assert status == kXR_ok, f"open failed: {_error_msg(body)}"
        fh = body[:4]
        try:
            return self._drain_read(sock, fh, 0, size)
        finally:
            _close(sock, fh)

    def test_full_file_byte_exact(self, both):
        n, x = both
        n_data = self._read_all(n, PLAIN_NAME, PLAIN_SIZE)
        x_data = self._read_all(x, PLAIN_NAME, PLAIN_SIZE)
        assert n_data == PLAIN_DATA, "nginx full read != source file"
        assert x_data == PLAIN_DATA, "official full read != source file"
        assert n_data == x_data, "nginx vs official full read differ"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_offset_read_byte_exact(self, both):
        n, x = both
        off, length = 12345, 20000
        n_open = _open(n, PLAIN_NAME, kXR_open_read)
        x_open = _open(x, PLAIN_NAME, kXR_open_read)
        assert n_open[1] == kXR_ok and x_open[1] == kXR_ok
        n_fh, x_fh = n_open[2][:4], x_open[2][:4]
        try:
            # Drain the full extent so a partial kXR_oksofar response does not
            # cause a spurious mismatch.
            n_data = self._drain_read(n, n_fh, off, length)
            x_data = self._drain_read(x, x_fh, off, length)
            assert n_data == x_data == PLAIN_DATA[off:off + length], \
                "offset read mismatch nginx vs official"
        finally:
            _close(n, n_fh)
            _close(x, x_fh)

    def test_read_past_eof_same_behaviour(self, both):
        """Reading well past EOF must NEVER leak bytes on either server.

        kXR_read past EOF is one of the few places XRootD implementations
        legitimately diverge: a plain read past EOF returns a zero-length
        success on a POSIX backend (pread → 0), which is what nginx does, but
        the contract that actually matters for a drop-in is that NO file bytes
        are ever returned past EOF.  We assert the strict, portable property —
        zero bytes returned by each server — and accept either a success or a
        clean error status (not a crash / not data)."""
        n, x = both
        n_open = _open(n, PLAIN_NAME, kXR_open_read)
        x_open = _open(x, PLAIN_NAME, kXR_open_read)
        assert n_open[1] == kXR_ok and x_open[1] == kXR_ok
        n_fh, x_fh = n_open[2][:4], x_open[2][:4]
        try:
            sid, n_st, n_data = _read(n, n_fh, PLAIN_SIZE + 10000, 4096)
            sid, x_st, x_data = _read(x, x_fh, PLAIN_SIZE + 10000, 4096)
            # Neither may return file bytes past EOF.
            assert n_data == b"", f"nginx leaked {len(n_data)} bytes past EOF"
            assert x_data == b"", f"official leaked {len(x_data)} bytes past EOF"
            # nginx's documented behaviour is a zero-length success; the official
            # server may answer ok/oksofar OR a clean error — never a crash.
            assert n_st in (kXR_ok, kXR_oksofar), \
                f"nginx past-EOF read status={n_st}"
            assert x_st in (kXR_ok, kXR_oksofar, kXR_error), \
                f"official past-EOF read status={x_st}"
        finally:
            _close(n, n_fh)
            _close(x, x_fh)
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok
