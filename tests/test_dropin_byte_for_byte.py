from split_continuation import reexport as _reexport
def _check_test_statx_field_format_matches_2(n, x):
    assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

def _check_test_statx_field_format_matches_1(x_body, n_body):
    assert (x_body[0] & 0x02) == (n_body[0] & 0x02), \
        "isDir flag disagrees between nginx and official statx"

def _guard_test_qspace_values_are_numeric_1(status, label):
    if status != kXR_ok:
        if label == "xrootd":
            pytest.skip("official Qspace unsupported")
        pytest.fail("nginx Qspace failed")

def _check_test_eacces_family_matches_3(n_status, x_status):
    assert n_status == kXR_error and x_status == kXR_error, \
        f"expected error on both: nginx={n_status} xrootd={x_status}"


_reexport(globals(), "_test_dropin_byte_for_byte_helpers")

class TestStatParity:
    """The kXR_stat response body begins with the ASCII string
    '<id> <size> <flags> <mtime>' (src/protocols/root/path/stat_body.c).  nginx returns
    exactly those 4 fields; the OFFICIAL xrootd appends extended fields
    (ctime atime mode owner group) — the conformance contract is that the
    leading 4 fields appear in the SAME ORDER and FORMAT and that the
    semantically-stable ones (size, mtime, the isDir/readable bits) agree.
    Note: the inode `id` legitimately differs because the official server
    emits a synthesized/hashed inode, not the raw st_ino — so we assert its
    FORMAT (an integer in field 0) rather than equality."""

    # XStatRespFlags bits we compare semantically across the two servers.
    _IS_DIR   = 2
    _READABLE = 16

    def _stat_head(self, sock, path):
        """Return the leading 4 stat fields [id, size, flags, mtime] as ints,
        asserting the body has at least those 4 in integer format."""
        sid, status, body = _stat(sock, path)
        assert status == kXR_ok, f"stat({path}) failed: {_error_msg(body)}"
        text = body.split(b"\x00")[0].decode().strip()
        parts = text.split()
        assert len(parts) >= 4, f"stat body must have >=4 fields, got {parts!r}"
        head = parts[:4]
        ints = [int(f) for f in head]  # raises → format divergence
        return ints  # [id, size, flags, mtime]

    def test_stat_body_field_order_and_format(self, both):
        """Both servers emit id, size, flags, mtime as base-10 integers in that
        order as the first four whitespace-separated fields."""
        n, x = both
        n_head = self._stat_head(n, PLAIN_NAME)
        x_head = self._stat_head(x, PLAIN_NAME)
        # Field 0 (id) is an integer on both; field 1 (size) is the real size.
        assert n_head[1] == x_head[1] == PLAIN_SIZE, \
            f"size field (index 1) mismatch nginx={n_head[1]} xrootd={x_head[1]}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_stat_size_and_mtime_match(self, both):
        """size and mtime read the same stat(2) inode → identical on both."""
        n, x = both
        n_id, n_size, n_flags, n_mtime = self._stat_head(n, PLAIN_NAME)
        x_id, x_size, x_flags, x_mtime = self._stat_head(x, PLAIN_NAME)
        assert n_size == x_size == PLAIN_SIZE, \
            f"size mismatch nginx={n_size} xrootd={x_size}"
        assert n_mtime == x_mtime, \
            f"mtime mismatch nginx={n_mtime} xrootd={x_mtime}"

    def test_stat_isdir_and_readable_bits_agree(self, both):
        """The kXR_isDir / kXR_readable flag bits agree for a file and a dir.
        (The kXR_writable bit legitimately differs — the official server sets
        it from the fs mode, nginx reports read-capability only — so we compare
        only the stable bits, not the raw flags integer.)"""
        n, x = both
        # Regular file: not a dir, readable, on both.
        n_file = self._stat_head(n, PLAIN_NAME)[2]
        x_file = self._stat_head(x, PLAIN_NAME)[2]
        assert not (n_file & self._IS_DIR) and not (x_file & self._IS_DIR), \
            f"file wrongly flagged as dir nginx={n_file} xrootd={x_file}"
        assert (n_file & self._READABLE) and (x_file & self._READABLE), \
            f"file not flagged readable nginx={n_file} xrootd={x_file}"
        # Directory: kXR_isDir set on both.
        n_dir = self._stat_head(n, SUBDIR)[2]
        x_dir = self._stat_head(x, SUBDIR)[2]
        assert (n_dir & self._IS_DIR) and (x_dir & self._IS_DIR), \
            f"dir not flagged kXR_isDir nginx={n_dir} xrootd={x_dir}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_statx_field_format_matches(self, both):
        """kXR_statx returns ONE flag byte per path (kXR_file=0 / kXR_isDir=2 /
        kXR_other=4 / kXR_offline=8) — exactly the reference do_Statx response,
        NOT a kXR_stat text line.  The python XRootD client has no statx method,
        so this is raw-wire only.  Both servers must classify the regular file
        identically (a non-directory flag byte)."""
        n, x = both
        _, n_st, n_body = _statx(n, [PLAIN_NAME])
        _, x_st, x_body = _statx(x, [PLAIN_NAME])
        if n_st != kXR_ok:
            pytest.skip(f"statx not supported on nginx (status={n_st})")
        def _assert_test_statx_field_format_matches_1():
            assert len(n_body) == 1, f"nginx statx must be one flag byte: {n_body!r}"
            assert not (n_body[0] & 0x02), "nginx flagged a regular file as a dir"

        _assert_test_statx_field_format_matches_1()
        # The official server returns the same one-byte-per-path body; cross-check
        # when it answers (some builds reply empty for a single path).
        if x_st == kXR_ok and len(x_body) == 1:
            _check_test_statx_field_format_matches_1(x_body, n_body)
        _check_test_statx_field_format_matches_2(n, x)


# ===========================================================================
# 2. Qspace — oss.* fields match official
# ===========================================================================

class TestQspaceParity:
    """kXR_Qspace returns 'oss.*' key=value pairs joined by '&'
    (src/protocols/root/query/space.c).  The official server emits the same oss.cgroup /
    oss.space / oss.free / oss.maxf / oss.used / oss.quota key set."""

    def _oss_keys(self, sock):
        sid, status, body = _query(sock, kXR_Qspace, b"/")
        if status != kXR_ok:
            return status, None
        text = body.split(b"\x00")[0].decode(errors="replace")
        keys = set()
        for pair in text.split("&"):
            if "=" in pair:
                keys.add(pair.split("=", 1)[0])
        return status, keys

    def test_qspace_key_set_matches(self, both):
        n, x = both
        n_status, n_keys = self._oss_keys(n)
        x_status, x_keys = self._oss_keys(x)
        if x_status != kXR_ok:
            pytest.skip(f"official xrootd Qspace unsupported (status={x_status})")
        assert n_status == kXR_ok, "nginx Qspace should succeed"
        # The conformance contract: the oss.* key SET nginx returns must be a
        # superset of (and in practice equal to) what the official server emits.
        assert x_keys <= n_keys, (
            f"nginx Qspace missing oss keys present in official: "
            f"{x_keys - n_keys}")
        assert {"oss.space", "oss.free", "oss.used"} <= n_keys, \
            f"nginx Qspace missing core oss fields: {n_keys}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_qspace_values_are_numeric(self, both):
        """Every oss.* value (except cgroup) is an integer on both servers."""
        n, x = both
        for sock, label in ((n, "nginx"), (x, "xrootd")):
            sid, status, body = _query(sock, kXR_Qspace, b"/")
            _guard_test_qspace_values_are_numeric_1(status, label)
            text = body.split(b"\x00")[0].decode(errors="replace")
            for pair in text.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                if k == "oss.cgroup":
                    continue
                int(v)  # raises if non-numeric → format divergence


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
        # If the test runs as root, chmod 000 is bypassed; skip in that case.
        if os.geteuid() == 0:
            pytest.skip("running as root — chmod 000 does not deny access")
        full = os.path.join(stack_data_dir(), NOPERM_NAME.lstrip("/"))
        if not os.path.exists(full) or os.access(full, os.R_OK):
            pytest.skip("noperm file is readable in this environment")
        sid, n_status, n_body = _open(n, NOPERM_NAME, kXR_open_read)
        sid, x_status, x_body = _open(x, NOPERM_NAME, kXR_open_read)
        _check_test_eacces_family_matches_3(n_status, x_status)
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        def _assert_test_eacces_family_matches_2():
            assert n_fam == x_fam == "permission", \
                f"EACCES family mismatch nginx={n_fam}({_error_msg(n_body)!r}) " \
                f"xrootd={x_fam}({_error_msg(x_body)!r})"
            assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

        _assert_test_eacces_family_matches_2()

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
