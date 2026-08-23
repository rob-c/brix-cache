from split_continuation import reexport as _reexport
def _check_test_dirlist_file_sizes_match_1(n_st, r_st):
    assert n_st.ok and r_st.ok

def _check_test_dirlist_file_sizes_match_2(content, n_entry, r_entry):
    assert n_entry.statinfo.size == r_entry.statinfo.size == len(content), (
        f"dirlist size mismatch: nginx={n_entry.statinfo.size}, "
        f"ref={r_entry.statinfo.size}, actual={len(content)}"
    )


_reexport(globals(), "_test_conformance_helpers")

class TestPing:
    def test_both_respond_to_ping(self):
        n_st, _ = _fs(NGINX_URL).ping(timeout=5)
        r_st, _ = _fs(REF_URL).ping(timeout=5)
        assert n_st.ok, f"nginx ping failed: {n_st.message}"
        assert r_st.ok, f"ref   ping failed: {r_st.message}"


# ---------------------------------------------------------------------------
# Stat
# ---------------------------------------------------------------------------

class TestStatConformance:

    def test_stat_known_file_both_succeed(self, scratch):
        path, _ = scratch
        n_st, n_info = _fs(NGINX_URL).stat(f"/{path}")
        r_st, r_info = _fs(REF_URL).stat(f"/{path}")
        assert n_st.ok == r_st.ok, (
            f"outcome mismatch: nginx={n_st.ok}, ref={r_st.ok}"
        )
        assert n_st.ok, "expected stat to succeed on both"

    def test_stat_file_size_matches(self, scratch):
        path, content = scratch
        n_st, n_info = _fs(NGINX_URL).stat(f"/{path}")
        r_st, r_info = _fs(REF_URL).stat(f"/{path}")
        assert n_st.ok and r_st.ok
        assert n_info.size == r_info.size == len(content), (
            f"size mismatch: nginx={n_info.size}, ref={r_info.size}, "
            f"actual={len(content)}"
        )

    def test_stat_file_not_flagged_as_directory(self, scratch):
        path, _ = scratch
        n_st, n_info = _fs(NGINX_URL).stat(f"/{path}")
        r_st, r_info = _fs(REF_URL).stat(f"/{path}")
        assert n_st.ok and r_st.ok
        n_isdir = bool(n_info.flags & StatInfoFlags.IS_DIR)
        r_isdir = bool(r_info.flags & StatInfoFlags.IS_DIR)
        assert n_isdir == r_isdir == False, (
            f"IS_DIR mismatch: nginx={n_isdir}, ref={r_isdir}"
        )

    def test_stat_root_is_directory(self):
        n_st, n_info = _fs(NGINX_URL).stat("//")
        r_st, r_info = _fs(REF_URL).stat("//")
        assert n_st.ok == r_st.ok
        if n_st.ok and r_st.ok:
            n_isdir = bool(n_info.flags & StatInfoFlags.IS_DIR)
            r_isdir = bool(r_info.flags & StatInfoFlags.IS_DIR)
            assert n_isdir == r_isdir == True, (
                f"root IS_DIR mismatch: nginx={n_isdir}, ref={r_isdir}"
            )

    def test_stat_nonexistent_both_fail(self):
        path = "//does_not_exist_xyzzy_42.bin"
        n_st, _ = _fs(NGINX_URL).stat(path)
        r_st, _ = _fs(REF_URL).stat(path)
        assert not n_st.ok, "nginx should fail for nonexistent path"
        assert not r_st.ok, "ref   should fail for nonexistent path"
        assert _error_family(n_st) == _error_family(r_st), (
            f"error family mismatch: nginx={_error_family(n_st)!r}, "
            f"ref={_error_family(r_st)!r}\n"
            f"  nginx: {n_st.message}\n  ref:   {r_st.message}"
        )

    def test_stat_large_file_size(self):
        """large200.bin is pre-seeded by the concurrent test fixtures."""
        path = "//large200.bin"
        n_st, n_info = _fs(NGINX_URL).stat(path)
        r_st, r_info = _fs(REF_URL).stat(path)
        assert n_st.ok == r_st.ok
        if n_st.ok and r_st.ok:
            assert n_info.size == r_info.size, (
                f"large200.bin size: nginx={n_info.size}, ref={r_info.size}"
            )

    def test_stat_readable_flag_matches(self, scratch):
        path, _ = scratch
        n_st, n_info = _fs(NGINX_URL).stat(f"/{path}")
        r_st, r_info = _fs(REF_URL).stat(f"/{path}")
        assert n_st.ok and r_st.ok
        n_readable = bool(n_info.flags & StatInfoFlags.IS_READABLE)
        r_readable = bool(r_info.flags & StatInfoFlags.IS_READABLE)
        assert n_readable == r_readable, (
            f"IS_READABLE mismatch: nginx={n_readable}, ref={r_readable}"
        )


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

class TestReadConformance:

    def test_read_small_file_identical(self, scratch):
        path, content = scratch
        n_st, n_data = _read_all(NGINX_URL, path)
        r_st, r_data = _read_all(REF_URL,   path)
        assert n_st.ok == r_st.ok
        assert n_st.ok, f"read failed: nginx={n_st.message}"
        assert n_data == r_data == content, (
            f"data mismatch: nginx_md5={_md5(n_data)}, "
            f"ref_md5={_md5(r_data)}, expected_md5={_md5(content)}"
        )

    def test_read_at_offset_identical(self, scratch):
        path, content = scratch
        offset = len(content) // 4
        chunk  = len(content) // 2

        def read_at(base_url):
            f = client.File()
            st, _ = f.open(f"{base_url}/{path}")
            assert st.ok
            st2, data = f.read(offset=offset, size=chunk)
            f.close()
            return st2, data

        n_st, n_data = read_at(NGINX_URL)
        r_st, r_data = read_at(REF_URL)
        assert n_st.ok == r_st.ok
        assert n_data == r_data == content[offset:offset + chunk], (
            "offset read mismatch between nginx and ref"
        )

    def test_read_beyond_eof_same_behaviour(self, scratch):
        path, content = scratch
        beyond = len(content) * 10

        def read_beyond(base_url):
            f = client.File()
            st, _ = f.open(f"{base_url}/{path}")
            assert st.ok
            st2, data = f.read(size=beyond)
            f.close()
            return st2, data

        n_st, n_data = read_beyond(NGINX_URL)
        r_st, r_data = read_beyond(REF_URL)
        # Both should succeed (returning EOF short-read), not error
        assert n_st.ok == r_st.ok, (
            f"beyond-EOF outcome differs: nginx={n_st.ok}, ref={r_st.ok}"
        )
        if n_st.ok and r_st.ok:
            assert n_data == r_data == content, (
                "beyond-EOF: data should equal full file content"
            )

    def test_open_nonexistent_both_fail(self):
        path = "//_no_such_file_xyzzy.bin"
        n_st, _ = _read_all(NGINX_URL, path)
        r_st, _ = _read_all(REF_URL,   path)
        assert not n_st.ok, "nginx should fail to open nonexistent file"
        assert not r_st.ok, "ref   should fail to open nonexistent file"

    def test_read_5mb_random_file_md5(self):
        """random.bin (5 MiB) — compare checksums to ensure no data corruption."""
        path = "//random.bin"
        n_st, n_data = _read_all(NGINX_URL, path)
        r_st, r_data = _read_all(REF_URL,   path)
        assert n_st.ok == r_st.ok
        if n_st.ok and r_st.ok:
            assert _md5(n_data) == _md5(r_data), (
                f"random.bin MD5 differs: nginx={_md5(n_data)}, "
                f"ref={_md5(r_data)}"
            )

    def test_read_multiple_chunks_same_data(self, scratch):
        """Read the same file in two chunks; verify both servers agree on each."""
        path, content = scratch
        mid = len(content) // 2

        def read_chunks(base_url):
            f = client.File()
            st, _ = f.open(f"{base_url}/{path}")
            assert st.ok
            _, d1 = f.read(offset=0,   size=mid)
            _, d2 = f.read(offset=mid, size=len(content) - mid)
            f.close()
            return d1, d2

        n_d1, n_d2 = read_chunks(NGINX_URL)
        r_d1, r_d2 = read_chunks(REF_URL)
        assert n_d1 == r_d1, "chunk-1 mismatch between nginx and ref"
        assert n_d2 == r_d2, "chunk-2 mismatch between nginx and ref"
        assert n_d1 + n_d2 == content, "nginx chunks don't reconstruct original"


# ---------------------------------------------------------------------------
# Dirlist
# ---------------------------------------------------------------------------

# Files seeded once per session by conftest and never deleted by any test — the
# stable contract both servers must agree on.  Everything else in the shared data
# root is transient scratch created/removed by other tests; under parallel
# execution (-n N) those legitimately differ between two non-simultaneous listings,
# so the cross-server comparison is restricted to this baseline.
_BASELINE_FILES = {"test.txt", "random.bin", "large200.bin"}



class TestDirlistConformance:

    def _entry_names(self, url: str, path: str) -> set[str]:
        # Pass the URL (not a FileSystem) so each retry reconnects fresh.
        st, listing = _dirlist_retry(url, path)
        assert st.ok, f"dirlist({url}{path}) failed: {st.message}"
        return {e.name for e in listing}

    def test_dirlist_root_same_names(self):
        n_names = self._entry_names(NGINX_URL, "//")
        r_names = self._entry_names(REF_URL,   "//")
        # Both servers read the same filesystem, so they must agree on the stable
        # seeded files.  Transient scratch from concurrent tests is excluded (it
        # races the two non-simultaneous listings) — see _BASELINE_FILES.
        assert _BASELINE_FILES <= n_names, (
            f"nginx root dirlist missing seeded files: {_BASELINE_FILES - n_names}"
        )
        assert _BASELINE_FILES <= r_names, (
            f"ref   root dirlist missing seeded files: {_BASELINE_FILES - r_names}"
        )

    def test_dirlist_file_sizes_match(self, scratch):
        """Both servers should agree on file sizes in a STAT dirlist."""
        path, content = scratch
        # list the parent dir (root) and find our file
        n_st, n_listing = _dirlist_retry(NGINX_URL, "//")
        r_st, r_listing = _dirlist_retry(REF_URL, "//")
        _check_test_dirlist_file_sizes_match_1(n_st, r_st)

        fname = os.path.basename(path)
        n_entry = next((e for e in n_listing if e.name == fname), None)
        r_entry = next((e for e in r_listing if e.name == fname), None)
        def _assert_test_dirlist_file_sizes_match_1():
            assert n_entry is not None, f"nginx dirlist missing {fname}"
            assert r_entry is not None, f"ref   dirlist missing {fname}"

        _assert_test_dirlist_file_sizes_match_1()
        _check_test_dirlist_file_sizes_match_2(content, n_entry, r_entry)

    def test_dirlist_nonexistent_both_fail(self):
        path = "//_no_such_dir_xyzzy/"
        n_st, _ = _fs(NGINX_URL).dirlist(path)
        r_st, _ = _fs(REF_URL  ).dirlist(path)
        assert not n_st.ok, "nginx should fail dirlist of nonexistent dir"
        assert not r_st.ok, "ref   should fail dirlist of nonexistent dir"


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------


class TestChecksumConformance:
    """
    nginx-xrootd implements kXR_Qcksum (adler32).  The reference xrootd
    server does not enable checksums by default, so we can't compare both
    servers directly.  Instead we compute the expected adler32 in Python
    and verify that nginx returns the correct value.
    """

    def _cksum(self, url: str, path: str):
        st, result = _fs(url).query(
            client.flags.QueryCode.CHECKSUM, f"/{path}"
        )
        return st, result

    def test_checksum_known_file_correct(self, scratch):
        """nginx returns the correct adler32 for a known file."""
        path, content = scratch
        n_st, n_result = self._cksum(NGINX_URL, path)
        assert n_st.ok, f"nginx checksum failed: {n_st.message}"
        # response format: "adler32 <hex8>\0"
        n_val = n_result.decode().split()[1].rstrip("\x00")
        expected = _adler32_hex(content)
        assert n_val == expected, (
            f"adler32 wrong for {path}: got={n_val}, expected={expected}"
        )

    def test_checksum_large_file_correct(self):
        """nginx returns the correct adler32 for the pre-seeded large200.bin."""
        path = "/large200.bin"
        fs_path = os.path.join(DATA_DIR, "large200.bin")
        assert os.path.exists(fs_path), (
            "central suite setup did not seed large200.bin")
        with open(fs_path, "rb") as fh:
            content = fh.read()
        n_st, n_result = self._cksum(NGINX_URL, path)
        assert n_st.ok, f"nginx checksum failed: {n_st.message}"
        n_val = n_result.decode().split()[1].rstrip("\x00")
        expected = _adler32_hex(content)
        assert n_val == expected, (
            f"large200.bin adler32: got={n_val}, expected={expected}"
        )

    def test_checksum_nonexistent_fails(self):
        """nginx returns an error for a nonexistent path."""
        path = "/_no_such_file_checksum_xyzzy.bin"
        n_st, _ = self._cksum(NGINX_URL, path)
        assert not n_st.ok, "nginx checksum of nonexistent path should fail"

    def test_checksum_after_write_correct(self, scratch):
        """Write a file through nginx, then verify nginx returns the correct checksum."""
        path, content = scratch
        n_st, n_result = self._cksum(NGINX_URL, path)
        assert n_st.ok, f"nginx post-write checksum failed: {n_st.message}"
        n_val = n_result.decode().split()[1].rstrip("\x00")
        expected = _adler32_hex(content)
        assert n_val == expected, (
            f"post-write checksum wrong: got={n_val}, expected={expected}"
        )


# ---------------------------------------------------------------------------
# Write round-trip
# ---------------------------------------------------------------------------
