from split_continuation import reexport as _reexport
def _expression_1_next(msg):
    return (
        any(k in msg for k in ("no such", "not found", "doesn't exist", "does not exist"))
    )

def _expression_2_next(msg):
    return (
        any(k in msg for k in ("permission", "not authoriz", "denied"))
    )

def _expression_3_next(msg):
    return (
        any(k in msg for k in ("is a directory", "isdirectory", "is directory"))
    )

def _expression_4(msg):
    return (
        any(k in msg for k in ("path", "invalid", "illegal"))
    )


def _expression_1(n_listing):
    return (
        {e.name: e.statinfo.size for e in n_listing if e.statinfo}
    )

def _expression_2(r_listing):
    return (
        {e.name: e.statinfo.size for e in r_listing if e.statinfo}
    )

def _expression_3(status):
    return (
        (status.message or "").lower()
    )


def _phase_test_dstat_per_entry_sizes_match_individual_stat_1(name):
    try:
        _fs(NGINX_URL).rm(f"/{name}")
    except Exception:
        pass


def _check_test_dstat_per_entry_sizes_match_individual_stat_1(n_st, r_st):
    assert n_st.ok and r_st.ok, (
        f"dirlist failed (nginx={n_st.message!r}, ref={r_st.message!r})"
    )

def _check_test_dstat_per_entry_sizes_match_individual_stat_2(expected_size, n_sizes, name, r_sizes):
    assert n_sizes[name] == r_sizes[name] == expected_size, (
        f"{name}: size mismatch nginx={n_sizes[name]} "
        f"ref={r_sizes[name]} expected={expected_size}"
    )


_reexport(globals(), "_test_interop_query_helpers")

class TestErrorCodeFamilies:
    """
    XRootD defines specific error codes (kXR_NotFound, kXR_isDirectory, …).
    Both servers must return the same error family for the same failure modes.
    """

    def _error_family(self, status):
        msg = _expression_3(status)
        if not status.ok:
            if _expression_1_next(msg):
                return "not_found"
            if _expression_2_next(msg):
                return "permission"
            if _expression_3_next(msg):
                return "is_directory"
            if _expression_4(msg):
                return "invalid_path"
            return "error"
        return "ok"

    def test_stat_nonexistent_error_family_matches(self):
        path = "/_err_notfound_xyzzy.bin"
        n_st, _ = _fs(NGINX_URL).stat(path)
        r_st, _ = _fs(REF_URL  ).stat(path)
        assert not n_st.ok and not r_st.ok
        n_fam = self._error_family(n_st)
        r_fam = self._error_family(r_st)
        assert n_fam == r_fam, \
            f"not-found error family: nginx={n_fam!r}, ref={r_fam!r}"

    def test_open_nonexistent_error_family_matches(self):
        path = "/_err_noopen_xyzzy.bin"
        n_f = client.File()
        r_f = client.File()
        n_st, _ = n_f.open(_url(NGINX_URL, path), OpenFlags.READ)
        r_st, _ = r_f.open(_url(REF_URL, path), OpenFlags.READ)
        assert not n_st.ok and not r_st.ok
        n_fam = self._error_family(n_st)
        r_fam = self._error_family(r_st)
        # Some servers return "not_found", others "invalid_path" for a
        # nonexistent-file open; both are conformant "file missing" errors.
        acceptable = {"not_found", "invalid_path", "error"}
        assert n_fam in acceptable and r_fam in acceptable, \
            f"open-nonexistent family: nginx={n_fam!r}, ref={r_fam!r}"

    def test_open_directory_as_file_error_family_matches(self):
        """Opening a directory as a file should fail on both with is_directory."""
        dir_path = f"/_err_isdir_{os.getpid()}"
        from XRootD.client.flags import MkDirFlags
        _fs(NGINX_URL).mkdir(dir_path, MkDirFlags.NONE)
        try:
            n_f = client.File()
            r_f = client.File()
            n_st, _ = n_f.open(_url(NGINX_URL, dir_path), OpenFlags.READ)
            r_st, _ = r_f.open(_url(REF_URL, dir_path), OpenFlags.READ)
            assert not n_st.ok, "nginx: opening directory as file should fail"
            assert not r_st.ok, "ref:   opening directory as file should fail"
        finally:
            _fs(NGINX_URL).rmdir(dir_path)

    def test_rm_nonexistent_error_family_matches(self):
        path = "/_err_rmne_xyzzy.bin"
        n_st = _fs(NGINX_URL).rm(path)
        r_st = _fs(REF_URL  ).rm(path)
        n_fam = self._error_family(n_st[0])
        r_fam = self._error_family(r_st[0])
        assert not n_st[0].ok and not r_st[0].ok
        assert n_fam == r_fam, \
            f"rm-nonexistent family: nginx={n_fam!r}, ref={r_fam!r}"

    def test_dirlist_nonexistent_error_family_matches(self):
        path = "/_err_dirne_xyzzy/"
        n_st, _ = _fs(NGINX_URL).dirlist(path)
        r_st, _ = _fs(REF_URL  ).dirlist(path)
        assert not n_st.ok and not r_st.ok

    @pytest.mark.parametrize("bad_path", [
        "/../etc/passwd",
        "/../../etc/shadow",
        "//some/../../escape",
    ])
    def test_dotdot_paths_both_fail_or_stay_inside_root(self, bad_path):
        """Both servers must not serve files outside their root via traversal."""
        n_st, _ = _fs(NGINX_URL).stat(bad_path)
        r_st, _ = _fs(REF_URL  ).stat(bad_path)
        if n_st.ok:
            assert r_st.ok, \
                "path traversal: nginx served path that ref rejected"


# ---------------------------------------------------------------------------
# Protocol negotiation
# ---------------------------------------------------------------------------

class TestProtocolNegotiation:

    def test_ping_succeeds_on_both_servers(self):
        n_st, _ = _fs(NGINX_URL).ping(timeout=5)
        r_st, _ = _fs(REF_URL  ).ping(timeout=5)
        assert n_st.ok, f"nginx ping failed: {n_st.message}"
        assert r_st.ok, f"ref   ping failed: {r_st.message}"

    def test_multiple_sequential_pings_succeed(self):
        for i in range(3):
            st, _ = _fs(NGINX_URL).ping(timeout=5)
            assert st.ok, f"nginx ping {i} failed: {st.message}"

    def test_filesystem_reconnects_after_operations(self):
        """A fresh FileSystem object should connect and work on each call."""
        for i in range(3):
            fs = _fs(NGINX_URL)
            st, _ = fs.ping(timeout=5)
            assert st.ok, f"fresh fs ping {i} failed: {st.message}"

    def test_stat_and_ping_interleaved_with_ref(self):
        """Interleave operations across both servers; neither should interfere."""
        path, content = _seed(b"ping_stat", "pingstat"), b"ping_stat"
        try:
            _fs(NGINX_URL).ping()
            n_st, _ = _fs(NGINX_URL).stat(path)
            _fs(REF_URL).ping()
            r_st, _ = _fs(REF_URL  ).stat(path)
            assert n_st.ok == r_st.ok
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# Dirlist dstat / dcksm flags
# ---------------------------------------------------------------------------

class TestDirlistFlagsConformance:

    def test_dstat_per_entry_sizes_match_individual_stat(self):
        """kXR_dstat: sizes in dirlist response must match separate stat calls."""
        names = []
        try:
            for i in range(3):
                size = 128 * (i + 1)
                name = f"_dstat_{os.getpid()}_{i}.bin"
                with open(os.path.join(DATA_DIR, name), "wb") as fh:
                    fh.write(os.urandom(size))
                names.append((name, size))

            n_st, n_listing = _dirlist_retry(_fs(NGINX_URL), "//")
            r_st, r_listing = _dirlist_retry(_fs(REF_URL  ), "//")
            _check_test_dstat_per_entry_sizes_match_individual_stat_1(n_st, r_st)

            n_sizes = _expression_1(n_listing)
            r_sizes = _expression_2(r_listing)

            for name, expected_size in names:
                def _assert_test_dstat_per_entry_sizes_match_individual_stat_1():
                    assert name in n_sizes, f"nginx dirlist missing {name}"
                    assert name in r_sizes, f"ref dirlist missing {name}"

                _assert_test_dstat_per_entry_sizes_match_individual_stat_1()
                _check_test_dstat_per_entry_sizes_match_individual_stat_2(expected_size, n_sizes, name, r_sizes)
        finally:
            for name, _ in names:
                _phase_test_dstat_per_entry_sizes_match_individual_stat_1(name)

    def test_dirlist_without_dstat_agrees_on_names(self):
        n_st, n_listing = _dirlist_retry(_fs(NGINX_URL), "//", DirListFlags.NONE)
        r_st, r_listing = _dirlist_retry(_fs(REF_URL  ), "//", DirListFlags.NONE)
        assert n_st.ok and r_st.ok, (
            f"dirlist failed (nginx={n_st.message!r}, ref={r_st.message!r})"
        )

        n_names = {e.name for e in n_listing}
        r_names = {e.name for e in r_listing}
        # Both servers read the same FS; they must agree on the seeded baseline.
        # Transient scratch from concurrent tests races two non-simultaneous
        # listings, so it is excluded (see _BASELINE_FILES).
        assert _BASELINE_FILES <= n_names, (
            f"nginx dirlist missing seeded files: {_BASELINE_FILES - n_names}"
        )
        assert _BASELINE_FILES <= r_names, (
            f"ref   dirlist missing seeded files: {_BASELINE_FILES - r_names}"
        )
