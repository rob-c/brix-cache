from split_continuation import reexport as _reexport
_reexport(globals(), "_test_interop_io_helpers")

class TestLocateConformance:

    def test_locate_existing_file_returns_ok_on_both(self):
        path, _ = _seed(512, "locate")
        try:
            n_st, n_locs = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
            r_st, r_locs = _fs(REF_URL  ).locate(path, OpenFlags.NONE)

            assert n_st.ok, f"nginx locate failed: {n_st.message}"
            assert r_st.ok, f"ref   locate failed: {r_st.message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_locate_nonexistent_fails_on_both(self):
        path = "/_no_locate_xyzzy.bin"
        n_st, _ = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
        r_st, _ = _fs(REF_URL  ).locate(path, OpenFlags.NONE)
        assert not n_st.ok, "nginx: locate of nonexistent should fail"
        assert not r_st.ok, "ref:   locate of nonexistent should fail"

    def test_locate_returns_at_least_one_location(self):
        path, _ = _seed(512, "loc_count")
        try:
            n_st, n_locs = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
            assert n_st.ok
            locs = list(n_locs)
            assert len(locs) >= 1, "locate returned no locations"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_locate_response_contains_host_and_port(self):
        path, _ = _seed(512, "loc_fmt")
        try:
            n_st, n_locs = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
            assert n_st.ok
            for loc in n_locs:
                # Each location should have a non-empty address
                assert loc.address, "locate entry has empty address"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_locate_directory_returns_ok(self):
        path = "//"
        n_st, _ = _fs(NGINX_URL).locate(path, OpenFlags.NONE)
        r_st, _ = _fs(REF_URL  ).locate(path, OpenFlags.NONE)
        # Both should succeed or both should fail (root directory is always present)
        assert n_st.ok == r_st.ok, \
            f"root locate outcome differs: nginx={n_st.ok}, ref={r_st.ok}"


# ---------------------------------------------------------------------------
# clone (kXR_clone) — server-side file copy
# ---------------------------------------------------------------------------

class TestCloneConformance:

    def test_clone_creates_identical_file(self):
        src_path, content = _seed(8192, "clone_src")
        dst_name = f"_clone_dst_{os.getpid()}.bin"
        dst_path = f"/{dst_name}"
        with open(os.path.join(DATA_DIR, dst_name), "wb") as fh:
            fh.write(b"\x00" * len(content))

        try:
            sock = _connect_nginx()
            try:
                src_fh = _raw_open(sock, 2, src_path, 0x0010)
                dst_fh = _raw_open(sock, 3, dst_path, 0x0020)
                status, body = _raw_clone(sock, 4, dst_fh,
                                          [(src_fh, 0, len(content), 0)])
                assert status == 0, f"clone failed: status={status} body={body!r}"
                _raw_close(sock, 5, src_fh)
                _raw_close(sock, 6, dst_fh)
            finally:
                sock.close()

            n_st, n_data = _read_all(NGINX_URL, dst_path)
            r_st, r_data = _read_all(REF_URL,   dst_path)
            assert n_st.ok, f"nginx read cloned file: {n_st.message}"
            assert r_st.ok, f"ref   read cloned file: {r_st.message}"
            assert n_data == r_data == content, \
                "clone: destination content differs from source"
        finally:
            _fs(NGINX_URL).rm(src_path)
            try:
                _fs(NGINX_URL).rm(dst_path)
            except Exception:
                pass

    def test_clone_source_unchanged(self):
        src_path, content = _seed(4096, "clone_src_intact")
        dst_name = f"_clone_dst_intact_{os.getpid()}.bin"
        dst_path = f"/{dst_name}"
        with open(os.path.join(DATA_DIR, dst_name), "wb") as fh:
            fh.write(b"\x00" * len(content))

        try:
            sock = _connect_nginx()
            try:
                src_fh = _raw_open(sock, 2, src_path, 0x0010)
                dst_fh = _raw_open(sock, 3, dst_path, 0x0020)
                status, body = _raw_clone(sock, 4, dst_fh,
                                          [(src_fh, 0, len(content), 0)])
                assert status == 0, f"clone failed: status={status} body={body!r}"
                _raw_close(sock, 5, src_fh)
                _raw_close(sock, 6, dst_fh)
            finally:
                sock.close()

            n_st, n_data = _read_all(NGINX_URL, src_path)
            assert n_st.ok
            assert n_data == content, "source file modified by clone"
        finally:
            _fs(NGINX_URL).rm(src_path)
            try:
                _fs(NGINX_URL).rm(dst_path)
            except Exception:
                pass
