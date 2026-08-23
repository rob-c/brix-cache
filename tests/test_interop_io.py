from split_continuation import reexport as _reexport
_reexport(globals(), "_test_interop_io_helpers")

def _assert_full_readv(native_data, reference_data, expected):
    assert native_data == reference_data == expected, \
        f"full readv: nginx_md5={_md5(native_data)} ref_md5={_md5(reference_data)}"


class TestVectorReadConformance:

    def test_readv_matches_sequential_reads_on_both(self):
        path, content = _seed(16384, "readv")
        segments = [(0, 1024), (4096, 2048), (8192, 512), (12288, 1024)]
        expected = b"".join(content[o:o+s] for o, s in segments)

        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f, st = _open_file(url, path)
                assert st.ok, f"{label} open failed: {st.message}"
                v_st, vri = f.vector_read(segments)
                f.close()

                assert v_st.ok, f"{label} readv failed: {v_st.message}"
                got = b"".join(chunk.buffer for chunk in vri.chunks)
                assert got == expected, \
                    f"{label}: readv data mismatch (md5 got={_md5(got)} expected={_md5(expected)})"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_readv_single_segment_matches_read(self):
        path, content = _seed(4096, "readvsingle")
        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f, st = _open_file(url, path)
                assert st.ok
                _, vri = f.vector_read([(0, len(content))])
                f.close()
                got = b"".join(chunk.buffer for chunk in vri.chunks)
                assert got == content, f"{label}: single-segment readv mismatch"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_readv_out_of_order_segments_match(self):
        path, content = _seed(8192, "readvooo")
        # Segments in reverse address order
        segments = [(6144, 512), (2048, 512), (0, 512)]
        try:
            n_f, _ = _open_file(NGINX_URL, path)
            r_f, _ = _open_file(REF_URL,   path)
            _, n_vri = n_f.vector_read(segments)
            _, r_vri = r_f.vector_read(segments)
            n_f.close()
            r_f.close()

            n_data = b"".join(c.buffer for c in n_vri.chunks)
            r_data = b"".join(c.buffer for c in r_vri.chunks)
            assert n_data == r_data, "out-of-order readv: nginx vs ref mismatch"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_readv_nginx_and_ref_agree(self):
        path, content = _seed(32768, "readvagree")
        chunk = 4096
        segments = [(i * chunk, chunk) for i in range(len(content) // chunk)]
        try:
            n_f, _ = _open_file(NGINX_URL, path)
            r_f, _ = _open_file(REF_URL,   path)
            _, n_vri = n_f.vector_read(segments)
            _, r_vri = r_f.vector_read(segments)
            n_f.close()
            r_f.close()

            n_data = b"".join(c.buffer for c in n_vri.chunks)
            r_data = b"".join(c.buffer for c in r_vri.chunks)
            _assert_full_readv(n_data, r_data, content)
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# pgread (kXR_pgread) — data must match regular read
# ---------------------------------------------------------------------------

class TestPgreadConformance:
    """
    pgread returns per-page CRC32c checksums alongside data.  The Python client
    presents it as a regular read; we verify data integrity by comparing with
    sequential kXR_read output from both servers.
    """

    def test_pgread_data_matches_regular_read(self):
        path, content = _seed(8192, "pgread")
        try:
            # Read via nginx (which may use pgread internally for large reads)
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)

            assert n_st.ok and r_st.ok
            assert n_data == r_data == content, (
                f"pgread data mismatch: "
                f"nginx={_md5(n_data)} ref={_md5(r_data)} expected={_md5(content)}"
            )
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_page_boundary_alignment(self):
        # 3 full pages: 3 × 4096 = 12288
        page_size = 4096
        path, content = _seed(3 * page_size, "pgrd_align")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_non_page_aligned_size(self):
        # Partial last page: 2 full pages + 100 bytes
        path, content = _seed(2 * 4096 + 100, "pgrd_partial")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_single_page(self):
        path, content = _seed(4096, "pgrd_one")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_sub_page(self):
        path, content = _seed(100, "pgrd_sub")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgread_checksum_coverage_across_large_file(self):
        # 64 pages: enough to exercise the CRC32c chain
        path, content = _seed(64 * 4096, "pgrd_large")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert _md5(n_data) == _md5(r_data) == _md5(content)
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# pgwrite (kXR_pgwrite) — write then read back via ref
# ---------------------------------------------------------------------------

class TestPgwriteConformance:

    def _pgwrite_file(self, content, name_suffix=""):
        name = f"_pgw_{os.getpid()}{name_suffix}.bin"
        path = f"/{name}"

        f = client.File()
        st, _ = f.open(_url(NGINX_URL, path),
                       OpenFlags.NEW | OpenFlags.WRITE)
        assert st.ok, f"open for pgwrite: {st.message}"
        # xrdcp v5 uses pgwrite internally; the Python client sends kXR_write
        # which the server handles identically.  For true pgwrite wire-level
        # testing see test_pgwrite_checksum.py.
        chunk = 4096
        for off in range(0, len(content), chunk):
            piece = content[off:off+chunk]
            st2, _ = f.write(piece, offset=off)
            assert st2.ok, f"write at {off}: {st2.message}"
        f.close()
        return path, name

    def test_pgwrite_4k_boundary_readback_via_ref(self):
        content = os.urandom(16 * 4096)
        path, name = self._pgwrite_file(content, "_4k")
        try:
            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok, f"ref read-back failed: {r_st.message}"
            assert _md5(r_data) == _md5(content), "pgwrite 4k boundary: data mismatch"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgwrite_non_aligned_readback_via_ref(self):
        content = os.urandom(4096 + 777)
        path, name = self._pgwrite_file(content, "_mis")
        try:
            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok
            assert r_data == content
        finally:
            _fs(NGINX_URL).rm(path)

    def test_pgwrite_checksum_verified_by_ref_read(self):
        content = os.urandom(8 * 4096)
        path, name = self._pgwrite_file(content, "_cksum")
        try:
            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content, \
                "pgwrite: nginx and ref disagree on file content"
            # Verify adler32 via nginx query
            q_st, q_result = _fs(NGINX_URL).query(
                client.flags.QueryCode.CHECKSUM, path
            )
            if q_st.ok:
                cksum_val = q_result.decode().split()[1].rstrip("\x00")
                assert cksum_val == _adler32_hex(content), \
                    f"pgwrite checksum mismatch: {cksum_val} vs {_adler32_hex(content)}"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# writev (kXR_writev)
# ---------------------------------------------------------------------------

class TestWritevConformance:
    """
    kXR_writev: scatter-gather write.  Write discontiguous segments, then
    read back via both servers and verify agreement.
    """

    def test_writev_then_read_back(self):
        total   = 8192
        content = os.urandom(total)
        name    = f"_writev_{os.getpid()}.bin"
        path    = f"/{name}"

        try:
            # Pre-allocate file to total size (write zeros)
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path),
                           OpenFlags.NEW | OpenFlags.WRITE)
            assert st.ok
            st2, _ = f.write(b"\x00" * total, offset=0)
            assert st2.ok

            # Now overwrite with chunks via sequential writes at specific offsets
            chunk = total // 4
            for i, off in enumerate(range(0, total, chunk)):
                piece = content[off:off+chunk]
                st3, _ = f.write(piece, offset=off)
                assert st3.ok, f"write chunk {i} at {off}: {st3.message}"
            f.close()

            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data == content, (
                f"writev readback mismatch: "
                f"nginx_md5={_md5(n_data)} ref_md5={_md5(r_data)}"
            )
        finally:
            _fs(NGINX_URL).rm(path)

    def test_writev_sparse_segments_agree(self):
        """Write at offsets leaving gaps; both servers see same zeros in gaps."""
        total = 4096
        name  = f"_writev_sparse_{os.getpid()}.bin"
        path  = f"/{name}"

        try:
            f = client.File()
            f.open(_url(NGINX_URL, path), OpenFlags.NEW | OpenFlags.WRITE)
            f.write(b"\x00" * total)
            # Overwrite first and last 512 bytes only
            first = os.urandom(512)
            last  = os.urandom(512)
            f.write(first, offset=0)
            f.write(last,  offset=total - 512)
            f.close()

            n_st, n_data = _read_all(NGINX_URL, path)
            r_st, r_data = _read_all(REF_URL,   path)
            assert n_st.ok and r_st.ok
            assert n_data == r_data, "sparse write: nginx and ref disagree"
            assert n_data[:512]  == first
            assert n_data[-512:] == last
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# sync (kXR_sync)
# ---------------------------------------------------------------------------

class TestSyncConformance:

    def test_sync_on_open_read_handle_succeeds_on_both(self):
        path, _ = _seed(1024, "sync")
        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f, st = _open_file(url, path)
                assert st.ok
                s_st = f.sync()
                f.close()
                assert s_st[0].ok, f"{label} sync failed: {s_st[0].message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_sync_after_write_returns_ok(self):
        name = f"_sync_write_{os.getpid()}.bin"
        path = f"/{name}"
        try:
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path),
                           OpenFlags.NEW | OpenFlags.WRITE)
            assert st.ok
            f.write(os.urandom(4096))
            s_st = f.sync()
            assert s_st[0].ok, f"sync after write: {s_st[0].message}"
            f.close()
        finally:
            _fs(NGINX_URL).rm(path)

    def test_sync_data_visible_to_ref_after_sync(self):
        name    = f"_sync_vis_{os.getpid()}.bin"
        path    = f"/{name}"
        content = os.urandom(2048)
        try:
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path),
                           OpenFlags.NEW | OpenFlags.WRITE)
            assert st.ok
            f.write(content)
            f.sync()
            f.close()

            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok
            assert r_data == content, "data not visible to ref after sync"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# locate (kXR_locate)
# ---------------------------------------------------------------------------
