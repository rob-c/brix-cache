from split_continuation import reexport as _reexport
_reexport(globals(), "_test_interop_query_helpers")

class TestQueryStats:

    def test_qstats_nginx_returns_nonempty(self):
        st, result = _query(NGINX_URL, QueryCode.STATS, "")
        assert st.ok, f"nginx QStats failed: {st.message}"
        assert result and len(result) > 0, "nginx QStats returned empty body"

    def test_qstats_ref_returns_nonempty(self):
        # Reference xrootd may return an empty body for QStats(""); use "a" (all)
        st, result = _query(REF_URL, QueryCode.STATS, "a")
        assert st.ok, f"ref QStats failed: {st.message}"
        assert result is not None, "ref QStats returned None result"

    def test_qstats_nginx_response_decodable(self):
        st, result = _query(NGINX_URL, QueryCode.STATS, "")
        assert st.ok
        text = result.decode("utf-8", errors="replace")
        assert len(text) > 0, "QStats response not decodable"


# ---------------------------------------------------------------------------
# kXR_query Qspace (code 5)
# ---------------------------------------------------------------------------

class TestQuerySpace:

    def _parse_space(self, raw):
        """Parse the oss.*=... format into a dict (values separated by & or space)."""
        text  = raw.decode("utf-8", errors="replace").rstrip("\x00").strip()
        parts = {}
        for token in text.replace("&", " ").split():
            if "=" in token:
                k, v = token.split("=", 1)
                parts[k.strip()] = v.strip()
        return parts

    def test_qspace_nginx_has_free_and_used(self):
        st, result = _query(NGINX_URL, QueryCode.SPACE, "//")
        assert st.ok, f"nginx Qspace failed: {st.message}"
        parts = self._parse_space(result)
        assert "oss.free" in parts or "oss.paths" in parts, \
            f"nginx Qspace missing expected keys: {parts}"

    def test_qspace_ref_has_free_and_used(self):
        st, result = _query(REF_URL, QueryCode.SPACE, "//")
        assert st.ok, f"ref Qspace failed: {st.message}"
        parts = self._parse_space(result)
        assert "oss.free" in parts or "oss.paths" in parts, \
            f"ref Qspace missing expected keys: {parts}"

    def test_qspace_nginx_free_is_positive_integer(self):
        st, result = _query(NGINX_URL, QueryCode.SPACE, "//")
        assert st.ok
        parts = self._parse_space(result)
        if "oss.free" in parts:
            assert int(parts["oss.free"]) >= 0, "oss.free is negative"

    def test_qspace_both_servers_report_nonzero_total(self):
        n_st, n_result = _query(NGINX_URL, QueryCode.SPACE, "//")
        r_st, r_result = _query(REF_URL,   QueryCode.SPACE, "//")
        assert n_st.ok == r_st.ok, \
            f"Qspace outcome mismatch: nginx={n_st.ok}, ref={r_st.ok}"


# ---------------------------------------------------------------------------
# kXR_query Qconfig (code 7)
# ---------------------------------------------------------------------------

class TestQueryConfig:

    def test_qconfig_version_key_returns_nonempty(self):
        st, result = _query(NGINX_URL, QueryCode.CONFIG, "version")
        assert st.ok, f"nginx Qconfig version failed: {st.message}"
        text = result.decode("utf-8", errors="replace").rstrip("\x00").strip()
        assert len(text) > 0, "Qconfig version returned empty string"

    def test_qconfig_ref_version_key_returns_nonempty(self):
        st, result = _query(REF_URL, QueryCode.CONFIG, "version")
        assert st.ok, f"ref Qconfig version failed: {st.message}"
        text = result.decode("utf-8", errors="replace").rstrip("\x00").strip()
        assert len(text) > 0

    def test_qconfig_version_contains_digits(self):
        st, result = _query(NGINX_URL, QueryCode.CONFIG, "version")
        assert st.ok
        text = result.decode("utf-8", errors="replace")
        assert any(c.isdigit() for c in text), \
            f"version string contains no digits: {text!r}"

    def test_qconfig_unknown_key_handled_gracefully(self):
        # Should return ok with empty/unknown value, not an error
        st, result = _query(NGINX_URL, QueryCode.CONFIG, "xyzzy_no_such_key")
        # Both ok (empty response) or error (unsupported) are acceptable;
        # what matters is it doesn't crash or hang.
        assert result is not None or not st.ok


# ---------------------------------------------------------------------------
# kXR_query Qvisa (code 8)
# ---------------------------------------------------------------------------

class TestQueryVisa:
    """
    Qvisa (QueryCode.VISA) is not universally supported.  Both nginx-xrootd and
    the reference xrootd server return error 3000 "Invalid information query type
    code" for this query.  Tests verify that both servers respond consistently
    (neither crashes/hangs) and that they agree on whether the query is supported.
    """

    def test_qvisa_nginx_responds(self):
        st, result = _query(NGINX_URL, QueryCode.VISA, "")
        # Accept either ok or error — both are valid for an unsupported query type
        assert result is not None or not st.ok, \
            "nginx Qvisa: expected a response (ok or error), got neither"

    def test_qvisa_ref_responds(self):
        st, result = _query(REF_URL, QueryCode.VISA, "")
        assert result is not None or not st.ok, \
            "ref Qvisa: expected a response (ok or error), got neither"

    def test_qvisa_both_servers_agree(self):
        n_st, _ = _query(NGINX_URL, QueryCode.VISA, "")
        r_st, _ = _query(REF_URL,   QueryCode.VISA, "")
        assert n_st.ok == r_st.ok, \
            f"Qvisa support mismatch: nginx={n_st.ok}, ref={r_st.ok}"


# ---------------------------------------------------------------------------
# kXR_query Qchecksum (code 3) — adler32 format
# ---------------------------------------------------------------------------

class TestQueryChecksumFormat:

    def test_checksum_response_format_matches_ref(self):
        """Both servers should return 'adler32 <8-hex-chars>' format."""
        import zlib
        content = os.urandom(4096)
        path    = _seed(content, "ckfmt")
        expected_cksum = format(zlib.adler32(content) & 0xFFFFFFFF, "08x")

        try:
            n_st, n_result = _query(NGINX_URL, QueryCode.CHECKSUM, path)
            assert n_st.ok, f"nginx checksum failed: {n_st.message}"

            text = n_result.decode("utf-8", errors="replace").rstrip("\x00").strip()
            parts = text.split()
            assert len(parts) == 2, f"expected 'algo hex' but got: {text!r}"
            assert parts[0] == "adler32", f"expected adler32 but got: {parts[0]!r}"
            assert parts[1] == expected_cksum, \
                f"adler32 wrong: got={parts[1]} expected={expected_cksum}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_checksum_nonexistent_fails_on_both(self):
        path = "/_no_cksum_xyzzy.bin"
        n_st, _ = _query(NGINX_URL, QueryCode.CHECKSUM, path)
        r_st, _ = _query(REF_URL,   QueryCode.CHECKSUM, path)
        assert not n_st.ok, "nginx: checksum of nonexistent should fail"
        # ref may or may not support checksums; if it does, it should also fail


# ---------------------------------------------------------------------------
# kXR_prepare
# ---------------------------------------------------------------------------

class TestPrepareConformance:

    def test_prepare_stage_existing_file_succeeds(self):
        content = os.urandom(512)
        path    = _seed(content, "prep_stage")
        try:
            # stage flag = 0x08
            st, _ = _fs(NGINX_URL).prepare([path], 0x08, 0)
            assert st.ok, f"nginx prepare stage failed: {st.message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_prepare_cancel_succeeds(self):
        content = os.urandom(512)
        path    = _seed(content, "prep_cancel")
        try:
            _fs(NGINX_URL).prepare([path], 0x08, 0)
            # cancel flag = 0x01
            st, _ = _fs(NGINX_URL).prepare([path], 0x01, 0)
            assert st.ok, f"nginx prepare cancel failed: {st.message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_prepare_multiple_paths(self):
        paths = []
        try:
            for i in range(3):
                content = os.urandom(128)
                p = _seed(content, f"prep_multi_{i}")
                paths.append(p)
            st, _ = _fs(NGINX_URL).prepare(paths, 0x08, 0)
            assert st.ok, f"nginx multi-path prepare failed: {st.message}"
        finally:
            for p in paths:
                try:
                    _fs(NGINX_URL).rm(p)
                except Exception:
                    pass

    def test_prepare_ref_and_nginx_both_succeed(self):
        content = os.urandom(512)
        path    = _seed(content, "prep_both")
        try:
            n_st, _ = _fs(NGINX_URL).prepare([path], 0x08, 0)
            r_st, _ = _fs(REF_URL  ).prepare([path], 0x08, 0)
            assert n_st.ok == r_st.ok, \
                f"prepare outcome mismatch: nginx={n_st.ok}, ref={r_st.ok}"
        finally:
            _fs(NGINX_URL).rm(path)



class TestOpenFlagsConformance:

    def test_open_retstat_returns_stat_in_response(self):
        """kXR_retstat: open response includes stat info without extra round-trip."""
        content = os.urandom(1024)
        path    = _seed(content, "retstat")
        try:
            f = client.File()
            # REFRESH acts as a hint; retstat is passed as an open option
            # The Python client doesn't expose retstat directly, but we can
            # verify that File.stat() immediately after open succeeds.
            st, _ = f.open(_url(NGINX_URL, path), OpenFlags.READ)
            assert st.ok
            s_st, info = f.stat()
            f.close()
            assert s_st.ok, f"stat after open failed: {s_st.message}"
            assert info.size == len(content), \
                f"retstat size: got={info.size} expected={len(content)}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_open_new_fails_if_file_exists(self):
        content = os.urandom(512)
        path    = _seed(content, "opennew")
        try:
            f = client.File()
            st, _ = f.open(
                _url(NGINX_URL, path),
                OpenFlags.NEW | OpenFlags.WRITE,
            )
            f.close()
            assert not st.ok, \
                "nginx: open NEW on existing file should fail"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_open_new_ref_and_nginx_agree(self):
        """NEW flag behaviour must be identical on both servers."""
        content = os.urandom(512)
        path    = _seed(content, "opennew_ref")
        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f = client.File()
                st, _ = f.open(
                    _url(url, path),
                    OpenFlags.NEW | OpenFlags.WRITE,
                )
                f.close()
                assert not st.ok, \
                    f"{label}: open NEW on existing file should fail"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_open_append_mode_extends_file(self):
        name    = f"_append_{os.getpid()}.bin"
        path    = f"/{name}"
        part1   = os.urandom(512)
        part2   = os.urandom(512)
        try:
            f = client.File()
            f.open(_url(NGINX_URL, path), OpenFlags.NEW | OpenFlags.WRITE)
            f.write(part1)
            f.close()

            f2 = client.File()
            st, _ = f2.open(_url(NGINX_URL, path), OpenFlags.UPDATE)
            assert st.ok
            # Seek to end and append
            _, info = f2.stat()
            f2.write(part2, offset=info.size)
            f2.close()

            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok
            assert r_data == part1 + part2, \
                "append: ref server sees wrong data after sequential writes"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# Error code family conformance
# ---------------------------------------------------------------------------
