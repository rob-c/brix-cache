from split_continuation import reexport as _reexport
_reexport(globals(), "_test_webdav_http_security_helpers")

class TestRangeRequests:
    """RFC 7233 partial content correctness."""

    def test_range_first_byte_only(self):
        _make_file(f"/{_PFX}range_file.bin", b"ABCDEFGHIJ")
        r = _get(f"/{_PFX}range_file.bin", headers={"Range": "bytes=0-0"})
        assert r.status_code == 206
        assert r.content == b"A"

    def test_range_last_byte_only(self):
        _make_file(f"/{_PFX}range_last.bin", b"ABCDEFGHIJ")
        r = _get(f"/{_PFX}range_last.bin", headers={"Range": "bytes=-1"})
        assert r.status_code == 206
        assert r.content == b"J"

    def test_range_exact_file_span(self):
        content = b"0123456789"
        _make_file(f"/{_PFX}range_exact.bin", content)
        r = _get(f"/{_PFX}range_exact.bin",
                 headers={"Range": f"bytes=0-{len(content)-1}"})
        assert r.status_code in (200, 206)
        assert r.content == content

    def test_range_middle_bytes(self):
        content = b"A" * 300
        _make_file(f"/{_PFX}range_mid.bin", content)
        r = _get(f"/{_PFX}range_mid.bin", headers={"Range": "bytes=100-199"})
        assert r.status_code == 206
        assert len(r.content) == 100

    def test_range_suffix_larger_than_file(self):
        content = b"X" * 50
        _make_file(f"/{_PFX}range_suffix.bin", content)
        r = _get(f"/{_PFX}range_suffix.bin", headers={"Range": "bytes=-99999"})
        assert r.status_code in (200, 206)
        assert r.content == content

    def test_range_beyond_end_returns_416(self):
        _make_file(f"/{_PFX}range_416.bin", b"X" * 10)
        r = _get(f"/{_PFX}range_416.bin", headers={"Range": "bytes=99999-100000"})
        assert r.status_code == 416

    def test_range_invalid_syntax_no_crash(self):
        _make_file(f"/{_PFX}range_inv.bin", b"HELLO")
        r = _get(f"/{_PFX}range_inv.bin", headers={"Range": "bytes=abc-def"})
        # Invalid range syntax → nginx may return 200 (ignored) or 416
        assert r.status_code in (200, 416)

    def test_range_reversed_start_gt_end(self):
        _make_file(f"/{_PFX}range_rev.bin", b"ABCDEFGHIJ")
        r = _get(f"/{_PFX}range_rev.bin", headers={"Range": "bytes=9-3"})
        # Reversed range: nginx returns 416 or 200
        assert r.status_code in (200, 416)

    def test_range_206_includes_content_range_header(self):
        content = b"0123456789"
        _make_file(f"/{_PFX}range_hdr.bin", content)
        r = _get(f"/{_PFX}range_hdr.bin", headers={"Range": "bytes=0-4"})
        assert r.status_code == 206
        assert "Content-Range" in r.headers
        assert r.headers["Content-Range"].startswith("bytes 0-4/")

    def test_range_206_content_range_total_correct(self):
        content = b"X" * 200
        _make_file(f"/{_PFX}range_total.bin", content)
        r = _get(f"/{_PFX}range_total.bin", headers={"Range": "bytes=0-9"})
        assert r.status_code == 206
        cr = r.headers.get("Content-Range", "")
        assert "/200" in cr

    def test_range_zero_to_zero_empty_file(self):
        _make_file(f"/{_PFX}range_empty.bin", b"")
        r = _get(f"/{_PFX}range_empty.bin", headers={"Range": "bytes=0-0"})
        # No bytes in file → 416 Requested Range Not Satisfiable
        assert r.status_code == 416

    def test_range_body_bytes_correct(self):
        content = bytes(range(256))
        _make_file(f"/{_PFX}range_bytes.bin", content)
        r = _get(f"/{_PFX}range_bytes.bin", headers={"Range": "bytes=10-19"})
        assert r.status_code == 206
        assert r.content == content[10:20]


# ---------------------------------------------------------------------------
# TestConditionalRequests
# ---------------------------------------------------------------------------

class TestConditionalRequests:
    """If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since."""

    def _setup_file(self, name, content=b"conditional test content"):
        path = f"/{_PFX}{name}"
        _make_file(path, content)
        r = _get(path)
        assert r.status_code == 200
        return path, r.headers.get("ETag", ""), r.headers.get("Last-Modified", "")

    def test_if_match_correct_etag_200(self):
        path, etag, _ = self._setup_file("ifm_correct.txt")
        if not etag:
            pytest.skip("Server did not return ETag")
        r = _get(path, headers={"If-Match": etag})
        assert r.status_code == 200

    def test_if_match_wrong_etag_412(self):
        path, _, _ = self._setup_file("ifm_wrong.txt")
        r = _get(path, headers={"If-Match": '"wrongetag99"'})
        assert r.status_code == 412

    def test_if_match_star_200(self):
        path, _, _ = self._setup_file("ifm_star.txt")
        r = _get(path, headers={"If-Match": "*"})
        assert r.status_code == 200

    def test_if_none_match_correct_etag_304(self):
        path, etag, _ = self._setup_file("ifnm_match.txt")
        if not etag:
            pytest.skip("Server did not return ETag")
        r = _get(path, headers={"If-None-Match": etag})
        assert r.status_code == 304

    def test_if_none_match_wrong_etag_200(self):
        path, _, _ = self._setup_file("ifnm_wrong.txt")
        r = _get(path, headers={"If-None-Match": '"wrongetag99"'})
        assert r.status_code == 200

    def test_if_modified_since_past_200(self):
        path, _, _ = self._setup_file("ims_past.txt")
        r = _get(path, headers={"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        assert r.status_code == 200

    def test_if_modified_since_future_no_crash(self):
        path, _, _ = self._setup_file("ims_future.txt")
        r = _get(path, headers={"If-Modified-Since": "Tue, 01 Jan 2030 00:00:00 GMT"})
        # File pre-dates the future date → 304; server may return 200 if header unsupported
        assert r.status_code in (200, 304)

    def test_if_unmodified_since_past_412(self):
        path, _, _ = self._setup_file("ius_past.txt")
        r = _get(path, headers={"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        assert r.status_code == 412

    def test_if_unmodified_since_future_200(self):
        path, _, _ = self._setup_file("ius_future.txt")
        r = _get(path, headers={"If-Unmodified-Since": "Tue, 01 Jan 2030 00:00:00 GMT"})
        assert r.status_code == 200

    def test_put_if_none_match_star_creates_new(self):
        path = f"/{_PFX}ifnm_create.txt"
        _remove(path)
        s = _session()
        r = s.put(_url(path), data=b"new", headers={"If-None-Match": "*"})
        assert r.status_code in (200, 201)

    def test_put_if_none_match_star_existing_behaviour(self):
        path = f"/{_PFX}ifnm_conflict.txt"
        _make_file(path, b"already exists")
        s = _session()
        r = s.put(_url(path), data=b"overwrite attempt",
                  headers={"If-None-Match": "*"})
        # RFC 7232 says 412 when resource exists; nginx WebDAV may accept (200/204) instead
        assert r.status_code in (200, 201, 204, 412)

    def test_etag_changes_after_put(self):
        path = f"/{_PFX}etag_change.txt"
        _make_file(path, b"original content")
        r1 = _get(path)
        etag1 = r1.headers.get("ETag", "")
        s = _session()
        s.put(_url(path), data=b"completely different new content 12345")
        r2 = _get(path)
        etag2 = r2.headers.get("ETag", "")
        if etag1 and etag2:
            assert etag1 != etag2

    def test_etag_stable_across_two_gets(self):
        path = f"/{_PFX}etag_stable.txt"
        _make_file(path, b"stable content")
        r1 = _get(path)
        r2 = _get(path)
        e1 = r1.headers.get("ETag", "")
        e2 = r2.headers.get("ETag", "")
        if e1 and e2:
            assert e1 == e2

    def test_head_etag_matches_get_etag(self):
        path = f"/{_PFX}head_etag.txt"
        _make_file(path, b"head test content")
        s = _session()
        rg = _get(path)
        rh = s.head(_url(path))
        eg = rg.headers.get("ETag", "")
        eh = rh.headers.get("ETag", "")
        if eg and eh:
            assert eg == eh

    def test_if_match_on_nonexistent_412(self):
        path = f"/{_PFX}ifm_missing.txt"
        _remove(path)
        s = _session()
        r = s.get(_url(path), headers={"If-Match": "*"})
        assert r.status_code in (404, 412)


# ---------------------------------------------------------------------------
# TestErrorStatusCodes
# ---------------------------------------------------------------------------

class TestErrorStatusCodes:
    """HTTP error status code correctness."""

    def test_404_missing_file(self):
        r = _get(f"/{_PFX}missing_xyz_abc_123.txt")
        assert r.status_code == 404

    def test_404_propfind_nonexistent(self):
        s = _session()
        r = s.request("PROPFIND", _url(f"/{_PFX}pf_missing.txt"),
                      headers={"Depth": "0"})
        assert r.status_code == 404

    def test_put_to_existing_directory_no_crash(self):
        _make_dir(f"/{_PFX}put_dir")
        s = _session()
        r = s.put(_url(f"/{_PFX}put_dir"), data=b"data")
        # Putting data to an existing directory → 405, 409, or 500 (server error)
        assert r.status_code in (405, 409, 500)

    def test_409_mkcol_parent_missing(self):
        s = _session()
        r = s.request("MKCOL", _url(f"/{_PFX}noparent/newdir"))
        assert r.status_code == 409

    def test_409_delete_nonempty_directory(self):
        _make_dir(f"/{_PFX}del_nempty")
        _make_file(f"/{_PFX}del_nempty/child.txt", b"x")
        s = _session()
        r = s.delete(_url(f"/{_PFX}del_nempty"))
        # Non-empty directory delete → 409 Conflict
        assert r.status_code == 409

    def test_207_propfind_existing_file(self):
        _make_file(f"/{_PFX}pf_exist.txt", b"propfind me")
        s = _session()
        r = s.request("PROPFIND", _url(f"/{_PFX}pf_exist.txt"),
                      headers={"Depth": "0"})
        assert r.status_code == 207

    def test_200_options_includes_allow_header(self):
        s = _session()
        r = s.options(_url("/"))
        assert r.status_code == 200
        allow = r.headers.get("Allow", "")
        assert "GET" in allow

    def test_204_delete_existing_file(self):
        _make_file(f"/{_PFX}del_exist.txt", b"delete me")
        s = _session()
        r = s.delete(_url(f"/{_PFX}del_exist.txt"))
        assert r.status_code in (200, 204)
        assert not os.path.exists(
            os.path.join(DATA_ROOT, f"{_PFX}del_exist.txt"))

    def test_201_mkcol_creates_directory(self):
        _remove(f"/{_PFX}mkcol_new")
        s = _session()
        r = s.request("MKCOL", _url(f"/{_PFX}mkcol_new"))
        assert r.status_code == 201
        assert os.path.isdir(os.path.join(DATA_ROOT, f"{_PFX}mkcol_new"))

    def test_delete_then_get_404(self):
        path = f"/{_PFX}del_gone.txt"
        _make_file(path, b"temporary")
        s = _session()
        s.delete(_url(path))
        r = _get(path)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# TestPropfindDepth
# ---------------------------------------------------------------------------

class TestPropfindDepth:
    """PROPFIND Depth header variants."""

    def _propfind(self, path, depth=None):
        s = _session()
        headers = {}
        if depth is not None:
            headers["Depth"] = str(depth)
        return s.request("PROPFIND", _url(path), headers=headers)

    def test_propfind_depth_0_returns_self_only(self):
        _make_dir(f"/{_PFX}pfd_dir")
        _make_file(f"/{_PFX}pfd_dir/child.txt", b"child")
        r = self._propfind(f"/{_PFX}pfd_dir", depth=0)
        assert r.status_code == 207
        body = r.text
        assert f"{_PFX}pfd_dir" in body
        assert "child.txt" not in body

    def test_propfind_depth_0_on_file(self):
        _make_file(f"/{_PFX}pfd_file.txt", b"file")
        r = self._propfind(f"/{_PFX}pfd_file.txt", depth=0)
        assert r.status_code == 207
        assert f"{_PFX}pfd_file.txt" in r.text

    def test_propfind_depth_1_returns_children(self):
        _make_dir(f"/{_PFX}pfd1_dir")
        _make_file(f"/{_PFX}pfd1_dir/alpha.txt", b"a")
        _make_file(f"/{_PFX}pfd1_dir/beta.txt", b"b")
        r = self._propfind(f"/{_PFX}pfd1_dir", depth=1)
        assert r.status_code == 207
        body = r.text
        assert "alpha.txt" in body
        assert "beta.txt" in body

    def test_propfind_depth_1_on_file(self):
        _make_file(f"/{_PFX}pfd1_file.txt", b"file")
        r = self._propfind(f"/{_PFX}pfd1_file.txt", depth=1)
        assert r.status_code == 207

    def test_propfind_no_depth_header_no_crash(self):
        _make_file(f"/{_PFX}pfd_nodepth.txt", b"x")
        r = self._propfind(f"/{_PFX}pfd_nodepth.txt", depth=None)
        assert r.status_code in (200, 207, 400)

    def test_propfind_response_is_valid_xml(self):
        _make_file(f"/{_PFX}pfd_xml.txt", b"xml check")
        r = self._propfind(f"/{_PFX}pfd_xml.txt", depth=0)
        assert r.status_code == 207
        # Should parse without error
        ET.fromstring(r.text)

    def test_propfind_includes_getcontentlength(self):
        content = b"X" * 42
        _make_file(f"/{_PFX}pfd_len.txt", content)
        r = self._propfind(f"/{_PFX}pfd_len.txt", depth=0)
        assert r.status_code == 207
        assert "42" in r.text

    def test_propfind_depth_0_empty_dir_no_children(self):
        _make_dir(f"/{_PFX}pfd_emptydir")
        r = self._propfind(f"/{_PFX}pfd_emptydir", depth=0)
        assert r.status_code == 207
        # Depth:0 → only the dir itself; no children returned
        body = r.text
        assert f"{_PFX}pfd_emptydir" in body


# ---------------------------------------------------------------------------
# TestPutContentRange
# ---------------------------------------------------------------------------
