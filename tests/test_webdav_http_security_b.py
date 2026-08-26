from split_continuation import reexport as _reexport
_reexport(globals(), "_test_webdav_http_security_helpers")

pytestmark = pytest.mark.registry_server("main")

class TestPutContentRange:
    """Partial PUT (resumable upload) via Content-Range header."""

    def test_put_no_content_range_full_overwrite(self):
        path = f"/{_PFX}cr_full.txt"
        s = _session()
        r = s.put(_url(path), data=b"complete content")
        assert r.status_code in (200, 201, 204)
        r2 = _get(path)
        assert r2.content == b"complete content"

    def test_put_content_range_first_segment_accepted(self):
        path = f"/{_PFX}cr_partial.bin"
        _remove(path)
        s = _session()
        segment = b"A" * 500
        r = s.put(_url(path), data=segment,
                  headers={"Content-Range": "bytes 0-499/1000"})
        # Server may accept (200/201) or return 501 (not implemented)
        assert r.status_code in (200, 201, 400, 501)

    def test_put_content_range_invalid_value_no_crash(self):
        path = f"/{_PFX}cr_invalid.bin"
        s = _session()
        r = s.put(_url(path), data=b"data",
                  headers={"Content-Range": "bytes blah-blah/total"})
        # Invalid Content-Range: server may reject (400/501) or ignore and create/replace (200/201/204)
        assert r.status_code in (200, 201, 204, 400, 501)

    def test_put_large_body_accepted(self):
        path = f"/{_PFX}cr_large.bin"
        s = _session()
        data = b"Z" * (1024 * 128)  # 128 KiB
        r = s.put(_url(path), data=data)
        assert r.status_code in (200, 201, 204)
        assert os.path.getsize(os.path.join(_data_root(), f"{_PFX}cr_large.bin")) == len(data)

    def test_put_then_get_roundtrip(self):
        path = f"/{_PFX}cr_rt.txt"
        content = b"roundtrip content 12345"
        s = _session()
        s.put(_url(path), data=content)
        r = _get(path)
        assert r.status_code == 200
        assert r.content == content


# ---------------------------------------------------------------------------
# TestHTTPWebDavPlain
# ---------------------------------------------------------------------------

class TestHTTPWebDavPlain:
    """Smoke tests on the plain HTTP WebDAV port (8080)."""

    def _hget(self, path, **kwargs):
        return requests.get(_http_url(path), **kwargs)

    def _hput(self, path, data=b""):
        return requests.put(_http_url(path), data=data)

    def _hdelete(self, path):
        return requests.delete(_http_url(path))

    def _hmkcol(self, path):
        return requests.request("MKCOL", _http_url(path))

    def _hpropfind(self, path, depth="0"):
        return requests.request("PROPFIND", _http_url(path),
                                headers={"Depth": depth})

    def test_http_put_get_roundtrip(self):
        path = f"/{_PFX}http_rt.txt"
        content = b"plain http roundtrip"
        r = self._hput(path, content)
        assert r.status_code in (200, 201, 204)
        r2 = self._hget(path)
        assert r2.status_code == 200
        assert r2.content == content

    def test_http_propfind_207(self):
        path = f"/{_PFX}http_pf.txt"
        _make_file(path, b"propfind over http")
        r = self._hpropfind(path, depth="0")
        assert r.status_code == 207

    def test_http_range_request_206(self):
        content = b"ABCDEFGHIJ"
        path = f"/{_PFX}http_range.bin"
        _make_file(path, content)
        r = self._hget(path, headers={"Range": "bytes=0-4"})
        assert r.status_code == 206
        assert r.content == b"ABCDE"

    def test_http_delete_removes_file(self):
        path = f"/{_PFX}http_del.txt"
        _make_file(path, b"delete via http")
        r = self._hdelete(path)
        assert r.status_code in (200, 204)
        assert not os.path.exists(os.path.join(_data_root(), path.lstrip("/")))

    def test_http_mkcol_creates_directory(self):
        path = f"/{_PFX}http_mkcol"
        _remove(path)
        r = self._hmkcol(path)
        assert r.status_code == 201
        assert os.path.isdir(os.path.join(_data_root(), path.lstrip("/")))

    # --- MOVE/COPY DESTINATION confinement ---------------------------------
    # The source path of MOVE/COPY is confined like any request URI, but the
    # DESTINATION arrives in a header and must be confined independently.  A
    # Destination that escapes the export root (via ".." or encoded "%2e%2e")
    # must be rejected and must not create/overwrite anything outside the root.

    def _outside_zone(self):
        return os.path.dirname(_data_root().rstrip("/"))   # one level above the root

    def _assert_no_escape(self, name):
        p = os.path.join(self._outside_zone(), name)
        if os.path.exists(p):
            try:
                os.rmdir(p) if os.path.isdir(p) else os.remove(p)
            except OSError:
                pass
            pytest.fail(
                f"CONFINEMENT BREACH: {p} created outside the export root")

    def test_http_move_destination_traversal_rejected(self):
        src = f"/{_PFX}http_mvdst_src.txt"
        _make_file(src, b"keep-me")
        pwned = f"{_PFX}pwned_mv"
        for dest in (f"/../{pwned}", f"/%2e%2e/{pwned}"):
            r = requests.request(
                "MOVE", _http_url(src),
                headers={"Destination": _http_url(dest),
                         "Overwrite": "T"})
            assert r.status_code not in (200, 201, 204), \
                f"MOVE to escaping Destination {dest} succeeded ({r.status_code})"
        assert os.path.exists(os.path.join(_data_root(), src.lstrip("/"))), \
            "source file vanished after a rejected MOVE"
        self._assert_no_escape(pwned)
        _remove(src)

    def test_http_copy_destination_traversal_rejected(self):
        src = f"/{_PFX}http_cpdst_src.txt"
        _make_file(src, b"keep-me")
        pwned = f"{_PFX}pwned_cp"
        for dest in (f"/../{pwned}", f"/%2e%2e/{pwned}"):
            r = requests.request(
                "COPY", _http_url(src),
                headers={"Destination": _http_url(dest),
                         "Overwrite": "T"})
            assert r.status_code not in (200, 201, 204), \
                f"COPY to escaping Destination {dest} succeeded ({r.status_code})"
        self._assert_no_escape(pwned)
        _remove(src)
