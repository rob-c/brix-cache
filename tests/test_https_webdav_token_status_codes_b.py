from split_continuation import reexport as _reexport
_reexport(globals(), "_test_https_webdav_token_status_codes_helpers")

class TestMove:
    """RFC 4918 §9.9 — MOVE is implemented."""

    def test_move_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}moved_{_uid()}.txt"
        r = _move(src, dst)
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_move_overwrite_existing_204(self):
        src, content, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _move(src, dst)
        assert r.status_code == 204
        assert _get(dst).content == content

    def test_move_source_gone_after_move(self):
        src, _, _ = _existing_file()
        dst = f"/{_PFX}moved_{_uid()}.txt"
        _move(src, dst)
        assert _get(src).status_code == 404

    def test_move_missing_source_404(self):
        r = _move(f"/{_PFX}no_{_uid()}.txt", f"/{_PFX}dst_{_uid()}.txt")
        assert r.status_code == 404

    def test_move_overwrite_false_destination_exists_412(self):
        src, _, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _move(src, dst, overwrite="F")
        assert r.status_code == 412

    def test_move_overwrite_false_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}moved_{_uid()}.txt"
        r = _move(src, dst, overwrite="F")
        assert r.status_code == 201

    def test_move_in_allow_header(self):
        r = _s().options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "MOVE" in allow

    def test_move_no_destination_header_400(self):
        src, _, _ = _existing_file()
        r = _s().request("MOVE", _url(src), timeout=10)
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# COPY
# ---------------------------------------------------------------------------


class TestCopy:
    """RFC 4918 §9.8 — server-side COPY."""

    def test_copy_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}copied_{_uid()}.txt"
        r = _copy(src, dst)
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_copy_source_preserved(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}copied_{_uid()}.txt"
        _copy(src, dst)
        assert _get(src).content == content

    def test_copy_overwrite_existing_204(self):
        src, content, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _copy(src, dst)
        assert r.status_code == 204
        assert _get(dst).content == content

    def test_copy_overwrite_false_destination_exists_412(self):
        src, _, _ = _existing_file()
        dst, _, _ = _existing_file()
        r = _copy(src, dst, overwrite="F")
        assert r.status_code == 412

    def test_copy_overwrite_false_new_destination_201(self):
        src, content, _ = _existing_file()
        dst = f"/{_PFX}copied_{_uid()}.txt"
        r = _copy(src, dst, overwrite="F")
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_copy_missing_source_404(self):
        r = _copy(f"/{_PFX}no_{_uid()}.txt", f"/{_PFX}dst_{_uid()}.txt")
        assert r.status_code == 404

    def test_copy_in_allow_header(self):
        r = _s().options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "COPY" in allow

    def test_copy_no_destination_header_400(self):
        src, _, _ = _existing_file()
        r = _s().request("COPY", _url(src), timeout=10)
        assert r.status_code == 400

    def test_copy_large_file_content_correct(self):
        path = f"/{_PFX}bigcopy_{_uid()}.bin"
        content = bytes(range(256)) * 1000  # 256 KB
        _put(path, content)
        dst = f"/{_PFX}bigcopy_dst_{_uid()}.bin"
        r = _copy(path, dst)
        assert r.status_code == 201
        assert _get(dst).content == content
