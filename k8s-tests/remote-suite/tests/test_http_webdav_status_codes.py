from _test_http_webdav_status_codes_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestOptions:
    def test_options_root_200(self):
        r = requests.options(_url("/"), timeout=10)
        assert r.status_code == 200

    def test_options_allow_header_has_get_put(self):
        r = requests.options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "GET" in allow
        assert "PUT" in allow

    def test_options_allow_header_has_webdav_methods(self):
        r = requests.options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        for method in ("DELETE", "MKCOL", "PROPFIND"):
            assert method in allow, f"{method} missing from Allow: {allow}"

    def test_options_cors_preflight_200(self):
        r = requests.options(
            _url("/"),
            headers={
                "Origin": "https://debug.example.test",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
            timeout=10,
        )
        assert r.status_code == 200
        assert r.headers.get("Access-Control-Allow-Origin")

    def test_options_cors_allows_put(self):
        r = requests.options(
            _url("/"),
            headers={
                "Origin": "https://debug.example.test",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
            timeout=10,
        )
        assert "PUT" in r.headers.get("Access-Control-Allow-Methods", "")


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_existing_200(self):
        path, content, _ = _existing_file()
        r = _get(path)
        assert r.status_code == 200
        assert r.content == content

    def test_get_missing_404(self):
        r = _get(f"/{_PFX}no_such_{_uid()}.txt")
        assert r.status_code == 404

    def test_get_directory_403(self):
        path = f"/{_PFX}dir_{_uid()}"
        _mkcol(path)
        r = _get(path + "/")
        assert r.status_code == 403

    def test_get_range_206(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        assert len(r.content) == 4

    def test_get_range_first_byte_206(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"Range": "bytes=0-0"})
        assert r.status_code == 206
        assert r.content == content[:1]

    def test_get_range_suffix_206(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"Range": f"bytes=-{len(content)}"})
        assert r.status_code == 206
        assert r.content == content

    def test_get_range_beyond_eof_416(self):
        path, content, _ = _existing_file()
        beyond = len(content) + 100
        r = _get(path, headers={"Range": f"bytes={beyond}-{beyond+10}"})
        assert r.status_code == 416

    def test_get_range_content_range_header_present(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        assert "Content-Range" in r.headers

    def test_get_range_content_range_format(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        cr = r.headers.get("Content-Range", "")
        assert cr.startswith("bytes "), f"unexpected Content-Range: {cr!r}"

    def test_get_if_none_match_matching_etag_304(self):
        path, _, _ = _existing_file()
        etag = _head(path).headers.get("ETag", "")
        if not etag:
            pytest.skip("server did not return ETag")
        r = _get(path, headers={"If-None-Match": etag})
        assert r.status_code == 304

    def test_get_if_none_match_wrong_etag_200(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"If-None-Match": '"totally-wrong-etag"'})
        assert r.status_code == 200
        assert r.content == content

    def test_get_if_match_correct_etag_200(self):
        path, content, _ = _existing_file()
        etag = _head(path).headers.get("ETag", "")
        if not etag:
            pytest.skip("server did not return ETag")
        r = _get(path, headers={"If-Match": etag})
        assert r.status_code == 200

    def test_get_if_match_wrong_etag_412(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"If-Match": '"does-not-exist"'})
        assert r.status_code == 412

    def test_get_if_modified_since_old_200(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        assert r.status_code == 200
        assert r.content == content

    def test_get_if_modified_since_future_304(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"If-Modified-Since": "Thu, 01 Jan 2099 00:00:00 GMT"})
        assert r.status_code == 304

    def test_get_if_unmodified_since_old_412(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        assert r.status_code == 412

    def test_get_if_unmodified_since_future_200(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"If-Unmodified-Since": "Thu, 01 Jan 2099 00:00:00 GMT"})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# HEAD
# ---------------------------------------------------------------------------


class TestHead:
    def test_head_existing_200(self):
        path, content, _ = _existing_file()
        r = _head(path)
        assert r.status_code == 200

    def test_head_content_length_correct(self):
        path, content, _ = _existing_file()
        r = _head(path)
        assert int(r.headers.get("Content-Length", -1)) == len(content)

    def test_head_missing_404(self):
        r = _head(f"/{_PFX}no_such_{_uid()}.bin")
        assert r.status_code == 404

    def test_head_returns_etag(self):
        path, _, _ = _existing_file()
        r = _head(path)
        assert "ETag" in r.headers, "RFC 7232 §2.3 requires ETag in GET/HEAD responses"

    def test_head_etag_matches_get(self):
        path, _, _ = _existing_file()
        etag_head = _head(path).headers.get("ETag", "")
        etag_get  = _get(path).headers.get("ETag", "")
        if not etag_head:
            pytest.skip("server did not return ETag")
        assert etag_head == etag_get

    def test_head_no_body(self):
        path, _, _ = _existing_file()
        r = _head(path)
        assert r.content == b""


# ---------------------------------------------------------------------------
# PUT
# ---------------------------------------------------------------------------


class TestPut:
    def test_put_new_file_201(self):
        path = f"/{_PFX}new_{_uid()}.txt"
        r = _put(path, b"new file")
        assert r.status_code == 201

    def test_put_content_stored_correctly(self):
        path, content, _ = _existing_file()
        r = _get(path)
        assert r.content == content

    def test_put_overwrite_204(self):
        path, _, _ = _existing_file()
        r = _put(path, b"overwritten content")
        assert r.status_code == 204
        assert _get(path).content == b"overwritten content"

    def test_put_zero_bytes_201(self):
        path = f"/{_PFX}zero_{_uid()}.bin"
        r = _put(path, b"")
        assert r.status_code == 201
        assert _get(path).status_code == 200
        assert _get(path).content == b""

    def test_put_if_none_match_star_new_file_201(self):
        path = f"/{_PFX}ifnm_{_uid()}.txt"
        r = _put(path, b"exclusive create", headers={"If-None-Match": "*"})
        assert r.status_code == 201

    def test_put_if_none_match_star_existing_412(self):
        path, _, _ = _existing_file()
        r = _put(path, b"should fail", headers={"If-None-Match": "*"})
        assert r.status_code == 412

    def test_put_if_match_star_existing_succeeds(self):
        path, _, _ = _existing_file()
        r = _put(path, b"conditional overwrite", headers={"If-Match": "*"})
        assert r.status_code == 204

    def test_put_if_match_wrong_etag_412(self):
        path, _, _ = _existing_file()
        r = _put(path, b"should fail", headers={"If-Match": '"wrong-etag-value"'})
        assert r.status_code == 412

    def test_put_binary_data_roundtrip(self):
        path = f"/{_PFX}bin_{_uid()}.bin"
        content = bytes(range(256)) * 4
        _put(path, content)
        assert _get(path).content == content

    def test_put_to_missing_parent_409(self):
        path = f"/{_PFX}noparent_{_uid()}/file.txt"
        r = _put(path, b"orphan")
        assert r.status_code == 409

    def test_put_etag_changes_after_overwrite(self):
        path, _, _ = _existing_file()
        etag_before = _head(path).headers.get("ETag", "")
        _put(path, b"updated " + _uid().encode())
        etag_after = _head(path).headers.get("ETag", "")
        if etag_before and etag_after:
            assert etag_before != etag_after


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_existing_file_204(self):
        path, _, _ = _existing_file()
        r = _delete(path)
        assert r.status_code == 204

    def test_delete_file_then_get_404(self):
        path, _, _ = _existing_file()
        _delete(path)
        assert _get(path).status_code == 404

    def test_delete_non_empty_directory_409(self):
        parent = f"/{_PFX}dir_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/file.txt", b"content")
        _mkcol(f"{parent}/subdir")
        _put(f"{parent}/subdir/file2.txt", b"content2")

        r = _delete(parent)
        # Non-empty directory → 409 Conflict; directory is NOT deleted.
        assert r.status_code == 409
        assert _propfind(parent).status_code == 207  # still exists


    def test_delete_empty_directory_204(self):
        path = f"/{_PFX}emptydir_{_uid()}"
        _mkcol(path)
        r = _delete(path)
        assert r.status_code == 204

    def test_delete_nonempty_directory_409(self):
        path = f"/{_PFX}fulldir_{_uid()}"
        _mkcol(path)
        _put(f"{path}/child.txt", b"child")
        r = _delete(path)
        assert r.status_code == 409

    def test_delete_missing_source_404(self):
        r = _delete(f"/{_PFX}no_{_uid()}.txt")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# MKCOL
# ---------------------------------------------------------------------------


class TestMkcol:
    def test_mkcol_new_directory_201(self):
        path = f"/{_PFX}dir_{_uid()}"
        r = _mkcol(path)
        assert r.status_code == 201

    def test_mkcol_existing_directory_405(self):
        path = f"/{_PFX}dup_{_uid()}"
        _mkcol(path)
        r = _mkcol(path)
        assert r.status_code == 405

    def test_mkcol_existing_file_405(self):
        path, _, _ = _existing_file()
        r = _mkcol(path)
        assert r.status_code == 405

    def test_mkcol_missing_parent_409(self):
        path = f"/{_PFX}noparent_{_uid()}/subdir"
        r = _mkcol(path)
        assert r.status_code == 409

    def test_mkcol_trailing_slash_201(self):
        path = f"/{_PFX}slashdir_{_uid()}/"
        r = _mkcol(path)
        assert r.status_code == 201

    def test_mkcol_is_visible_in_propfind(self):
        path = f"/{_PFX}vis_{_uid()}"
        _mkcol(path)
        r = _propfind("/", depth="1")
        assert path.lstrip("/") in r.text or path in r.text


# ---------------------------------------------------------------------------
# PROPFIND
# ---------------------------------------------------------------------------
