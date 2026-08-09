from split_continuation import reexport as _reexport
_reexport(globals(), "_test_https_webdav_token_status_codes_helpers")

class TestAuthentication:
    def test_get_with_bearer_token_200(self):
        path, content, _ = _existing_file()
        r = _get(path)
        assert r.status_code == 200
        assert r.content == content

    def test_get_without_auth_200_optional_auth(self):
        """Optional-auth mode: unauthenticated requests are served."""
        path, content, _ = _existing_file()
        r = _get(path, session=_sa())
        assert r.status_code == 200

    def test_put_without_auth_201_optional_auth(self):
        """Optional-auth mode: unauthenticated PUT is accepted."""
        path = f"/{_PFX}anon_{_uid()}.txt"
        r = _put(path, b"anon upload", session=_sa())
        assert r.status_code == 201

    def test_head_without_auth_200(self):
        path, _, _ = _existing_file()
        r = _head(path, session=_sa())
        assert r.status_code == 200

    def test_propfind_without_auth_207(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0", session=_sa())
        assert r.status_code == 207


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------


class TestOptions:
    def test_options_200(self):
        r = _s().options(_url("/"), timeout=10)
        assert r.status_code == 200

    def test_options_allow_has_core_methods(self):
        r = _s().options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        for method in ("GET", "PUT", "DELETE", "PROPFIND", "MKCOL"):
            assert method in allow, f"{method} not in Allow: {allow}"

    def test_options_no_cors_on_tls_port(self):
        """CORS is only configured on the HTTP port (8080), not HTTPS (8443)."""
        r = _s().options(
            _url("/"),
            headers={
                "Origin": "https://debug.example.test",
                "Access-Control-Request-Method": "GET",
            },
            timeout=10,
        )
        assert r.status_code == 200
        assert "Access-Control-Allow-Origin" not in r.headers


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
        r = _get(f"/{_PFX}no_{_uid()}.txt")
        assert r.status_code == 404

    def test_get_range_206(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        assert len(r.content) == 4

    def test_get_range_beyond_eof_416(self):
        path, content, _ = _existing_file()
        beyond = len(content) + 100
        r = _get(path, headers={"Range": f"bytes={beyond}-{beyond+10}"})
        assert r.status_code == 416

    def test_get_range_206_includes_content_range(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        assert "Content-Range" in r.headers

    def test_get_if_none_match_304(self):
        path, _, _ = _existing_file()
        etag = _head(path).headers.get("ETag", "")
        if not etag:
            pytest.skip("no ETag")
        r = _get(path, headers={"If-None-Match": etag})
        assert r.status_code == 304

    def test_get_if_none_match_wrong_200(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"If-None-Match": '"wrong-etag"'})
        assert r.status_code == 200
        assert r.content == content

    def test_get_if_match_correct_200(self):
        path, _, _ = _existing_file()
        etag = _head(path).headers.get("ETag", "")
        if not etag:
            pytest.skip("no ETag")
        r = _get(path, headers={"If-Match": etag})
        assert r.status_code == 200

    def test_get_if_match_wrong_412(self):
        path, _, _ = _existing_file()
        r = _get(path, headers={"If-Match": '"nonexistent-etag"'})
        assert r.status_code == 412

    def test_get_if_modified_since_old_200(self):
        path, content, _ = _existing_file()
        r = _get(path, headers={"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
        assert r.status_code == 200

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

    def test_head_content_length(self):
        path, content, _ = _existing_file()
        r = _head(path)
        assert int(r.headers.get("Content-Length", -1)) == len(content)

    def test_head_missing_404(self):
        r = _head(f"/{_PFX}no_{_uid()}.bin")
        assert r.status_code == 404

    def test_head_has_etag(self):
        path, _, _ = _existing_file()
        r = _head(path)
        assert "ETag" in r.headers, "RFC 7232 §2.3 requires ETag in GET/HEAD responses"

    def test_head_no_body(self):
        path, _, _ = _existing_file()
        r = _head(path)
        assert r.content == b""

    def test_head_etag_matches_get(self):
        path, _, _ = _existing_file()
        etag_head = _head(path).headers.get("ETag", "")
        etag_get  = _get(path).headers.get("ETag", "")
        if not etag_head:
            pytest.skip("no ETag")
        assert etag_head == etag_get


# ---------------------------------------------------------------------------
# PUT
# ---------------------------------------------------------------------------


class TestPut:
    def test_put_new_201(self):
        path = f"/{_PFX}new_{_uid()}.txt"
        r = _put(path, b"new file content")
        assert r.status_code == 201

    def test_put_overwrite_succeeds(self):
        path, _, _ = _existing_file()
        new_content = b"overwritten " + _uid().encode()
        _put(path, new_content)
        assert _get(path).content == new_content

    def test_put_zero_bytes(self):
        path = f"/{_PFX}zero_{_uid()}.bin"
        r = _put(path, b"")
        assert r.status_code == 201
        assert _get(path).content == b""

    def test_put_if_none_match_star_new_201(self):
        path = f"/{_PFX}excl_{_uid()}.txt"
        r = _put(path, b"exclusive", headers={"If-None-Match": "*"})
        assert r.status_code == 201

    def test_put_if_none_match_star_existing_412(self):
        path, _, _ = _existing_file()
        r = _put(path, b"fail", headers={"If-None-Match": "*"})
        assert r.status_code == 412

    def test_put_if_match_star_overwrite_succeeds(self):
        path, _, _ = _existing_file()
        r = _put(path, b"conditional overwrite", headers={"If-Match": "*"})
        assert r.status_code == 204

    def test_put_if_match_wrong_etag_412(self):
        path, _, _ = _existing_file()
        r = _put(path, b"fail", headers={"If-Match": '"wrong-etag"'})
        assert r.status_code == 412

    def test_put_to_missing_parent_409(self):
        path = f"/{_PFX}orphan_{_uid()}/file.txt"
        r = _put(path, b"orphan")
        assert r.status_code == 409

    def test_put_binary_roundtrip(self):
        path = f"/{_PFX}bin_{_uid()}.bin"
        content = bytes(range(256)) * 8
        _put(path, content)
        assert _get(path).content == content


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_file_204(self):
        path, _, _ = _existing_file()
        r = _delete(path)
        assert r.status_code == 204

    def test_delete_then_get_404(self):
        path, _, _ = _existing_file()
        _delete(path)
        assert _get(path).status_code == 404

    def test_delete_missing_404(self):
        r = _delete(f"/{_PFX}gone_{_uid()}.txt")
        assert r.status_code == 404

    def test_delete_empty_dir_204(self):
        path = f"/{_PFX}emptydir_{_uid()}"
        _mkcol(path)
        r = _delete(path)
        assert r.status_code == 204

    def test_delete_nonempty_dir_409(self):
        path = f"/{_PFX}fulldir_{_uid()}"
        _mkcol(path)
        _put(f"{path}/child.txt", b"child")
        r = _delete(path)
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# MKCOL
# ---------------------------------------------------------------------------


class TestMkcol:
    def test_mkcol_new_dir_201(self):
        path = f"/{_PFX}mkd_{_uid()}"
        r = _mkcol(path)
        assert r.status_code == 201

    def test_mkcol_existing_dir_405(self):
        path = f"/{_PFX}dup_{_uid()}"
        _mkcol(path)
        r = _mkcol(path)
        assert r.status_code == 405

    def test_mkcol_existing_file_405(self):
        path, _, _ = _existing_file()
        r = _mkcol(path)
        assert r.status_code == 405

    def test_mkcol_missing_parent_409(self):
        r = _mkcol(f"/{_PFX}nopar_{_uid()}/sub")
        assert r.status_code == 409

    def test_mkcol_visible_via_propfind(self):
        path = f"/{_PFX}vis_{_uid()}"
        _mkcol(path)
        r = _propfind("/", depth="1")
        assert path.lstrip("/") in r.text or path in r.text


# ---------------------------------------------------------------------------
# PROPFIND
# ---------------------------------------------------------------------------


class TestPropfind:
    def test_propfind_file_depth0_207(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207

    def test_propfind_dir_depth1_207(self):
        path = f"/{_PFX}pfdir_{_uid()}"
        _mkcol(path)
        r = _propfind(path, depth="1")
        assert r.status_code == 207

    def test_propfind_missing_404(self):
        r = _propfind(f"/{_PFX}no_{_uid()}", depth="0")
        assert r.status_code == 404

    def test_propfind_xml_valid(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        ET.fromstring(r.content)

    def test_propfind_depth1_lists_children(self):
        path = f"/{_PFX}chld_{_uid()}"
        _mkcol(path)
        fname = f"kid_{_uid()}.txt"
        _put(f"{path}/{fname}", b"kid")
        r = _propfind(path, depth="1")
        assert r.status_code == 207
        assert fname in r.text

    def test_propfind_depth0_no_children(self):
        path = f"/{_PFX}nochld_{_uid()}"
        _mkcol(path)
        fname = f"notlisted_{_uid()}.txt"
        _put(f"{path}/{fname}", b"x")
        r = _propfind(path, depth="0")
        assert fname not in r.text

    def test_propfind_includes_file_size(self):
        path, content, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert str(len(content)) in r.text

    def test_propfind_content_type_xml(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        ct = r.headers.get("Content-Type", "")
        assert "xml" in ct.lower()


# ---------------------------------------------------------------------------
# MOVE
# ---------------------------------------------------------------------------
