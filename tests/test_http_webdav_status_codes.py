"""
tests/test_http_webdav_status_codes.py

Comprehensive HTTP status-code and RFC compliance tests for the plain-HTTP
WebDAV endpoint (port 8080, anonymous access, no TLS).

Tests assert RFC-correct behaviour.  Known compliance gaps are marked
``@pytest.mark.xfail`` with the precise RFC citation; they appear as ``x``
(expected failure) in the output and will flip to ``X`` (unexpected pass)
once the gap is resolved.

RFC compliance: all tested behaviours are now compliant.

Run:
    python3 -m pytest tests/test_http_webdav_status_codes.py -v
"""

import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

_PFX = "htsc_"


@pytest.fixture(scope="module", autouse=True)
def _base(test_env):
    global BASE
    BASE = test_env["http_webdav_url"]


def _url(path):
    return BASE + path


def _uid():
    return uuid.uuid4().hex[:12]


def _put(path, data=b"hello", **kw):
    return requests.put(_url(path), data=data, timeout=10, **kw)


def _get(path, **kw):
    return requests.get(_url(path), timeout=10, **kw)


def _head(path, **kw):
    return requests.head(_url(path), timeout=10, **kw)


def _delete(path, **kw):
    return requests.delete(_url(path), timeout=10, **kw)


def _mkcol(path, **kw):
    return requests.request("MKCOL", _url(path), timeout=10, **kw)


def _propfind(path, depth="1", body=None, **kw):
    if body is None:
        body = (
            '<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
        )
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "PROPFIND", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _move(src, dst, overwrite="T", **kw):
    headers = {
        "Destination": BASE + dst,
        "Overwrite": overwrite,
    }
    headers.update(kw.pop("headers", {}))
    return requests.request("MOVE", _url(src), headers=headers, timeout=10, **kw)


def _copy(src, dst, overwrite="T", depth=None, **kw):
    headers = {
        "Destination": BASE + dst,
        "Overwrite": overwrite,
    }
    if depth is not None:
        headers["Depth"] = depth
    headers.update(kw.pop("headers", {}))
    return requests.request("COPY", _url(src), headers=headers, timeout=10, **kw)


def _lock(path, timeout=None, **kw):
    headers = {}
    if timeout:
        headers["Timeout"] = f"Second-{timeout}"
    headers.update(kw.pop("headers", {}))
    # Default exclusive write lock body if not provided
    body = kw.pop("data",
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<D:lockinfo xmlns:D="DAV:">'
        '<D:lockscope><D:exclusive/></D:lockscope>'
        '<D:locktype><D:write/></D:locktype>'
        '</D:lockinfo>'
    )
    return requests.request("LOCK", _url(path), data=body, headers=headers, timeout=10, **kw)


def _unlock(path, token, **kw):
    if not token.startswith("<"):
        token = f"<{token}>"
    headers = {"Lock-Token": token}
    headers.update(kw.pop("headers", {}))
    return requests.request("UNLOCK", _url(path), headers=headers, timeout=10, **kw)


def _existing_file():
    """Create a file in the server root and return (path, content, etag)."""
    path = f"/{_PFX}{_uid()}.txt"
    content = f"test content {_uid()}".encode()
    r = _put(path, content)
    assert r.status_code == 201, f"setup PUT failed: {r.status_code}"
    etag = r.headers.get("ETag", "")
    return path, content, etag


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------


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


class TestPropfind:
    def test_propfind_file_depth0_207(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207

    def test_propfind_directory_depth1_207(self):
        path = f"/{_PFX}pfdir_{_uid()}"
        _mkcol(path)
        r = _propfind(path, depth="1")
        assert r.status_code == 207

    def test_propfind_directory_depth0_207(self):
        path = f"/{_PFX}pfd0_{_uid()}"
        _mkcol(path)
        r = _propfind(path, depth="0")
        assert r.status_code == 207

    def test_propfind_missing_resource_404(self):
        r = _propfind(f"/{_PFX}no_such_{_uid()}", depth="0")
        assert r.status_code == 404

    def test_propfind_response_is_valid_xml(self):
        path, _, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        ET.fromstring(r.content)  # must not raise

    def test_propfind_depth1_lists_children(self):
        path = f"/{_PFX}lst_{_uid()}"
        _mkcol(path)
        fname = f"child_{_uid()}.txt"
        _put(f"{path}/{fname}", b"child content")
        r = _propfind(path, depth="1")
        assert r.status_code == 207
        assert fname in r.text

    def test_propfind_depth0_does_not_list_children(self):
        path = f"/{_PFX}d0_{_uid()}"
        _mkcol(path)
        fname = f"child_{_uid()}.txt"
        _put(f"{path}/{fname}", b"child")
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        assert fname not in r.text

    def test_propfind_includes_content_length(self):
        path, content, _ = _existing_file()
        r = _propfind(path, depth="0")
        assert r.status_code == 207
        assert str(len(content)) in r.text

    def test_propfind_no_depth_header_does_not_crash(self):
        path, _, _ = _existing_file()
        headers = {"Content-Type": "application/xml"}
        body = '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
        r = requests.request(
            "PROPFIND", _url(path), data=body, headers=headers, timeout=10
        )
        assert r.status_code == 207


# ---------------------------------------------------------------------------
# MOVE
# ---------------------------------------------------------------------------


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
        r = requests.options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "MOVE" in allow

    def test_move_no_destination_header_400(self):
        src, _, _ = _existing_file()
        r = requests.request("MOVE", _url(src), timeout=10)
        assert r.status_code == 400

    def test_move_directory_overwrite_204(self):
        src = f"/{_PFX}dir_src_{_uid()}"
        _mkcol(src)
        _put(f"{src}/file.txt", b"content")

        dst = f"/{_PFX}dir_dst_{_uid()}"
        _mkcol(dst)
        _put(f"{dst}/old.txt", b"old")

        r = _move(src, dst)
        assert r.status_code == 204
        assert _get(f"{dst}/file.txt").content == b"content"
        assert _get(f"{dst}/old.txt").status_code == 404
        assert _propfind(src).status_code == 404


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
        r = requests.options(_url("/"), timeout=10)
        allow = r.headers.get("Allow", "")
        assert "COPY" in allow

    def test_copy_no_destination_header_400(self):
        src, _, _ = _existing_file()
        r = requests.request("COPY", _url(src), timeout=10)
        assert r.status_code == 400

    def test_copy_large_file_content_correct(self):
        path = f"/{_PFX}bigcopy_{_uid()}.bin"
        content = bytes(range(256)) * 1000  # 256 KB
        _put(path, content)
        dst = f"/{_PFX}bigcopy_dst_{_uid()}.bin"
        r = _copy(path, dst)
        assert r.status_code == 201
        assert _get(dst).content == content

    def test_copy_directory_recursive_201(self):
        parent = f"/{_PFX}dir_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/file1.txt", b"content1")
        _put(f"{parent}/file2.txt", b"content2")
        _mkcol(f"{parent}/subdir")
        _put(f"{parent}/subdir/file3.txt", b"content3")

        dst = f"/{_PFX}dir_dst_{_uid()}"
        r = _copy(parent, dst)
        assert r.status_code == 201
        assert _get(f"{dst}/file1.txt").content == b"content1"
        assert _get(f"{dst}/file2.txt").content == b"content2"
        assert _get(f"{dst}/subdir/file3.txt").content == b"content3"

    def test_copy_directory_depth_0_201(self):
        parent = f"/{_PFX}dir_{_uid()}"
        _mkcol(parent)
        _put(f"{parent}/file1.txt", b"content1")
        dst = f"/{_PFX}dir_dst_{_uid()}"
        r = _copy(parent, dst, depth="0")
        assert r.status_code == 201
        # Check that the directory was created but its contents were not copied
        assert _propfind(dst).status_code == 207
        assert _get(f"{dst}/file1.txt").status_code == 404

    def test_copy_directory_overwrite_204(self):
        src = f"/{_PFX}dir_src_{_uid()}"
        _mkcol(src)
        _put(f"{src}/new.txt", b"new")

        dst = f"/{_PFX}dir_dst_{_uid()}"
        _mkcol(dst)
        _put(f"{dst}/old.txt", b"old")

        # COPY src to dst with Overwrite: T (default)
        r = _copy(src, dst)
        assert r.status_code == 204
        assert _get(f"{dst}/new.txt").content == b"new"
        # The old content should be gone (collection replaced)
        assert _get(f"{dst}/old.txt").status_code == 404

    def test_copy_directory_overwrite_false_412(self):
        src = f"/{_PFX}dir_src_{_uid()}"
        _mkcol(src)
        dst = f"/{_PFX}dir_dst_{_uid()}"
        _mkcol(dst)

        r = _copy(src, dst, overwrite="F")
        assert r.status_code == 412

# ---------------------------------------------------------------------------
# LOCK / UNLOCK
# ---------------------------------------------------------------------------


class TestLock:
    def test_lock_new_file_201(self):
        path = f"/{_PFX}lock_{_uid()}.txt"
        r = _lock(path)
        assert r.status_code == 201
        assert "Lock-Token" in r.headers
        token = r.headers["Lock-Token"].strip("<>")
        assert "opaquelocktoken:" in token

        # Verify it shows up in PROPFIND
        r = _propfind(path)
        assert r.status_code == 207
        assert token in r.text
        assert "<D:lockdiscovery>" in r.text
        assert "<D:supportedlock>" in r.text

    def test_lock_refresh_200(self):
        path = f"/{_PFX}refresh_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        # Refresh using If header
        headers = {"If": f"({token})"}
        r = _lock(path, headers=headers, data="")
        assert r.status_code == 200

    def test_lock_enforcement_put_423(self):
        path = f"/{_PFX}locked_put_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        # PUT without lock token should fail
        r = _put(path, b"failed content")
        assert r.status_code == 423

        # PUT with lock token (in If header) should succeed
        headers = {"If": f"({token})"}
        r = _put(path, b"success content", headers=headers)
        assert r.status_code in (201, 204)
        assert _get(path).content == b"success content"

    def test_lock_enforcement_delete_423(self):
        path = f"/{_PFX}locked_del_{_uid()}.txt"
        _put(path, b"content")
        r_lock = _lock(path)
        token = r_lock.headers["Lock-Token"]

        r = _delete(path)
        assert r.status_code == 423

        headers = {"If": f"({token})"}
        r = _delete(path, headers=headers)
        assert r.status_code == 204

    def test_unlock_204(self):
        path = f"/{_PFX}to_unlock_{_uid()}.txt"
        r = _lock(path)
        token = r.headers["Lock-Token"]

        r = _unlock(path, token)
        assert r.status_code == 204

        # Verify PUT now succeeds without token
        r = _put(path, b"after unlock")
        assert r.status_code in (201, 204)

    def test_lock_conflict_423(self):
        path = f"/{_PFX}conflict_{_uid()}.txt"
        _lock(path)

        # Second lock attempt from "someone else" (no If header)
        r = _lock(path)
        assert r.status_code == 423

    def test_lock_expiration(self):
        path = f"/{_PFX}expires_{_uid()}.txt"
        # 1 second timeout
        r = _lock(path, timeout=1)
        assert r.status_code == 201

        # Immediately should fail
        assert _put(path, b"too soon").status_code == 423

        # Wait for expiration
        time.sleep(2)

        # Should now succeed
        assert _put(path, b"expired").status_code in (201, 204)
