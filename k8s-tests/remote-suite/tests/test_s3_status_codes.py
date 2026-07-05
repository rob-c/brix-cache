# brix-remote-ok
"""
tests/test_s3_status_codes.py

Comprehensive HTTP status-code and S3 API compliance tests for the S3-compatible
object storage endpoint (port 9001, anonymous access).

Tests assert S3-API-correct behaviour directly; regressions must fail normally.

S3 API compliance: all tested behaviours are now compliant.

Run:
    python3 -m pytest tests/test_s3_status_codes.py -v
"""

import os
import tempfile
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests
from settings import NGINX_S3_PORT, SERVER_HOST

BUCKET = "testbucket"
S3_NS  = "http://s3.amazonaws.com/doc/2006-03-01/"
_PFX   = "s3sc_"

BASE = f"http://{SERVER_HOST}:{NGINX_S3_PORT}"


def _uid():
    return uuid.uuid4().hex[:12]


def _obj_url(key):
    return f"{BASE}/{BUCKET}/{key}"


def _list_url(**params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{BASE}/{BUCKET}/?list-type=2"
    return f"{url}&{qs}" if qs else url


def _put(key, data=b"", **kw):
    return requests.put(_obj_url(key), data=data, timeout=10, **kw)


def _get(key, **kw):
    return requests.get(_obj_url(key), timeout=10, **kw)


def _head(key, **kw):
    return requests.head(_obj_url(key), timeout=10, **kw)


def _delete(key, **kw):
    return requests.delete(_obj_url(key), timeout=10, **kw)


def _list(**params):
    return requests.get(_list_url(**params), timeout=10)


def _existing_object():
    """Put an object and return (key, content, etag)."""
    key     = f"{_PFX}{_uid()}.bin"
    content = f"s3 status test {_uid()}".encode()
    r       = _put(key, content)
    assert r.status_code == 200, f"setup PUT failed: {r.status_code}"
    etag    = r.headers.get("ETag", "")
    return key, content, etag


def _s3_error_code(xml_text):
    """Parse the <Code> element from an S3 XML error body."""
    try:
        root = ET.fromstring(xml_text)
        code = root.findtext("Code") or root.findtext(f"{{{S3_NS}}}Code")
        return code or ""
    except ET.ParseError:
        return ""


# ---------------------------------------------------------------------------
# PutObject
# ---------------------------------------------------------------------------


class TestPutObject:
    def test_put_new_object_200(self):
        r = _put(f"{_PFX}new_{_uid()}.bin", b"content")
        assert r.status_code == 200

    def test_put_content_stored_correctly(self):
        key, content, _ = _existing_object()
        assert _get(key).content == content

    def test_put_overwrite_200(self):
        key, _, _ = _existing_object()
        r = _put(key, b"overwritten")
        assert r.status_code == 200
        assert _get(key).content == b"overwritten"

    def test_put_zero_byte_object_200(self):
        key = f"{_PFX}zero_{_uid()}.bin"
        r = _put(key, b"")
        assert r.status_code == 200
        r2 = _get(key)
        assert r2.status_code == 200
        assert r2.content == b""

    def test_put_returns_etag_header(self):
        key = f"{_PFX}etag_{_uid()}.bin"
        r = _put(key, b"etag test")
        assert r.status_code == 200
        assert "ETag" in r.headers, "S3 API requires ETag in PutObject response"

    def test_put_binary_data_roundtrip(self):
        key = f"{_PFX}bin_{_uid()}.bin"
        content = bytes(range(256)) * 4
        _put(key, content)
        assert _get(key).content == content

    def test_put_large_object_200(self):
        key = f"{_PFX}large_{_uid()}.bin"
        content = b"x" * (1024 * 1024)  # 1 MiB
        r = _put(key, content)
        assert r.status_code == 200
        assert _get(key).content == content

    def test_put_etag_changes_after_overwrite(self):
        key, _, _ = _existing_object()
        etag1 = _head(key).headers.get("ETag", "")
        _put(key, b"different content " + _uid().encode())
        etag2 = _head(key).headers.get("ETag", "")
        if etag1 and etag2:
            assert etag1 != etag2


# ---------------------------------------------------------------------------
# GetObject
# ---------------------------------------------------------------------------


class TestGetObject:
    def test_get_existing_200(self):
        key, content, _ = _existing_object()
        r = _get(key)
        assert r.status_code == 200
        assert r.content == content

    def test_get_missing_404(self):
        r = _get(f"{_PFX}no_such_{_uid()}.bin")
        assert r.status_code == 404

    def test_get_missing_error_body_is_xml(self):
        r = _get(f"{_PFX}no_{_uid()}.bin")
        assert r.status_code == 404
        ET.fromstring(r.content)  # must parse as XML

    def test_get_missing_error_code_is_no_such_key(self):
        r = _get(f"{_PFX}no_{_uid()}.bin")
        assert r.status_code == 404
        assert _s3_error_code(r.text) == "NoSuchKey"

    def test_get_range_206(self):
        key, _, _ = _existing_object()
        r = _get(key, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        assert len(r.content) == 4

    def test_get_range_correct_bytes_returned(self):
        key = f"{_PFX}rng_{_uid()}.bin"
        content = b"0123456789abcdef"
        _put(key, content)
        r = _get(key, headers={"Range": "bytes=4-7"})
        assert r.status_code == 206
        assert r.content == b"4567"

    def test_get_range_content_range_header(self):
        key, content, _ = _existing_object()
        r = _get(key, headers={"Range": "bytes=0-3"})
        assert r.status_code == 206
        cr = r.headers.get("Content-Range", "")
        assert cr.startswith("bytes "), f"unexpected Content-Range: {cr!r}"

    def test_get_range_beyond_eof_416(self):
        key, content, _ = _existing_object()
        beyond = len(content) + 1000
        r = _get(key, headers={"Range": f"bytes={beyond}-{beyond+100}"})
        assert r.status_code == 416

    def test_get_range_suffix_206(self):
        key, content, _ = _existing_object()
        r = _get(key, headers={"Range": f"bytes=-{len(content)}"})
        assert r.status_code == 206
        assert r.content == content

    def test_get_range_first_byte_206(self):
        key = f"{_PFX}fb_{_uid()}.bin"
        content = b"ABCDEF"
        _put(key, content)
        r = _get(key, headers={"Range": "bytes=0-0"})
        assert r.status_code == 206
        assert r.content == b"A"

    def test_get_content_length_header(self):
        key, content, _ = _existing_object()
        r = _get(key)
        assert int(r.headers.get("Content-Length", -1)) == len(content)

    def test_get_returns_etag(self):
        key, _, _ = _existing_object()
        r = _get(key)
        assert "ETag" in r.headers

    def test_get_etag_stable_two_requests(self):
        key, _, _ = _existing_object()
        etag1 = _get(key).headers.get("ETag", "")
        etag2 = _get(key).headers.get("ETag", "")
        if etag1:
            assert etag1 == etag2


# ---------------------------------------------------------------------------
# HeadObject
# ---------------------------------------------------------------------------


class TestHeadObject:
    def test_head_existing_200(self):
        key, content, _ = _existing_object()
        r = _head(key)
        assert r.status_code == 200

    def test_head_content_length_correct(self):
        key, content, _ = _existing_object()
        r = _head(key)
        assert int(r.headers.get("Content-Length", -1)) == len(content)

    def test_head_missing_404(self):
        r = _head(f"{_PFX}no_{_uid()}.bin")
        assert r.status_code == 404

    def test_head_has_etag(self):
        key, _, _ = _existing_object()
        r = _head(key)
        assert "ETag" in r.headers

    def test_head_no_body(self):
        key, _, _ = _existing_object()
        r = _head(key)
        assert r.content == b""

    def test_head_etag_matches_get(self):
        key, _, _ = _existing_object()
        etag_head = _head(key).headers.get("ETag", "")
        etag_get  = _get(key).headers.get("ETag", "")
        if etag_head:
            assert etag_head == etag_get


# ---------------------------------------------------------------------------
# DeleteObject
# ---------------------------------------------------------------------------


class TestDeleteObject:
    def test_delete_existing_204(self):
        key, _, _ = _existing_object()
        r = _delete(key)
        assert r.status_code == 204

    def test_delete_then_get_404(self):
        key, _, _ = _existing_object()
        _delete(key)
        assert _get(key).status_code == 404

    def test_delete_idempotent_204(self):
        """S3 spec: DELETE on a non-existent key must not return 4xx."""
        r = _delete(f"{_PFX}never_{_uid()}.bin")
        assert r.status_code == 204

    def test_delete_then_head_404(self):
        key, _, _ = _existing_object()
        _delete(key)
        assert _head(key).status_code == 404

    def test_delete_then_list_not_present(self):
        key, _, _ = _existing_object()
        _delete(key)
        r = _list(prefix=key)
        assert r.status_code == 200
        root = ET.fromstring(r.content)
        keys = [el.text for el in root.findall(f".//{{{S3_NS}}}Key")]
        assert key not in keys, f"deleted key {key!r} still appears in listing"


# ---------------------------------------------------------------------------
# ListObjectsV2
# ---------------------------------------------------------------------------


class TestListObjectsV2:
    def test_list_200(self):
        r = _list(prefix=f"{_PFX}list_{_uid()}")
        assert r.status_code == 200

    def test_list_response_is_valid_xml(self):
        r = _list(prefix=f"{_PFX}xml_{_uid()}")
        assert r.status_code == 200
        ET.fromstring(r.content)

    def test_list_uploaded_key_appears(self):
        uid = _uid()
        prefix = f"{_PFX}appear_{uid}_"
        keys = [f"{prefix}{i}" for i in range(3)]
        for k in keys:
            _put(k, b"x")
        r = _list(prefix=prefix)
        assert r.status_code == 200
        for k in keys:
            assert k in r.text

    def test_list_prefix_filter_excludes_others(self):
        uid = _uid()
        pfx_a = f"{_PFX}pa_{uid}_"
        pfx_b = f"{_PFX}pb_{uid}_"
        _put(f"{pfx_a}file", b"a")
        _put(f"{pfx_b}file", b"b")
        r = _list(prefix=pfx_a)
        assert r.status_code == 200
        assert pfx_a + "file" in r.text
        assert pfx_b + "file" not in r.text

    def test_list_empty_prefix_200(self):
        r = _list(prefix=f"definitely_not_here_{_uid()}_zz")
        assert r.status_code == 200
        root = ET.fromstring(r.content)
        keys = root.findall(f".//{{{S3_NS}}}Key")
        assert keys == []

    def test_list_max_keys_pagination(self):
        uid = _uid()
        prefix = f"{_PFX}page_{uid}_"
        total = 5
        for i in range(total):
            _put(f"{prefix}{i:04d}", b"p")
        r = _list(prefix=prefix, **{"max-keys": "2"})
        assert r.status_code == 200
        root = ET.fromstring(r.content)
        keys_page1 = root.findall(f".//{{{S3_NS}}}Key")
        assert len(keys_page1) == 2
        trunc = root.findtext(f"{{{S3_NS}}}IsTruncated")
        assert trunc == "true"

    def test_list_max_keys_pagination_collects_all(self):
        uid = _uid()
        prefix = f"{_PFX}allpg_{uid}_"
        total = 5
        for i in range(total):
            _put(f"{prefix}{i:04d}", b"q")
        collected = []
        token = None
        while True:
            params = {"prefix": prefix, **{"max-keys": "2"}}
            if token:
                params["continuation-token"] = token
            r = _list(**params)
            assert r.status_code == 200
            root = ET.fromstring(r.content)
            collected.extend(el.text for el in root.findall(f".//{{{S3_NS}}}Key"))
            trunc = root.findtext(f"{{{S3_NS}}}IsTruncated")
            if trunc != "true":
                break
            token = root.findtext(f"{{{S3_NS}}}NextContinuationToken")
        assert len(collected) == total
        assert collected == sorted(collected)

    def test_list_delimiter_groups_common_prefixes(self):
        uid = _uid()
        top = f"{_PFX}dlim_{uid}"
        _put(f"{top}/dira/file1.txt", b"1")
        _put(f"{top}/dirb/file2.txt", b"2")
        _put(f"{top}/top.txt", b"3")
        r = _list(prefix=f"{top}/", delimiter="/")
        assert r.status_code == 200
        assert "dira" in r.text
        assert "dirb" in r.text
        assert "top.txt" in r.text

    def test_list_sentinel_not_included(self):
        uid = _uid()
        prefix = f"{_PFX}sent_{uid}/"
        sentinel = f"{prefix}.xrdcls3.dirsentinel"
        real_key = f"{prefix}real.txt"
        _put(sentinel, b"")
        _put(real_key, b"real")
        r = _list(prefix=prefix)
        assert r.status_code == 200
        assert real_key in r.text
        assert sentinel not in r.text


# ---------------------------------------------------------------------------
# Error response structure
# ---------------------------------------------------------------------------


class TestErrorResponses:
    def test_get_404_xml_has_error_element(self):
        r = _get(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        root = ET.fromstring(r.content)
        assert root.tag in ("Error", f"{{{S3_NS}}}Error"), (
            f"unexpected root tag: {root.tag}"
        )

    def test_get_404_xml_has_code_element(self):
        r = _get(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        assert _s3_error_code(r.text) == "NoSuchKey"

    def test_get_404_xml_has_message_element(self):
        r = _get(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        root = ET.fromstring(r.content)
        msg = (
            root.findtext("Message")
            or root.findtext(f"{{{S3_NS}}}Message")
            or ""
        )
        assert msg, "404 error body should include <Message>"

    def test_head_404_no_xml_body(self):
        """HEAD responses must have no body (even error responses)."""
        r = _head(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        assert r.content == b""

    def test_post_object_method_not_allowed(self):
        key = f"{_PFX}post_{_uid()}.bin"
        _put(key, b"exists")
        r = requests.post(_obj_url(key), data=b"body", timeout=10)
        assert r.status_code == 405

    def test_get_range_416_body_or_empty(self):
        key, content, _ = _existing_object()
        beyond = len(content) + 1000
        r = _get(key, headers={"Range": f"bytes={beyond}-{beyond+100}"})
        assert r.status_code == 416

    def test_list_bad_bucket_nosuchbucket_404(self):
        r = requests.get(
            f"{BASE}/no_such_bucket_ever/?list-type=2", timeout=10
        )
        assert r.status_code == 404
        assert _s3_error_code(r.text) == "NoSuchBucket"

    def test_list_content_type_is_xml(self):
        r = _list(prefix=f"{_PFX}ct_{_uid()}")
        assert r.status_code == 200
        ct = r.headers.get("Content-Type", "")
        assert "xml" in ct.lower(), f"expected XML content-type, got: {ct!r}"


# ---------------------------------------------------------------------------
# Path traversal / confinement security (Phase C of shared-code-plan-2)
# ---------------------------------------------------------------------------


class TestPathTraversal:
    """S3 key resolution must reject dot-dot traversal with 403 or 404."""

    def test_s3_path_traversal_dotdot_get_403(self):
        # Key containing ".." should be rejected (403 or 404 — never 200/500)
        r = requests.get(f"{BASE}/{BUCKET}/../../etc/passwd", timeout=10)
        assert r.status_code in (403, 404), (
            f"dot-dot traversal key should be rejected, got {r.status_code}"
        )

    def test_s3_path_traversal_dotdot_put_403(self):
        r = requests.put(
            f"{BASE}/{BUCKET}/../../tmp/evil.txt",
            data=b"should not land outside root",
            timeout=10,
        )
        assert r.status_code in (403, 404), (
            f"dot-dot traversal PUT should be rejected, got {r.status_code}"
        )

    def test_s3_path_traversal_dotdot_delete_403(self):
        r = requests.delete(f"{BASE}/{BUCKET}/../../etc/shadow", timeout=10)
        assert r.status_code in (403, 404), (
            f"dot-dot traversal DELETE should be rejected, got {r.status_code}"
        )


class TestSymlinkConfinement:
    """A symlink inside the S3 bucket pointing outside root must be blocked."""

    @pytest.fixture(autouse=True)
    def _setup_symlink(self):
        from tests.settings import DATA_ROOT
        # S3 keys map directly to DATA_ROOT — a key "foo" resolves to DATA_ROOT/foo.
        os.makedirs(DATA_ROOT, exist_ok=True)

        self._outside = tempfile.TemporaryDirectory()
        outside_file = os.path.join(self._outside.name, "secret.txt")
        with open(outside_file, "wb") as fh:
            fh.write(b"outside-root secret\n")

        link_name = f"sym_{uuid.uuid4().hex[:8]}"
        self._link_path = os.path.join(DATA_ROOT, link_name)
        self._link_key = link_name
        os.symlink(outside_file, self._link_path)

        yield

        if os.path.lexists(self._link_path):
            os.unlink(self._link_path)
        self._outside.cleanup()

    def test_s3_symlink_escape_get_403(self):
        r = _get(self._link_key)
        assert r.status_code in (403, 404), (
            f"symlink escape GET should be blocked, got {r.status_code}"
        )
