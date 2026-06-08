"""S3-compatible object storage tests.

Tests the nginx xrootd_s3 module against the S3 REST API subset used by
XrdClS3: GetObject, HeadObject, PutObject, DeleteObject, ListObjectsV2.

Uses the pre-started nginx_shared instance (port 9001), anonymous mode.
"""

import os
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import pytest
import requests


BUCKET = "testbucket"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


def _obj_url(s3_url, key):
    return f"{s3_url}/{BUCKET}/{key}"


def _list_url(s3_url, **params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    base = f"{s3_url}/{BUCKET}/?list-type=2"
    return f"{base}&{qs}" if qs else base


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _parse_list(xml_text):
    root = ET.fromstring(xml_text)

    def _tag(name):
        return f"{{{S3_NS}}}{name}"

    keys = [el.text for el in root.findall(f".//{_tag('Key')}")]
    prefixes = [
        el.find(_tag("Prefix")).text
        for el in root.findall(f".//{_tag('CommonPrefixes')}")
    ]
    truncated = root.findtext(_tag("IsTruncated")) == "true"
    next_token = root.findtext(_tag("NextContinuationToken"))
    return keys, prefixes, truncated, next_token


# ---------------------------------------------------------------------------
# OPTIONS / CORS preflight
# ---------------------------------------------------------------------------


def test_options_allow_methods(s3_url):
    r = requests.options(f"{s3_url}/{BUCKET}/", timeout=10)
    assert r.status_code == 200
    allow = r.headers.get("Allow", "")
    for method in ("GET", "HEAD", "PUT", "DELETE", "POST", "OPTIONS"):
        assert method in allow


def test_options_cors_preflight(s3_url):
    r = requests.options(
        f"{s3_url}/{BUCKET}/",
        headers={
            "Origin": "https://client.example.test",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "authorization,x-amz-date",
        },
        timeout=10,
    )
    assert r.status_code == 200
    assert r.headers.get("Access-Control-Allow-Origin") == "*"
    assert "OPTIONS" in r.headers.get("Access-Control-Allow-Methods", "")
    assert r.headers.get("Access-Control-Allow-Headers") == (
        "authorization,x-amz-date"
    )


# ---------------------------------------------------------------------------
# PutObject / GetObject
# ---------------------------------------------------------------------------


def test_put_and_get(s3_url):
    uid = uuid.uuid4().hex
    key = f"test_put_{uid}.bin"
    content = f"s3 test data {uid}".encode()

    r = requests.put(_obj_url(s3_url, key), data=content, timeout=10)
    assert r.status_code == 200, f"PUT failed: {r.status_code} {r.text}"

    r = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 200
    assert r.content == content


def test_get_missing_returns_404(s3_url):
    r = requests.get(_obj_url(s3_url, f"no_such_{uuid.uuid4().hex}"), timeout=10)
    assert r.status_code == 404
    assert "NoSuchKey" in r.text


# ---------------------------------------------------------------------------
# HeadObject
# ---------------------------------------------------------------------------


def test_head_object(s3_url):
    uid = uuid.uuid4().hex
    key = f"test_head_{uid}.bin"
    content = b"head object content"

    requests.put(_obj_url(s3_url, key), data=content, timeout=10)

    r = requests.head(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 200
    assert int(r.headers.get("Content-Length", -1)) == len(content)
    assert "ETag" in r.headers


def test_head_missing_returns_404(s3_url):
    r = requests.head(_obj_url(s3_url, f"no_such_{uuid.uuid4().hex}"), timeout=10)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Range download (partial GET)
# ---------------------------------------------------------------------------


def test_range_get(s3_url):
    uid = uuid.uuid4().hex
    key = f"test_range_{uid}.bin"
    content = b"0123456789abcdef"

    requests.put(_obj_url(s3_url, key), data=content, timeout=10)

    r = requests.get(
        _obj_url(s3_url, key), headers={"Range": "bytes=4-7"}, timeout=10
    )
    assert r.status_code == 206
    assert r.content == b"4567"


# ---------------------------------------------------------------------------
# DeleteObject
# ---------------------------------------------------------------------------


def test_delete_object(s3_url):
    uid = uuid.uuid4().hex
    key = f"test_del_{uid}.bin"

    requests.put(_obj_url(s3_url, key), data=b"to delete", timeout=10)

    r = requests.delete(_obj_url(s3_url, key), timeout=10)
    assert r.status_code in (200, 204), f"DELETE failed: {r.status_code}"

    r = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 404


def test_delete_idempotent(s3_url):
    """S3 DELETE on a non-existent key must return 204, not 404."""
    r = requests.delete(
        _obj_url(s3_url, f"never_existed_{uuid.uuid4().hex}"), timeout=10
    )
    assert r.status_code in (200, 204)


# ---------------------------------------------------------------------------
# Zero-byte object (directory sentinel pattern)
# ---------------------------------------------------------------------------


def test_zero_byte_put_get(s3_url):
    uid = uuid.uuid4().hex
    key = f"test_zero_{uid}.bin"

    r = requests.put(_obj_url(s3_url, key), data=b"", timeout=10)
    assert r.status_code == 200

    r = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 200
    assert r.content == b""


def test_directory_sentinel_creates_directory(s3_url, test_env):
    """PUT of .xrdcls3.dirsentinel should create the parent directory."""
    uid = uuid.uuid4().hex
    dir_name = f"sentinel_dir_{uid}"
    sentinel_key = f"{dir_name}/.xrdcls3.dirsentinel"

    r = requests.put(_obj_url(s3_url, sentinel_key), data=b"", timeout=10)
    assert r.status_code == 200

    expected_dir = os.path.join(test_env["data_dir"], dir_name)
    assert os.path.isdir(expected_dir), (
        f"Expected directory {expected_dir} to exist after sentinel PUT"
    )


# ---------------------------------------------------------------------------
# ListObjectsV2
# ---------------------------------------------------------------------------


def test_list_basic(s3_url):
    uid = uuid.uuid4().hex
    keys = [f"list_basic_{uid}_{i}.txt" for i in range(3)]
    for k in keys:
        requests.put(_obj_url(s3_url, k), data=b"x", timeout=10)

    r = requests.get(_list_url(s3_url, prefix=f"list_basic_{uid}"), timeout=10)
    assert r.status_code == 200
    listed, _, truncated, _ = _parse_list(r.text)
    for k in keys:
        assert k in listed, f"{k} not in listing"
    assert not truncated


def test_list_type_detection_requires_exact_key(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?not-list-type=2", timeout=10)
    assert r.status_code == 400
    assert "InvalidURI" in r.text


def test_list_type_detection_rejects_wrong_value(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?list-type=12", timeout=10)
    assert r.status_code == 400
    assert "InvalidURI" in r.text


def test_list_type_detection_not_substring_in_value(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?prefix=list-type=2", timeout=10)
    assert r.status_code == 400
    assert "InvalidURI" in r.text


def test_list_prefix_filter(s3_url):
    uid = uuid.uuid4().hex
    prefix_a = f"pfx_a_{uid}_"
    prefix_b = f"pfx_b_{uid}_"

    for i in range(2):
        requests.put(_obj_url(s3_url, f"{prefix_a}{i}"), data=b"a", timeout=10)
        requests.put(_obj_url(s3_url, f"{prefix_b}{i}"), data=b"b", timeout=10)

    r = requests.get(_list_url(s3_url, prefix=prefix_a), timeout=10)
    assert r.status_code == 200
    listed, _, _, _ = _parse_list(r.text)
    for item in listed:
        assert item.startswith(prefix_a), f"unexpected key {item!r}"


def test_list_max_keys_pagination(s3_url):
    uid = uuid.uuid4().hex
    prefix = f"page_{uid}_"
    total = 5

    for i in range(total):
        requests.put(
            _obj_url(s3_url, f"{prefix}{i:04d}"), data=b"p", timeout=10
        )

    r = requests.get(
        _list_url(s3_url, prefix=prefix, **{"max-keys": "2"}), timeout=10
    )
    assert r.status_code == 200
    page1, _, truncated1, next_tok = _parse_list(r.text)
    assert len(page1) == 2
    assert truncated1
    assert next_tok

    collected = list(page1)
    token = next_tok
    while token:
        r = requests.get(
            _list_url(
                s3_url,
                prefix=prefix,
                **{"max-keys": "2", "continuation-token": token},
            ),
            timeout=10,
        )
        assert r.status_code == 200
        page, _, trunc, token = _parse_list(r.text)
        collected.extend(page)

    assert len(collected) == total
    assert collected == sorted(collected)


def test_list_delimiter_common_prefixes(s3_url):
    uid = uuid.uuid4().hex
    dir_a = f"dlist_{uid}/dira"
    dir_b = f"dlist_{uid}/dirb"

    requests.put(_obj_url(s3_url, f"{dir_a}/file1.txt"), data=b"1", timeout=10)
    requests.put(_obj_url(s3_url, f"{dir_b}/file2.txt"), data=b"2", timeout=10)
    requests.put(_obj_url(s3_url, f"dlist_{uid}/top.txt"), data=b"3", timeout=10)

    r = requests.get(
        _list_url(s3_url, prefix=f"dlist_{uid}/", delimiter="/"),
        timeout=10,
    )
    assert r.status_code == 200
    keys, prefixes, _, _ = _parse_list(r.text)

    assert f"dlist_{uid}/top.txt" in keys
    assert any("dira" in p for p in prefixes), f"dira not in prefixes {prefixes}"
    assert any("dirb" in p for p in prefixes), f"dirb not in prefixes {prefixes}"


def test_list_sentinel_excluded(s3_url):
    """Directory sentinels must not appear in ListObjectsV2 results."""
    uid = uuid.uuid4().hex
    prefix = f"sent_{uid}/"
    sentinel = f"{prefix}.xrdcls3.dirsentinel"
    real_key = f"{prefix}real.txt"

    requests.put(_obj_url(s3_url, sentinel), data=b"", timeout=10)
    requests.put(_obj_url(s3_url, real_key), data=b"real", timeout=10)

    r = requests.get(_list_url(s3_url, prefix=prefix), timeout=10)
    assert r.status_code == 200
    listed, _, _, _ = _parse_list(r.text)
    assert real_key in listed
    assert sentinel not in listed


# ---------------------------------------------------------------------------
# Overwrite
# ---------------------------------------------------------------------------


def test_overwrite(s3_url):
    uid = uuid.uuid4().hex
    key = f"overwrite_{uid}.bin"

    requests.put(_obj_url(s3_url, key), data=b"v1", timeout=10)
    requests.put(_obj_url(s3_url, key), data=b"v2", timeout=10)

    r = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 200
    assert r.content == b"v2"


# ---------------------------------------------------------------------------
# Anonymous access (no Authorization header required)
# ---------------------------------------------------------------------------


def test_anonymous_access_no_auth_header(s3_url):
    uid = uuid.uuid4().hex
    key = f"anon_{uid}.txt"

    r = requests.put(_obj_url(s3_url, key), data=b"anon", timeout=10)
    assert r.status_code == 200

    r = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST Object (browser form upload)
# ---------------------------------------------------------------------------


def test_post_object_form_upload(s3_url):
    uid = uuid.uuid4().hex
    key = f"post_form_{uid}.txt"
    content = f"browser form upload {uid}".encode()

    r = requests.post(
        f"{s3_url}/{BUCKET}/",
        data={"key": key, "success_action_status": "201"},
        files={"file": ("upload.txt", content, "text/plain")},
        timeout=10,
    )
    assert r.status_code == 201, f"POST Object failed: {r.status_code} {r.text}"
    assert "PostResponse" in r.text

    r = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r.status_code == 200
    assert r.content == content


def test_post_object_missing_key_returns_400(s3_url):
    r = requests.post(
        f"{s3_url}/{BUCKET}/",
        files={"file": ("upload.txt", b"missing-key", "text/plain")},
        timeout=10,
    )
    assert r.status_code == 400
    assert "InvalidArgument" in r.text


def test_post_object_path_traversal_rejected(s3_url):
    r = requests.post(
        f"{s3_url}/{BUCKET}/",
        data={"key": f"../../../post_escape_{uuid.uuid4().hex}.txt"},
        files={"file": ("upload.txt", b"blocked", "text/plain")},
        timeout=10,
    )
    assert r.status_code == 403
    assert "AccessDenied" in r.text


# ---------------------------------------------------------------------------
# CopyObject (PUT with x-amz-copy-source)
# ---------------------------------------------------------------------------


def test_copy_object(s3_url):
    uid = uuid.uuid4().hex
    src_key = f"copy_src_{uid}.txt"
    dst_key = f"copy_dst_{uid}.txt"
    content = f"copy object content {uid}".encode()

    r = requests.put(_obj_url(s3_url, src_key), data=content, timeout=10)
    assert r.status_code == 200, f"source PUT failed: {r.status_code}"

    r = requests.put(
        _obj_url(s3_url, dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/{src_key}"},
        timeout=10,
    )
    assert r.status_code == 200, f"CopyObject failed: {r.status_code} {r.text}"
    assert "CopyObjectResult" in r.text
    assert "ETag" in r.text

    r = requests.get(_obj_url(s3_url, dst_key), timeout=10)
    assert r.status_code == 200
    assert r.content == content


def test_copy_object_missing_source(s3_url):
    uid = uuid.uuid4().hex
    dst_key = f"copy_dst_nosrc_{uid}.txt"

    r = requests.put(
        _obj_url(s3_url, dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/no_such_src_{uid}"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 for missing source, got {r.status_code}"
    assert "NoSuchKey" in r.text


def test_copy_object_path_traversal(s3_url):
    uid = uuid.uuid4().hex
    dst_key = f"copy_dst_trav_{uid}.txt"

    r = requests.put(
        _obj_url(s3_url, dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/../../../etc/passwd"},
        timeout=10,
    )
    assert r.status_code in (400, 403), (
        f"path traversal source should be rejected, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# DeleteObjects (POST /?delete)
# ---------------------------------------------------------------------------


def _delete_objects_url(s3_url):
    return f"{s3_url}/{BUCKET}/?delete"


def _delete_objects_body(*keys):
    objects_xml = "".join(
        f"<Object><Key>{escape(k)}</Key></Object>" for k in keys
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"{objects_xml}"
        "</Delete>"
    ).encode()


def test_delete_objects_success(s3_url):
    uid = uuid.uuid4().hex
    keys = [f"del_multi_{uid}_{i}.txt" for i in range(3)]
    for k in keys:
        requests.put(_obj_url(s3_url, k), data=b"x", timeout=10)

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(*keys),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200, f"DeleteObjects failed: {r.status_code} {r.text}"
    assert "DeleteResult" in r.text
    for k in keys:
        assert k in r.text, f"key {k} not in DeleteResult"
        assert "Deleted" in r.text

    for k in keys:
        r2 = requests.get(_obj_url(s3_url, k), timeout=10)
        assert r2.status_code == 404, f"key {k} should be deleted"


def test_delete_objects_xml_entity_key(s3_url):
    uid = uuid.uuid4().hex
    key = f"del_multi_entity_{uid}_a&b.txt"
    requests.put(_obj_url(s3_url, key), data=b"x", timeout=10)

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(key),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200, f"DeleteObjects failed: {r.status_code} {r.text}"
    ET.fromstring(r.text)

    r2 = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r2.status_code == 404, "XML-escaped key should delete original object"


def test_delete_objects_nonexistent_is_ok(s3_url):
    uid = uuid.uuid4().hex
    key = f"never_existed_del_{uid}.txt"

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(key),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200
    assert "DeleteResult" in r.text
    assert "Deleted" in r.text
    assert "Error" not in r.text or "AccessDenied" not in r.text


def test_delete_objects_path_traversal(s3_url):
    """Keys with path traversal must be rejected with AccessDenied, not deleted."""
    uid = uuid.uuid4().hex
    traversal_key = f"../../../etc/hosts_del_{uid}"

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(traversal_key),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200
    assert "DeleteResult" in r.text
    assert "AccessDenied" in r.text
    assert "Deleted" not in r.text
