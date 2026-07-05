"""Plain HTTP WebDAV tests (no TLS, anonymous access).

Uses the pre-started nginx_shared instance (port 8080).
Verifies basic WebDAV operations over http://.
"""

import uuid

import pytest
import requests


@pytest.fixture(scope="module")
def base_url(test_env):
    return test_env["http_webdav_url"]


def _put(base_url, path, data=b""):
    return requests.put(f"{base_url}{path}", data=data, timeout=10)


def _get(base_url, path):
    return requests.get(f"{base_url}{path}", timeout=10)


def _head(base_url, path):
    return requests.head(f"{base_url}{path}", timeout=10)


def _delete(base_url, path):
    return requests.delete(f"{base_url}{path}", timeout=10)


def _mkcol(base_url, path):
    return requests.request("MKCOL", f"{base_url}{path}", timeout=10)


def _propfind(base_url, path, depth="1"):
    body = (
        '<?xml version="1.0"?>'
        '<D:propfind xmlns:D="DAV:">'
        "<D:allprop/>"
        "</D:propfind>"
    )
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    return requests.request(
        "PROPFIND", f"{base_url}{path}", data=body, headers=headers, timeout=10
    )


# ---------------------------------------------------------------------------
# Basic read/write round-trip
# ---------------------------------------------------------------------------


def test_put_and_get(base_url):
    uid = uuid.uuid4().hex
    path = f"/test_put_{uid}.txt"
    content = f"hello from test_put_{uid}".encode()

    r = _put(base_url, path, content)
    assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"

    r = _get(base_url, path)
    assert r.status_code == 200
    assert r.content == content


def test_head(base_url):
    uid = uuid.uuid4().hex
    path = f"/test_head_{uid}.txt"
    content = b"head test content"

    _put(base_url, path, content)

    r = _head(base_url, path)
    assert r.status_code == 200
    assert int(r.headers.get("Content-Length", -1)) == len(content)


def test_delete(base_url):
    uid = uuid.uuid4().hex
    path = f"/test_del_{uid}.txt"

    _put(base_url, path, b"to be deleted")

    r = _delete(base_url, path)
    assert r.status_code in (200, 204)

    r = _get(base_url, path)
    assert r.status_code == 404


def test_get_missing_returns_404(base_url):
    r = _get(base_url, f"/no_such_file_{uuid.uuid4().hex}.bin")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Range requests
# ---------------------------------------------------------------------------


def test_range_request(base_url):
    uid = uuid.uuid4().hex
    path = f"/test_range_{uid}.bin"
    content = b"0123456789abcdef"

    _put(base_url, path, content)

    r = requests.get(
        f"{base_url}{path}", headers={"Range": "bytes=4-7"}, timeout=10
    )
    assert r.status_code == 206
    assert r.content == b"4567"


# ---------------------------------------------------------------------------
# MKCOL and directory listing
# ---------------------------------------------------------------------------


def test_mkcol_and_propfind(base_url):
    uid = uuid.uuid4().hex
    dir_path = f"/test_dir_{uid}"
    file_path = f"{dir_path}/file.txt"

    r = _mkcol(base_url, dir_path)
    assert r.status_code in (200, 201)

    _put(base_url, file_path, b"in directory")

    r = _propfind(base_url, dir_path)
    assert r.status_code == 207
    assert "file.txt" in r.text


# ---------------------------------------------------------------------------
# Overwrite existing file
# ---------------------------------------------------------------------------


def test_overwrite(base_url):
    uid = uuid.uuid4().hex
    path = f"/test_overwrite_{uid}.txt"

    _put(base_url, path, b"original")
    _put(base_url, path, b"updated")

    r = _get(base_url, path)
    assert r.status_code == 200
    assert r.content == b"updated"


# ---------------------------------------------------------------------------
# Zero-byte file
# ---------------------------------------------------------------------------


def test_zero_byte_file(base_url):
    uid = uuid.uuid4().hex
    path = f"/test_zero_{uid}.bin"

    r = _put(base_url, path, b"")
    assert r.status_code in (200, 201)

    r = _get(base_url, path)
    assert r.status_code == 200
    assert r.content == b""


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------


def test_options(base_url):
    r = requests.options(f"{base_url}/", timeout=10)
    assert r.status_code == 200
    allow = r.headers.get("Allow", "")
    assert "GET" in allow
    assert "PUT" in allow


def test_cors_preflight(base_url):
    origin = "https://debug.example.test"
    r = requests.options(
        f"{base_url}/",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        },
        timeout=10,
    )

    assert r.status_code == 200
    assert r.headers.get("Access-Control-Allow-Origin") == origin
    assert r.headers.get("Access-Control-Allow-Credentials") == "true"
    assert "PUT" in r.headers.get("Access-Control-Allow-Methods", "")
    assert r.headers.get("Access-Control-Max-Age") == "600"
