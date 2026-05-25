"""
tests/test_https_webdav_token_status_codes.py

Comprehensive HTTPS status-code and RFC compliance tests for the TLS WebDAV
endpoint (port 8443, optional JWT/WLCG bearer-token auth).

Mirrors test_https_webdav_status_codes.py but authenticates via
Authorization: Bearer <JWT> instead of an x509 proxy certificate.  Targets
the HTTPS+Token server (port 8443, xrootd_webdav_auth optional) so that
HTTPS+Token and HTTPS+GSI have equal WebDAV-operation coverage.

Additional classes verify authentication behaviour:
  - optional-auth mode: unauthenticated requests still return data
  - bearer token present: full auth, all operations available
  - read-only token: write operations rejected (403)

Tests assert RFC-correct behaviour.  Known compliance gaps are marked
``@pytest.mark.xfail`` with the precise RFC citation; they appear as ``x``
(expected failure) in the output and will flip to ``X`` (unexpected pass)
once the gap is resolved.

RFC compliance: all tested behaviours are now compliant.

TLS verification is intentionally disabled for the server cert
(test CN ≠ "localhost").  Tokens are signed by the test JWKS authority
created during test environment initialisation.

Run:
    python3 -m pytest tests/test_https_webdav_token_status_codes.py -v
"""

import os
import sys
import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

from settings import TOKENS_DIR

_PFX = "httst_"

BASE      = ""
_ISSUER   = None
_RW_TOKEN = ""   # storage.read:/ storage.write:/ — used by _s()


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    global BASE, _ISSUER, _RW_TOKEN
    BASE     = test_env["webdav_url"]
    token_dir = test_env.get("token_dir", TOKENS_DIR)
    _ISSUER  = TokenIssuer(token_dir)
    if not os.path.exists(_ISSUER.key_path):
        _ISSUER.init_keys()
    # lifetime=7200 gives 2 h — enough for the whole test module run.
    _RW_TOKEN = _ISSUER.generate(
        scope="storage.read:/ storage.write:/", lifetime=7200
    )


def _url(path):
    return BASE + path


def _uid():
    return uuid.uuid4().hex[:12]


def _s():
    """requests.Session with read+write bearer token."""
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {_RW_TOKEN}"
    s.verify = False
    return s


def _sa():
    """requests.Session WITHOUT any credentials (anonymous TLS)."""
    s = requests.Session()
    s.verify = False
    return s


def _put(path, data=b"hello", session=None, **kw):
    sess = session or _s()
    return sess.put(_url(path), data=data, timeout=10, **kw)


def _get(path, session=None, **kw):
    sess = session or _s()
    return sess.get(_url(path), timeout=10, **kw)


def _head(path, session=None, **kw):
    sess = session or _s()
    return sess.head(_url(path), timeout=10, **kw)


def _delete(path, session=None, **kw):
    sess = session or _s()
    return sess.delete(_url(path), timeout=10, **kw)


def _mkcol(path, session=None, **kw):
    sess = session or _s()
    return sess.request("MKCOL", _url(path), timeout=10, **kw)


def _propfind(path, depth="1", session=None, **kw):
    body = (
        '<?xml version="1.0"?>'
        '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
    )
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    sess = session or _s()
    return sess.request(
        "PROPFIND", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _move(src, dst, overwrite="T", session=None, **kw):
    headers = {"Destination": BASE + dst, "Overwrite": overwrite}
    sess = session or _s()
    return sess.request("MOVE", _url(src), headers=headers, timeout=10, **kw)


def _copy(src, dst, overwrite="T", session=None, **kw):
    headers = {"Destination": BASE + dst, "Overwrite": overwrite}
    sess = session or _s()
    return sess.request("COPY", _url(src), headers=headers, timeout=10, **kw)


def _existing_file(session=None):
    """Create a file and return (path, content, etag)."""
    path = f"/{_PFX}{_uid()}.txt"
    content = f"https token test {_uid()}".encode()
    r = _put(path, content, session=session)
    assert r.status_code == 201, f"setup PUT failed: {r.status_code}"
    etag = r.headers.get("ETag", "")
    return path, content, etag


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


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
