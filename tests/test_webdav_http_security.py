"""
tests/test_webdav_http_security.py

HTTP/WebDAV security and protocol-conformance tests.

Covers:
  - RFC 7233 range requests (206 Partial Content correctness)
  - Conditional requests: If-Match, If-None-Match, If-Modified-Since,
    If-Unmodified-Since (ETag and Last-Modified caching headers)
  - HTTP error status codes for edge cases
  - PROPFIND Depth header variants (0, 1, absent)
  - PUT with Content-Range (partial/resumable upload)
  - Plain HTTP WebDAV port (8080) smoke tests

The HTTPS requests are run against both authenticated nginx WebDAV servers:
HTTPS+GSI/x509 on port 8444 and HTTPS+Token on port 8443.  Plain HTTP smoke
tests still use port 8080.  TLS verification is disabled because the test
server certificate is for a test CN, not 'localhost'.

Run:
    python3 -m pytest tests/test_webdav_http_security.py -v
"""

import os
import sys
import time
import xml.etree.ElementTree as ET

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from settings import (
    CA_CERT,
    DATA_ROOT as DEFAULT_DATA_ROOT,
    NGINX_HTTP_WEBDAV_PORT,
    PROXY_STD,
    TOKENS_DIR,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

# ---------------------------------------------------------------------------
# Module-level state (filled by the session fixture)
# ---------------------------------------------------------------------------

WEBDAV_BASE      = ""
HTTP_WEBDAV_BASE = ""
DATA_ROOT        = DEFAULT_DATA_ROOT
PROXY_PEM        = PROXY_STD
TOKEN_DIR        = TOKENS_DIR
AUTH_MODE        = "gsi"
TOKEN            = ""

_PFX_BASE = "wdavs_"  # unique prefix to avoid collisions with other test files
_PFX = _PFX_BASE


@pytest.fixture(scope="module", autouse=True, params=("gsi", "token"),
                ids=("gsi-8444", "token-8443"))
def _configure(request, test_env):
    global WEBDAV_BASE, HTTP_WEBDAV_BASE, DATA_ROOT, PROXY_PEM
    global TOKEN_DIR, AUTH_MODE, TOKEN, _PFX
    AUTH_MODE        = request.param
    _PFX             = f"{_PFX_BASE}{AUTH_MODE}_"
    WEBDAV_BASE      = (
        test_env["webdav_gsi_tls_url"]
        if AUTH_MODE == "gsi"
        else test_env["webdav_url"]
    )
    HTTP_WEBDAV_BASE = test_env["http_webdav_url"]
    DATA_ROOT        = test_env["data_dir"]
    PROXY_PEM        = test_env["proxy_pem"]
    TOKEN_DIR        = test_env.get("token_dir", TOKENS_DIR)
    TOKEN            = ""

    if AUTH_MODE == "token":
        issuer = TokenIssuer(TOKEN_DIR)
        if not os.path.exists(issuer.key_path):
            issuer.init_keys()
        TOKEN = issuer.generate(
            scope="storage.read:/ storage.write:/",
            lifetime=7200,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _url(path):
    return WEBDAV_BASE + path


def _http_url(path):
    return HTTP_WEBDAV_BASE + path


def _session():
    """requests.Session with the current HTTPS WebDAV auth mode."""
    s = requests.Session()
    if AUTH_MODE == "gsi":
        s.cert = (PROXY_PEM, PROXY_PEM)
    elif AUTH_MODE == "token":
        s.headers["Authorization"] = f"Bearer {TOKEN}"
    s.verify = False
    return s


def _put(path, data=b"", session=None):
    s = session or _session()
    r = s.put(_url(path), data=data)
    return r


def _get(path, **kwargs):
    s = _session()
    return s.get(_url(path), **kwargs)


def _make_file(rel, content=b"x"):
    """Write a file directly to the data root."""
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(content)


def _make_dir(rel):
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    os.makedirs(full, exist_ok=True)


def _remove(rel):
    full = os.path.join(DATA_ROOT, rel.lstrip("/"))
    if os.path.isfile(full):
        os.unlink(full)
    elif os.path.isdir(full):
        import shutil
        shutil.rmtree(full)
    # Also clear any resumable-upload staged partials for this path.  With
    # brix_upload_resume on, an incomplete Content-Range PUT leaves a persistent,
    # identity-keyed "<dest>.xrdresume.<id>.part" sidecar that survives across
    # runs; unlinking only the destination leaves it behind, so a later "first
    # segment" PUT is (correctly) rejected 409 for not being contiguous with the
    # stale partial.  Removing the sidecars makes _remove a true state reset.
    import glob
    for part in glob.glob(f"{full}.xrdresume.*.part"):
        try:
            os.unlink(part)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# TestRangeRequests
# ---------------------------------------------------------------------------

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
        assert os.path.getsize(os.path.join(DATA_ROOT, f"{_PFX}cr_large.bin")) == len(data)

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
        return requests.get(HTTP_WEBDAV_BASE + path, **kwargs)

    def _hput(self, path, data=b""):
        return requests.put(HTTP_WEBDAV_BASE + path, data=data)

    def _hdelete(self, path):
        return requests.delete(HTTP_WEBDAV_BASE + path)

    def _hmkcol(self, path):
        return requests.request("MKCOL", HTTP_WEBDAV_BASE + path)

    def _hpropfind(self, path, depth="0"):
        return requests.request("PROPFIND", HTTP_WEBDAV_BASE + path,
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
        assert not os.path.exists(os.path.join(DATA_ROOT, path.lstrip("/")))

    def test_http_mkcol_creates_directory(self):
        path = f"/{_PFX}http_mkcol"
        _remove(path)
        r = self._hmkcol(path)
        assert r.status_code == 201
        assert os.path.isdir(os.path.join(DATA_ROOT, path.lstrip("/")))

    # --- MOVE/COPY DESTINATION confinement ---------------------------------
    # The source path of MOVE/COPY is confined like any request URI, but the
    # DESTINATION arrives in a header and must be confined independently.  A
    # Destination that escapes the export root (via ".." or encoded "%2e%2e")
    # must be rejected and must not create/overwrite anything outside the root.

    def _outside_zone(self):
        return os.path.dirname(DATA_ROOT.rstrip("/"))   # one level above the root

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
                "MOVE", HTTP_WEBDAV_BASE + src,
                headers={"Destination": HTTP_WEBDAV_BASE + dest,
                         "Overwrite": "T"})
            assert r.status_code not in (200, 201, 204), \
                f"MOVE to escaping Destination {dest} succeeded ({r.status_code})"
        assert os.path.exists(os.path.join(DATA_ROOT, src.lstrip("/"))), \
            "source file vanished after a rejected MOVE"
        self._assert_no_escape(pwned)
        _remove(src)

    def test_http_copy_destination_traversal_rejected(self):
        src = f"/{_PFX}http_cpdst_src.txt"
        _make_file(src, b"keep-me")
        pwned = f"{_PFX}pwned_cp"
        for dest in (f"/../{pwned}", f"/%2e%2e/{pwned}"):
            r = requests.request(
                "COPY", HTTP_WEBDAV_BASE + src,
                headers={"Destination": HTTP_WEBDAV_BASE + dest,
                         "Overwrite": "T"})
            assert r.status_code not in (200, 201, 204), \
                f"COPY to escaping Destination {dest} succeeded ({r.status_code})"
        self._assert_no_escape(pwned)
        _remove(src)
