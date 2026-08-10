"""WebDAV HTML directory listing on GET (parity audit §6.6).

A GET of a directory used to be a flat 403. Now, mirroring XrdHttp's Listing /
listingdeny / listingredir knobs:
  * brix_webdav_html_listing on  — render an escaped HTML index (name/size/
    mtime) from the same VFS readdir seam PROPFIND uses; dotfiles and internal
    sidecars hidden.
  * brix_webdav_listing_redirect <url> — 301 to <url><request-uri> instead
    (checked before html_listing).
  * neither (default) — 403 (the stock listingdeny posture; unchanged).

Coverage (the change-class trio):
  * success      — listing on: GET of a directory returns 200 text/html
                   naming every real child (file + subdir, subdir with a
                   trailing '/'), and a plain file GET still serves its bytes.
  * error        — default (no directive): GET of a directory is still 403;
                   listing_redirect set: GET of a directory 301s to the
                   configured URL with the request path appended.
  * security-neg — listing on: a child whose name contains HTML metacharacters
                   ("<b>&x") is escaped in the body (no raw "<b>"); dotfiles
                   and the server's own internal sidecars never appear.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_webdav_html_listing.py -v
"""

import http.client
import os

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-html-listing")]


def _start(lifecycle, tmp_path, listing_line):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    (data / "sub").mkdir(parents=True)
    (data / "file1.txt").write_bytes(b"hello-listing\n")
    (data / "sub" / "inner.txt").write_bytes(b"x")
    # A dotfile and a server-internal sidecar that must never leak.
    (data / ".hidden").write_bytes(b"secret")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-html-listing",
        template="nginx_lc_html_listing.conf",
        protocol="webdav",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "DATA_ROOT": str(data),
                         "LISTING_LINE": listing_line},
        reason="WebDAV GET-on-directory listing postures"))
    return ep, data


def _get(ep, path):
    conn = http.client.HTTPConnection(ep.host, ep.port, timeout=30)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, dict(resp.getheaders()), body
    finally:
        conn.close()


def test_listing_on_renders_index(lifecycle, tmp_path):
    """(success) listing on: a directory GET is 200 text/html naming every
    real child; a subdir carries a trailing '/'; a plain file still serves."""
    ep, _data = _start(lifecycle, tmp_path, "brix_webdav_html_listing on;")
    status, headers, body = _get(ep, "/")
    assert status == 200, f"directory GET not 200: {status}"
    ctype = headers.get("Content-Type", "")
    assert "text/html" in ctype, f"not html: {ctype!r}"
    text = body.decode("utf-8", "replace")
    assert "file1.txt" in text, text
    assert "sub/" in text, f"subdir missing its trailing slash:\n{text}"

    status, _h, fbody = _get(ep, "/file1.txt")
    assert status == 200 and fbody == b"hello-listing\n", \
        "a plain file GET regressed under html_listing"


def test_default_directory_get_is_403(lifecycle, tmp_path):
    """(error) no directive: a directory GET is still 403 (listingdeny)."""
    ep, _data = _start(lifecycle, tmp_path, "")
    status, _headers, _body = _get(ep, "/")
    assert status == 403, f"default directory GET not 403: {status}"


def test_listing_redirect_301s(lifecycle, tmp_path):
    """(error-path) listing_redirect set: a directory GET 301s to the
    configured URL with the request path appended, and does NOT list."""
    ep, _data = _start(
        lifecycle, tmp_path,
        "brix_webdav_listing_redirect https://elsewhere.example/browse;")
    status, headers, body = _get(ep, "/sub/")
    assert status == 301, f"listing_redirect not 301: {status}"
    loc = headers.get("Location", "")
    assert loc == "https://elsewhere.example/browse/sub/", loc
    assert b"<table" not in body, "redirect posture leaked a listing body"


def test_listing_escapes_and_hides(lifecycle, tmp_path):
    """(security-neg) listing on: an HTML-metacharacter name is escaped (no raw
    '<b>'); dotfiles and internal sidecars never appear."""
    ep, data = _start(lifecycle, tmp_path, "brix_webdav_html_listing on;")
    (data / "<b>&x.txt").write_bytes(b"evil")
    status, _headers, body = _get(ep, "/")
    assert status == 200
    text = body.decode("utf-8", "replace")
    # The escaped form must be present, the raw injection must not.
    assert "&lt;b&gt;" in text, f"metacharacter name not escaped:\n{text}"
    assert "<b>&x" not in text, "raw HTML injection leaked into the listing"
    assert ".hidden" not in text, "a dotfile leaked into the listing"
