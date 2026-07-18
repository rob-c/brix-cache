"""Phase-36 §7.2.3 — WebDAV / XrdHttp over IPv6 (HTTP client).

Exercises the WebDAV method surface (GET/HEAD/PUT + Range + Want-Digest, DELETE,
MKCOL, MOVE/COPY, PROPFIND depth 0/1, LOCK/UNLOCK, OPTIONS) against the dedicated
"ipv6-webdav" nginx instance bound to the IPv6 loopback ``[::1]`` and pre-started
by ``manage_test_servers.sh start-all``
(``start_dedicated_nginx "ipv6-webdav" "nginx_ipv6_webdav.conf" "${IPV6_WEBDAV_PORT}"``),
serving ``IPV6_WEBDAV_DATA_ROOT`` as an anonymous, writable WebDAV root
(``tests/configs/nginx_ipv6_webdav.conf``: ``listen [::1]:{PORT};`` +
``brix_webdav on; brix_webdav_auth none; brix_allow_write on;``).

The Python ``requests`` / ``http.client`` stack handles the ``[::1]`` bracket
form correctly (unlike the PyXRootD root:// client, which mishandles
``root://[::1]`` literals), so every request simply targets
``http://[::1]:IPV6_WEBDAV_PORT``.

GATING vs REGRESSION (phase-36 §7.3):
  * The PROPFIND / MOVE / COPY ``Destination``-header cases are tagged GATING:
    they assert the server never emits a bare (unbracketed) IPv6 literal into a
    href / re-emitted ``Destination`` (``webdav/propfind.c``; the bracket-on-emit
    contract).  A bare ``::1`` in a ``host:port`` authority is ambiguous, so the
    correct behaviour is *relative* hrefs (no host literal at all) — that is what
    these tests pin.
  * Everything else is REGRESSION / SMOKE: it proves WebDAV/XrdHttp functions
    identically over IPv6 as over IPv4, exercising the already-clean socket /
    resolution layer over ``[::1]``.

Skip discipline (never fail on instance-absent):
  * every test depends on the session fixture ``requires_ipv6_loopback`` (auto,
    via the module-scoped autouse ``_ipv6_webdav`` fixture);
  * ``reachable6(IPV6_WEBDAV_PORT)`` probes the dedicated instance and skips
    cleanly if it is down.

Run with ``TEST_SKIP_SERVER_SETUP=1`` against an already-running start-all.
"""

import os
import socket
import uuid
import zlib
import xml.etree.ElementTree as ET

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from settings import HOST6, IPV6_WEBDAV_DATA_ROOT, IPV6_WEBDAV_PORT, url_host

DAV_NS = "DAV:"

# IPv6 literal must be bracketed in a URL authority; requests/http.client handle
# this correctly.  This is the whole point of the IPv6 WebDAV suite.
BASE_URL = f"http://{url_host(HOST6)}:{IPV6_WEBDAV_PORT}"

# Seed file content (24 bytes, matches the harness-seeded test.txt convention).
SEED_NAME = "ipv6_seed.txt"
SEED_CONTENT = b"hello from nginx-xrootd\n"


# ---------------------------------------------------------------------------
# Reachability probe (AF_INET6 loopback) — mirrors tests/test_ipv6_s3.py so a
# same-port IPv4 listener can never mask a down IPv6 instance.
# ---------------------------------------------------------------------------
def reachable6(port: int, timeout: float = 3.0) -> bool:
    """True if [::1]:port accepts an IPv6 TCP connection."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((HOST6, port, 0, 0))
            return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _ipv6_webdav(requires_ipv6_loopback):
    """Gate the whole module on IPv6 loopback + a live ipv6-webdav instance, and
    seed a readable file into the (shared-filesystem) data root.

    Depending on the session-scoped ``requires_ipv6_loopback`` makes every test a
    clean no-op on hosts without usable ``::1``.  We then probe the dedicated
    instance and skip if it is down — instance-absent never reddens the suite.
    """
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    # The dedicated instance shares this local filesystem (DATA_DIR ==
    # IPV6_WEBDAV_DATA_ROOT == ${TEST_ROOT}/data-ipv6-webdav).  start-all creates
    # and seeds it, but a TEST_SKIP_SERVER_SETUP run may target a freshly wiped
    # tree, so seed a known-readable file defensively.
    os.makedirs(IPV6_WEBDAV_DATA_ROOT, exist_ok=True)
    seed_path = os.path.join(IPV6_WEBDAV_DATA_ROOT, SEED_NAME)
    with open(seed_path, "wb") as f:
        f.write(SEED_CONTENT)

    if not reachable6(IPV6_WEBDAV_PORT):
        pytest.skip(
            f"dedicated ipv6-webdav nginx not reachable on [::1]:{IPV6_WEBDAV_PORT} — "
            f"run tests/manage_test_servers.sh start-all"
        )


# ---------------------------------------------------------------------------
# URL + method helpers (mirror tests/test_http_webdav.py /
# test_http_webdav_status_codes.py, retargeted at http://[::1]:PORT).
# ---------------------------------------------------------------------------
def _url(path):
    return f"{BASE_URL}{path}"


def _uid():
    return uuid.uuid4().hex[:12]


def _put(path, data=b"", **kw):
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
    headers = {"Destination": f"{BASE_URL}{dst}", "Overwrite": overwrite}
    headers.update(kw.pop("headers", {}))
    return requests.request("MOVE", _url(src), headers=headers, timeout=10, **kw)


def _copy(src, dst, overwrite="T", depth=None, **kw):
    headers = {"Destination": f"{BASE_URL}{dst}", "Overwrite": overwrite}
    if depth is not None:
        headers["Depth"] = depth
    headers.update(kw.pop("headers", {}))
    return requests.request("COPY", _url(src), headers=headers, timeout=10, **kw)


def _lock(path, timeout=None, **kw):
    headers = {}
    if timeout:
        headers["Timeout"] = f"Second-{timeout}"
    headers.update(kw.pop("headers", {}))
    body = kw.pop(
        "data",
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<D:lockinfo xmlns:D="DAV:">'
        "<D:lockscope><D:exclusive/></D:lockscope>"
        "<D:locktype><D:write/></D:locktype>"
        "</D:lockinfo>",
    )
    return requests.request(
        "LOCK", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _unlock(path, token, **kw):
    if not token.startswith("<"):
        token = f"<{token}>"
    headers = {"Lock-Token": token}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "UNLOCK", _url(path), headers=headers, timeout=10, **kw
    )


def _hrefs(xml_text):
    """Return every <D:href> text from a 207 Multi-Status body.

    NOTE: this descends into *all* hrefs, including those nested inside live
    properties such as ``<D:owner><D:href>...</D:href></D:owner>`` (the DAV:owner
    principal href, e.g. ``anonymous``).  It is the right helper for the
    host-literal scan (a bare ``::1`` must not appear in *any* href) but it
    over-counts for "one response per resource" assertions — use
    ``_response_hrefs`` for those.
    """
    root = ET.fromstring(xml_text)
    return [el.text or "" for el in root.iter(f"{{{DAV_NS}}}href")]


def _response_hrefs(xml_text):
    """Return one resource href per ``<D:response>`` — the direct-child
    ``<D:response><D:href>`` only, ignoring hrefs nested inside live properties
    (e.g. the ``<D:owner>`` principal href).  This is the per-resource count the
    PROPFIND multistatus actually models."""
    root = ET.fromstring(xml_text)
    out = []
    for resp in root.iter(f"{{{DAV_NS}}}response"):
        href = resp.find(f"{{{DAV_NS}}}href")
        if href is not None:
            out.append(href.text or "")
    return out


# ---------------------------------------------------------------------------
# OPTIONS  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_options_returns_200():
    """REGRESSION: OPTIONS over [::1] returns 200 with a DAV-capable Allow set."""
    r = requests.options(_url("/"), timeout=10)
    assert r.status_code == 200
    allow = r.headers.get("Allow", "")
    assert "GET" in allow and "PUT" in allow
    assert "PROPFIND" in allow
    # The DAV: compliance header advertises WebDAV class 1/2.
    assert "DAV" in r.headers


# ---------------------------------------------------------------------------
# PUT / GET / HEAD — byte-exact round-trip  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_put_and_get_byte_exact():
    """REGRESSION: anonymous PUT then GET over [::1] is byte-exact."""
    uid = _uid()
    path = f"/ipv6_put_{uid}.txt"
    content = f"ipv6 webdav payload {uid}".encode()

    r = _put(path, content)
    assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"

    r = _get(path)
    assert r.status_code == 200
    assert r.content == content


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_get_seeded_file_byte_exact():
    """REGRESSION: GET of the pre-seeded file returns its exact bytes."""
    r = _get(f"/{SEED_NAME}")
    assert r.status_code == 200
    assert r.content == SEED_CONTENT


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_head_returns_content_length():
    """REGRESSION: HEAD returns 200 with the correct Content-Length."""
    uid = _uid()
    path = f"/ipv6_head_{uid}.txt"
    content = b"ipv6 head object content"

    _put(path, content)

    r = _head(path)
    assert r.status_code == 200
    assert int(r.headers.get("Content-Length", -1)) == len(content)


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_get_missing_returns_404():
    """REGRESSION: GET of a missing path is 404; IPv6 takes the same code path."""
    r = _get(f"/ipv6_no_such_{_uid()}.bin")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Range GET  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_range_request():
    """REGRESSION: a partial (Range) GET returns 206 with the exact slice."""
    uid = _uid()
    path = f"/ipv6_range_{uid}.bin"
    content = b"0123456789abcdef"

    _put(path, content)

    r = requests.get(
        _url(path), headers={"Range": "bytes=4-13"}, timeout=10
    )
    assert r.status_code == 206
    assert r.content == b"456789abcd"
    assert len(r.content) == 10
    assert r.headers.get("Content-Range", "").startswith("bytes 4-13/")


# ---------------------------------------------------------------------------
# Want-Digest  (REGRESSION/SMOKE) — XrdHttp checksum header over IPv6
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_want_digest_adler32():
    """REGRESSION: a Want-Digest: adler32 GET over [::1] attaches a Digest header
    whose adler32 matches the file content (adler32 is the canonical, always-wired
    XrdHttp checksum)."""
    uid = _uid()
    path = f"/ipv6_digest_{uid}.bin"
    content = f"ipv6 digest payload {uid}".encode()
    _put(path, content)

    r = requests.get(_url(path), headers={"Want-Digest": "adler32"}, timeout=10)
    assert r.status_code == 200
    digest = r.headers.get("Digest", "")
    assert "adler32=" in digest.lower(), f"no adler32 Digest: {digest!r}"
    expected = f"{zlib.adler32(content) & 0xFFFFFFFF:08x}"
    assert expected in digest.lower(), f"{digest!r} vs adler32={expected}"


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_want_digest_sha256():
    """REGRESSION: Want-Digest: sha-256 → Digest header matching the file hash.
    sha-256 is an OpenSSL EVP path; if a build omits it the server simply returns
    no sha-256 Digest, so we skip cleanly rather than hard-fail on an absent (not
    wrong) header."""
    uid = _uid()
    path = f"/ipv6_sha_{uid}.bin"
    content = f"ipv6 sha256 payload {uid}".encode()
    _put(path, content)

    r = requests.get(_url(path), headers={"Want-Digest": "sha-256"}, timeout=10)
    assert r.status_code == 200
    digest = r.headers.get("Digest", "")
    if not digest or "sha" not in digest.lower():
        pytest.skip(f"sha-256 Digest not produced by this build: {digest!r}")
    # XrdHttp emits base64 of the raw sha-256; just assert the algorithm token is
    # present and the value is non-empty (exact-encoding parity is covered by the
    # IPv4 XrdHttp suite).
    assert "sha" in digest.lower()
    assert "=" in digest


# ---------------------------------------------------------------------------
# DELETE  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_delete_file():
    """REGRESSION: DELETE removes the file; a subsequent GET is 404."""
    uid = _uid()
    path = f"/ipv6_del_{uid}.txt"

    _put(path, b"to be deleted")

    r = _delete(path)
    assert r.status_code in (200, 204), f"DELETE failed: {r.status_code}"

    r = _get(path)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# MKCOL  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_mkcol_directory():
    """REGRESSION: MKCOL creates a collection; a child PUT then succeeds."""
    uid = _uid()
    dir_path = f"/ipv6_dir_{uid}"

    r = _mkcol(dir_path)
    assert r.status_code in (200, 201), f"MKCOL failed: {r.status_code}"

    child = f"{dir_path}/child.txt"
    r = _put(child, b"in collection")
    assert r.status_code in (200, 201)
    assert _get(child).content == b"in collection"


# ---------------------------------------------------------------------------
# MOVE / COPY  (GATING — re-emitted Destination must not carry a bare literal)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_move_destination_header_bracketed():
    """GATING (§3 propfind/move emit contract): MOVE with a bracketed IPv6
    Destination (``http://[::1]:PORT/dst``) succeeds — src gone, dst present —
    and the server never reflects a *bare* (unbracketed) ``::1`` authority back
    into a Location/Destination header it emits."""
    uid = _uid()
    src = f"/ipv6_move_src_{uid}.txt"
    dst = f"/ipv6_move_dst_{uid}.txt"
    content = f"ipv6 move {uid}".encode()

    _put(src, content)

    r = _move(src, dst)
    assert r.status_code in (201, 204), f"MOVE failed: {r.status_code} {r.text}"

    assert _get(src).status_code == 404, "source must be gone after MOVE"
    moved = _get(dst)
    assert moved.status_code == 200
    assert moved.content == content

    # Any reflected authority (Location) must be bracketed, never bare ::1.
    loc = r.headers.get("Location", "")
    if "::1" in loc:
        assert "[::1]" in loc, f"bare IPv6 literal in MOVE Location: {loc!r}"


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_copy_destination_header():
    """GATING (§3 propfind/move emit contract): COPY with a bracketed IPv6
    Destination duplicates the file (src kept, dst byte-exact) with no host
    corruption in any emitted authority."""
    uid = _uid()
    src = f"/ipv6_copy_src_{uid}.txt"
    dst = f"/ipv6_copy_dst_{uid}.txt"
    content = f"ipv6 copy {uid}".encode()

    _put(src, content)

    r = _copy(src, dst)
    assert r.status_code in (201, 204), f"COPY failed: {r.status_code} {r.text}"

    assert _get(src).status_code == 200, "source must remain after COPY"
    copied = _get(dst)
    assert copied.status_code == 200
    assert copied.content == content

    loc = r.headers.get("Location", "")
    if "::1" in loc:
        assert "[::1]" in loc, f"bare IPv6 literal in COPY Location: {loc!r}"


# ---------------------------------------------------------------------------
# PROPFIND depth 0 / 1  (GATING — hrefs must be relative, no host literal)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_propfind_depth_0():
    """GATING (§3 webdav/propfind.c href contract): PROPFIND Depth: 0 returns 207
    with exactly one well-formed <D:href> for the file itself, and the href is a
    path (relative) — it must NOT embed the IPv6 host literal in any form."""
    uid = _uid()
    path = f"/ipv6_pf0_{uid}.txt"
    _put(path, b"propfind depth0")

    r = _propfind(path, depth="0")
    assert r.status_code == 207, f"PROPFIND failed: {r.status_code} {r.text}"

    # Count one href per <D:response> (depth 0 == exactly the resource itself).
    # The allprop body also carries a nested <D:owner><D:href> principal href,
    # which _hrefs() would over-count — _response_hrefs() ignores it.
    resp_hrefs = _response_hrefs(r.text)
    assert len(resp_hrefs) == 1, f"depth 0 must yield one response, got {resp_hrefs}"
    href = resp_hrefs[0]
    assert href.endswith(f"ipv6_pf0_{uid}.txt"), href
    # The host-literal invariant still scans every href (incl. nested ones).
    for h in _hrefs(r.text):
        _assert_href_has_no_host_literal(h)


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_propfind_depth_1():
    """GATING (§3 webdav/propfind.c href contract): PROPFIND Depth: 1 on a
    collection returns 207 with the collection itself plus each member, every
    <D:href> well-formed and host-literal-free."""
    uid = _uid()
    coll = f"/ipv6_pf1_{uid}"
    _mkcol(coll)
    members = [f"{coll}/m{i}.txt" for i in range(3)]
    for m in members:
        _put(m, b"member")

    r = _propfind(coll, depth="1")
    assert r.status_code == 207, f"PROPFIND failed: {r.status_code} {r.text}"

    hrefs = _hrefs(r.text)
    # collection + 3 members.
    assert len(hrefs) >= 4, f"expected collection + 3 members, got {hrefs}"
    for href in hrefs:
        _assert_href_has_no_host_literal(href)
    # Each member name appears in some href.
    for i in range(3):
        assert any(h.endswith(f"m{i}.txt") for h in hrefs), f"m{i}.txt missing"


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_propfind_href_no_host_literal():
    """GATING (§3 href contract): assert directly that no emitted href contains
    the IPv6 host literal in any form (``::1`` / ``[::1]`` / ``[::``).  This is
    the precise wire-bracketing invariant the §3 fixes encode for WebDAV: hrefs
    are server-relative paths, never absolute ``http://[::1]:PORT/...`` URLs that
    could carry (or worse, *mangle*) the authority."""
    uid = _uid()
    coll = f"/ipv6_pfhost_{uid}"
    _mkcol(coll)
    _put(f"{coll}/f.txt", b"x")

    r = _propfind(coll, depth="1")
    assert r.status_code == 207
    for href in _hrefs(r.text):
        _assert_href_has_no_host_literal(href)


def _assert_href_has_no_host_literal(href: str):
    """A WebDAV href must not embed the IPv6 host literal.  A bare ``::1`` would
    be the §3 bracket bug; an absolute ``http://[::1]:PORT/...`` (bracketed or
    not) is also wrong here because nginx emits server-relative hrefs."""
    for bad in ("::1", "[::1]", "[::"):
        assert bad not in href, f"href carries IPv6 host literal {bad!r}: {href!r}"


# ---------------------------------------------------------------------------
# PROPFIND allprop properties  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_propfind_allprop_properties():
    """REGRESSION: a Depth: 0 allprop PROPFIND exposes the standard live
    properties (getcontentlength / getlastmodified / resourcetype)."""
    uid = _uid()
    path = f"/ipv6_props_{uid}.bin"
    _put(path, b"0123456789")  # 10 bytes

    r = _propfind(path, depth="0")
    assert r.status_code == 207
    body = r.text
    assert "getcontentlength" in body
    assert "getlastmodified" in body
    assert "resourcetype" in body
    # The reported length must match the body we wrote.
    root = ET.fromstring(body)
    lengths = [
        el.text for el in root.iter(f"{{{DAV_NS}}}getcontentlength")
    ]
    assert "10" in lengths, f"getcontentlength wrong: {lengths}"


# ---------------------------------------------------------------------------
# LOCK / UNLOCK  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_lock_then_unlock():
    """REGRESSION: LOCK over [::1] returns 201 with an opaquelocktoken Lock-Token
    that PROPFIND surfaces in <D:lockdiscovery>, and UNLOCK with that token
    releases the lock (re-LOCK then succeeds)."""
    uid = _uid()
    path = f"/ipv6_lock_{uid}.txt"

    r = _lock(path)
    assert r.status_code == 201, f"LOCK failed: {r.status_code} {r.text}"
    assert "Lock-Token" in r.headers
    token = r.headers["Lock-Token"].strip("<>")
    assert "opaquelocktoken:" in token

    # PROPFIND surfaces the active lock.
    pf = _propfind(path, depth="0")
    assert pf.status_code == 207
    assert "<D:lockdiscovery>" in pf.text
    assert token in pf.text

    # UNLOCK releases it.
    r = _unlock(path, token)
    assert r.status_code == 204, f"UNLOCK failed: {r.status_code}"

    # Re-LOCK now succeeds (lock truly released).
    r = _lock(path)
    assert r.status_code in (200, 201)


@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_lock_enforces_put_without_token():
    """REGRESSION: a locked resource rejects a PUT lacking the lock token (423),
    and accepts it once the token is supplied in the If: header — lock semantics
    are unchanged over IPv6."""
    uid = _uid()
    path = f"/ipv6_lockenf_{uid}.txt"

    r = _lock(path)
    assert r.status_code == 201
    token = r.headers["Lock-Token"]

    r = _put(path, b"blocked")
    assert r.status_code == 423, f"locked PUT must be 423, got {r.status_code}"

    r = _put(path, b"allowed", headers={"If": f"({token})"})
    assert r.status_code in (200, 201, 204)
    assert _get(path).content == b"allowed"


# ---------------------------------------------------------------------------
# Overwrite  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_overwrite_existing():
    """REGRESSION: a second PUT overwrites the object; GET returns the new body."""
    uid = _uid()
    path = f"/ipv6_overwrite_{uid}.txt"

    _put(path, b"original")
    _put(path, b"updated")

    r = _get(path)
    assert r.status_code == 200
    assert r.content == b"updated"


# ---------------------------------------------------------------------------
# Security-negative: path traversal must not bypass confinement over IPv6
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_path_traversal_rejected():
    """SECURITY-NEG: a ``../`` escape PUT is rejected (never 200/201/500); IPv6
    does not bypass the confined-resolver contract enforced for every transport.

    The ``requests``/``urllib`` client normalises ``/../../../etc/X`` to
    ``/etc/X`` before it reaches the wire, so the server sees a PUT into a parent
    collection (``/etc``) that does not exist inside the confined data root and
    answers ``409 Conflict`` (the same missing-parent semantics as
    ``test_put_to_missing_parent_409``).  That is a valid rejection: confinement
    holds (nothing is created outside the root) and the request never succeeds.
    409 is therefore part of the accepted-rejection set; the gating assertion
    below still pins "no escape, no crash" (never 200/201/500).
    """
    uid = _uid()
    r = _put(f"/../../../etc/ipv6_escape_{uid}", b"blocked")
    assert r.status_code in (400, 403, 404, 409), (
        f"path-traversal PUT must be rejected, got {r.status_code}"
    )
    assert r.status_code not in (200, 201, 500)
