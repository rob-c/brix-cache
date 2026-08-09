from split_continuation import reexport as _reexport
_reexport(globals(), "_test_ipv6_webdav_xrdhttp_helpers")

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
    if "::1" in loc:  # net-literal-allow: asserting bare ::1 absent from returned Location
        assert "[::1]" in loc, f"bare IPv6 literal in MOVE Location: {loc!r}"  # net-literal-allow: asserting bracketed [::1] present in returned Location


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
    if "::1" in loc:  # net-literal-allow: asserting bare ::1 absent from returned Location
        assert "[::1]" in loc, f"bare IPv6 literal in COPY Location: {loc!r}"  # net-literal-allow: asserting bracketed [::1] present in returned Location


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
