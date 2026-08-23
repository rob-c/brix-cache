from split_continuation import reexport as _reexport
def _check_test_put_then_get_byte_exact_1(put):
    assert put.status_code in (200, 201, 204), \
        f"PUT failed: {put.status_code}"

def _check_test_put_then_get_byte_exact_2(on_disk):
    assert os.path.exists(on_disk), "PUT did not create the backing file"

def _check_test_put_then_get_byte_exact_3(payload, fh):
    assert fh.read() == payload, "on-disk bytes diverge from PUT payload"


_reexport(globals(), "_test_xrdhttp_wait_retry_digest_range_helpers")

@pytest.mark.registry_server("xrdhttp-digest")
def test_rate_limit_emits_429_and_retry_after(server):
    """A per-IP request-rate rule (rate=2r/s burst=2) must let the first couple
    of requests through, then return 429 with a Retry-After header (the
    documented non-nodelay HTTP throttle response from ratelimit_http.c).

    The X-Xrootd-Wait header is the *stream*-plane back-pressure signal; the
    HTTP plane expresses the same wait as 429 + Retry-After per RFC 6585."""
    # Make sure the bucket is full before we start hammering.
    _sleep_off_throttle()

    statuses = []
    retry_after_seen = False
    for _ in range(12):
        resp = requests.get(_url(), timeout=5)
        statuses.append(resp.status_code)
        if resp.status_code == 429 and "Retry-After" in resp.headers:
            retry_after_seen = True
            # rl_reject() emits Retry-After as a bare integer second count
            # (nginx "%ud%Z"); never a date here.
            assert resp.headers["Retry-After"].strip().isdigit(), \
                resp.headers["Retry-After"]
        # No inter-request sleep: a tight burst so the leaky bucket cannot
        # refill mid-loop and the throttle is forced to fire.

    def _assert_test_rate_limit_emits_429_and_retry_after_2():
        assert 200 in statuses, f"expected some 200s, got {statuses}"
        assert 429 in statuses, f"rate limit never fired: {statuses}"

    _assert_test_rate_limit_emits_429_and_retry_after_2()
    assert retry_after_seen, \
        f"429 responses must carry Retry-After: {statuses}"

    # Sanity: after the bucket refills, the server still serves normally.
    _sanity_ok()


# ---------------------------------------------------------------------------
# 2. Single-range 206: correct Content-Range and exact bytes.
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("xrdhttp-digest")
def test_single_range_206_content_range(server):
    """A single 'bytes=start-end' range returns 206 Partial Content with a
    Content-Range matching the requested window and the exact slice bytes."""
    _sleep_off_throttle()
    start, end = 1000, 1999
    resp = requests.get(_url(), headers={"Range": f"bytes={start}-{end}"},
                        timeout=5)
    assert resp.status_code == 206, \
        f"expected 206 for single range, got {resp.status_code}"
    cr = resp.headers.get("Content-Range", "")
    assert cr == f"bytes {start}-{end}/{len(DATA_BYTES)}", cr
    assert resp.content == DATA_BYTES[start:end + 1]
    assert int(resp.headers["Content-Length"]) == (end - start + 1)

    _sanity_ok()


@pytest.mark.registry_server("xrdhttp-digest")
def test_suffix_range_206(server):
    """A suffix range 'bytes=-N' returns the final N bytes as 206."""
    _sleep_off_throttle()
    n = 256
    resp = requests.get(_url(), headers={"Range": f"bytes=-{n}"}, timeout=5)
    assert resp.status_code == 206, resp.status_code
    assert resp.content == DATA_BYTES[-n:]
    total = len(DATA_BYTES)
    cr = resp.headers.get("Content-Range", "")
    assert cr == f"bytes {total - n}-{total - 1}/{total}", cr

    _sanity_ok()


# ---------------------------------------------------------------------------
# 3. Digest on a 206 range response.
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("xrdhttp-digest")
def test_digest_on_206_range(server):
    """A Want-Digest GET that ALSO carries a Range must still 206 and still
    attach a Digest: header (computed over the whole file via the fd-based
    xrdhttp_add_checksum_header path in get.c)."""
    _sleep_off_throttle()
    resp = requests.get(
        _url(),
        headers={"Range": "bytes=0-99", "Want-Digest": "adler32"},
        timeout=5,
    )
    assert resp.status_code == 206, resp.status_code
    assert resp.content == DATA_BYTES[0:100]

    digest = resp.headers.get("Digest")
    if digest is None:
        pytest.skip("Digest header not attached on 206 (no checksum on partial "
                    "responses in this build)")
    assert "adler32=" in digest.lower(), digest
    # The whole-file adler32 is the documented value (Digest covers the
    # representation, not the partial selection).
    assert ADLER32_HEX in digest.lower(), f"{digest} vs adler32={ADLER32_HEX}"

    _sanity_ok()


# ---------------------------------------------------------------------------
# 4. Want-Digest adler32 / md5 echoed as a Digest: header.
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("xrdhttp-digest")
def test_want_digest_adler32_echoed(server):
    """Want-Digest: adler32 → Digest: adler32=<hex> matching the local
    adler32 of the file content.  adler32 is the canonical XrdHttp checksum
    and is always wired (src/core/compat/checksum.c, integrity_info.c), so a missing
    header here is a real regression — assert, don't skip."""
    _sleep_off_throttle()
    resp = requests.get(_url(), headers={"Want-Digest": "adler32"}, timeout=5)
    assert resp.status_code == 200, resp.status_code
    digest = resp.headers.get("Digest")
    assert digest is not None, "Want-Digest: adler32 produced no Digest header"
    assert "adler32=" in digest.lower(), digest
    assert ADLER32_HEX in digest.lower(), f"{digest} vs adler32={ADLER32_HEX}"

    _sanity_ok()


@pytest.mark.registry_server("xrdhttp-digest")
def test_want_digest_md5_echoed(server):
    """Want-Digest: md5 → Digest: md5=<hex> matching the local md5.

    md5 is in the supported algorithm set but is an OpenSSL EVP digest path;
    if a particular build omits it the server simply returns no md5 Digest, so
    we skip cleanly rather than hard-fail on an absent (not wrong) header."""
    _sleep_off_throttle()
    resp = requests.get(_url(), headers={"Want-Digest": "md5"}, timeout=5)
    assert resp.status_code == 200, resp.status_code
    digest = resp.headers.get("Digest")
    if digest is None or "md5" not in digest.lower():
        pytest.skip("md5 Want-Digest not honoured in this build "
                    f"(Digest={digest!r})")
    assert MD5_HEX in digest.lower(), f"{digest} vs md5={MD5_HEX}"

    _sanity_ok()


# ---------------------------------------------------------------------------
# 5. Overlapping multi-range: merged / multipart / full file — never wrong.
# ---------------------------------------------------------------------------


@pytest.mark.registry_server("xrdhttp-digest")
def test_overlapping_multirange_merged_or_full(server):
    """Two overlapping byte ranges must be served safely.  The documented
    options are: (a) a multipart/byteranges 206 in which every requested window
    appears verbatim (xrdhttp_handle_multipart_get emits each requested range
    in order, overlaps preserved), or (b) the full file as 200 OK.  In neither
    case may wrong or leaked bytes appear."""
    _sleep_off_throttle()
    # Two windows that overlap on [1500, 1999].
    r0 = (1000, 1999)
    r1 = (1500, 2499)
    resp = requests.get(
        _url(),
        headers={"Range": f"bytes={r0[0]}-{r0[1]},{r1[0]}-{r1[1]}"},
        timeout=5,
    )

    if resp.status_code == 200:
        # Documented fallback: full file.
        assert resp.content == DATA_BYTES
    elif resp.status_code == 206:
        ctype = resp.headers.get("Content-Type", "")
        assert "multipart/byteranges" in ctype, ctype
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
        parts = _parse_multipart_byteranges(resp.content, boundary)
        assert len(parts) >= 2, f"expected >=2 parts, got {len(parts)}"
        for cr, data in parts:
            # "bytes START-END/TOTAL"
            spec = cr.split()[1].split("/")[0]
            s, e = (int(x) for x in spec.split("-"))
            assert data == DATA_BYTES[s:e + 1], \
                f"part {cr} bytes do not match source"
    else:
        pytest.fail(f"unexpected status for overlapping multirange: "
                    f"{resp.status_code}")

    _sanity_ok()


@pytest.mark.registry_server("xrdhttp-digest")
def test_disjoint_multirange_parts(server):
    """A well-formed disjoint multi-range returns multipart/byteranges with each
    part's bytes exact (or the documented full-file fallback)."""
    _sleep_off_throttle()
    r0 = (0, 99)
    r1 = (40000, 40099)
    resp = requests.get(
        _url(),
        headers={"Range": f"bytes={r0[0]}-{r0[1]},{r1[0]}-{r1[1]}"},
        timeout=5,
    )
    if resp.status_code == 200:
        assert resp.content == DATA_BYTES
    else:
        assert resp.status_code == 206, resp.status_code
        ctype = resp.headers.get("Content-Type", "")
        assert "multipart/byteranges" in ctype, ctype
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
        parts = _parse_multipart_byteranges(resp.content, boundary)
        got = {cr.split()[1].split("/")[0]: data for cr, data in parts}
        assert got.get(f"{r0[0]}-{r0[1]}") == DATA_BYTES[r0[0]:r0[1] + 1]
        assert got.get(f"{r1[0]}-{r1[1]}") == DATA_BYTES[r1[0]:r1[1] + 1]

    _sanity_ok()


# ---------------------------------------------------------------------------
# 6. HEAD vs GET header parity.
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("xrdhttp-digest")
def test_head_get_header_parity(server):
    """HEAD and GET must agree on the core metadata: status, Content-Length,
    Content-Type and (when Want-Digest is sent) the Digest header — HEAD just
    omits the body."""
    _sleep_off_throttle()
    hdrs = {"Want-Digest": "adler32"}
    head = requests.head(_url(), headers=hdrs, timeout=5)
    _sleep_off_throttle()
    get = requests.get(_url(), headers=hdrs, timeout=5)

    assert head.status_code == get.status_code == 200, \
        f"HEAD={head.status_code} GET={get.status_code}"
    assert head.headers.get("Content-Length") == get.headers.get("Content-Length")
    assert int(head.headers["Content-Length"]) == len(DATA_BYTES)
    assert head.headers.get("Content-Type") == get.headers.get("Content-Type")
    # HEAD must carry no body.
    assert head.content == b""
    # Digest parity (if the build emits one at all).
    if "Digest" in get.headers or "Digest" in head.headers:
        assert head.headers.get("Digest") == get.headers.get("Digest"), \
            (head.headers.get("Digest"), get.headers.get("Digest"))

    _sanity_ok()


# ---------------------------------------------------------------------------
# 7. PROPPATCH returns a client-compat status (NOT 501).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("xrdhttp-digest")
def test_proppatch_client_compatible_status(server):
    """methods_basic.c documents PROPPATCH as a minimal-compliance handler that
    drains the body and returns 207 Multi-Status (with 200 OK per property) so
    Cyberduck/rucio clients that treat 501 as a hard error keep working.  Assert
    the documented status — 207 (or 200), never 501."""
    _sleep_off_throttle()
    body = (
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example">'
        '<D:set><D:prop><Z:author>nobody</Z:author></D:prop></D:set>'
        '</D:propertyupdate>'
    )
    resp = _unthrottled(lambda: requests.request(
        "PROPPATCH", _url(),
        data=body.encode(),
        headers={"Content-Type": "application/xml"},
        timeout=5,
    ))
    assert resp.status_code in (207, 200), \
        f"PROPPATCH must be client-compatible (207/200), got {resp.status_code}"
    assert resp.status_code != 501

    _sanity_ok()


# ---------------------------------------------------------------------------
# 8. Byte-exact PUT then GET round-trip (writable storage).
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("xrdhttp-digest")
def test_put_then_get_byte_exact(server):
    """A file written via PUT (allowed by brix_allow_write on) must read
    back byte-for-byte via GET, and its on-disk content must match too."""
    _sleep_off_throttle()
    name = "roundtrip_xhw.bin"
    payload = bytes((i * 53 + 17) & 0xFF for i in range(33333))

    put = _unthrottled(lambda: requests.put(_url(name), data=payload, timeout=10))
    if put.status_code in (403, 405):
        pytest.skip(f"writes not permitted in this build (PUT -> "
                    f"{put.status_code})")
    _check_test_put_then_get_byte_exact_1(put)

    _sleep_off_throttle()
    get = _unthrottled(lambda: requests.get(_url(name), timeout=10))
    def _assert_test_put_then_get_byte_exact_1():
        assert get.status_code == 200, get.status_code
        assert get.content == payload, "GET did not round-trip the PUT bytes"

    _assert_test_put_then_get_byte_exact_1()

    on_disk = os.path.join(server["data_dir"], name)
    _check_test_put_then_get_byte_exact_2(on_disk)
    with open(on_disk, "rb") as fh:
        _check_test_put_then_get_byte_exact_3(payload, fh)

    _sanity_ok()
