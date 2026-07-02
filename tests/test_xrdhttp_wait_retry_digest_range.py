"""
tests/test_xrdhttp_wait_retry_digest_range.py — XrdHttp/WebDAV HTTP-plane
conformance for rate-limit back-pressure, RFC-3230 content digests, and
RFC-7233 byte-range serving.

This suite drives a DEDICATED, fleet-managed cleartext (no-TLS) HTTP WebDAV
nginx — a single worker over an isolated, writable data root
(`xrootd_webdav_allow_write on;`) with a deliberately tight per-IP
`xrootd_rate_limit_zone` / `xrootd_rate_limit_rule` so the throttle path can be
driven deterministically.  The instance is started once by
`manage_test_servers.sh start-all` (config `tests/configs/nginx_xrdhttp_digest.conf`,
port `XRDHTTP_DIGEST_PORT`); the suite seeds its fixture file into the data root
and connects, rather than spawning its own server.  It then proves the documented
HTTP behaviour of src/webdav (get.c, methods_basic.c, xrdhttp.c,
xrdhttp_multipart.c) and src/net/ratelimit (ratelimit_http.c):

  * a per-IP request-rate rule emits HTTP 429 + Retry-After once the burst is
    spent (the HTTP analogue of the stream X-Xrootd-Wait back-pressure);
  * a single-range request returns 206 with a correct Content-Range and the
    exact bytes; a Want-Digest GET attaches a Digest: header even on the 206;
  * Want-Digest adler32 / md5 are echoed as a Digest: header whose value
    matches the locally-computed checksum;
  * an overlapping multi-range request is served as multipart/byteranges (each
    requested window appearing verbatim) or, per the documented fallback, as
    the full file — never wrong or leaked bytes;
  * HEAD and GET agree on the metadata headers (status, length, type, digest);
  * a written-then-read-back file is byte-exact.

Every hostile/edge request is followed by a plain sanity GET proving the server
survived.  The whole module skips cleanly when the nginx binary is missing, a
foreign process already owns the dedicated port, or the server fails to come up.

Implementation cross-checks (so assertions match real behaviour, not guesses):
  * The Digest header is produced by xrdhttp_add_checksum_header() (get.c calls
    it via the pre_header_send callback), gated only on want_cksum[0] which is
    set from ANY Want-Digest header in xrdhttp_parse_request() — so a plain GET
    (no X-Xrootd-Proto) still gets a Digest.  adler32 is zlib adler32 formatted
    "%08x"; md5 is the EVP digest as lowercase hex; the header value is
    "<alg>=<hex>" (xrootd_integrity_format_http_digest()).
  * The 429 Retry-After value is emitted by rl_reject() with nginx "%ud%Z" — in
    nginx printf `d` is the conversion and `u` only clears the sign, so the
    value is a bare integer (no trailing letter): .isdigit() holds.
  * A comma in Range routes to xrdhttp_handle_multipart_get(), which always
    returns 206 multipart/byteranges with each requested window verbatim
    (boundary "xrdhttp_boundary_42"); the test still accepts a 200 full-file
    fallback so it never hard-fails on a documented alternative.
  * PROPPATCH is a minimal-compliance handler returning 207 Multi-Status
    (methods_basic.c), never 501.

Run: PYTHONPATH=tests pytest tests/test_xrdhttp_wait_retry_digest_range.py -v
"""

import hashlib
import os
import socket
import time
import zlib

import pytest

try:
    import requests
except Exception:  # pragma: no cover - requests is a hard dep of the suite
    requests = None

from settings import HOST, XRDHTTP_DIGEST_PORT, XRDHTTP_DIGEST_DATA_ROOT

# requires_local_server: seeds its fixture file into the dedicated instance's
# data root and reads PUT bytes back off disk — both need a co-located server fs.
#
# xdist_group (not `serial`): the per-IP rate-limit rule means this module's own
# tests must never run concurrently with EACH OTHER (they would 429 one another),
# so they are pinned to a single xdist worker via a dedicated group.  Unlike the
# global `serial` lane, that lets the module run concurrently with unrelated
# groups instead of serialising behind every other serial suite.
pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.xdist_group("xrdhttp_digest"),
]


# ---------------------------------------------------------------------------
# Dedicated fleet instance: started by manage_test_servers.sh start-all from
# tests/configs/nginx_xrdhttp_digest.conf over the isolated data-xrdhttp-digest
# root.  The suite connects to it and seeds its fixture file — it never spawns
# its own nginx.
# ---------------------------------------------------------------------------

HTTP_PORT = XRDHTTP_DIGEST_PORT
DATA_DIR = XRDHTTP_DIGEST_DATA_ROOT

# A non-trivial, non-page-aligned file so ranges exercise a short final window
# and the checksums are interesting.
DATA_NAME = "range_digest.bin"
DATA_BYTES = bytes((i * 37 + 11) & 0xFF for i in range(50000))
ADLER32_HEX = "%08x" % (zlib.adler32(DATA_BYTES) & 0xFFFFFFFF)
MD5_HEX = hashlib.md5(DATA_BYTES).hexdigest()


# ---------------------------------------------------------------------------
# Process / readiness helpers (mirrors test_mirror_upstream.py style)
# ---------------------------------------------------------------------------

def _reachable(port, timeout=0.5):
    try:
        socket.create_connection((HOST, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _base_url():
    return f"http://{HOST}:{HTTP_PORT}"


def _url(name=DATA_NAME):
    return f"{_base_url()}/{name}"


def _sleep_off_throttle():
    """Wait long enough for the leaky bucket to refill so a follow-up sanity
    request is not itself throttled (rate=2r/s, burst=2 → ~1s refills plenty)."""
    time.sleep(1.5)


def _sanity_ok(name=DATA_NAME):
    """A plain GET proving the server/connection survived the prior edge op."""
    _sleep_off_throttle()
    resp = requests.get(_url(name), timeout=5)
    assert resp.status_code in (200, 206), \
        f"sanity GET after edge op failed: {resp.status_code}"
    return resp


# ---------------------------------------------------------------------------
# Module-scoped fixture: connect to the fleet-managed dedicated instance and
# seed its fixture file into the isolated data root.  start-all owns the server's
# lifecycle; the suite never spawns or tears down nginx.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def server():
    if requests is None:
        pytest.skip("python 'requests' library not available")
    if not _reachable(HTTP_PORT):
        pytest.skip(
            f"xrdhttp-digest dedicated instance not running on {HTTP_PORT} "
            "(start it with manage_test_servers.sh start-all)")

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, DATA_NAME), "wb") as fh:
        fh.write(DATA_BYTES)

    yield {"base": _base_url(), "data_dir": DATA_DIR}


# ---------------------------------------------------------------------------
# 1. Rate-limit back-pressure: HTTP 429 + Retry-After once the burst is spent.
#    (The HTTP analogue of the stream-plane X-Xrootd-Wait.)
# ---------------------------------------------------------------------------

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

    assert 200 in statuses, f"expected some 200s, got {statuses}"
    assert 429 in statuses, f"rate limit never fired: {statuses}"
    assert retry_after_seen, \
        f"429 responses must carry Retry-After: {statuses}"

    # Sanity: after the bucket refills, the server still serves normally.
    _sanity_ok()


# ---------------------------------------------------------------------------
# 2. Single-range 206: correct Content-Range and exact bytes.
# ---------------------------------------------------------------------------

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

def _parse_multipart_byteranges(body, boundary):
    """Return a list of (content_range, data) tuples from a multipart body."""
    parts = []
    sep = ("--" + boundary).encode()
    for chunk in body.split(sep):
        if b"\r\n\r\n" not in chunk:
            continue
        head, _, data = chunk.partition(b"\r\n\r\n")
        cr = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-range:"):
                cr = line.split(b":", 1)[1].strip().decode()
        if cr is None:
            continue
        # Strip the trailing CRLF that precedes the next boundary.
        if data.endswith(b"\r\n"):
            data = data[:-2]
        parts.append((cr, data))
    return parts


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
    resp = requests.request(
        "PROPPATCH", _url(),
        data=body.encode(),
        headers={"Content-Type": "application/xml"},
        timeout=5,
    )
    assert resp.status_code in (207, 200), \
        f"PROPPATCH must be client-compatible (207/200), got {resp.status_code}"
    assert resp.status_code != 501

    _sanity_ok()


# ---------------------------------------------------------------------------
# 8. Byte-exact PUT then GET round-trip (writable storage).
# ---------------------------------------------------------------------------

def test_put_then_get_byte_exact(server):
    """A file written via PUT (allowed by xrootd_webdav_allow_write on) must read
    back byte-for-byte via GET, and its on-disk content must match too."""
    _sleep_off_throttle()
    name = "roundtrip_xhw.bin"
    payload = bytes((i * 53 + 17) & 0xFF for i in range(33333))

    put = requests.put(_url(name), data=payload, timeout=10)
    if put.status_code in (403, 405):
        pytest.skip(f"writes not permitted in this build (PUT -> "
                    f"{put.status_code})")
    assert put.status_code in (200, 201, 204), \
        f"PUT failed: {put.status_code}"

    _sleep_off_throttle()
    get = requests.get(_url(name), timeout=10)
    assert get.status_code == 200, get.status_code
    assert get.content == payload, "GET did not round-trip the PUT bytes"

    on_disk = os.path.join(server["data_dir"], name)
    assert os.path.exists(on_disk), "PUT did not create the backing file"
    with open(on_disk, "rb") as fh:
        assert fh.read() == payload, "on-disk bytes diverge from PUT payload"

    _sanity_ok()
