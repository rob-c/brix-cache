"""
tests/test_xrdhttp_wait_retry_digest_range.py — XrdHttp/WebDAV HTTP-plane
conformance for rate-limit back-pressure, RFC-3230 content digests, and
RFC-7233 byte-range serving.

This suite drives a DEDICATED, fleet-managed cleartext (no-TLS) HTTP WebDAV
nginx — a single worker over an isolated, writable data root
(`brix_allow_write on;`) with a deliberately tight per-IP
`brix_rate_limit_zone` / `brix_rate_limit_rule` so the throttle path can be
driven deterministically.  The instance is started once by
`manage_test_servers.sh start-all` (config `tests/configs/nginx_xrdhttp_digest.conf`,
port `XRDHTTP_DIGEST_PORT`); the suite seeds its fixture file into the data root
and connects, rather than spawning its own server.  It then proves the documented
HTTP behaviour of src/protocols/webdav (get.c, methods_basic.c, xrdhttp.c,
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
    "<alg>=<hex>" (brix_integrity_format_http_digest()).
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

import fcntl
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


@pytest.fixture(autouse=True)
def _rate_budget_mutex():
    """Serialize this module's tests across pytest-xdist workers.

    The dedicated xrdhttp-digest server enforces a per-IP rate rule (2r/s
    burst=2) and every worker arrives from 127.0.0.1, so the leaky bucket is
    ONE shared budget for the whole run. Under `--dist load` the module's
    tests land on several workers at once and drain it continuously — seen
    live as all-429 responses even straight after _sleep_off_throttle().
    Holding this cross-process flock for the duration of each test gives it
    the bucket to itself; the _sleep_off_throttle() every test starts with
    then genuinely refills it."""
    lock_path = os.path.join(os.path.dirname(DATA_DIR), "xrdhttp-digest.rate.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o666)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


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


def _unthrottled(fn, attempts=6):
    """Issue a request (a zero-arg callable returning a Response), retrying on a
    transient 429 by honouring Retry-After.  The per-IP leaky bucket (2r/s) that
    these functional tests share can still be momentarily spent under heavy load
    even after _sleep_off_throttle(); RFC 6585 says a client backs off and
    retries, so the test does the same instead of failing on a transient
    throttle.  A persistent 429 (bucket never refills — a real regression) still
    surfaces after the attempts are exhausted; non-429 responses return at once."""
    resp = fn()
    for _ in range(attempts - 1):
        if resp.status_code != 429:
            return resp
        ra = resp.headers.get("Retry-After", "").strip()
        time.sleep((float(ra) if ra.isdigit() else 1.5) + 0.25)
        resp = fn()
    return resp


def _sanity_ok(name=DATA_NAME):
    """A plain GET proving the server/connection survived the prior edge op."""
    _sleep_off_throttle()
    resp = _unthrottled(lambda: requests.get(_url(name), timeout=5))
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
