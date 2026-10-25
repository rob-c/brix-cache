"""Per-page origin verification: `verify_pages` on a root:// store line.

WHAT: brix (WebDAV read node, PRIMARY storage = root:// origin) ─► a scriptable
      XRootD origin (_test_phase115_pgread_verify_helpers.PgOrigin).

WHY:  phase-115 W4.3.  A plain kXR_read carries NO integrity: TCP's 16-bit
      checksum is not a guarantee, and an in-path box that mutates bytes is
      exactly the deployment this project targets.  `brix_cache_verify` closes
      only half the gap — it checks a COMPLETED fill against a whole-file
      digest, so it cannot help a partial/slice read (no whole file to hash)
      or an origin that advertises no digest at all.  `verify_pages` closes the
      other half: the read is issued as kXR_pgread and every 4 KiB page's
      CRC32c is checked before the byte reaches the caller.

      The contract this suite pins:
        1 SUCCESS  — a page-reading origin serves BYTE-EXACT under both modes,
                     and the origin really was asked to page-read.
        2 NEG      — a single corrupted page is REFUSED even though every other
                     byte is perfect (the whole-file digest path cannot see
                     this on a range read).
        3 COMPAT   — an origin that cannot page-read: `require` fails closed,
                     `best-effort` falls back to kXR_read and still serves —
                     asking ONCE per open, not once per 1 MiB chunk.
        4 HOSTILE  — a well-formed frame carrying pages for an offset nobody
                     requested is refused (it would otherwise be a
                     write-anywhere primitive), and an endless train of empty
                     PARTIAL frames is refused rather than wedging the worker.
        5 SHAPE    — a refusal reaches the CLIENT as a transport abort, never
                     as a short body that could pass for a legitimate EOF.
                     See REFUSAL_ABORTS: the CRC mismatch is discovered after
                     the headers are committed, so aborting is the only
                     refusal left — and the only one a client cannot mistake
                     for success.

Run:
  TEST_NGINX_BIN=/path/to/objs/nginx \\
    PYTHONPATH=tests python3 -m pytest tests/test_phase115_pgread_verify.py -v
"""
import hashlib
import struct
from types import SimpleNamespace

import pytest
import requests

import _test_phase115_pgread_verify_helpers as page_fixture
from _test_phase115_pgread_verify_helpers import PgOrigin
from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-pgread-verify"),
              pytest.mark.timeout(180)]

# 40 KiB — 10 full pages, small enough that the pure-Python CRC32c in the stub
# is instant, large enough that a single dropped or duplicated page shows up.
PAYLOAD = bytes((i * 31 + 7) & 0xFF for i in range(40 * 1024))
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()

# A read window that spans several pages but stays inside one 1 MiB origin
# chunk, so a leg that fails on the FIRST frame is unambiguous.
RANGE_LEN = 9000


@pytest.mark.parametrize('payload,expected', [(b'', 0), (b'123456789', 0xE3069283)])
def test_fixture_checksum_keeps_independent_castagnoli_vectors(payload, expected):
    assert page_fixture._page_checksum(payload, {}) == expected


def _count_fixture_checksums(monkeypatch):
    calls = []
    original = page_fixture.crc32c

    def checksum(payload):
        calls.append(payload)
        return original(payload)

    monkeypatch.setattr(page_fixture, 'crc32c', checksum)
    return calls


def test_fixture_checksum_cache_is_scoped_to_one_response(monkeypatch):
    page = bytes(range(256)) * 16
    calls = _count_fixture_checksums(monkeypatch)
    first = page_fixture.pack_pages(page * 3, 0)
    second = page_fixture.pack_pages(page * 3, 0)
    assert first == second
    assert calls == [page, page]


def test_fixture_checksum_cache_does_not_hide_changed_page_bytes():
    page = bytes(range(256)) * 16
    changed = bytes([page[0] ^ 1]) + page[1:]
    checksums = {}
    assert page_fixture._page_checksum(page, checksums) == page_fixture.crc32c(page)
    assert page_fixture._page_checksum(changed, checksums) == page_fixture.crc32c(changed)
    assert checksums[page] != checksums[changed]


def test_fixture_checksum_cache_cannot_poison_neighbouring_pages(monkeypatch):
    page = bytes(range(256)) * 16
    checksum = page_fixture.crc32c(page)
    good = struct.pack('!I', checksum) + page
    bad = struct.pack('!I', checksum ^ 0xDEADBEEF) + page
    calls = _count_fixture_checksums(monkeypatch)
    assert page_fixture.pack_pages(page * 3, 0, corrupt_page=1) == good + bad + good
    assert calls == [page]


def test_fixture_checksum_cache_stays_bounded_when_every_page_is_distinct():
    checksums = {}
    for index in range(66):
        page = bytes([index]) * 4096
        assert page_fixture._page_checksum(page, checksums) == page_fixture.crc32c(page)
    assert len(checksums) == 64
    assert all(len(page) <= 4096 for page in checksums)


@pytest.mark.parametrize('offset', [1, 17, 4095, 4096])
def test_fixture_checksum_cache_preserves_unaligned_page_boundaries(offset):
    payload = bytes(range(256)) * 33
    first = 4096 - offset % 4096
    chunks = [payload[:first], *(payload[pos:pos + 4096]
              for pos in range(first, len(payload), 4096))]
    expected = b''.join(struct.pack('!I', page_fixture.crc32c(chunk)) + chunk
                        for chunk in chunks if chunk)
    assert page_fixture.pack_pages(payload, offset) == expected


def _queued_fixture_connections(monkeypatch, behaviour, origin_class=PgOrigin):
    """Capture worker starts without opening sockets or depending on timing."""
    queued, closed, observed = [], [], []
    origin = origin_class.__new__(origin_class)
    origin.connections = 0
    origin._lock = page_fixture.threading.Lock()
    origin._connection_context = page_fixture.threading.local()
    origin.behaviour = behaviour
    origin._request_loop = lambda connection: None
    origin._perform_handshake = lambda connection: observed.append(
        (connection.index, origin._connection_context.index)) or True

    def worker(*, target, args, daemon):
        assert daemon is True
        return SimpleNamespace(start=lambda: queued.append((target, args)))

    monkeypatch.setattr(page_fixture.threading, 'Thread', worker)
    for index in range(4):
        connection = SimpleNamespace(index=index, settimeout=lambda _: None,
            close=lambda item=index: closed.append(item))
        origin._start_connection(connection)
    return origin, queued, closed, observed


@pytest.mark.parametrize('behaviour,expected', [
    ('ok', [3, 2, 1, 0]),
    ('handshake_poison_recovery', [2, 1, 0]),
    ('frame_poison_recovery', [2, 1, 0]),
])
def test_fixture_connection_faults_follow_accept_order_even_when_workers_reverse(
        monkeypatch, behaviour, expected):
    origin, queued, closed, observed = _queued_fixture_connections(monkeypatch, behaviour)
    assert origin.connections == 4
    for target, arguments in reversed(queued):
        target(*arguments)
    assert observed == [(index, index) for index in expected]
    assert sorted(closed) == [0, 1, 2, 3]


def test_fixture_connection_dispatch_preserves_single_argument_subclass_hooks(monkeypatch):
    class CallbackOrigin(PgOrigin):
        def _serve(self, connection):
            self.callbacks.append((connection.index, self._connection_context.index,
                                   self._connection_context.postlogin_protocols))
            connection.close()

    origin, queued, closed, _ = _queued_fixture_connections(monkeypatch, 'ok', CallbackOrigin)
    origin.callbacks = []
    for target, arguments in reversed(queued):
        target(*arguments)
    assert origin.callbacks == [(index, index, 0) for index in (3, 2, 1, 0)]
    assert sorted(closed) == [0, 1, 2, 3]


@pytest.mark.parametrize('behaviour', ['ok', 'corrupt', 'bad_status_crc'])
def test_fixture_pgread_coalescing_preserves_normal_and_hostile_wire_bytes(behaviour):
    origin = PgOrigin.__new__(PgOrigin)
    origin.behaviour, origin.corrupt_page = behaviour, 1
    sid, offset = b'\x00\x17', 17
    payload = bytes(range(256)) * 48
    corruption = 1 if behaviour == 'corrupt' else -1
    pages = page_fixture.pack_pages(payload, offset, corruption)
    status = page_fixture.pgread_status_frame(sid, offset, len(pages))
    if behaviour == 'bad_status_crc':
        status = status[:8] + bytes([status[8] ^ 0x80]) + status[9:]
    writes = []
    origin._send_pgread(SimpleNamespace(sendall=writes.append), sid, offset, payload)
    assert writes == [status + pages]


def _node(lifecycle, name, origin, policy):
    """A WebDAV read node whose primary storage is `origin`, with `policy` (a
    store-line param string, possibly empty) appended to the store line."""
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_p115_pgread_verify.conf",
        protocol="http",
        readiness="tcp",
        template_values={
            "BIND_HOST": HOST,
            "BACKEND": f"root://{HOST}:{origin.port}{policy}",
        },
        reason="Phase-115 W4.3: per-page origin verification (verify_pages).",
    ))


def _get(inst, headers=None, timeout=30):
    return requests.get(f"http://{HOST}:{inst.port}/f.bin",
                        headers=headers or {}, timeout=timeout)


# The wire forms a refusal can legitimately take, discovered by running this
# suite against the real server rather than assumed when it was written.
#
# A per-page CRC32c failure is found MID-BODY: `sd_xroot_pread` has already
# returned some verified pages to the serve path, the response headers (and a
# Content-Length taken from the origin stat) are long gone, and the read fails
# with EIO.  There is no status code left to send.  The only refusal available
# at that point is to abort the connection, which is what nginx does — and it
# is the RIGHT one: the client gets a transport error, not a short body it
# might mistake for a legitimate EOF.  requests surfaces that as
# ConnectionError/ChunkedEncodingError raised out of `get`, so a refusal has to
# be an outcome this suite can hold, not an exception that kills the row before
# its assertion runs.
REFUSAL_ABORTS = (requests.exceptions.ConnectionError,
                  requests.exceptions.ChunkedEncodingError)


def _attempt(inst, headers=None, timeout=30):
    """GET the object, returning the aborted connection instead of raising.

    Used by every row that expects a REFUSAL.  The success rows deliberately
    keep using `_get`, so an abort there is still a hard error rather than a
    quietly tolerated outcome.
    """
    try:
        return _get(inst, headers=headers, timeout=timeout)
    except REFUSAL_ABORTS as exc:
        return exc


def _served(resp):
    """Did the client receive the complete, correct object?

    An aborted connection is emphatically not served — and answering False
    here rather than raising is what lets the refusal rows state their
    assertion in terms of the contract instead of the transport.
    """
    if isinstance(resp, BaseException):
        return False
    return resp.status_code == 200 and \
        hashlib.sha256(resp.content).hexdigest() == DIGEST


# --- 1 SUCCESS ---------------------------------------------------------------

@pytest.mark.parametrize("policy,name", [
    (" verify_pages", "req"),                  # the bare token means require
    (" verify_pages=best-effort", "be"),
])
def test_page_verified_read_is_byte_exact(lifecycle, policy, name):
    """SUCCESS: a page-reading origin serves the file byte-exact under both
    modes, and the origin was asked to PAGE-read — a green byte comparison
    alone would also pass if verify_pages silently did nothing."""
    with PgOrigin(PAYLOAD) as origin:
        inst = _node(lifecycle, f"lc-p115-pgv-ok-{name}", origin, policy)
        resp = _get(inst)
        assert _served(resp), f"status={resp.status_code} len={len(resp.content)}"
        pgreads, reads = origin.counts()
        assert pgreads > 0, "verify_pages did not issue a single kXR_pgread"
        assert reads == 0, f"fell back to plain kXR_read {reads}x with a " \
                           f"page-capable origin"


def test_partial_range_is_page_verified_too(lifecycle):
    """SUCCESS/design: a RANGE read is exactly the case the whole-file digest
    engine cannot cover — there is no complete file to hash — so it is the case
    verify_pages exists for.  The bytes must match the slice, page-read."""
    with PgOrigin(PAYLOAD) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-range", origin, " verify_pages")
        resp = _get(inst, headers={"Range": f"bytes=0-{RANGE_LEN - 1}"})
        assert resp.status_code in (200, 206), resp.status_code
        assert resp.content == PAYLOAD[:len(resp.content)], "range mismatch"
        assert origin.counts()[0] > 0, "range read did not use kXR_pgread"


def test_without_the_param_the_origin_is_never_page_read(lifecycle):
    """SUCCESS/control: the default is unchanged.  Without `verify_pages` the
    driver must issue plain kXR_read — this is what makes every assertion above
    about the param and not about the driver."""
    with PgOrigin(PAYLOAD) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-default", origin, "")
        assert _served(_get(inst))
        pgreads, reads = origin.counts()
        assert pgreads == 0, "page-read without being asked to"
        assert reads > 0


# --- 2 NEG (the security negative) -------------------------------------------

def test_one_corrupted_page_is_refused(lifecycle):
    """NEG: every byte the origin sends is plausible and the frame is
    well-formed; ONE page's CRC32c is wrong.  The read must NOT succeed with
    those bytes.  This is the corruption a whole-file digest cannot catch on a
    range read and TCP cannot catch at all."""
    with PgOrigin(PAYLOAD, behaviour="corrupt", corrupt_page=3) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-corrupt", origin, " verify_pages")
        resp = _attempt(inst)
        assert not _served(resp), (
            "served a page whose CRC32c did not match — verify_pages is a "
            f"no-op (status={resp.status_code}, {len(resp.content)} bytes)")


def test_corruption_is_refused_under_best_effort_too(lifecycle):
    """NEG: best-effort relaxes WHICH ORIGINS may be read, never WHETHER a
    delivered page is checked.  A page that fails its own checksum is a
    corrupt page under every mode."""
    with PgOrigin(PAYLOAD, behaviour="corrupt", corrupt_page=0) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-corrupt-be", origin,
                     " verify_pages=best-effort")
        assert not _served(_attempt(inst)), "best-effort served a corrupt page"


# --- 3 COMPAT ----------------------------------------------------------------

def test_require_fails_closed_against_a_pre_pgread_origin(lifecycle):
    """COMPAT/teeth: an origin that does not advertise kXR_suppgrw cannot be
    read verified.  Under `require` the read must FAIL rather than quietly
    degrade — otherwise any origin could disarm the policy by staying silent.
    And it must fail WITHOUT a wasted round trip: the capability came from the
    kXR_protocol advert, so no kXR_pgread is ever sent."""
    with PgOrigin(PAYLOAD, advertise=False) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-noadv-req", origin,
                     " verify_pages=require")
        resp = _attempt(inst)
        assert not _served(resp), "require served unverified bytes"
        pgreads, _ = origin.counts()
        assert pgreads == 0, "asked an origin that advertised no pgread support"


def test_best_effort_serves_a_pre_pgread_origin(lifecycle):
    """COMPAT: the same origin under best-effort still serves — this is what
    isolates require's teeth from plumbing that would break every read."""
    with PgOrigin(PAYLOAD, advertise=False) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-noadv-be", origin,
                     " verify_pages=best-effort")
        assert _served(_get(inst)), "best-effort refused a pre-5.x origin"
        pgreads, reads = origin.counts()
        assert pgreads == 0 and reads > 0


def test_advertise_then_refuse_is_handled_and_asked_only_once(lifecycle):
    """COMPAT (the discovered case): an origin may advertise kXR_suppgrw and
    still answer kXR_pgread with kXR_Unsupported — a federation whose export
    disabled paged reads.  best-effort must fall back and serve, and must
    record the verdict per OPEN: one refused pgread, not one per chunk."""
    with PgOrigin(PAYLOAD, behaviour="refuse") as origin:
        inst = _node(lifecycle, "lc-p115-pgv-refuse-be", origin,
                     " verify_pages=best-effort")
        assert _served(_get(inst)), "no fallback after a late pgread refusal"
        pgreads, reads = origin.counts()
        assert pgreads >= 1 and reads > 0
        assert pgreads <= 2, (
            f"asked {pgreads}x — the refusal must be remembered for the open, "
            f"not rediscovered per chunk")


def test_advertise_then_refuse_still_fails_closed_under_require(lifecycle):
    """COMPAT/teeth: the same origin under `require` must refuse.  The fallback
    is a concession to best-effort only; require means never an unverified
    byte, whichever layer the origin says no at."""
    with PgOrigin(PAYLOAD, behaviour="refuse") as origin:
        inst = _node(lifecycle, "lc-p115-pgv-refuse-req", origin,
                     " verify_pages=require")
        assert not _served(_attempt(inst)), "require served after a pgread refusal"


# --- 4 HOSTILE ---------------------------------------------------------------

def test_pages_for_an_unrequested_offset_are_refused(lifecycle):
    """HOSTILE: the frame is well-formed and every page checksum is correct —
    only the file offset is not the one requested.  Trusting it would let an
    origin place bytes anywhere in the caller's buffer, so it must be refused,
    not written at the offset the client wanted."""
    with PgOrigin(PAYLOAD, behaviour="bad_offset") as origin:
        inst = _node(lifecycle, "lc-p115-pgv-badoff", origin, " verify_pages")
        assert not _served(_attempt(inst)), "accepted pages for another offset"


def test_endless_empty_partial_frames_do_not_wedge_the_worker(lifecycle):
    """HOSTILE: an endless train of PARTIAL frames carrying no pages makes no
    progress.  A reader that simply loops until FINAL holds a thread-pool
    worker forever; the refusal must be prompt.  The assertion is the timeout
    itself — this test hanging IS the bug."""
    with PgOrigin(PAYLOAD, behaviour="empty_partial") as origin:
        inst = _node(lifecycle, "lc-p115-pgv-empty", origin, " verify_pages")
        resp = _attempt(inst, timeout=45)
        assert not _served(resp), "served bytes from a no-progress train"


# --- 5 SHAPE: what the refusal looks like from the client -------------------

def _assert_clean_prefix(body: bytes, page: int) -> None:
    """STREAMED refusal: a byte-exact prefix that stops before `page`."""
    assert PAYLOAD.startswith(body), (
        f"{len(body)} bytes were delivered that are not a clean prefix of the "
        "object — a page that failed its CRC32c reached the client")
    assert len(body) <= page * 4096, (
        f"delivered {len(body)} bytes, past the corrupt page at offset "
        f"{page * 4096} — verification is happening behind the send")


def _assert_no_object_bytes(body: bytes, status, page: int) -> None:
    """MATERIALISED refusal: a status whose body is not the object.

    Both directions are needed.  The first catches the corrupt page arriving
    inside an error response; the second catches the partially filled scratch
    being sent AS the error response, which delivers only clean pages and so
    survives the first.
    """
    assert PAYLOAD[page * 4096:(page + 1) * 4096] not in body, (
        f"the page that failed its CRC32c reached the client inside a "
        f"{status} body of {len(body)} bytes")
    assert body == b"" or not PAYLOAD.startswith(body), (
        f"a {status} body is a {len(body)}-byte prefix of the object — the "
        "partially filled scratch was sent as the error response")


def test_a_refused_read_delivers_no_corrupt_bytes(lifecycle):
    """SECURITY-NEGATIVE for the refusal SHAPE, not just its verdict.

    `not _served(...)` alone would also pass if the node handed back the
    corrupt page and then aborted — the caller would still have the bad bytes
    in hand.  The page that failed its CRC32c must never appear in whatever the
    client did receive.

    There are two honest shapes for that, and §P5 moved this door from the
    first to the second:

    * STREAMED — the response header is already on the wire, the read fails
      behind it, and the client is left holding a byte-exact PREFIX that stops
      before the bad page.
    * MATERIALISED — the object is read and verified into a buffer before any
      header is composed, so the failure still has a status line to travel in
      and the body is an error page carrying no object bytes at all.

    §P5 made the memfile fill ask for the whole remainder in one `pread`
    instead of stepping through it in 64 KiB, so the corrupt page is now hit
    while the memfd is still being built — before the serve has decided
    anything about the response.  The second shape is strictly stronger (a
    truncated 200 can only be caught by comparing what arrived against
    Content-Length; a status cannot be missed) and is what the sibling row
    below asks for, but a door that streams is not wrong, so both are accepted.
    What is NOT accepted, in either shape, is a body that reaches the corrupt
    page — which is the single property this row exists to hold.
    """
    with PgOrigin(PAYLOAD, behaviour="corrupt", corrupt_page=3) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-shape-bytes", origin,
                     " verify_pages")
        resp = _attempt(inst)
        assert not _served(resp)
        body = b"" if isinstance(resp, BaseException) else resp.content
        status = None if isinstance(resp, BaseException) else resp.status_code

        if status is not None and status // 100 == 2:
            _assert_clean_prefix(body, 3)
        else:
            _assert_no_object_bytes(body, status, 3)


def test_the_refusal_is_an_abort_and_not_a_silent_short_read(lifecycle):
    """SECURITY-NEGATIVE: the failure must be undeniable at the transport.

    The dangerous alternative is a clean 200 whose body simply stops early:
    with the Content-Length the origin stat produced, that is indistinguishable
    from a legitimate EOF to any client that does not check, and a corrupt
    object would be cached downstream as a good one.  Corrupt page 0, so not a
    single verified byte can precede the failure.
    """
    with PgOrigin(PAYLOAD, behaviour="corrupt", corrupt_page=0) as origin:
        inst = _node(lifecycle, "lc-p115-pgv-shape-abort", origin,
                     " verify_pages")
        resp = _attempt(inst)
        if isinstance(resp, BaseException):
            return                       # an abort: the strongest refusal
        assert resp.status_code != 200, (
            "a 200 whose body stopped short is a silent truncation — the "
            f"client cannot tell it from EOF (got {len(resp.content)} of "
            f"{len(PAYLOAD)} bytes)")
