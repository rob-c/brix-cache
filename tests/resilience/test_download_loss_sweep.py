"""
test_download_loss_sweep.py — DOWNLOAD-side faults on the WebDAV and S3 planes.

THE GAP: every HTTP-family fault test in `tests/resilience/` injected on the
UPLOAD leg (`corrupt ... up` against PUT). The download leg — the direction in
which a cache, a worker node, or a `xrdcp`-equivalent actually pulls data — had
no loss, truncation or corruption coverage on either plane, and no test asserted
that a client CAN tell a damaged download from a good one.
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §6 + item 16.

MEASURED CONTRACT (scratch probes, 2026-08-05; `brix-fault-proxy` in path,
faults applied `down` = server->client):

    fault                    WebDAV GET              S3 GET
    none                     200, byte-exact         200, byte-exact
    lossy 5                  IncompleteRead          IncompleteRead
    truncate-at n            IncompleteRead          IncompleteRead
    corrupt 0.01 down        200, body ALTERED       200, body ALTERED
    truncate-at > range      206, byte-exact         206, byte-exact

The two failure modes are different in kind and that is the point:

  * A severed or truncated stream is caught by HTTP framing itself — the body is
    shorter than `Content-Length`, so the client raises rather than returning a
    short read. What must never happen is a silent 200 with a short body.
  * A LENGTH-PRESERVING bit flip is invisible to HTTP. The only defence is an
    end-to-end digest, and the two planes differ:
      - WebDAV answers `Want-Digest: md5|adler32|sha-256` with a real `Digest`
        header computed over the object, so a client that asks CAN detect it.
      - S3 offers no digest channel, and its `ETag` is `s3_etag()` =
        mtime+size (`src/protocols/s3/util.c:167`), NOT the object MD5 that the
        AWS contract promises for a single-part object. An S3 client that
        verifies a download against the ETag — the documented way — is verifying
        nothing. Pinned below as a *known exposure*, not asserted as correct.

Trio per CLAUDE.md:
  * success   — with the proxy in path and no fault, both planes are byte-exact
                and the WebDAV `Digest` matches the true md5 (the integrity
                channel is honest, so a later mismatch means something).
  * error     — loss and truncation are always surfaced as a failure, never as a
                silent short body; a truncation point beyond a Range request
                does not disturb that request (no false positive).
  * security  — a length-preserving corruption is caught by the WebDAV digest
                channel, and is NOT caught by the S3 ETag: the ETag is identical
                before and after, so an ETag-verifying client would accept
                poisoned bytes.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_download_loss_sweep.py -v
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from settings import HOST  # noqa: E402

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

pytestmark = pytest.mark.timeout(300)

SIZE = 2 * 1024 * 1024        # big enough that a per-chunk fault is near-certain
KEY = "sweep.bin"
CORRUPT_PCT = 0.01            # per-byte flip probability; ~200 flips at 2 MiB
LOSS_PCT = 5                  # per-chunk probability of severing the stream


def _why_skip():
    if not os.path.isfile(servers.NGINX_BIN):
        return f"nginx not built: {servers.NGINX_BIN}"
    if not os.path.isfile(servers.FAULT_PROXY):
        return f"brix-fault-proxy not built: {servers.FAULT_PROXY}"
    if not _HAVE_REQUESTS:
        return "python requests not available"
    return None


_skip_reason = _why_skip()
if _skip_reason:
    pytest.skip(_skip_reason, allow_module_level=True)


class Plane:
    """One HTTP-family server, its fault proxy, and the seeded object.

    `direct` bypasses the proxy — used to read the server's own view (headers,
    digests) without a fault in the way.
    """

    def __init__(self, kind):
        self.kind = kind
        self._stack = []

    def __enter__(self):
        cls = servers.NginxWebdavAnon if self.kind == "webdav" else servers.NginxS3Anon
        self.ng = cls().__enter__()
        self._stack.append(self.ng)
        self.fp = servers.FaultProxy(self.ng.port).__enter__()
        self._stack.append(self.fp)

        self.body = os.urandom(SIZE)
        self.md5 = hashlib.md5(self.body).hexdigest()
        with open(os.path.join(self.ng.data, KEY), "wb") as fh:
            fh.write(self.body)

        tail = KEY if self.kind == "webdav" else f"{servers.NginxS3Anon.bucket}/{KEY}"
        self.through = f"http://{HOST}:{self.fp.listen}/{tail}"
        self.direct = f"http://{HOST}:{self.ng.port}/{tail}"
        return self

    def __exit__(self, *exc):
        for obj in reversed(self._stack):
            obj.__exit__(*exc)
        return False


@pytest.fixture(scope="module", params=["webdav", "s3"])
def plane(request):
    with Plane(request.param) as p:
        yield p
        p.fp.clear()


@pytest.fixture(autouse=True)
def _no_leftover_faults(plane):
    """Every test starts from a clean proxy, whatever the previous one set."""
    plane.fp.clear()
    yield
    plane.fp.clear()


# --------------------------------------------------------------------------- #
# Success — the un-faulted path, and an honest integrity channel.              #
# --------------------------------------------------------------------------- #
def test_clean_download_through_the_proxy_is_byte_exact(plane):
    """No false positive: the fault proxy in path costs nothing when idle."""
    r = requests.get(plane.through, timeout=120)
    assert r.status_code == 200
    assert r.content == plane.body
    assert int(r.headers["Content-Length"]) == SIZE


def test_webdav_advertises_a_digest_that_matches_the_object(plane):
    """The WebDAV integrity channel is honest — a later mismatch means damage.

    S3 has no `Want-Digest` support at all, which is the exposure pinned by
    test_s3_etag_does_not_detect_corruption below.
    """
    if plane.kind != "webdav":
        pytest.skip("S3 exposes no Want-Digest channel — see the ETag test")
    r = requests.head(plane.direct, headers={"Want-Digest": "md5"}, timeout=60)
    assert r.status_code == 200
    assert r.headers["Digest"] == f"md5={plane.md5}"


def test_range_read_under_a_later_truncation_point_is_unaffected(plane):
    """The cut is armed past the end of the range, so the range must complete."""
    plane.fp.set_truncate(SIZE // 4, "down")
    r = requests.get(plane.through, headers={"Range": "bytes=0-1023"}, timeout=120)
    assert r.status_code == 206
    assert r.content == plane.body[:1024]


# --------------------------------------------------------------------------- #
# Error — damage that changes the LENGTH is always surfaced.                   #
# --------------------------------------------------------------------------- #
def test_truncated_download_is_never_a_silent_short_body(plane):
    """A mid-body sever must raise, not return 200 with half the object."""
    plane.fp.set_truncate(SIZE // 2, "down")
    with pytest.raises(requests.exceptions.RequestException):
        r = requests.get(plane.through, timeout=120)
        # If the client did NOT raise, the only acceptable outcome is the whole
        # object; a short 200 body is the failure this test exists to catch.
        assert r.content == plane.body, (
            f"silent short body: {len(r.content)} of {SIZE} bytes, "
            f"status {r.status_code}")


def test_lossy_download_either_fails_or_delivers_everything(plane):
    """Under 5% per-chunk loss, every outcome is all-or-raise across rounds."""
    plane.fp.set_loss(LOSS_PCT)
    saw_failure = False
    for _ in range(6):
        try:
            r = requests.get(plane.through, timeout=120)
        except requests.exceptions.RequestException:
            saw_failure = True
            continue
        assert r.content == plane.body, (
            f"partial body returned as success: {len(r.content)} of {SIZE}")
    assert saw_failure, "loss never fired — the sweep proved nothing"


# --------------------------------------------------------------------------- #
# Security — length-preserving corruption, and what each plane can do about it.#
# --------------------------------------------------------------------------- #
def test_corruption_is_invisible_to_http_but_caught_by_the_digest(plane):
    """WebDAV: the bytes arrive altered with a clean 200, and only the digest
    the server advertises separates them from a good download."""
    if plane.kind != "webdav":
        pytest.skip("S3 exposes no Want-Digest channel — see the ETag test")
    advertised = requests.head(plane.direct, headers={"Want-Digest": "md5"},
                               timeout=60).headers["Digest"]
    plane.fp.set_corrupt(CORRUPT_PCT, "down")
    for _ in range(8):
        try:
            r = requests.get(plane.through, timeout=120)
        except requests.exceptions.RequestException:
            continue        # the flip landed in the response headers — still caught
        if r.status_code != 200 or r.content == plane.body:
            continue        # no flip landed in the body this round
        got = f"md5={hashlib.md5(r.content).hexdigest()}"
        assert got != advertised, "corrupted body matched the advertised digest"
        return
    pytest.fail("never observed a corrupted-body round to judge")


def test_s3_etag_does_not_detect_corruption(plane):
    """KNOWN EXPOSURE, pinned so a change is deliberate.

    `s3_etag()` is mtime+size (`src/protocols/s3/util.c:167`), so the ETag of a
    corrupted download is identical to the ETag of the object: an S3 client that
    follows the AWS contract — single-part ETag == object MD5 — would accept the
    poisoned bytes. Nothing here asserts that is *right*; it asserts what a
    caller may rely on today, so closing the gap has to break this test.
    """
    if plane.kind != "s3":
        pytest.skip("the ETag contract under test is the S3 one")
    etag = requests.head(plane.direct, timeout=60).headers["ETag"]
    assert plane.md5 not in etag, (
        "the ETag is now digest-backed — update the integrity story, this test "
        "pins the weak-ETag exposure")
    plane.fp.set_corrupt(CORRUPT_PCT, "down")
    for _ in range(8):
        try:
            r = requests.get(plane.through, timeout=120)
        except requests.exceptions.RequestException:
            continue
        if r.status_code != 200 or r.content == plane.body:
            continue
        assert r.headers.get("ETag") == etag, (
            "unexpected: the ETag moved with the corrupted body")
        return
    pytest.fail("never observed a corrupted-body round to judge")
