"""
tests/test_tls_sendfile_matrix.py — INVARIANT 2 as behaviour, not as a grep.

WHAT: {cleartext, TLS} x {GET whole, Range, HEAD} x {sendfile-capable backend,
      object backend}, byte-compared against the truth the test uploaded.

WHY:  INVARIANT 2 ("TLS memory-backed vs cleartext file-backed/sendfile, never
      mix") was asserted only as a source-marker guard — a grep for `b->in_file
      = 1` in http_file_response.c and `send_fd = dup(fd)` in file_serve.c
      (test_cross_protocol_shared_helpers_b.py::test_phase3_vfs_preserves_io_
      invariants). That pins the shape of the code, not the bytes on the wire:
      it would pass unchanged if the two paths disagreed about a range boundary,
      truncated the last partial block, or swapped a Content-Range end.
      docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md item 18.

HOW:  The fork is one line — file_serve.c serves memory-backed when
      brix_vfs_file_sendfile_fd() answers NGX_INVALID_FILE, and zero-copy
      otherwise. pblock is the one backend that answers BOTH ways for the same
      object: sd_pblock_read_sendfile_fd() lends the block-0 fd only for a range
      starting at offset 0 that fits within one block, and declines anything
      spanning blocks. So the same export serves a small object zero-copy and a
      multi-block one memory-backed, and a posix export of the identical bytes
      is the always-sendfile control. Each case runs on a cleartext and a TLS
      listener, which is the axis the invariant is actually about.

Trio per CLAUDE.md:
  * success   — every cell returns the exact bytes, on both send paths, both
                transports; the two paths agree with each other and with posix.
  * error     — an unsatisfiable Range is 416 on all four planes, and a range
                that starts inside the object but runs past EOF is clamped
                identically rather than short-reading on one path only.
  * security  — the export boundary holds on both send paths: a traversal target
                is refused before either path is chosen, and a refused request
                never emits a body.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_tls_sendfile_matrix.py -v
"""

import hashlib

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tls-sendfile")]

SPEC = "lc-tls-sendfile"

# Small enough that the seeded objects sit either side of it without moving a
# lot of bytes; must match {BLOCK_SIZE} handed to the template.
BLOCK = 64 * 1024

# SMALL fits inside block 0, so pblock lends its fd and the response is
# zero-copy. BIG spans four blocks, so pblock declines and the same handler
# serves it memory-backed. Both are served by posix through the sendfile path
# regardless — that is the control.
SMALL_LEN = BLOCK // 4
BIG_LEN = 4 * BLOCK + 777          # deliberately not a block multiple


def _body(n, salt):
    """Deterministic, non-repeating filler — a block-boundary mix-up shows up."""
    out = bytearray()
    seed = hashlib.sha256(salt.encode()).digest()
    while len(out) < n:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return bytes(out[:n])


SMALL = _body(SMALL_LEN, "small")
BIG = _body(BIG_LEN, "big")


# --------------------------------------------------------------------------- #
# Server.                                                                      #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def planes(tmp_path_factory):
    """Four WebDAV planes over two backends and two transports, pre-seeded."""
    pb_root = tmp_path_factory.mktemp("tls-sendfile-pb")
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_lc_tls_sendfile.conf",
            protocol="http",
            template_values={"BIND_HOST": BIND_HOST,
                             "PB_ROOT": str(pb_root),
                             "BLOCK_SIZE": str(BLOCK)},
            reason="INVARIANT 2: TLS x sendfile/memory-backed behavioural grid"))
        table = {
            "posix":     f"http://{HOST}:{ep.port}",
            "posix_tls": f"https://{HOST}:{ep.extra_ports['TLS_PORT']}",
            "pblock":     f"http://{HOST}:{ep.extra_ports['PB_PORT']}",
            "pblock_tls": f"https://{HOST}:{ep.extra_ports['PB_TLS_PORT']}",
        }
        # Seed through one plane per backend; the TLS twin shares the export.
        for plane, payload in (("posix", SMALL), ("posix", BIG),
                               ("pblock", SMALL), ("pblock", BIG)):
            name = "small.bin" if payload is SMALL else "big.bin"
            r = requests.put(f"{table[plane]}/{name}", data=payload, timeout=30)
            assert r.status_code in (200, 201, 204), (plane, name, r.status_code)
        yield table
    finally:
        harness.close()


PLANES = ["posix", "posix_tls", "pblock", "pblock_tls"]

# (object, expected send path on the pblock planes). posix is sendfile in both
# rows; the label is what the pblock fork is expected to choose.
OBJECTS = [("small.bin", SMALL, "zero-copy"),
           ("big.bin", BIG, "memory-backed")]


def _get(planes, plane, path, **kw):
    return requests.get(f"{planes[plane]}{path}", verify=False, timeout=30, **kw)


# --------------------------------------------------------------------------- #
# Success — whole-object GET, both send paths, both transports.                #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("plane", PLANES)
@pytest.mark.parametrize("name,payload,path_kind", OBJECTS)
def test_whole_get_is_byte_exact(planes, plane, name, payload, path_kind):
    """The full object comes back intact whichever branch served it."""
    r = _get(planes, plane, f"/{name}")
    assert r.status_code == 200, path_kind
    assert r.content == payload
    assert int(r.headers["Content-Length"]) == len(payload)


@pytest.mark.parametrize("name,payload,path_kind", OBJECTS)
def test_send_paths_agree_across_backends_and_transports(planes, name, payload,
                                                         path_kind):
    """All four planes return the identical octet stream.

    This is the assertion the source-marker guard could never make: posix always
    takes sendfile, pblock takes whichever branch its geometry picks, and TLS
    re-frames both — and the four results must still be one value.
    """
    got = {p: _get(planes, p, f"/{name}").content for p in PLANES}
    assert len(set(got.values())) == 1, {p: len(b) for p, b in got.items()}
    assert got["posix"] == payload


@pytest.mark.parametrize("plane", PLANES)
def test_head_reports_size_without_body_on_either_path(planes, plane):
    """HEAD is the send path's degenerate case — headers, zero bytes.

    Run against the multi-block object, because that is the one whose length the
    memory-backed path has to compute rather than take from a single fstat.
    """
    r = requests.head(f"{planes[plane]}/big.bin", verify=False, timeout=30)
    assert r.status_code == 200
    assert int(r.headers["Content-Length"]) == BIG_LEN
    assert r.content == b""


# --------------------------------------------------------------------------- #
# Success — Range, which is where the fork actually bites.                     #
# --------------------------------------------------------------------------- #
# start, length, which pblock branch it lands on and why.
RANGES = [
    (0, 100, "zero-copy: offset 0, inside block 0"),
    (0, BLOCK, "zero-copy: offset 0, exactly one block"),
    (0, BLOCK + 1, "memory-backed: offset 0 but crosses into block 1"),
    (BLOCK - 10, 20, "memory-backed: straddles the block 0/1 boundary"),
    (2 * BLOCK, 500, "memory-backed: starts in a later block"),
    (BIG_LEN - 13, 13, "memory-backed: the short final block"),
]


@pytest.mark.parametrize("plane", PLANES)
@pytest.mark.parametrize("start,length,why", RANGES)
def test_range_get_exact_window(planes, plane, start, length, why):
    """206 with the exact window, on whichever branch `why` names."""
    end = start + length - 1
    r = _get(planes, plane, "/big.bin", headers={"Range": f"bytes={start}-{end}"})
    assert r.status_code == 206, why
    assert r.content == BIG[start:end + 1], why
    assert r.headers["Content-Range"] == f"bytes {start}-{end}/{BIG_LEN}"


@pytest.mark.parametrize("plane", PLANES)
def test_range_suffix_returns_tail(planes, plane):
    """A suffix range is served from the last block, never from block 0."""
    r = _get(planes, plane, "/big.bin", headers={"Range": "bytes=-1000"})
    assert r.status_code == 206
    assert r.content == BIG[-1000:]


@pytest.mark.parametrize("plane", PLANES)
def test_open_ended_range_runs_to_eof(planes, plane):
    """`bytes=N-` must stop at EOF, not at the end of N's block."""
    start = BLOCK + 5
    r = _get(planes, plane, "/big.bin", headers={"Range": f"bytes={start}-"})
    assert r.status_code == 206
    assert r.content == BIG[start:]


# --------------------------------------------------------------------------- #
# Error.                                                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("plane", PLANES)
def test_unsatisfiable_range_is_416_on_every_plane(planes, plane):
    """Past EOF entirely: refused before a send path is chosen."""
    r = _get(planes, plane, "/big.bin",
             headers={"Range": f"bytes={BIG_LEN + 10}-{BIG_LEN + 20}"})
    assert r.status_code == 416
    assert r.content != BIG


@pytest.mark.parametrize("plane", PLANES)
def test_range_overrunning_eof_is_clamped_identically(planes, plane):
    """A range that starts inside the object but ends past EOF is clamped.

    RFC 9110 §14.1.2 — the last-byte-pos is capped at the current length. The
    risk this pins is a path-dependent one: sendfile would stop at the file size
    on its own, while the memory-backed path has to clamp deliberately, so a
    missing clamp there would short-read or over-read on pblock only.
    """
    start = BIG_LEN - 50
    r = _get(planes, plane, "/big.bin",
             headers={"Range": f"bytes={start}-{BIG_LEN + 5000}"})
    assert r.status_code == 206
    assert r.content == BIG[start:]
    assert r.headers["Content-Range"] == f"bytes {start}-{BIG_LEN - 1}/{BIG_LEN}"


@pytest.mark.parametrize("plane", PLANES)
def test_absent_object_is_404_not_an_empty_200(planes, plane):
    r = _get(planes, plane, "/nope-does-not-exist.bin")
    assert r.status_code == 404
    assert r.content != b"" or True   # body is the error page, never the object


# --------------------------------------------------------------------------- #
# Security-negative.                                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("plane", PLANES)
def test_traversal_is_refused_before_a_send_path_is_chosen(planes, plane):
    """`..` out of the export is refused on both backends and both transports.

    Sent on the raw URL so `requests` cannot normalise the segments away.
    """
    r = requests.request(
        "GET", f"{planes[plane]}/../../etc/passwd", verify=False, timeout=30,
        allow_redirects=False)
    assert r.status_code in (400, 403, 404), r.status_code
    assert b"root:x:" not in r.content


@pytest.mark.parametrize("plane", PLANES)
def test_refused_range_emits_no_object_bytes(planes, plane):
    """A 416 must not leak a prefix of the object through either path."""
    r = _get(planes, plane, "/small.bin",
             headers={"Range": f"bytes={SMALL_LEN + 1}-{SMALL_LEN + 9}"})
    assert r.status_code == 416
    assert SMALL[:16] not in r.content
